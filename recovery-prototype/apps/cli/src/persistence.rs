//! Encrypted share storage and session-state persistence.
//!
//! Shares are encrypted at rest with Argon2id-derived AES-256-GCM keys.
//! Phase 1 uses stub passphrases per share type; Phase 2 swaps for
//! hardware-backed key material (Secure Enclave / iCloud / printed-code).

use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use argon2::Argon2;
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use recovery_orchestrator::State;
use serde::{Deserialize, Serialize};
use slf_receipts::Receipt;
use thiserror::Error;

use frost_tier0::{GroupPublicKey, Share};

#[derive(Debug, Error)]
pub enum PersistError {
    #[error("invalid user-id: {0}")]
    InvalidUserId(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("malformed stored data")]
    Malformed,
    #[error("frost: {0}")]
    Frost(#[from] frost_tier0::Error),
}

/// The three share types persisted to disk.
pub enum ShareKind {
    Device,
    Cloud,
    RecoveryCode,
}

impl ShareKind {
    pub fn filename(&self) -> &'static str {
        match self {
            Self::Device => "device.share",
            Self::Cloud => "cloud.share",
            Self::RecoveryCode => "recovery_code.share",
        }
    }

    /// Stub passphrase for Phase 1 (replaced by hardware keys in Phase 2).
    fn passphrase(&self) -> &'static str {
        match self {
            Self::Device => "spa-device-stub",
            Self::Cloud => "spa-cloud-stub",
            Self::RecoveryCode => "spa-recovery-code-stub",
        }
    }
}

/// Handle to a validated per-user directory.
pub struct UserDir(PathBuf);

impl UserDir {
    /// Create or open the per-user directory under `base`.
    ///
    /// Rejects `user_id` values that could cause path traversal:
    /// empty strings, any containing `/`, or containing `..`.
    pub fn new(base: &Path, user_id: &str) -> Result<Self, PersistError> {
        if user_id.is_empty() || user_id.contains('/') || user_id.contains("..") {
            return Err(PersistError::InvalidUserId(user_id.to_owned()));
        }
        let path = base.join(user_id);
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    pub fn share_path(&self, kind: &ShareKind) -> PathBuf {
        self.0.join(kind.filename())
    }

    pub fn group_pubkey_path(&self) -> PathBuf {
        self.0.join("group_pubkey.json")
    }

    pub fn session_path(&self) -> PathBuf {
        self.0.join("session.json")
    }

    pub fn receipts_path(&self) -> PathBuf {
        self.0.join("receipts.json")
    }
}

// ── Encrypted blob ────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct EncryptedBlob {
    salt_hex: String,
    nonce_hex: String,
    ct_hex: String,
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], PersistError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| PersistError::Crypto(e.to_string()))?;
    Ok(key)
}

fn encrypt_blob(passphrase: &str, plaintext: &[u8]) -> Result<EncryptedBlob, PersistError> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| PersistError::Crypto(e.to_string()))?;

    Ok(EncryptedBlob {
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce_bytes),
        ct_hex: hex::encode(ct),
    })
}

fn decrypt_blob(passphrase: &str, blob: &EncryptedBlob) -> Result<Vec<u8>, PersistError> {
    let salt = hex::decode(&blob.salt_hex).map_err(|_| PersistError::Malformed)?;
    let nonce_bytes = hex::decode(&blob.nonce_hex).map_err(|_| PersistError::Malformed)?;
    let ct = hex::decode(&blob.ct_hex).map_err(|_| PersistError::Malformed)?;

    let key = derive_key(passphrase, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ct.as_slice())
        .map_err(|e| PersistError::Crypto(e.to_string()))
}

// ── Share I/O ─────────────────────────────────────────────────────────────────

pub fn save_share(dir: &UserDir, kind: &ShareKind, share: &Share) -> Result<(), PersistError> {
    let blob = encrypt_blob(kind.passphrase(), &share.to_bytes())?;
    let json = serde_json::to_string(&blob)?;
    fs::write(dir.share_path(kind), json)?;
    Ok(())
}

pub fn load_share(dir: &UserDir, kind: &ShareKind) -> Result<Share, PersistError> {
    let json = fs::read_to_string(dir.share_path(kind))?;
    let blob: EncryptedBlob = serde_json::from_str(&json)?;
    let bytes = decrypt_blob(kind.passphrase(), &blob)?;
    Ok(Share::from_bytes(&bytes)?)
}

pub fn delete_share(dir: &UserDir, kind: &ShareKind) -> Result<(), PersistError> {
    let path = dir.share_path(kind);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

// ── Group public key I/O ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct GroupKeyRecord {
    pubkey_hex: String,
    threshold: u16,
}

pub fn save_group_pubkey(dir: &UserDir, gpk: &GroupPublicKey) -> Result<(), PersistError> {
    let record = GroupKeyRecord {
        pubkey_hex: hex::encode(gpk.to_bytes()?),
        threshold: gpk.threshold(),
    };
    fs::write(dir.group_pubkey_path(), serde_json::to_string(&record)?)?;
    Ok(())
}

pub fn load_group_pubkey(dir: &UserDir) -> Result<GroupPublicKey, PersistError> {
    let json = fs::read_to_string(dir.group_pubkey_path())?;
    let record: GroupKeyRecord = serde_json::from_str(&json)?;
    let bytes = hex::decode(&record.pubkey_hex).map_err(|_| PersistError::Malformed)?;
    Ok(GroupPublicKey::from_bytes(&bytes, record.threshold)?)
}

// ── Session state I/O ─────────────────────────────────────────────────────────

/// Persisted session state: lifecycle state + optional test clock.
#[derive(Serialize, Deserialize)]
pub struct SessionRecord {
    pub state: State,
    /// Unix epoch seconds for the injected test clock. `None` in production.
    pub test_clock_epoch_secs: Option<i64>,
}

pub fn save_session(dir: &UserDir, record: &SessionRecord) -> Result<(), PersistError> {
    fs::write(dir.session_path(), serde_json::to_string(record)?)?;
    Ok(())
}

pub fn load_session(dir: &UserDir) -> Result<SessionRecord, PersistError> {
    let json = fs::read_to_string(dir.session_path())?;
    Ok(serde_json::from_str(&json)?)
}

// ── Receipt chain I/O ─────────────────────────────────────────────────────────

pub fn save_receipts(dir: &UserDir, receipts: &[Receipt]) -> Result<(), PersistError> {
    fs::write(dir.receipts_path(), serde_json::to_string(receipts)?)?;
    Ok(())
}

pub fn load_receipts(dir: &UserDir) -> Result<Vec<Receipt>, PersistError> {
    let path = dir.receipts_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let json = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&json)?)
}

pub fn append_receipt(dir: &UserDir, receipt: Receipt) -> Result<(), PersistError> {
    let mut chain = load_receipts(dir)?;
    chain.push(receipt);
    save_receipts(dir, &chain)
}

/// Construct the next receipt in the chain, linking it to the last entry.
pub fn next_receipt(
    dir: &UserDir,
    kind: slf_receipts::ReceiptKind,
    subject: &str,
    timestamp: u64,
    signature: &str,
    payload: serde_json::Value,
) -> Result<Receipt, PersistError> {
    let chain = load_receipts(dir)?;
    let prev_hash = chain.last().map(|r| r.content_hash_hex());
    Ok(Receipt::emit(
        kind, subject, prev_hash, timestamp, signature, payload,
    ))
}

pub fn now_secs(test_epoch: Option<i64>) -> u64 {
    match test_epoch {
        Some(secs) => secs as u64,
        None => Utc::now().timestamp() as u64,
    }
}

pub fn test_clock(epoch_secs: i64) -> recovery_orchestrator::TestClock {
    let dt = DateTime::from_timestamp(epoch_secs, 0).expect("valid epoch");
    recovery_orchestrator::TestClock::new(dt)
}
