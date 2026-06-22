//! Encrypted share storage and session-state persistence.
//!
//! Shares are encrypted at rest with Argon2id-derived AES-256-GCM keys. The
//! Argon2id -> AES-256-GCM construction is unchanged from Phase 1 (ADR-002);
//! what KC-2 (PCC-3158) changed is *where the wrapping secret comes from*.
//!
//! ## Share-at-rest key custody (KC-2)
//!
//! Phase 1 derived the AES key from a per-share **stub passphrase baked into the
//! binary** (`"spa-device-stub"`, ...). Those constants shipped inside the
//! executable, so any reader of a `.share` file was implicitly a reader of the
//! passphrase: the encryption protected nothing against a real attacker.
//!
//! KC-2 replaces the stubs with a [`ShareSource`]. The wrapping secret for every
//! share is now bound to a **per-device root key** ([`DeviceBoundSource`]) that
//! is generated once from OS entropy, stored at `<base>/.spa-device-key` with
//! `0600` permissions, and **never written into a `.share` blob**. A share
//! copied to another host carries no copy of that host-absent root key, so its
//! Argon2id -> AES-GCM key cannot be re-derived and GCM authentication fails.
//! That is the "a copied share file is useless off the originating device"
//! property (proven by the `share_copied_off_device_*` tests below).
//!
//! ## What this is and is NOT (the Phase boundary)
//!
//! The device root key is the prototype **stand-in** for a non-exportable
//! Secure-Enclave key. It is an on-disk `0600` keyfile, not hardware-isolated:
//! an attacker already executing code as the user can still read it. That is the
//! deliberate Phase boundary. Phase 2 swaps [`DeviceBoundSource`] for real
//! backends behind the same [`ShareSource`] trait, with no change to
//! [`save_share`] / [`load_share`] or any caller:
//!
//! | Share           | Phase 1.5 (here)         | Phase 2 backend                                    |
//! |-----------------|--------------------------|----------------------------------------------------|
//! | `device`        | device root key (`0600`) | Secure Enclave — a P-256 key attests the software   |
//! |                 |                          | Ed25519 share (the libsignal P-256-attests-Ed25519 |
//! |                 |                          | bridge); the share lives behind the attestation.   |
//! | `cloud`         | device root key (`0600`) | iCloud Keychain, HSM-wrapped synchronizable item.  |
//! | `recovery_code` | device root key (`0600`) | user-entered 28-char printable code.               |
//!
//! The Ed25519 / Secure-Enclave-P256 gap (the Enclave is P-256-only) is bridged
//! in Phase 2 exactly as ADR-002 "Phase 2 hardware migration" records: an
//! Enclave-resident P-256 key attests a software Ed25519 key and the FROST share
//! lives behind that attestation gate. Implementing the bridge is platform FFI
//! and is tracked as the KC-2 Phase-2 follow-up in the backlog. **All three
//! shares are device-bound in this phase** (decided 2026-06-22): the CLI
//! recovers on a single device, so device-binding `recovery_code` does not break
//! the prototype, and it is strictly stronger than the old binary constant.
//! `recovery_code`'s portable user-code source is a Phase-2 [`ShareSource`]
//! impl, not a regression here.

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

    /// Domain-separation label mixed into the wrapping secret so each share
    /// type derives a distinct AES key from the same device root key. Without
    /// this, all three shares would share a key and a `device.share` blob would
    /// decrypt with the `cloud` secret.
    fn domain_label(&self) -> &'static str {
        match self {
            Self::Device => "spa-share-kc2/device",
            Self::Cloud => "spa-share-kc2/cloud",
            Self::RecoveryCode => "spa-share-kc2/recovery_code",
        }
    }
}

// ── Zeroizing key material ──────────────────────────────────────────────────────

/// Opaque, best-effort zeroizing byte buffer for derived key material.
///
/// The `cli` crate does not depend on the `zeroize` crate and KC-2's file scope
/// is `persistence.rs` only, so this is a local minimal wrapper rather than a
/// `zeroize::Zeroizing`: it overwrites its bytes on drop and uses
/// [`std::hint::black_box`] to keep the optimizer from eliding the writes as
/// dead stores (the workspace forbids `unsafe`, so no `volatile` is available).
/// It is prototype-grade — Phase 2's Secure-Enclave key never enters process
/// memory, which makes this moot.
pub struct Secret(Vec<u8>);

impl Secret {
    /// Wrap raw key material. Phase-2 [`ShareSource`] impls build the secret
    /// they extracted from their backend through this constructor.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
        // Prevent the loop above from being optimized away as dead stores.
        let _ = std::hint::black_box(&self.0);
    }
}

// ── ShareSource: where the wrapping secret comes from ───────────────────────────

/// Source of the secret keying material that wraps a share at rest.
///
/// The one method abstracts *where the wrapping secret comes from*; the
/// Argon2id -> AES-256-GCM derivation around it is fixed (ADR-002). Returning
/// material that never travels with the `.share` file — a device-bound root key,
/// a Secure-Enclave key, a user-entered code — is what makes a copied share
/// useless off the originating device. See the module docs for the Phase-2
/// backends that slot in behind this trait without touching any caller.
pub trait ShareSource {
    /// Yield the wrapping secret for `kind`. The bytes are fed through Argon2id
    /// with a per-file random salt to derive the AES-256-GCM key.
    fn wrapping_secret(&self, kind: &ShareKind) -> Result<Secret, PersistError>;
}

/// Phase-1.5 device-bound [`ShareSource`].
///
/// Derives every share's wrapping secret from a 32-byte per-device root key
/// persisted once at `<base>/.spa-device-key` (`0600`). The root key is the
/// prototype stand-in for the non-exportable Secure-Enclave key; because it is
/// never written into a `.share` blob, a share copied to a host that lacks this
/// device's root key cannot be decrypted.
pub struct DeviceBoundSource {
    root_key: Secret,
}

const DEVICE_KEY_FILE: &str = ".spa-device-key";
const DEVICE_KEY_LEN: usize = 32;

impl DeviceBoundSource {
    /// Load the device root key from `<base>/.spa-device-key`, creating it on
    /// first use with 32 bytes of OS entropy and `0600` permissions.
    pub fn load_or_create(base: &Path) -> Result<Self, PersistError> {
        let path = base.join(DEVICE_KEY_FILE);
        let key = if path.exists() {
            let hexed = fs::read_to_string(&path)?;
            let bytes = hex::decode(hexed.trim()).map_err(|_| PersistError::Malformed)?;
            if bytes.len() != DEVICE_KEY_LEN {
                return Err(PersistError::Malformed);
            }
            bytes
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut bytes = [0u8; DEVICE_KEY_LEN];
            OsRng.fill_bytes(&mut bytes);
            fs::write(&path, hex::encode(bytes))?;
            restrict_to_owner(&path)?;
            bytes.to_vec()
        };
        Ok(Self {
            root_key: Secret::new(key),
        })
    }

    /// Construct from explicit root-key bytes — used in tests to simulate a
    /// second, different device.
    #[cfg(test)]
    pub fn from_root_key(bytes: [u8; DEVICE_KEY_LEN]) -> Self {
        Self {
            root_key: Secret::new(bytes.to_vec()),
        }
    }
}

impl ShareSource for DeviceBoundSource {
    fn wrapping_secret(&self, kind: &ShareKind) -> Result<Secret, PersistError> {
        let label = kind.domain_label().as_bytes();
        let mut material = Vec::with_capacity(self.root_key.as_bytes().len() + label.len());
        material.extend_from_slice(self.root_key.as_bytes());
        material.extend_from_slice(label);
        Ok(Secret::new(material))
    }
}

/// Restrict a file to owner read/write (`0600`) on Unix; no-op elsewhere.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<(), PersistError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) -> Result<(), PersistError> {
    Ok(())
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

    /// Directory that owns the device root key. The key is device-scoped, not
    /// per-user, so it lives at the base (parent of `<user_id>`); a copy of a
    /// single user's directory therefore does not carry it.
    fn device_key_base(&self) -> &Path {
        self.0.parent().unwrap_or(&self.0)
    }
}

// ── Encrypted blob ────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct EncryptedBlob {
    salt_hex: String,
    nonce_hex: String,
    ct_hex: String,
}

fn derive_key(secret: &[u8], salt: &[u8]) -> Result<[u8; 32], PersistError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(secret, salt, &mut key)
        .map_err(|e| PersistError::Crypto(e.to_string()))?;
    Ok(key)
}

fn encrypt_blob(secret: &[u8], plaintext: &[u8]) -> Result<EncryptedBlob, PersistError> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(secret, &salt)?;
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

fn decrypt_blob(secret: &[u8], blob: &EncryptedBlob) -> Result<Vec<u8>, PersistError> {
    let salt = hex::decode(&blob.salt_hex).map_err(|_| PersistError::Malformed)?;
    let nonce_bytes = hex::decode(&blob.nonce_hex).map_err(|_| PersistError::Malformed)?;
    let ct = hex::decode(&blob.ct_hex).map_err(|_| PersistError::Malformed)?;

    let key = derive_key(secret, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ct.as_slice())
        .map_err(|e| PersistError::Crypto(e.to_string()))
}

// ── Share I/O ─────────────────────────────────────────────────────────────────

pub fn save_share(dir: &UserDir, kind: &ShareKind, share: &Share) -> Result<(), PersistError> {
    let source = DeviceBoundSource::load_or_create(dir.device_key_base())?;
    let secret = source.wrapping_secret(kind)?;
    let blob = encrypt_blob(secret.as_bytes(), &share.to_bytes())?;
    let json = serde_json::to_string(&blob)?;
    fs::write(dir.share_path(kind), json)?;
    Ok(())
}

pub fn load_share(dir: &UserDir, kind: &ShareKind) -> Result<Share, PersistError> {
    let source = DeviceBoundSource::load_or_create(dir.device_key_base())?;
    let secret = source.wrapping_secret(kind)?;
    let json = fs::read_to_string(dir.share_path(kind))?;
    let blob: EncryptedBlob = serde_json::from_str(&json)?;
    let bytes = decrypt_blob(secret.as_bytes(), &blob)?;
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

// ── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use frost_tier0::dealer_keygen;

    /// AC#3, blob level: a `.share` blob copied verbatim to a device with a
    /// different root key cannot be decrypted; the originating device still can.
    #[test]
    fn share_copied_off_device_cannot_be_decrypted() {
        let device_a = DeviceBoundSource::from_root_key([0x11; 32]);
        let secret_a = device_a.wrapping_secret(&ShareKind::Device).unwrap();
        let blob = encrypt_blob(secret_a.as_bytes(), b"long-lived FROST share bytes").unwrap();

        // The blob is copied to device B, whose device root key differs.
        let device_b = DeviceBoundSource::from_root_key([0x22; 32]);
        let secret_b = device_b.wrapping_secret(&ShareKind::Device).unwrap();
        assert!(
            decrypt_blob(secret_b.as_bytes(), &blob).is_err(),
            "share decrypted off-device — device binding is broken"
        );

        // The originating device still decrypts it.
        let recovered = decrypt_blob(secret_a.as_bytes(), &blob).unwrap();
        assert_eq!(recovered, b"long-lived FROST share bytes");
    }

    /// Domain separation: even on the same device, a `device` blob does not
    /// decrypt with the `cloud` secret.
    #[test]
    fn share_kinds_derive_distinct_keys() {
        let device = DeviceBoundSource::from_root_key([0x33; 32]);
        let dev_secret = device.wrapping_secret(&ShareKind::Device).unwrap();
        let blob = encrypt_blob(dev_secret.as_bytes(), b"device-only").unwrap();

        let cloud_secret = device.wrapping_secret(&ShareKind::Cloud).unwrap();
        assert!(
            decrypt_blob(cloud_secret.as_bytes(), &blob).is_err(),
            "cross-kind decrypt succeeded — domain separation is broken"
        );
    }

    /// The device key is materialized `0600` at the base, and a second
    /// `load_share` (a separate process in the CLI) reads the same key, so the
    /// onboard -> sign round-trip works on one device.
    #[test]
    fn device_key_persists_and_round_trips_a_real_share() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let dir = UserDir::new(base, "tester").unwrap();
        let (shares, _gpk) = dealer_keygen(2, 3, &mut OsRng).unwrap();

        save_share(&dir, &ShareKind::Device, &shares[0]).unwrap();

        let key_path = base.join(DEVICE_KEY_FILE);
        assert!(key_path.exists(), "device key not materialized at base");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "device key file is not 0600");
        }

        let loaded = load_share(&dir, &ShareKind::Device).unwrap();
        assert_eq!(
            loaded.participant_id().unwrap(),
            shares[0].participant_id().unwrap(),
            "share did not round-trip with the persisted device key"
        );
    }

    /// AC#3, end to end: copy ONLY the `.share` file to a fresh host. The new
    /// host mints a different device root key, so `load_share` fails.
    #[test]
    fn share_file_moved_to_new_host_fails_to_load() {
        let tmp_a = tempfile::tempdir().unwrap();
        let dir_a = UserDir::new(tmp_a.path(), "u").unwrap();
        let (shares, _gpk) = dealer_keygen(2, 3, &mut OsRng).unwrap();
        save_share(&dir_a, &ShareKind::Device, &shares[0]).unwrap();

        // Host B: fresh base => no device key yet.
        let tmp_b = tempfile::tempdir().unwrap();
        let dir_b = UserDir::new(tmp_b.path(), "u").unwrap();
        fs::copy(
            dir_a.share_path(&ShareKind::Device),
            dir_b.share_path(&ShareKind::Device),
        )
        .unwrap();

        // load_share on host B auto-creates a *different* root key => decrypt fails.
        assert!(
            load_share(&dir_b, &ShareKind::Device).is_err(),
            "share file decrypted on a host that never held the device key"
        );
    }
}
