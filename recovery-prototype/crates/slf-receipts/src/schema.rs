//! Receipt data model and canonical content-hash computation (DCP-1 / DCP-2).
//!
//! ## Canonical serialization (DCP-1)
//!
//! [`Receipt::content_hash`] hashes a deterministic byte representation of the
//! receipt. Determinism requires that equal inputs always produce the same
//! byte sequence:
//!
//! 1. The five pre-image fields (`kind`, `subject`, `prev_hash`, `timestamp`,
//!    `payload`) are assembled into a `BTreeMap<String, Value>` so JSON object
//!    keys are emitted in ASCII-alphabetical order regardless of insertion
//!    order.
//! 2. `serde_json` serializes the map compactly (no whitespace) using its
//!    default Map representation, which is also `BTreeMap`-backed (i.e.
//!    nested object keys inside `payload` are likewise sorted when
//!    constructed without the `preserve_order` feature).
//! 3. The resulting UTF-8 bytes are hashed with BLAKE3.
//!
//! The `signature` field is intentionally excluded from the pre-image so
//! that the hash can be computed before signing and verified without
//! knowledge of the private key.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// All SLF receipt event types (design v0.1 §9).
///
/// Each variant maps to a stable snake_case wire name via the explicit
/// `serde(rename = …)` attributes so the mapping survives any future
/// Rust identifier refactoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptKind {
    #[serde(rename = "recovery_initiation")]
    RecoveryInitiation,
    #[serde(rename = "recovery_factor_assertion")]
    RecoveryFactorAssertion,
    #[serde(rename = "recovery_cooldown_start")]
    RecoveryCooldownStart,
    #[serde(rename = "recovery_cooldown_cancel")]
    RecoveryCooldownCancel,
    #[serde(rename = "recovery_probation_clear")]
    RecoveryProbationClear,
    #[serde(rename = "wallet_unit_rebind")]
    WalletUnitRebind,
    #[serde(rename = "credential_reissuance_request")]
    CredentialReissuanceRequest,
    #[serde(rename = "credential_reissuance_complete")]
    CredentialReissuanceComplete,
    #[serde(rename = "inheritance_trigger")]
    InheritanceTrigger,
    #[serde(rename = "inheritance_cancellation")]
    InheritanceCancellation,
    #[serde(rename = "proxy_designation")]
    ProxyDesignation,
    #[serde(rename = "proxy_activation")]
    ProxyActivation,
    #[serde(rename = "proxy_expiration")]
    ProxyExpiration,
    #[serde(rename = "court_order_disclosure")]
    CourtOrderDisclosure,
    #[serde(rename = "compromise_rotation")]
    CompromiseRotation,
}

/// A single SLF receipt — the atomic unit of the sovereign lifecycle record.
///
/// Receipts form a hash-linked chain: each receipt (after the first)
/// carries the BLAKE3 content hash of its predecessor in `prev_hash`,
/// making retroactive tampering detectable by [`crate::chain::verify_chain`].
/// This hash-linking gives the chain **tamper-evidence (integrity)**, not
/// **authenticity** — see the `signature` field note below.
///
/// In Phase 1 the `signature` field is unused: receipts are emitted with an
/// empty string and no cryptographic signature is bound into the receipt.
/// Binding the FROST-Ed25519 signature over [`Receipt::content_hash`] into
/// the receipt (so the chain proves authenticity, not just integrity) is a
/// Phase 2 item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub kind: ReceiptKind,
    /// Stable identifier for the entity this receipt pertains to (e.g. a DID
    /// or opaque account reference).
    pub subject: String,
    /// BLAKE3 hex hash of the immediately preceding receipt, or `None` for
    /// the chain anchor (first link).
    pub prev_hash: Option<String>,
    /// Unix epoch seconds. Callers are responsible for monotonicity within a
    /// chain; the verifier does not check timestamp ordering.
    pub timestamp: u64,
    /// Unused in Phase 1: receipts are emitted with this field empty and no
    /// cryptographic signature is bound into the receipt. The chain provides
    /// tamper-evidence by hash-linking (`prev_hash`), which proves integrity,
    /// **not** authenticity. Binding a FROST-Ed25519 signature over
    /// [`Receipt::content_hash`] into this field is a Phase 2 item; until then
    /// the field is retained for forward wire-compatibility only.
    pub signature: String,
    /// Arbitrary structured payload specific to [`Receipt::kind`].
    pub payload: Value,
}

impl Receipt {
    /// Construct and return a new receipt.
    ///
    /// The caller is responsible for computing the correct `prev_hash` (the
    /// content hash of the preceding receipt) and supplying a valid
    /// `signature` over [`Receipt::content_hash`] of the returned value.
    pub fn emit(
        kind: ReceiptKind,
        subject: impl Into<String>,
        prev_hash: Option<String>,
        timestamp: u64,
        signature: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            kind,
            subject: subject.into(),
            prev_hash,
            timestamp,
            signature: signature.into(),
            payload,
        }
    }

    /// Compute the BLAKE3 hash of the canonical pre-image.
    ///
    /// The pre-image is the compact JSON serialization of the five
    /// non-signature fields assembled into a `BTreeMap` (alphabetical key
    /// order). See the module-level doc for the full rationale.
    pub fn content_hash(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes();
        *blake3::hash(&bytes).as_bytes()
    }

    /// Lowercase hex encoding of [`Receipt::content_hash`].
    pub fn content_hash_hex(&self) -> String {
        hex::encode(self.content_hash())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut map: BTreeMap<String, Value> = BTreeMap::new();
        map.insert(
            "kind".into(),
            serde_json::to_value(&self.kind).expect("ReceiptKind serializes"),
        );
        map.insert("payload".into(), self.payload.clone());
        map.insert(
            "prev_hash".into(),
            serde_json::to_value(&self.prev_hash).expect("Option<String> serializes"),
        );
        map.insert("subject".into(), Value::String(self.subject.clone()));
        map.insert("timestamp".into(), Value::Number(self.timestamp.into()));
        serde_json::to_vec(&map).expect("BTreeMap<String,Value> always serializes")
    }
}
