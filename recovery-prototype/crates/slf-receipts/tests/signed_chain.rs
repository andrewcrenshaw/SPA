//! Regression tests for authenticated receipt-chain verification (KC-1).
//!
//! `verify_chain` proves **integrity** (hash linkage). `verify_signed_chain`
//! additionally proves **authenticity**: every receipt must carry a signature
//! over its `content_hash` that the supplied verifier accepts. These tests
//! exercise that contract — valid, unsigned, forged, malformed, and tampered
//! chains — and demonstrate the integrity-vs-authenticity gap directly.
//!
//! The production signature is a FROST-Ed25519 signature verified at the call
//! site via `frost_tier0::GroupPublicKey::verify`. `slf-receipts` deliberately
//! depends on no curve crate, so these tests inject a BLAKE3 keyed-MAC oracle
//! as the verifier. The oracle has the same binding semantics the real path
//! relies on: the signature is bound to `content_hash` and a secret the forger
//! does not hold, so tampering or forgery is rejected.

use serde_json::json;
use slf_receipts::chain::verify_signed_chain;
use slf_receipts::{ChainError, Receipt, ReceiptKind};

/// Stand-in group secret. In production the verifier is the FROST group public
/// key; here it keys a BLAKE3 MAC so forgery requires knowing this value.
const GROUP_SECRET: &[u8] = b"test-frost-group-secret-key-KC-1";

/// Produce the hex MAC the signing oracle would bind over `content_hash`.
fn oracle_sign(content_hash: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(GROUP_SECRET);
    h.update(content_hash);
    hex::encode(h.finalize().as_bytes())
}

/// Verifier closure passed to `verify_signed_chain`: recomputes the MAC over
/// the message (`content_hash`) and compares against the decoded signature.
fn oracle_verify(message: &[u8], sig: &[u8]) -> bool {
    let mut h = blake3::Hasher::new();
    h.update(GROUP_SECRET);
    h.update(message);
    h.finalize().as_bytes() == sig
}

/// Build a receipt and bind a valid oracle signature over its content hash.
/// The signature field is excluded from the content-hash pre-image, so setting
/// it after computing the hash does not perturb the hash or the chain linkage.
fn sign(mut r: Receipt) -> Receipt {
    let sig = oracle_sign(&r.content_hash());
    r.signature = sig;
    r
}

fn signed_anchor() -> Receipt {
    sign(Receipt::emit(
        ReceiptKind::RecoveryInitiation,
        "did:example:alice",
        None,
        1_000_000_000,
        "",
        json!({"tier": 0, "factors": ["device", "recovery_code"]}),
    ))
}

fn signed_extend(chain: &[Receipt], kind: ReceiptKind, ts: u64) -> Receipt {
    let prev = chain.last().expect("chain must be non-empty");
    sign(Receipt::emit(
        kind,
        "did:example:alice",
        Some(prev.content_hash_hex()),
        ts,
        "",
        json!({}),
    ))
}

fn valid_signed_chain() -> Vec<Receipt> {
    let mut chain = vec![signed_anchor()];
    chain.push(signed_extend(
        &chain,
        ReceiptKind::RecoveryFactorAssertion,
        1_000_000_001,
    ));
    chain.push(signed_extend(
        &chain,
        ReceiptKind::RecoveryCooldownStart,
        1_000_000_002,
    ));
    chain
}

// ── happy path ──────────────────────────────────────────────────────────────

#[test]
fn signed_chain_valid() {
    let chain = valid_signed_chain();
    verify_signed_chain(&chain, oracle_verify).expect("valid signed chain must pass");
}

// ── AC: rejects an unsigned receipt ───────────────────────────────────────────

#[test]
fn signed_chain_unsigned_rejected() {
    let mut chain = valid_signed_chain();
    chain[1].signature = String::new(); // absent signature

    let err =
        verify_signed_chain(&chain, oracle_verify).expect_err("unsigned receipt must be rejected");
    assert!(
        matches!(err, ChainError::MissingSignature { index: 1 }),
        "expected MissingSignature at index 1, got {err:?}"
    );
}

// ── AC: rejects a forged / invalid signature ──────────────────────────────────

#[test]
fn signed_chain_forged_signature_rejected() {
    let mut chain = valid_signed_chain();
    // Re-sign over unrelated content: well-formed hex, valid length, but it is
    // not a signature over this receipt's content_hash. Hash linkage stays
    // intact (signature is excluded from the pre-image), so this isolates the
    // authenticity failure from the integrity failure.
    chain[1].signature = oracle_sign(b"attacker-chosen-message");

    let err =
        verify_signed_chain(&chain, oracle_verify).expect_err("forged signature must be rejected");
    assert!(
        matches!(err, ChainError::InvalidSignature { index: 1 }),
        "expected InvalidSignature at index 1, got {err:?}"
    );
}

// ── malformed signature encoding ──────────────────────────────────────────────

#[test]
fn signed_chain_malformed_signature_rejected() {
    let mut chain = valid_signed_chain();
    chain[1].signature = "zz-not-valid-hex".to_string();

    let err = verify_signed_chain(&chain, oracle_verify)
        .expect_err("malformed signature must be rejected");
    assert!(
        matches!(err, ChainError::MalformedSignature { index: 1 }),
        "expected MalformedSignature at index 1, got {err:?}"
    );
}

// ── hash linkage is still enforced under authenticated verification ────────────

#[test]
fn signed_chain_tampered_payload_rejected() {
    let mut chain = valid_signed_chain();
    // Mutate a payload: this breaks the next link's prev_hash. The hash-linkage
    // check runs first, so we expect a PrevHashMismatch (integrity failure).
    chain[1].payload = json!({"tampered": true});

    let err =
        verify_signed_chain(&chain, oracle_verify).expect_err("tampered chain must be rejected");
    assert!(
        matches!(err, ChainError::PrevHashMismatch { index: 2, .. }),
        "expected PrevHashMismatch at index 2, got {err:?}"
    );
}

// ── the core KC-1 guarantee: authenticity catches what integrity cannot ───────

#[test]
fn integrity_passes_but_authenticity_rejects_forged_chain() {
    use slf_receipts::chain::verify_chain;

    let mut chain = valid_signed_chain();
    // Forge a signature only (hash linkage untouched).
    chain[1].signature = oracle_sign(b"attacker-chosen-message");

    // Integrity-only verification accepts the forged chain...
    verify_chain(&chain).expect("hash-only verify_chain accepts a forged-signature chain");

    // ...but authenticated verification rejects it. This is the gap KC-1 closes.
    let err = verify_signed_chain(&chain, oracle_verify)
        .expect_err("authenticated verification must reject the forged chain");
    assert!(
        matches!(err, ChainError::InvalidSignature { index: 1 }),
        "got {err:?}"
    );
}

// ── empty chain is rejected before any signature work ─────────────────────────

#[test]
fn signed_chain_empty_rejected() {
    let err = verify_signed_chain(&[], oracle_verify).expect_err("empty chain must be rejected");
    assert!(
        matches!(err, ChainError::Empty),
        "expected Empty, got {err:?}"
    );
}
