//! Integration tests for slf-receipts chain verification.
//!
//! AC coverage:
//! - `deterministic_serialize` — same receipt always hashes to the same hex
//! - `chain_valid`             — five-link valid chain passes verify_chain
//! - `chain_tampered`          — single-field mutation causes rejection
//! - `chain_empty_rejected`    — empty slice returns ChainError::Empty
//! - `chain_single_link`       — one-receipt anchor-only chain passes
//! - `anchor_with_prev_hash`   — anchor carrying prev_hash is rejected

use serde_json::json;
use slf_receipts::{
    chain::{verify_chain, ChainError},
    schema::{Receipt, ReceiptKind},
};

fn make_anchor() -> Receipt {
    Receipt::emit(
        ReceiptKind::RecoveryInitiation,
        "did:example:alice",
        None,
        1_000_000_000,
        "",
        json!({"tier": 0, "factors": ["device", "recovery_code"]}),
    )
}

fn extend_chain(chain: &[Receipt], kind: ReceiptKind, ts: u64) -> Receipt {
    let prev = chain.last().expect("chain must be non-empty");
    Receipt::emit(
        kind,
        "did:example:alice",
        Some(prev.content_hash_hex()),
        ts,
        "",
        json!({}),
    )
}

// ── AC: deterministic_serialize ───────────────────────────────────────────────

#[test]
fn deterministic_serialize() {
    let r = make_anchor();
    let h1 = r.content_hash_hex();
    let h2 = r.content_hash_hex();
    assert_eq!(h1, h2, "content_hash_hex must be stable across calls");
    assert_eq!(h1.len(), 64, "BLAKE3 hex is 64 chars");

    // A structurally identical receipt built independently must hash the same.
    let r2 = Receipt::emit(
        ReceiptKind::RecoveryInitiation,
        "did:example:alice",
        None,
        1_000_000_000,
        "",
        json!({"tier": 0, "factors": ["device", "recovery_code"]}),
    );
    assert_eq!(
        r.content_hash_hex(),
        r2.content_hash_hex(),
        "equal receipts must produce equal hashes"
    );
}

// ── AC: chain_valid ───────────────────────────────────────────────────────────

#[test]
fn chain_valid() {
    let mut chain = vec![make_anchor()];
    chain.push(extend_chain(&chain, ReceiptKind::RecoveryFactorAssertion, 1_000_000_001));
    chain.push(extend_chain(&chain, ReceiptKind::RecoveryCooldownStart, 1_000_000_002));
    chain.push(extend_chain(&chain, ReceiptKind::RecoveryCooldownCancel, 1_000_000_003));
    chain.push(extend_chain(&chain, ReceiptKind::RecoveryProbationClear, 1_000_000_004));

    assert_eq!(chain.len(), 5);
    verify_chain(&chain).expect("valid five-link chain must pass");
}

// ── AC: chain_tampered ────────────────────────────────────────────────────────

#[test]
fn chain_tampered() {
    let mut chain = vec![make_anchor()];
    chain.push(extend_chain(&chain, ReceiptKind::RecoveryFactorAssertion, 1_000_000_001));
    chain.push(extend_chain(&chain, ReceiptKind::WalletUnitRebind, 1_000_000_002));

    // Tamper with the middle link's payload — its hash changes, making link 2's
    // prev_hash stale.
    chain[1].payload = json!({"tampered": true});

    let err = verify_chain(&chain).expect_err("tampered chain must be rejected");
    assert!(
        matches!(err, ChainError::PrevHashMismatch { index: 2, .. }),
        "expected PrevHashMismatch at index 2, got {err:?}"
    );
}

// ── extra coverage ────────────────────────────────────────────────────────────

#[test]
fn chain_empty_rejected() {
    let err = verify_chain(&[]).expect_err("empty chain must be rejected");
    assert!(matches!(err, ChainError::Empty), "expected Empty, got {err:?}");
}

#[test]
fn chain_single_link() {
    let chain = vec![make_anchor()];
    verify_chain(&chain).expect("single anchor-only chain must pass");
}

#[test]
fn anchor_with_prev_hash_rejected() {
    let bogus_anchor = Receipt::emit(
        ReceiptKind::RecoveryInitiation,
        "did:example:alice",
        Some("deadbeef".repeat(8)), // non-None prev_hash on first link
        1_000_000_000,
        "",
        json!({}),
    );
    let err =
        verify_chain(&[bogus_anchor]).expect_err("anchor with prev_hash must be rejected");
    assert!(
        matches!(err, ChainError::AnchorHasPrevHash),
        "expected AnchorHasPrevHash, got {err:?}"
    );
}
