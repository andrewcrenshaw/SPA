//! Verify that a 10-link SLF receipt chain round-trips through a fresh verifier.
//!
//! Serializes the chain to JSON (simulating at-rest storage) then deserializes
//! into a fresh `Vec<Receipt>` and calls `verify_chain` — the same path a real
//! verifier would follow on startup.

use serde_json::json;
use slf_receipts::chain::verify_chain;
use slf_receipts::schema::{Receipt, ReceiptKind};

fn build_chain(n: usize) -> Vec<Receipt> {
    assert!(n >= 1);

    let kinds = [
        ReceiptKind::RecoveryInitiation,
        ReceiptKind::RecoveryFactorAssertion,
        ReceiptKind::RecoveryCooldownStart,
        ReceiptKind::RecoveryCooldownCancel,
        ReceiptKind::RecoveryProbationClear,
        ReceiptKind::WalletUnitRebind,
        ReceiptKind::CredentialReissuanceRequest,
        ReceiptKind::CredentialReissuanceComplete,
        ReceiptKind::InheritanceTrigger,
        ReceiptKind::InheritanceCancellation,
    ];

    let anchor = Receipt::emit(
        kinds[0].clone(),
        "did:example:test",
        None,
        1_000_000_000,
        "",
        json!({"step": 0}),
    );

    let mut chain = vec![anchor];
    for i in 1..n {
        let prev_hash = chain.last().unwrap().content_hash_hex();
        let r = Receipt::emit(
            kinds[i % kinds.len()].clone(),
            "did:example:test",
            Some(prev_hash),
            1_000_000_000 + i as u64,
            "",
            json!({"step": i}),
        );
        chain.push(r);
    }
    chain
}

#[test]
fn ten_link_chain_verifies_on_fresh_verifier() {
    let chain = build_chain(10);
    assert_eq!(chain.len(), 10);

    // Round-trip through JSON to simulate loading from storage into a fresh verifier.
    let serialized = serde_json::to_string(&chain).unwrap();
    let fresh: Vec<Receipt> = serde_json::from_str(&serialized).unwrap();

    verify_chain(&fresh).expect("10-link chain must verify on a fresh verifier");
}

#[test]
fn tampered_chain_fails_verification() {
    let mut chain = build_chain(10);
    chain[5].prev_hash = Some("deadbeef".repeat(8));
    let err = verify_chain(&chain).unwrap_err();
    assert!(
        matches!(
            err,
            slf_receipts::ChainError::PrevHashMismatch { index: 5, .. }
        ),
        "expected PrevHashMismatch at index 5, got: {err:?}"
    );
}
