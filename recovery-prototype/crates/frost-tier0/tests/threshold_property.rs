//! T2 — AC-2 + adjacent threshold properties.
//!
//! - Single-share signing must be rejected with `InsufficientSigners`.
//! - 3-of-3 (above threshold) also verifies.
//! - Tampered message must fail verification.

use frost_tier0::{aggregate, commit, dealer_keygen, sign_partial, Error};
use rand_core::OsRng;

#[test]
fn single_share_signing_returns_insufficient_signers_error() {
    let mut rng = OsRng;
    let (shares, _group_pk) = dealer_keygen(2, 3, &mut rng).expect("keygen");

    let message = b"single-share-attempt";

    let (nonces, c) = commit(&shares[0], &mut rng).expect("commit");

    // Only one commitment in flight; sign must reject without invoking
    // the underlying protocol and without producing a partial signature.
    let err = sign_partial(&shares[0], &nonces, &[c], message)
        .expect_err("sign_partial must reject single-commitment input");

    assert!(
        matches!(err, Error::InsufficientSigners { have: 1, need: 2 }),
        "expected InsufficientSigners{{have:1,need:2}}, got {err:?}"
    );
}

#[test]
fn aggregate_also_rejects_under_threshold_signature_shares() {
    let mut rng = OsRng;
    let (shares, group_pk) = dealer_keygen(2, 3, &mut rng).expect("keygen");

    let message = b"aggregate-rejects-under-threshold";

    // Build a full set of commitments so sign_partial accepts, then
    // hand aggregate only one signature share. Aggregate must reject
    // with the same typed error.
    let (n0, c0) = commit(&shares[0], &mut rng).expect("commit 0");
    let (_n1, c1) = commit(&shares[1], &mut rng).expect("commit 1");
    let cs = vec![c0.clone(), c1];

    let s0 = sign_partial(&shares[0], &n0, &cs, message).expect("sign 0");

    let err = aggregate(&group_pk, &cs, &[s0], message)
        .expect_err("aggregate must reject under-threshold shares");

    assert!(
        matches!(err, Error::InsufficientSigners { have: 1, need: 2 }),
        "expected InsufficientSigners{{have:1,need:2}}, got {err:?}"
    );
}

#[test]
fn all_three_shares_also_produce_valid_signature() {
    let mut rng = OsRng;
    let (shares, group_pk) = dealer_keygen(2, 3, &mut rng).expect("keygen");

    let message = b"all-three-participate";

    let (n0, c0) = commit(&shares[0], &mut rng).expect("commit 0");
    let (n1, c1) = commit(&shares[1], &mut rng).expect("commit 1");
    let (n2, c2) = commit(&shares[2], &mut rng).expect("commit 2");

    let cs = vec![c0.clone(), c1.clone(), c2.clone()];

    let s0 = sign_partial(&shares[0], &n0, &cs, message).expect("sign 0");
    let s1 = sign_partial(&shares[1], &n1, &cs, message).expect("sign 1");
    let s2 = sign_partial(&shares[2], &n2, &cs, message).expect("sign 2");

    let sig = aggregate(&group_pk, &cs, &[s0, s1, s2], message).expect("aggregate");
    group_pk
        .verify(message, &sig)
        .expect("3-of-3 signature must verify");
}

#[test]
fn signature_does_not_verify_for_different_message() {
    let mut rng = OsRng;
    let (shares, group_pk) = dealer_keygen(2, 3, &mut rng).expect("keygen");

    let signed_message = b"the-message-actually-signed";
    let other_message = b"a-completely-different-payload";

    let (n0, c0) = commit(&shares[0], &mut rng).expect("commit 0");
    let (n1, c1) = commit(&shares[1], &mut rng).expect("commit 1");
    let cs = vec![c0.clone(), c1.clone()];

    let s0 = sign_partial(&shares[0], &n0, &cs, signed_message).expect("sign 0");
    let s1 = sign_partial(&shares[1], &n1, &cs, signed_message).expect("sign 1");

    let sig = aggregate(&group_pk, &cs, &[s0, s1], signed_message).expect("aggregate");

    group_pk
        .verify(other_message, &sig)
        .expect_err("verification of a different message must fail");
}
