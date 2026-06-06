//! T2 — AC-1: a valid 2-of-3 FROST-Ed25519 signature verifies
//! against the group public key.

use frost_tier0::{aggregate, commit, dealer_keygen, sign_partial};
use rand_core::OsRng;

#[test]
fn two_of_three_signature_verifies_against_group_public_key() {
    let mut rng = OsRng;
    let (shares, group_pk) = dealer_keygen(2, 3, &mut rng).expect("keygen");
    assert_eq!(shares.len(), 3);

    let message = b"spa-recovery-tier0-happy-path";

    // Pick the first two shares to participate.
    let (nonces_a, commit_a) = commit(&shares[0], &mut rng).expect("commit a");
    let (nonces_b, commit_b) = commit(&shares[1], &mut rng).expect("commit b");

    let commitments = vec![commit_a.clone(), commit_b.clone()];

    let sig_a = sign_partial(&shares[0], &nonces_a, &commitments, message).expect("sign a");
    let sig_b = sign_partial(&shares[1], &nonces_b, &commitments, message).expect("sign b");

    let sig = aggregate(&group_pk, &commitments, &[sig_a, sig_b], message).expect("aggregate");

    group_pk.verify(message, &sig).expect("signature must verify");
}
