//! Verify that any two of the three FROST shares can produce a valid signature.
//!
//! The 2-of-3 scheme assigns shares to: device (0), cloud (1), recovery_code (2).
//! All three pairings must independently produce a verifiable group signature.

use frost_tier0::{aggregate, commit, dealer_keygen, sign_partial, GroupPublicKey, Share};
use rand_core::OsRng;

fn sign_with_pair(shares: &[Share], gpk: &GroupPublicKey, indices: [usize; 2], msg: &[u8]) {
    let (n0, c0) = commit(&shares[indices[0]], &mut OsRng).unwrap();
    let (n1, c1) = commit(&shares[indices[1]], &mut OsRng).unwrap();
    let cs = vec![c0.clone(), c1.clone()];
    let s0 = sign_partial(&shares[indices[0]], &n0, &cs, msg).unwrap();
    let s1 = sign_partial(&shares[indices[1]], &n1, &cs, msg).unwrap();
    let sig = aggregate(gpk, &cs, &[s0, s1], msg).unwrap();
    gpk.verify(msg, &sig).unwrap();
}

#[test]
fn device_and_cloud_recover() {
    let (shares, gpk) = dealer_keygen(2, 3, &mut OsRng).unwrap();
    sign_with_pair(&shares, &gpk, [0, 1], b"device+cloud");
}

#[test]
fn device_and_recovery_code_recover() {
    let (shares, gpk) = dealer_keygen(2, 3, &mut OsRng).unwrap();
    sign_with_pair(&shares, &gpk, [0, 2], b"device+recovery_code");
}

#[test]
fn cloud_and_recovery_code_recover() {
    let (shares, gpk) = dealer_keygen(2, 3, &mut OsRng).unwrap();
    sign_with_pair(&shares, &gpk, [1, 2], b"cloud+recovery_code");
}
