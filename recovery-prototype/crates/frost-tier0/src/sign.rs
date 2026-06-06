//! Round-1 / round-2 / aggregate signing primitives.
//!
//! All long-lived secret material (the `Share`) lives in `dkg.rs`; this
//! module only handles per-session nonces and aggregation. The upstream
//! `frost_core::round1::SigningNonces` carried inside [`SigningNonces`]
//! already derives `Zeroize` + `Drop`, so per-session secrets are wiped
//! on drop without further work here.

use std::collections::BTreeMap;

use frost_ed25519 as frost;

use crate::dkg::{GroupPublicKey, Share};
use crate::Error;

/// One participant's per-session signing nonces. Held privately by the
/// signer between round 1 (commit) and round 2 (sign); never transmitted.
///
/// Inner upstream type implements `Zeroize` + `Drop`.
pub struct SigningNonces {
    pub(crate) inner: frost::round1::SigningNonces,
}

/// One participant's public commitment to the round-1 nonces, broadcast
/// to all other signers before round 2.
#[derive(Clone)]
pub struct SigningCommitment {
    pub(crate) id: frost::Identifier,
    pub(crate) inner: frost::round1::SigningCommitments,
}

/// One participant's round-2 partial signature. Combined by [`aggregate`]
/// into a single Ed25519 [`Signature`].
#[derive(Clone, Debug)]
pub struct SignatureShare {
    pub(crate) id: frost::Identifier,
    pub(crate) inner: frost::round2::SignatureShare,
}

/// A complete, verifiable Ed25519 signature produced by [`aggregate`].
#[derive(Clone, Debug)]
pub struct Signature {
    pub(crate) inner: frost::Signature,
}

impl Signature {
    /// Serialize the signature to its 64-byte Ed25519 wire form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.inner.serialize()?)
    }
}

/// Round 1: produce this participant's nonces and the matching public
/// commitment. The nonces must be retained locally until round 2; the
/// commitment is broadcast to the coordinator.
pub fn commit<R: rand_core::RngCore + rand_core::CryptoRng>(
    share: &Share,
    rng: &mut R,
) -> Result<(SigningNonces, SigningCommitment), Error> {
    let kp = share.to_key_package()?;
    let (nonces, commitments) = frost::round1::commit(kp.signing_share(), rng);
    Ok((
        SigningNonces { inner: nonces },
        SigningCommitment {
            id: *kp.identifier(),
            inner: commitments,
        },
    ))
}

/// Round 2: produce this participant's partial signature given the full
/// list of round-1 commitments and the message under signature.
pub fn sign_partial(
    share: &Share,
    nonces: &SigningNonces,
    commitments: &[SigningCommitment],
    message: &[u8],
) -> Result<SignatureShare, Error> {
    let kp = share.to_key_package()?;

    // Surface a typed precondition error before invoking the underlying
    // protocol so callers see the same `InsufficientSigners` whether the
    // shortage is caught at sign-time or at aggregate-time.
    let min = *kp.min_signers();
    if commitments.len() < min as usize {
        return Err(Error::InsufficientSigners {
            have: commitments.len() as u16,
            need: min,
        });
    }

    let mut map = BTreeMap::new();
    for c in commitments {
        map.insert(c.id, c.inner);
    }

    let signing_package = frost::SigningPackage::new(map, message);
    let sig_share = frost::round2::sign(&signing_package, &nonces.inner, &kp)?;

    Ok(SignatureShare {
        id: *kp.identifier(),
        inner: sig_share,
    })
}

/// Combine `threshold` partial signatures into one verifiable signature.
///
/// Returns [`Error::InsufficientSigners`] before performing any
/// cryptographic work if fewer partial signatures than the group
/// threshold are supplied.
pub fn aggregate(
    group_pubkey: &GroupPublicKey,
    commitments: &[SigningCommitment],
    sig_shares: &[SignatureShare],
    message: &[u8],
) -> Result<Signature, Error> {
    if sig_shares.len() < group_pubkey.min_signers as usize {
        return Err(Error::InsufficientSigners {
            have: sig_shares.len() as u16,
            need: group_pubkey.min_signers,
        });
    }

    let mut cmap = BTreeMap::new();
    for c in commitments {
        cmap.insert(c.id, c.inner);
    }
    let mut smap = BTreeMap::new();
    for s in sig_shares {
        smap.insert(s.id, s.inner);
    }

    let signing_package = frost::SigningPackage::new(cmap, message);
    let sig = frost::aggregate(&signing_package, &smap, &group_pubkey.inner)?;
    Ok(Signature { inner: sig })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dealer_keygen;

    #[test]
    fn signature_serializes_to_64_bytes() {
        let mut rng = rand_core::OsRng;
        let (shares, group_pk) = dealer_keygen(2, 3, &mut rng).expect("keygen");
        let msg = b"sig-bytes-test";

        let (n0, c0) = commit(&shares[0], &mut rng).unwrap();
        let (n1, c1) = commit(&shares[1], &mut rng).unwrap();
        let cs = vec![c0.clone(), c1.clone()];
        let s0 = sign_partial(&shares[0], &n0, &cs, msg).unwrap();
        let s1 = sign_partial(&shares[1], &n1, &cs, msg).unwrap();

        let sig = aggregate(&group_pk, &cs, &[s0, s1], msg).unwrap();
        let bytes = sig.to_bytes().unwrap();
        assert_eq!(bytes.len(), 64, "Ed25519 signatures are 64 bytes");
    }
}
