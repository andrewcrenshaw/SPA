//! Trusted-dealer keygen + opaque share material.
//!
//! Tier 0 deliberately does **not** run an interactive DKG; shares are
//! materialized once at onboarding by [`dealer_keygen`] and distributed
//! out-of-band. The module name retains the conventional `dkg` label
//! because that is the protocol position it occupies in the FROST
//! lifecycle, not because the underlying primitive is interactive.
//!
//! See `lib.rs` module-level docs for the DCP-1 ciphersuite record and
//! the DCP-2 secret-hygiene record.

use frost_ed25519 as frost;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;

/// A single participant's long-lived signing material.
///
/// `Share` is the only public type that holds long-lived secret bytes.
/// Internally it stores the serialized upstream `KeyPackage` inside a
/// [`Zeroizing`] buffer and itself derives [`Zeroize`] + [`ZeroizeOnDrop`],
/// so dropping a `Share` overwrites the secret before deallocation
/// (DCP-2).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    key_package_bytes: Zeroizing<Vec<u8>>,
}

impl Share {
    pub(crate) fn from_key_package(kp: &frost::keys::KeyPackage) -> Result<Self, Error> {
        let bytes = kp.serialize()?;
        Ok(Self {
            key_package_bytes: Zeroizing::new(bytes),
        })
    }

    pub(crate) fn to_key_package(&self) -> Result<frost::keys::KeyPackage, Error> {
        Ok(frost::keys::KeyPackage::deserialize(
            &self.key_package_bytes,
        )?)
    }

    /// Stable identifier for this share within the group.
    pub fn participant_id(&self) -> Result<ParticipantId, Error> {
        let kp = self.to_key_package()?;
        Ok(ParticipantId {
            inner: *kp.identifier(),
        })
    }

    /// Serialize this share to bytes for encrypted-at-rest storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_package_bytes.to_vec()
    }

    /// Reconstruct a share from previously serialized bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let _ = frost::keys::KeyPackage::deserialize(bytes)?;
        Ok(Self {
            key_package_bytes: Zeroizing::new(bytes.to_vec()),
        })
    }
}

/// Opaque identifier for a Tier-0 participant within a single FROST group.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ParticipantId {
    pub(crate) inner: frost::Identifier,
}

/// The shared verifying material derived at keygen.
///
/// Holds the upstream `PublicKeyPackage` alongside the threshold parameter
/// the dealer used; [`crate::aggregate`] uses the latter to reject
/// under-threshold signing attempts deterministically.
#[derive(Clone)]
pub struct GroupPublicKey {
    pub(crate) inner: frost::keys::PublicKeyPackage,
    pub(crate) min_signers: u16,
}

impl GroupPublicKey {
    /// Minimum number of participants required to produce a valid signature.
    pub fn threshold(&self) -> u16 {
        self.min_signers
    }

    /// Verify an aggregated [`Signature`](crate::Signature) against this group key.
    pub fn verify(&self, message: &[u8], sig: &crate::Signature) -> Result<(), Error> {
        Ok(self.inner.verifying_key().verify(message, &sig.inner)?)
    }

    /// Serialize the public key package to bytes for storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.inner.serialize()?)
    }

    /// Reconstruct from bytes, providing the original threshold value.
    pub fn from_bytes(bytes: &[u8], threshold: u16) -> Result<Self, Error> {
        Ok(Self {
            inner: frost::keys::PublicKeyPackage::deserialize(bytes)?,
            min_signers: threshold,
        })
    }
}

/// Run trusted-dealer FROST-Ed25519 keygen.
///
/// Produces `total` shares with a `threshold`-of-`total` reconstruction
/// rule and a shared [`GroupPublicKey`]. The dealer's full signing key
/// never leaves this function: only the per-participant shares are
/// returned, and they are wrapped in [`Share`] before exiting the call.
pub fn dealer_keygen<R: rand_core::RngCore + rand_core::CryptoRng>(
    threshold: u16,
    total: u16,
    rng: &mut R,
) -> Result<(Vec<Share>, GroupPublicKey), Error> {
    let (secret_shares, pubkey_pkg) = frost::keys::generate_with_dealer(
        total,
        threshold,
        frost::keys::IdentifierList::Default,
        rng,
    )?;

    let mut shares = Vec::with_capacity(secret_shares.len());
    for (_id, secret) in secret_shares {
        let kp = frost::keys::KeyPackage::try_from(secret)?;
        shares.push(Share::from_key_package(&kp)?);
    }

    Ok((
        shares,
        GroupPublicKey {
            inner: pubkey_pkg,
            min_signers: threshold,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_distinct_participant_ids() {
        let mut rng = rand_core::OsRng;
        let (shares, _) = dealer_keygen(2, 3, &mut rng).expect("keygen");
        let ids: Vec<_> = shares.iter().map(|s| s.participant_id().unwrap()).collect();
        assert_eq!(ids.len(), 3);
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "participant ids must be distinct");
            }
        }
    }

    #[test]
    fn share_round_trip_preserves_key_package() {
        let mut rng = rand_core::OsRng;
        let (shares, _) = dealer_keygen(2, 3, &mut rng).expect("keygen");
        // Round-trip via the public `Clone` impl and the internal
        // deserializer — both should yield a usable KeyPackage.
        let cloned = shares[0].clone();
        let kp1 = shares[0].to_key_package().expect("kp1");
        let kp2 = cloned.to_key_package().expect("kp2");
        assert_eq!(kp1.identifier(), kp2.identifier());
    }
}
