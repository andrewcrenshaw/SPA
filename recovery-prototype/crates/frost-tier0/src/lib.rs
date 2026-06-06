//! `frost-tier0` — Tier-0 threshold signing primitives for the SPA recovery
//! prototype.
//!
//! ## Ciphersuite (DCP-1)
//!
//! Wraps the Zcash Foundation [`frost-ed25519`] crate (RFC 9591 FROST over
//! Ed25519 / SHA-512), pinned at version `=2.2.0`. The wrapped impl was
//! independently audited by Least Authority in Q1 2025. See ADR-001
//! (to be authored under T7) for the full ciphersuite-selection record.
//!
//! ## Key-generation model
//!
//! Tier 0 uses **trusted-dealer keygen** (not runtime DKG). Shares are
//! materialized once at onboarding by [`dealer_keygen`] and distributed
//! out-of-band; no protocol exists for nodes to refresh or re-share at
//! runtime. The wrapped FROST-Ed25519 round-1 / round-2 / aggregate
//! primitives are exposed for the signing path only.
//!
//! ## Secret hygiene (DCP-2)
//!
//! [`Share`] is the only public type that holds long-lived secret material.
//! It wraps a serialized upstream `KeyPackage` inside a
//! [`Zeroizing`](zeroize::Zeroizing) buffer and derives
//! [`Zeroize`](zeroize::Zeroize) + [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop),
//! so dropping a `Share` overwrites the secret bytes before deallocation.
//! The upstream `SigningNonces` type (carried inside [`SigningNonces`])
//! already derives `Zeroize` + `Drop` in `frost-core 2.x`, so per-session
//! nonces are likewise wiped on drop.
//!
//! Raw `frost_ed25519::SigningKey` / `KeyPackage` types are **not**
//! re-exported; callers see only the opaque wrappers in this crate.

mod dkg;
mod sign;

pub use crate::dkg::{dealer_keygen, GroupPublicKey, ParticipantId, Share};
pub use crate::sign::{
    aggregate, commit, sign_partial, Signature, SignatureShare, SigningCommitment, SigningNonces,
};

use thiserror::Error;

/// All errors surfaced by `frost-tier0`.
///
/// Variants either wrap an upstream `frost_ed25519::Error` (protocol-level
/// failures) or report a Tier-0-specific precondition violation.
#[derive(Debug, Error)]
pub enum Error {
    /// Aggregation was attempted with fewer signature shares than the
    /// group threshold. Surfaced before any cryptographic work.
    #[error("insufficient signers: have {have}, need {need}")]
    InsufficientSigners { have: u16, need: u16 },

    /// Wrapper around the underlying frost-ed25519 protocol error.
    #[error("frost protocol error: {0}")]
    Frost(#[from] frost_ed25519::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_non_empty() {
        let e = Error::InsufficientSigners { have: 1, need: 2 };
        assert!(!e.to_string().is_empty());
        assert!(e.to_string().contains("insufficient"));
    }

    #[test]
    fn dealer_keygen_returns_threshold_metadata() {
        let mut rng = rand_core::OsRng;
        let (shares, gpk) = dealer_keygen(2, 3, &mut rng).expect("keygen");
        assert_eq!(shares.len(), 3);
        assert_eq!(gpk.threshold(), 2);
    }

    #[test]
    fn dealer_keygen_honors_non_default_threshold_total() {
        let mut rng = rand_core::OsRng;
        let (shares, gpk) = dealer_keygen(3, 5, &mut rng).expect("3-of-5 keygen");
        assert_eq!(shares.len(), 5);
        assert_eq!(gpk.threshold(), 3);
    }
}
