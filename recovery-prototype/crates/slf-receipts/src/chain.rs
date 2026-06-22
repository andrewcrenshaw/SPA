//! Hash-chain verification for Receipt SLF sequences.
//!
//! A receipt chain is a slice of [`Receipt`] values where every receipt
//! after the first carries the BLAKE3 content hash of its predecessor in
//! `prev_hash`. [`verify_chain`] walks the slice and returns the first
//! violation as a typed [`ChainError`].

use thiserror::Error;

use crate::schema::Receipt;

/// Errors produced by [`verify_chain`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    /// The chain contains no receipts.
    #[error("chain is empty")]
    Empty,

    /// The first receipt in the chain carries a `prev_hash`, which is only
    /// valid for non-anchor links.
    #[error("link 0: anchor receipt must have no prev_hash")]
    AnchorHasPrevHash,

    /// A non-anchor link's `prev_hash` does not match the recomputed hash of
    /// the preceding receipt.
    ///
    /// `index` is the position of the offending link (≥ 1).
    #[error("link {index}: prev_hash mismatch — expected {expected}, got {got}")]
    PrevHashMismatch {
        index: usize,
        expected: String,
        got: String,
    },

    /// A non-anchor link is missing `prev_hash` entirely.
    #[error("link {index}: non-anchor receipt must carry prev_hash")]
    MissingPrevHash { index: usize },

    /// A receipt carries no signature under authenticated verification
    /// ([`verify_signed_chain`]). An empty `signature` field proves integrity
    /// (via hash linkage) but not authenticity, which this path requires.
    #[error("link {index}: receipt has no signature (authenticity required)")]
    MissingSignature { index: usize },

    /// A receipt's `signature` field is not valid lowercase hex and cannot be
    /// decoded for verification.
    #[error("link {index}: signature is not valid hex")]
    MalformedSignature { index: usize },

    /// A receipt's signature decoded successfully but did not verify against
    /// its `content_hash` under the supplied verifier — i.e. it is forged,
    /// stale, or signed over different content.
    #[error("link {index}: signature does not verify against content_hash")]
    InvalidSignature { index: usize },
}

/// Verify the integrity of a receipt chain.
///
/// Checks:
/// 1. The chain is non-empty.
/// 2. The first receipt (`index 0`) has no `prev_hash`.
/// 3. Every subsequent receipt's `prev_hash` equals the BLAKE3 content hash
///    of the immediately preceding receipt (recomputed in place).
///
/// Signature verification is **not** performed here; this function validates
/// structural hash-chain continuity only.
pub fn verify_chain(chain: &[Receipt]) -> Result<(), ChainError> {
    if chain.is_empty() {
        return Err(ChainError::Empty);
    }

    if chain[0].prev_hash.is_some() {
        return Err(ChainError::AnchorHasPrevHash);
    }

    for i in 1..chain.len() {
        let expected = chain[i - 1].content_hash_hex();
        match &chain[i].prev_hash {
            None => return Err(ChainError::MissingPrevHash { index: i }),
            Some(got) if got == &expected => {}
            Some(got) => {
                return Err(ChainError::PrevHashMismatch {
                    index: i,
                    expected,
                    got: got.clone(),
                });
            }
        }
    }

    Ok(())
}

/// Verify both the **integrity** and the **authenticity** of a receipt chain.
///
/// This is the authenticated counterpart to [`verify_chain`]. It performs the
/// full hash-linkage check (by delegating to [`verify_chain`]) and then, for
/// every receipt, requires a signature bound over the receipt's
/// [`content_hash`](Receipt::content_hash):
///
/// 1. The `signature` field must be non-empty — an absent signature is rejected
///    with [`ChainError::MissingSignature`].
/// 2. The signature must decode as lowercase hex — otherwise
///    [`ChainError::MalformedSignature`].
/// 3. The decoded bytes must verify against the receipt's `content_hash` under
///    `verify_sig` — otherwise [`ChainError::InvalidSignature`].
///
/// `verify_sig` is the cryptographic verifier, injected by the caller so this
/// crate stays free of any curve dependency. It receives the 32-byte
/// `content_hash` as the message and the decoded signature bytes, and returns
/// `true` iff the signature is valid. In SPA this is a thin wrapper over
/// `frost_tier0::GroupPublicKey::verify`, binding a FROST-Ed25519 signature
/// over the content hash (ADR-SLF-SPA-PHASE2-KEY-CUSTODY, K3).
///
/// The hash-linkage check runs first: a chain that fails integrity is rejected
/// before any signature work, so a tampered payload surfaces as a
/// [`ChainError::PrevHashMismatch`] rather than an [`ChainError::InvalidSignature`].
pub fn verify_signed_chain<F>(chain: &[Receipt], verify_sig: F) -> Result<(), ChainError>
where
    F: Fn(&[u8], &[u8]) -> bool,
{
    verify_chain(chain)?;

    for (i, receipt) in chain.iter().enumerate() {
        if receipt.signature.is_empty() {
            return Err(ChainError::MissingSignature { index: i });
        }
        let sig_bytes = receipt
            .signature_bytes()
            .map_err(|_| ChainError::MalformedSignature { index: i })?;
        if !verify_sig(&receipt.content_hash(), &sig_bytes) {
            return Err(ChainError::InvalidSignature { index: i });
        }
    }

    Ok(())
}
