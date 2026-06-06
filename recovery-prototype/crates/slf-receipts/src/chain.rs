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
    #[error(
        "link {index}: prev_hash mismatch — expected {expected}, got {got}"
    )]
    PrevHashMismatch {
        index: usize,
        expected: String,
        got: String,
    },

    /// A non-anchor link is missing `prev_hash` entirely.
    #[error("link {index}: non-anchor receipt must carry prev_hash")]
    MissingPrevHash { index: usize },
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
