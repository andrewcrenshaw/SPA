//! `slf-receipts` — SLF Receipt data model, emission, and chain verification.
//!
//! ## Structure
//!
//! - [`schema`]: [`Receipt`] struct, [`ReceiptKind`] enum, and canonical
//!   BLAKE3 content-hash computation (DCP-1 / DCP-2).
//! - [`chain`]: [`verify_chain`] — walks a receipt slice and asserts
//!   hash-chain continuity.
//!
//! ## Quick start
//!
//! ```rust
//! use slf_receipts::schema::{Receipt, ReceiptKind};
//! use slf_receipts::chain::verify_chain;
//! use serde_json::json;
//!
//! let anchor = Receipt::emit(
//!     ReceiptKind::RecoveryInitiation,
//!     "did:example:alice",
//!     None,
//!     1_000_000_000,
//!     "",
//!     json!({"tier": 0}),
//! );
//!
//! let link = Receipt::emit(
//!     ReceiptKind::RecoveryFactorAssertion,
//!     "did:example:alice",
//!     Some(anchor.content_hash_hex()),
//!     1_000_000_001,
//!     "",
//!     json!({"factor": "recovery_code"}),
//! );
//!
//! verify_chain(&[anchor, link]).unwrap();
//! ```

pub mod chain;
pub mod schema;

pub use chain::{verify_chain, ChainError};
pub use schema::{Receipt, ReceiptKind};
