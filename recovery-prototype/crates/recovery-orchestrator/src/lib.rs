//! `recovery-orchestrator` — lifecycle state machine for SPA recovery.
//!
//! ## States
//!
//! ```text
//! Uninitialized → Onboarded → RecoveryInitiated → Cooldown(48h) → Probation(24h) → Live
//! ```
//!
//! Cancel during `Cooldown` returns to `Onboarded`. State-changing operations are
//! rejected during `Probation`. All transitions return `Result<State, TransitionError>`
//! — no panics.
//!
//! ## Clock injection
//!
//! [`Clock`] decouples the machine from wall time. Use [`SystemClock`] in production
//! and [`TestClock`] in tests; call [`TestClock::advance_secs`] to skip cooldown
//! windows without sleeping.

pub mod clock;
pub mod state_machine;

pub use clock::{Clock, SystemClock, TestClock};
pub use state_machine::{State, StateMachine, TransitionError};
