use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::clock::Clock;

const COOLDOWN_HOURS: i64 = 48;
const PROBATION_HOURS: i64 = 24;

/// Recovery lifecycle states.
///
/// `State: Copy` — all variants hold only `DateTime<Utc>` (Copy) or no data,
/// so pattern-matching in transition methods can read the current state without
/// consuming it, then overwrite `self.state` inside the same arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    Uninitialized,
    Onboarded,
    RecoveryInitiated,
    /// 48-hour cooldown window. Any configured factor may call `cancel()`.
    Cooldown {
        ends_at: DateTime<Utc>,
    },
    /// 24-hour probation after cooldown expires. Presentation allowed; grants blocked.
    Probation {
        ends_at: DateTime<Utc>,
    },
    Live,
}

#[derive(Debug, Error, PartialEq)]
pub enum TransitionError {
    #[error("cannot transition from {0} state")]
    InvalidState(String),

    #[error("cooldown has not elapsed: 48-hour window still active")]
    CooldownNotElapsed,

    #[error("probation has not elapsed: 24-hour window still active")]
    ProbationNotElapsed,

    /// Returned by `grant()` when the machine is in `Probation`.
    #[error("probation active: state-changing operations not permitted")]
    ProbationActive,
}

pub struct StateMachine<C: Clock> {
    state: State,
    clock: C,
}

impl<C: Clock> StateMachine<C> {
    pub fn new(clock: C) -> Self {
        Self {
            state: State::Uninitialized,
            clock,
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn onboard(&mut self) -> Result<State, TransitionError> {
        if matches!(self.state, State::Uninitialized) {
            self.state = State::Onboarded;
            Ok(self.state)
        } else {
            Err(TransitionError::InvalidState(format!("{:?}", self.state)))
        }
    }

    pub fn initiate_recovery(&mut self) -> Result<State, TransitionError> {
        if matches!(self.state, State::Onboarded) {
            self.state = State::RecoveryInitiated;
            Ok(self.state)
        } else {
            Err(TransitionError::InvalidState(format!("{:?}", self.state)))
        }
    }

    pub fn present_factors(&mut self) -> Result<State, TransitionError> {
        if matches!(self.state, State::RecoveryInitiated) {
            let ends_at = self.clock.now() + Duration::hours(COOLDOWN_HOURS);
            self.state = State::Cooldown { ends_at };
            Ok(self.state)
        } else {
            Err(TransitionError::InvalidState(format!("{:?}", self.state)))
        }
    }

    /// Advance the machine if the active timer has elapsed.
    ///
    /// - `Cooldown` → `Probation` after 48 h
    /// - `Probation` → `Live` after 24 h
    ///
    /// Returns `Err(CooldownNotElapsed)` or `Err(ProbationNotElapsed)` when the
    /// timer has not yet expired. State is unchanged on error.
    pub fn tick(&mut self) -> Result<State, TransitionError> {
        let now = self.clock.now();
        match self.state {
            State::Cooldown { ends_at } if now >= ends_at => {
                self.state = State::Probation {
                    ends_at: now + Duration::hours(PROBATION_HOURS),
                };
                Ok(self.state)
            }
            State::Cooldown { .. } => Err(TransitionError::CooldownNotElapsed),
            State::Probation { ends_at } if now >= ends_at => {
                self.state = State::Live;
                Ok(self.state)
            }
            State::Probation { .. } => Err(TransitionError::ProbationNotElapsed),
            _ => Err(TransitionError::InvalidState(format!("{:?}", self.state))),
        }
    }

    /// Cancel an in-progress recovery and return to `Onboarded`.
    ///
    /// Only valid during `Cooldown`. The machine does not enforce which factor
    /// calls `cancel()`; any configured factor may do so (DCP-2).
    pub fn cancel(&mut self) -> Result<State, TransitionError> {
        if matches!(self.state, State::Cooldown { .. }) {
            self.state = State::Onboarded;
            Ok(self.state)
        } else {
            Err(TransitionError::InvalidState(format!("{:?}", self.state)))
        }
    }

    /// Check whether credential presentation is allowed in the current state.
    /// Read-only; does not advance state. Succeeds in `Onboarded`, `Probation`, `Live`.
    pub fn present(&self) -> Result<(), TransitionError> {
        match self.state {
            State::Probation { .. } | State::Live | State::Onboarded => Ok(()),
            _ => Err(TransitionError::InvalidState(format!("{:?}", self.state))),
        }
    }

    /// Check whether issuing a new grant is permitted in the current state.
    /// Blocked in `Probation`; succeeds in `Onboarded` and `Live`.
    pub fn grant(&self) -> Result<(), TransitionError> {
        match self.state {
            State::Probation { .. } => Err(TransitionError::ProbationActive),
            State::Live | State::Onboarded => Ok(()),
            _ => Err(TransitionError::InvalidState(format!("{:?}", self.state))),
        }
    }
}
