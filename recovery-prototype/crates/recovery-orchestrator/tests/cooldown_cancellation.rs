use chrono::Utc;
use recovery_orchestrator::{State, StateMachine, TestClock, TransitionError};

fn into_cooldown() -> (TestClock, StateMachine<TestClock>) {
    let clock = TestClock::new(Utc::now());
    let mut sm = StateMachine::new(clock.clone());
    sm.onboard().unwrap();
    sm.initiate_recovery().unwrap();
    sm.present_factors().unwrap();
    (clock, sm)
}

// AC-3: Cancel during cooldown returns state to Onboarded.
#[test]
fn cooldown_cancel_returns_to_onboarded() {
    let (_, mut sm) = into_cooldown();
    let next = sm.cancel().unwrap();
    assert_eq!(next, State::Onboarded);
    assert_eq!(sm.state(), &State::Onboarded);
}

#[test]
fn cooldown_cancel_rejected_when_not_in_cooldown() {
    let clock = TestClock::new(Utc::now());
    let mut sm = StateMachine::new(clock);
    sm.onboard().unwrap();
    // still Onboarded, not in Cooldown
    assert!(matches!(sm.cancel(), Err(TransitionError::InvalidState(_))));
}

// After cancel, the full path can be re-entered.
#[test]
fn cooldown_cancel_allows_re_initiation() {
    let (_, mut sm) = into_cooldown();
    sm.cancel().unwrap();
    sm.initiate_recovery().unwrap();
    sm.present_factors().unwrap();
    assert!(matches!(sm.state(), State::Cooldown { .. }));
}
