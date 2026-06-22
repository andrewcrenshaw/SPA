use chrono::Utc;
use recovery_orchestrator::{State, StateMachine, TestClock, TransitionError};

fn clock_and_machine() -> (TestClock, StateMachine<TestClock>) {
    let clock = TestClock::new(Utc::now());
    let sm = StateMachine::new(clock.clone());
    (clock, sm)
}

fn into_probation(clock: &TestClock, sm: &mut StateMachine<TestClock>) {
    sm.onboard().unwrap();
    sm.initiate_recovery().unwrap();
    sm.present_factors().unwrap();
    clock.advance_secs(48 * 3600 + 1);
    sm.tick().unwrap();
}

// AC-1: Machine transitions from Uninitialized to Onboarded.
#[test]
fn onboard_transitions_from_uninitialized() {
    let (_, mut sm) = clock_and_machine();
    let next = sm.onboard().unwrap();
    assert_eq!(next, State::Onboarded);
    assert_eq!(sm.state(), &State::Onboarded);
}

#[test]
fn onboard_rejected_when_already_onboarded() {
    let (_, mut sm) = clock_and_machine();
    sm.onboard().unwrap();
    assert!(matches!(
        sm.onboard(),
        Err(TransitionError::InvalidState(_))
    ));
}

#[test]
fn recovery_path_reaches_cooldown() {
    let (_, mut sm) = clock_and_machine();
    sm.onboard().unwrap();
    sm.initiate_recovery().unwrap();
    sm.present_factors().unwrap();
    assert!(matches!(sm.state(), State::Cooldown { .. }));
}

// AC-2: Cooldown blocks state changes until clock advances 48 hours.
#[test]
fn cooldown_blocks_state_changes_before_48h() {
    let (clock, mut sm) = clock_and_machine();
    sm.onboard().unwrap();
    sm.initiate_recovery().unwrap();
    sm.present_factors().unwrap();
    clock.advance_secs(47 * 3600); // one hour short
    let err = sm.tick().unwrap_err();
    assert_eq!(err, TransitionError::CooldownNotElapsed);
    assert!(matches!(sm.state(), State::Cooldown { .. }));
}

#[test]
fn cooldown_expires_into_probation_after_48h() {
    let (clock, mut sm) = clock_and_machine();
    sm.onboard().unwrap();
    sm.initiate_recovery().unwrap();
    sm.present_factors().unwrap();
    clock.advance_secs(48 * 3600 + 1);
    sm.tick().unwrap();
    assert!(matches!(sm.state(), State::Probation { .. }));
}

// AC-4: Probation allows presentation but blocks new grants.
#[test]
fn probation_rules_allow_presentation() {
    let (clock, mut sm) = clock_and_machine();
    into_probation(&clock, &mut sm);
    sm.present().unwrap();
}

#[test]
fn probation_rules_block_grants() {
    let (clock, mut sm) = clock_and_machine();
    into_probation(&clock, &mut sm);
    let err = sm.grant().unwrap_err();
    assert_eq!(err, TransitionError::ProbationActive);
}

#[test]
fn probation_expires_into_live_after_24h() {
    let (clock, mut sm) = clock_and_machine();
    into_probation(&clock, &mut sm);
    clock.advance_secs(24 * 3600 + 1);
    sm.tick().unwrap();
    assert_eq!(sm.state(), &State::Live);
}
