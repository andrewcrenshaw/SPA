//! Command implementations for the `recovery` CLI.

use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use rand_core::OsRng;
use recovery_orchestrator::{State, StateMachine, SystemClock};
use serde_json::json;
use slf_receipts::{verify_chain, ReceiptKind};
use thiserror::Error;

use crate::persistence::{
    append_receipt, delete_share, load_group_pubkey, load_receipts, load_session, load_share,
    next_receipt, now_secs, save_group_pubkey, save_session, save_share, test_clock, PersistError,
    SessionRecord, ShareKind, UserDir,
};

#[derive(Debug, Error)]
pub enum CmdError {
    #[error("persist: {0}")]
    Persist(#[from] PersistError),
    #[error("frost: {0}")]
    Frost(#[from] frost_tier0::Error),
    #[error("chain: {0}")]
    Chain(#[from] slf_receipts::ChainError),
    #[error("lifecycle: {0}")]
    Lifecycle(#[from] recovery_orchestrator::TransitionError),
    #[error("{0}")]
    Other(String),
}

// ── onboard ───────────────────────────────────────────────────────────────────

pub fn onboard(base: &Path, user_id: &str) -> Result<(), CmdError> {
    let dir = UserDir::new(base, user_id)?;

    // 2-of-3 trusted-dealer keygen
    let (shares, gpk) = frost_tier0::dealer_keygen(2, 3, &mut OsRng)?;

    save_share(&dir, &ShareKind::Device, &shares[0])?;
    save_share(&dir, &ShareKind::Cloud, &shares[1])?;
    save_share(&dir, &ShareKind::RecoveryCode, &shares[2])?;
    save_group_pubkey(&dir, &gpk)?;

    // Initialize lifecycle state machine
    let mut machine = StateMachine::new(SystemClock);
    machine.onboard()?;
    save_session(
        &dir,
        &SessionRecord {
            state: *machine.state(),
            test_clock_epoch_secs: None,
        },
    )?;

    // Anchor receipt (identity anchor — first link in the chain)
    let ts = now_secs(None);
    let anchor = next_receipt(
        &dir,
        ReceiptKind::RecoveryInitiation,
        user_id,
        ts,
        "",
        json!({"step": "onboard", "threshold": gpk.threshold()}),
    )?;
    append_receipt(&dir, anchor)?;

    println!("onboarded: {user_id}");
    println!("shares: device.share cloud.share recovery_code.share");
    println!("state: Onboarded");
    Ok(())
}

// ── sign ──────────────────────────────────────────────────────────────────────

pub fn sign(base: &Path, user_id: &str, message: &str) -> Result<(), CmdError> {
    let dir = UserDir::new(base, user_id)?;
    let gpk = load_group_pubkey(&dir)?;

    let device = load_share(&dir, &ShareKind::Device)?;
    let cloud = load_share(&dir, &ShareKind::Cloud)?;

    // FROST round 1
    let (n0, c0) = frost_tier0::commit(&device, &mut OsRng)?;
    let (n1, c1) = frost_tier0::commit(&cloud, &mut OsRng)?;
    let commitments = vec![c0.clone(), c1.clone()];

    // FROST round 2
    let s0 = frost_tier0::sign_partial(&device, &n0, &commitments, message.as_bytes())?;
    let s1 = frost_tier0::sign_partial(&cloud, &n1, &commitments, message.as_bytes())?;

    // Aggregate
    let sig = frost_tier0::aggregate(&gpk, &commitments, &[s0, s1], message.as_bytes())?;
    let sig_hex = hex::encode(sig.to_bytes()?);

    // Verify immediately
    gpk.verify(message.as_bytes(), &sig)
        .map_err(|e| CmdError::Other(e.to_string()))?;

    println!("signature: {sig_hex}");
    println!("verified: ok");
    Ok(())
}

// ── lose-device ───────────────────────────────────────────────────────────────

pub fn lose_device(base: &Path, user_id: &str) -> Result<(), CmdError> {
    let dir = UserDir::new(base, user_id)?;
    let sess = load_session(&dir)?;

    let ts = now_secs(sess.test_clock_epoch_secs);
    let receipt = next_receipt(
        &dir,
        ReceiptKind::CompromiseRotation,
        user_id,
        ts,
        "",
        json!({"factor": "device", "action": "lose-device"}),
    )?;
    append_receipt(&dir, receipt)?;

    delete_share(&dir, &ShareKind::Device)?;

    println!("device share removed");
    println!("receipts: appended CompromiseRotation");
    Ok(())
}

// ── recover ───────────────────────────────────────────────────────────────────

/// Present cloud + recovery_code factors, start the 48-hour cooldown.
pub fn recover(base: &Path, user_id: &str) -> Result<(), CmdError> {
    let dir = UserDir::new(base, user_id)?;
    let mut sess = load_session(&dir)?;

    // Build state machine from persisted state + clock
    let new_state = match sess.test_clock_epoch_secs {
        Some(epoch) => {
            let clock = test_clock(epoch);
            let mut m = StateMachine::new(clock);
            restore_state(&mut m, sess.state)?;
            m.initiate_recovery()?;
            m.present_factors()?;
            *m.state()
        }
        None => {
            let mut m = StateMachine::new(SystemClock);
            restore_state(&mut m, sess.state)?;
            m.initiate_recovery()?;
            m.present_factors()?;
            *m.state()
        }
    };

    sess.state = new_state;
    save_session(&dir, &sess)?;

    let ts = now_secs(sess.test_clock_epoch_secs);
    let r1 = next_receipt(
        &dir,
        ReceiptKind::RecoveryFactorAssertion,
        user_id,
        ts,
        "",
        json!({"factors": ["cloud", "recovery_code"]}),
    )?;
    append_receipt(&dir, r1.clone())?;

    let r2 = next_receipt(
        &dir,
        ReceiptKind::RecoveryCooldownStart,
        user_id,
        ts + 1,
        "",
        json!({"cooldown_hours": 48}),
    )?;
    append_receipt(&dir, r2)?;

    println!("state: Cooldown");
    println!("cooldown: 48h — use cooldown-advance with SPA_TEST_CLOCK=1 to skip");
    Ok(())
}

// ── cooldown-advance ──────────────────────────────────────────────────────────

/// Advance the test clock by `secs` and transition the state machine if timers elapsed.
///
/// Works directly against the persisted `ends_at` timestamps rather than
/// replaying transitions, which would recompute a fresh `ends_at` from the
/// advanced clock and prevent the comparison from ever succeeding.
pub fn cooldown_advance(base: &Path, user_id: &str, secs: u64) -> Result<(), CmdError> {
    let dir = UserDir::new(base, user_id)?;
    let mut sess = load_session(&dir)?;

    let base_epoch = sess
        .test_clock_epoch_secs
        .unwrap_or_else(|| Utc::now().timestamp());
    let new_epoch = base_epoch + secs as i64;
    let new_now = DateTime::from_timestamp(new_epoch, 0)
        .ok_or_else(|| CmdError::Other("epoch overflow".into()))?;

    let mut state = sess.state;

    // Cooldown → Probation
    if let State::Cooldown { ends_at } = state {
        if new_now >= ends_at {
            let probation_ends = new_now + Duration::hours(24);
            state = State::Probation {
                ends_at: probation_ends,
            };
            let receipt = next_receipt(
                &dir,
                ReceiptKind::RecoveryFactorAssertion,
                user_id,
                new_epoch as u64,
                "",
                json!({"transition": "probation"}),
            )?;
            append_receipt(&dir, receipt)?;
        }
    }

    // Probation → Live
    if let State::Probation { ends_at } = state {
        if new_now >= ends_at {
            state = State::Live;
            let receipt = next_receipt(
                &dir,
                ReceiptKind::RecoveryProbationClear,
                user_id,
                new_epoch as u64,
                "",
                json!({"transition": "live"}),
            )?;
            append_receipt(&dir, receipt)?;
        }
    }

    sess.state = state;
    sess.test_clock_epoch_secs = Some(new_epoch);
    save_session(&dir, &sess)?;

    println!("state: {:?}", sess.state);
    Ok(())
}

// ── audit ─────────────────────────────────────────────────────────────────────

pub fn audit(base: &Path, user_id: &str) -> Result<(), CmdError> {
    let dir = UserDir::new(base, user_id)?;
    let chain = load_receipts(&dir)?;

    for (i, r) in chain.iter().enumerate() {
        println!(
            "[{i}] {:?} subject={} ts={}",
            r.kind, r.subject, r.timestamp
        );
    }

    verify_chain(&chain)?;
    println!("chain: ok ({} receipts)", chain.len());
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Replay persisted `State` into a freshly-created state machine.
///
/// `StateMachine::new` always starts at `Uninitialized`. We replay the
/// minimum number of transitions needed to reach the target state.
/// `Cooldown` and `Probation` carry their `ends_at` timestamp, so we
/// restore them directly via `present_factors` / manual override via
/// internal tick paths — this helper only needs to get us to the right
/// base state so the caller can continue from there.
fn restore_state<C: recovery_orchestrator::Clock>(
    m: &mut StateMachine<C>,
    state: State,
) -> Result<(), CmdError> {
    match state {
        State::Uninitialized => {}
        State::Onboarded => {
            m.onboard()?;
        }
        State::RecoveryInitiated => {
            m.onboard()?;
            m.initiate_recovery()?;
        }
        State::Cooldown { .. } => {
            m.onboard()?;
            m.initiate_recovery()?;
            m.present_factors()?;
        }
        State::Probation { .. } | State::Live => {
            // For probation/live, we can't replay cleanly without the original
            // clock position. Persist and reload state directly via the
            // tick-after-advance path in cooldown_advance.
            //
            // For restore purposes in recover/audit flows that don't need to
            // advance: treat these as terminal — no transitions to replay.
        }
    }
    Ok(())
}
