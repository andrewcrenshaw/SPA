//! Fuzz-style lifecycle loop: 100 iterations, each with a distinct seeded RNG.
//!
//! Not a cargo-fuzz harness (DCP-1) — a deterministic loop is
//! sufficient for Phase 1 state-machine invariants and crypto-path stability.
//! Validates that no seed produces a panic, incorrect signature, or unexpected
//! state-machine result.

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use recovery_orchestrator::{State, StateMachine, SystemClock};

const ITERATIONS: u64 = 100;

#[test]
fn lifecycle_is_stable_across_one_hundred_seeds() {
    for seed in 0..ITERATIONS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        // ── Crypto path ───────────────────────────────────────────────────────

        let (shares, gpk) = frost_tier0::dealer_keygen(2, 3, &mut rng)
            .unwrap_or_else(|e| panic!("seed {seed}: keygen: {e}"));
        assert_eq!(shares.len(), 3, "seed {seed}: expected 3 shares");
        assert_eq!(gpk.threshold(), 2, "seed {seed}: expected threshold 2");

        // Rotate through all three share pairings to exercise every combination.
        let pair = match seed % 3 {
            0 => [0usize, 1],
            1 => [0, 2],
            _ => [1, 2],
        };

        let msg = format!("spa-fuzz-seed-{seed}");
        let msg_bytes = msg.as_bytes();

        let (n0, c0) = frost_tier0::commit(&shares[pair[0]], &mut rng)
            .unwrap_or_else(|e| panic!("seed {seed}: commit[0]: {e}"));
        let (n1, c1) = frost_tier0::commit(&shares[pair[1]], &mut rng)
            .unwrap_or_else(|e| panic!("seed {seed}: commit[1]: {e}"));
        let cs = vec![c0.clone(), c1.clone()];

        let s0 = frost_tier0::sign_partial(&shares[pair[0]], &n0, &cs, msg_bytes)
            .unwrap_or_else(|e| panic!("seed {seed}: sign[0]: {e}"));
        let s1 = frost_tier0::sign_partial(&shares[pair[1]], &n1, &cs, msg_bytes)
            .unwrap_or_else(|e| panic!("seed {seed}: sign[1]: {e}"));

        let sig = frost_tier0::aggregate(&gpk, &cs, &[s0, s1], msg_bytes)
            .unwrap_or_else(|e| panic!("seed {seed}: aggregate: {e}"));

        gpk.verify(msg_bytes, &sig)
            .unwrap_or_else(|e| panic!("seed {seed}: verify: {e}"));

        // ── State-machine path ────────────────────────────────────────────────

        let mut m = StateMachine::new(SystemClock);
        assert_eq!(*m.state(), State::Uninitialized, "seed {seed}: initial state");

        m.onboard()
            .unwrap_or_else(|e| panic!("seed {seed}: onboard: {e}"));
        assert_eq!(*m.state(), State::Onboarded, "seed {seed}: post-onboard");

        m.initiate_recovery()
            .unwrap_or_else(|e| panic!("seed {seed}: initiate_recovery: {e}"));
        assert_eq!(
            *m.state(),
            State::RecoveryInitiated,
            "seed {seed}: post-initiate"
        );

        m.present_factors()
            .unwrap_or_else(|e| panic!("seed {seed}: present_factors: {e}"));
        assert!(
            matches!(*m.state(), State::Cooldown { .. }),
            "seed {seed}: expected Cooldown after present_factors"
        );

        // Cancel returns to Onboarded — invariant must hold every seed.
        m.cancel()
            .unwrap_or_else(|e| panic!("seed {seed}: cancel: {e}"));
        assert_eq!(
            *m.state(),
            State::Onboarded,
            "seed {seed}: cancel must restore Onboarded"
        );
    }
}
