# ADR-003 — Recovery Lifecycle State Machine Shape

**Date:** 2026-05-25
**Status:** Accepted
**Author:** alex (Architect)
**Scope:** SPA recovery-prototype, Phase 1
**Related:** Sovereign Personal Agent architecture (design companion) — see `spec/SPA-ARCHITECTURE.md` in the [SLF repo](https://github.com/andrewcrenshaw/slf), [ADR-001](ADR-001-frost-ciphersuite.md), [ADR-002](ADR-002-share-storage-model.md)

---

## Context

§2 of the recovery design specification specifies universal-primitive invariants that apply to
every recovery action:

- **§2.1 Cooldowns** on every state-changing action (48 h for device rebind)
- **§2.2 Receipt SLFs** for every recovery action
- **§2.7 Recovery probation** — a 24-hour post-recovery window during which the new
  wallet can present credentials but cannot issue new grants or perform state-changing
  substrate operations; grants are paused, not revoked

These invariants are described prose-style in the design document. Phase 1 must
encode them as a concrete state machine that the CLI in `apps/cli/` drives, with
the following properties:

1. Every state-changing operation is gated on the current state — invalid
   transitions return `Err`, not panic
2. Cooldown and probation windows are time-driven, but tests must be able to
   advance time without sleeping
3. A cancel signal during cooldown returns the user to the pre-recovery state
   (the §2.1 "cancel by old device, recovery contact, any guardian" requirement)
4. Probation enforces a *capability* split (presentation allowed, state changes
   blocked) rather than a simple "frozen" flag
5. The state machine is library-shaped — no I/O, no clock-of-its-own — so the
   same code drives both the CLI and the future Phase 2 mobile harness

## Decision

**The recovery-orchestrator crate (`recovery-prototype/crates/recovery-orchestrator`)
implements a six-state machine with an injectable `Clock` trait and explicit
cancellation channel.**

The states, defined in `src/state_machine.rs`:

```rust
pub enum State {
    Uninitialized,
    Onboarded,
    RecoveryInitiated,
    Cooldown { ends_at: DateTime<Utc> },
    Probation { ends_at: DateTime<Utc> },
    Live,
}
```

The transition graph:

```
Uninitialized
   └─ onboard() ─────────────► Onboarded

Onboarded
   ├─ present() / grant() ─► Onboarded (read-only checks, state unchanged)
   └─ initiate_recovery() ──► RecoveryInitiated

RecoveryInitiated
   └─ present_factors() ────► Cooldown { ends_at = now + 48h }

Cooldown { ends_at }
   ├─ tick(clock) ─────────► Probation { ends_at = now + 24h }  (if now >= ends_at)
   ├─ tick(clock) ─────────► Cooldown   (still in window)
   └─ cancel() ────────────► Onboarded

Probation { ends_at }
   ├─ tick(clock) ─────────► Live  (if now >= ends_at)
   ├─ tick(clock) ─────────► Probation  (still in window)
   ├─ present() ───────────► Ok (read-only presentation is allowed)
   └─ grant() ─────────────► Err(TransitionError::ProbationActive)

Live
   └─ present() / grant() ─► Live (same read-only surface as Onboarded)
```

Every transition method returns `Result<State, TransitionError>` (the new `State`
on success, a `TransitionError` variant on an invalid transition); the read-only
checks `present()` and `grant()` return `Result<(), TransitionError>`. No method
returns a receipt — see "Consequences" on receipt emission.

The `Clock` trait, defined in `src/clock.rs`, has two implementations:

```rust
pub trait Clock {
    fn now(&self) -> DateTime<Utc>;
}

pub struct SystemClock;                              // real chrono::Utc::now()
pub struct TestClock(Arc<Mutex<DateTime<Utc>>>);     // manually advanceable
```

The `StateMachine<C: Clock>` type is generic over the clock so production code
uses `StateMachine<SystemClock>` and tests use `StateMachine<TestClock>`. The
`TestClock` holds an absolute `DateTime<Utc>` instant (not an offset) and exposes
`advance_secs(secs: i64)`, which moves that instant forward by the given number of
seconds. Cloning a `TestClock` shares the same underlying instant (it wraps the
`DateTime` in `Arc<Mutex<…>>`), so advancing one handle advances the other. This is
the standard "injectable wall clock" pattern, lifted from Tokio's
`tokio::time::pause()` and the Rust standard test ecosystem.

Cancellation is not a separate channel; it is a method call (`cancel()`) that the
CLI invokes when the user runs `spa-recovery cancel-recovery`. The semantics
match §2.1 of the recovery design specification: "any guardian / old device / recovery
contact" can trigger cancel; the orchestrator does not enforce *who* called
cancel, only that the call originated through an authenticated CLI path.

## Rationale

### Why six states (not five, not seven)

We initially drafted a five-state design that merged `Cooldown` and `Probation` into
a single `WaitForActivation` state with a phase indicator. We backed out of that for
two reasons:

1. **Capability surface differs.** Cooldown allows the user to cancel and roll back
   to `Onboarded`. Probation does not — once probation starts, the recovery is
   conceptually complete; the 24-hour delay is a safety net for fraud signals to
   surface, not a cancellation window. Merging them would require a boolean
   `cancellable: bool` field on the merged state, which is exactly the kind of
   "stringly-typed state machine" the type system can prevent.
2. **The Receipt SLF schema distinguishes them.** Per
   §9 of the recovery design specification, `recovery_cooldown_start` /
   `recovery_cooldown_cancel` and `recovery_probation_clear` are distinct event
   subtypes. Encoding them as one state would force the emit-site to carry the
   distinction in a side-channel string field. The type system already has the
   shape — use it.

A seven-state alternative would split `Live` into `Live` and `LiveWithStaleAnchor`
(reflecting the SPA architecture §2.5 anchor-rotation flow). We deferred that — it
is Phase 4+ work, and the `Live` state is the terminal sink for Phase 1's
purposes.

### Why an injectable `Clock` trait rather than `tokio::time::pause`

- `tokio::time::pause` couples the prototype to tokio's runtime, which is not
  needed by any other crate in Phase 1 — the orchestrator is synchronous,
  receipt verification is synchronous, FROST sign/verify is synchronous.
- A trait-based clock is library-portable: Phase 2 mobile platforms can wire
  in `CFAbsoluteTimeGetCurrent` on iOS or `System.currentTimeMillis()` on
  Android without changing the orchestrator's source.
- The trait has one method. The implementation cost is six lines (`SystemClock`)
  and ~20 lines (`TestClock`). The cost is negligible.

### Why cancel returns to `Onboarded` not `Uninitialized`

The user who triggered recovery still has the original device + identity anchor.
Returning to `Onboarded` preserves the pre-recovery state — same shares, same
Receipt chain head, same anchor binding. Returning to `Uninitialized` would
require re-running `onboard`, which is the wrong UX shape.

This also matches the §4.3 "Coerced recovery" flow of the recovery design specification:
"Cooldown windows give multi-channel veto." A veto restores the prior good
state; it does not start over.

### Why probation allows `present()` but blocks `grant()`

This is the literal §2.7 specification:

> - Can PRESENT credentials and issue read-only Frames (verifiable but non-binding)
> - Cannot issue new grants
> - Cannot perform state-changing operations on substrate (no writes, no deletions,
>   no DEK rotations)

Encoding the capability split at the state level (rather than at each operation
site) means the orchestrator is the single source of truth for "is this op allowed
right now." The read-only `present()` check succeeds during `Probation`, while
`grant()` returns `Err(TransitionError::ProbationActive)` whenever `State::Probation`
is current.

### Why `tick(clock)` rather than auto-advancing

The orchestrator is library-pure: it does not run a background thread, does not
own the clock, does not perform I/O. The CLI calls `tick()` on every command
invocation. The Phase 2 mobile harness will call `tick()` when the app
foregrounds (or on a periodic WatchKit task). This keeps the orchestrator
testable, predictable, and free of subtle async-cancellation bugs that come with
"the state machine spawns its own timer."

## Status

**Accepted.** The shape was implemented in commit
[`8d1df25`](https://github.com/andrewcrenshaw/SPA/commit/8d1df25)
and validated by `tests/state_transitions.rs` + `tests/cooldown_cancellation.rs`
in the recovery-orchestrator crate, plus the workspace-level
`tests/fuzz_lifecycle.rs` running 100 seeded iterations.

## Consequences

### Positive

- The state machine is a 204-LOC library with zero I/O and zero panics on any
  transition path; every invalid transition returns a `TransitionError` enum
  variant
- The CLI binary and any future mobile harness drive the *same* state machine
  source — there is no Phase-2-specific re-implementation
- The `TestClock` lets the e2e_lifecycle integration test run the full
  48-hour cooldown + 24-hour probation in <1 ms of wall time
- The `Cooldown` and `Probation` payloads carry their `ends_at` timestamps
  inline, so the orchestrator is fully serializable for crash-recovery in
  Phase 2 (`serde::Serialize` on `State` already works)

### Negative / accepted costs

- **Receipt emission is a CLI convention, not a structural guarantee.** The
  orchestrator's transition methods return `Result<State, TransitionError>` and emit
  *no* receipts — they only mutate in-memory state. Receipts are emitted by the CLI
  (`apps/cli/src/commands.rs`) as a separate step alongside each state change, by
  convention. So the "a Receipt SLF is emitted for every state-changing action"
  property (§2.2) is upheld by the CLI call sites, not enforced by the type system:
  a future caller could advance the state machine without appending a receipt and
  nothing in the orchestrator would prevent it. Binding emission structurally (e.g.
  having transitions return the receipts they require) is candidate Phase-2 work.
- The state machine does not enforce the "any guardian / old device / recovery
  contact" identity-of-canceller rule from §2.1. That enforcement lives in the
  CLI's authentication layer, not in the orchestrator. This is correct
  (separation of concerns) but worth flagging for Phase 2 — when the mobile
  harness adopts the orchestrator, it must replicate the canceller-identity
  gate at its own boundary.
- `tick()` is a polled operation, not event-driven. If a Phase 2 mobile app
  fails to invoke `tick()` for an extended period (e.g., the user closes
  the app for a week), cooldown progress is correctly recovered on next
  `tick()` — but no automatic in-app notification fires "your cooldown is
  ready to clear." That UX wiring is the harness's responsibility, not the
  orchestrator's.
- The read-only `present()` / `grant()` checks succeed from both `Onboarded` and
  `Live`. In the SPA architecture there is no operational difference between the
  two — `Live` is `Onboarded` with a recovery-receipt in its chain history. We considered
  collapsing them into a single state and using a boolean
  `has_completed_recovery: bool`, and rejected the same reasoning we used
  against merging Cooldown and Probation: the Receipt SLF schema distinguishes
  them, and the type system should match.
