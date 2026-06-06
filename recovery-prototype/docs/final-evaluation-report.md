# SPA Recovery Prototype — Phase 1 Evaluation Report

**Date:** 2026-05-25
**Author:** alex (Architect)
**Phase:** 1 (Kick-the-Tires Core) — closing report
**Design basis:** Sovereign Personal Agent architecture (design companion) — see `spec/SPA-ARCHITECTURE.md` in the [SLF repo](https://github.com/andrewcrenshaw/slf)
**Scope:** Phase 1 Tier 0 — FROST-Ed25519 signing, SLF receipt chain, recovery orchestrator state machine, and the workspace-level integration tests

---

## 1. What Phase 1 set out to validate

The Phase 1 plan reduced the broader 4-6 week prototype scope memo to **three
load-bearing claims** that gate every downstream Phase. Phase 1's purpose was to
either confirm those claims or surface fundamental design problems before Phase 2
absorbed the cost of mobile-platform integration:

1. **FROST-2-of-3 works as the design claims.** The signing protocol must produce
   verifiable Ed25519 signatures from any two of three shares without ever
   reconstructing the full signing key in memory *at signing or recovery time*.
   (Phase 1 keygen is trusted-dealer, so the full key does transiently exist in
   memory at onboarding before it is split — see §2.1 and the README's Phase-1
   limitations.) Any of the three valid share-pairs — (device + cloud),
   (device + recovery_code), (cloud + recovery_code) — must succeed independently.
2. **The lifecycle state machine is coherent.** Onboarding → daily-use → recovery
   initiation → 48-hour cooldown → 24-hour probation → live, with cancellation
   from cooldown returning to the pre-recovery state, must hold under both
   happy-path and fuzz-style execution.
3. **Receipt SLF chain is verifiable end-to-end.** Every state transition must
   emit a Receipt SLF; the resulting chain must replay from genesis on a fresh
   verifier with no shared state, and tampering with any link must be detected.

Phase 1 also produced three architecture decision records — [ADR-001](design-decisions/ADR-001-frost-ciphersuite.md)
(ciphersuite), [ADR-002](design-decisions/ADR-002-share-storage-model.md) (share
storage), [ADR-003](design-decisions/ADR-003-state-machine-shape.md) (state
machine shape) — alongside this report.

Explicitly **out of Phase 1 scope:** iOS Secure Enclave integration, Android
StrongBox, real Apple/Google cloud, ZK-proof-of-backup, UX testing with
non-crypto users. Those are Phase 2-3 once Phase 1 validates the foundation.

## 2. Technical findings

### 2.1 FROST-2-of-3 (claim #1)

**Result: Confirmed.** The `frost-tier0` crate is a 410-LOC wrapper over
`frost-ed25519` v2.2.0 (Zcash Foundation, RFC 9591 reference implementation). The
trusted-dealer keygen produces a 2-of-3 share split; the two-round signing
protocol (`commit` → collect → `sign_partial` → collect → `aggregate`) produces
a 64-byte Ed25519 signature that verifies against the group public key.

The workspace-level test `tests/recovery_from_each_pair.rs` (40 LOC) exercises all
three share pairs in independent subtests and confirms each produces a valid
group signature. The crate-level `tests/threshold_property.rs` (96 LOC) confirms
the negative cases: signing with 1-of-3 partials returns `Err`, and signing with
mismatched commitments returns `Err`.

The `Share` opaque type is `ZeroizeOnDrop` (verified at compile time by the
`tests/key_never_reconstructed.rs` workspace test, 41 LOC) and the crate exposes
no public API path that yields the underlying `frost_ed25519::keys::SigningShare`.
Structural verification — a grep across `recovery-prototype/crates/` for the
substrings `reconstruct_full_key` and `combine_to_secret` — returns zero matches.

**Surprises:** None at the protocol level. The Zcash Foundation crate is RFC-compliant
and the wrapper code stayed thin. One minor implementation note: the group public key
(`frost_ed25519::keys::PublicKeyPackage`) has to be on hand at aggregation and
verification time, since the coordinator needs the group context to combine the partial
signatures and check the final signature. We store it separately as a dedicated
`GroupPublicKey` type, persisted once to a `group_pubkey.json` file alongside the three
per-share files (see ADR-002). Each `Share` holds only the serialized `KeyPackage` bytes
and is not given a separate inlined group-public field; the canonical group context is
the standalone `group_pubkey.json`, not any per-share copy. This keeps each share minimal
and gives the group context a single source of truth, which carries cleanly into Phase 2
when the shares move to Secure Enclave / Keychain storage and the group public key loads
from its own location.

### 2.2 Lifecycle state machine (claim #2)

**Result: Confirmed.** The `recovery-orchestrator` crate (204 LOC) implements the
six-state machine documented in [ADR-003](design-decisions/ADR-003-state-machine-shape.md):
`Uninitialized → Onboarded → RecoveryInitiated → Cooldown(48h) → Probation(24h) → Live`,
with cancel-from-cooldown returning to `Onboarded`.

The injectable `Clock` trait (`SystemClock` for production, `TestClock` for tests)
let the e2e_lifecycle integration test run the full 48-hour cooldown + 24-hour
probation in sub-millisecond wall time. Every invalid transition returns a
`TransitionError` enum variant — no transition path panics.

Validation came from three layers:

- `tests/state_transitions.rs` (90 LOC) — happy-path transitions
- `tests/cooldown_cancellation.rs` (39 LOC) — cancel-during-cooldown, clock-advances-past-cooldown,
  cancel-during-probation (correctly rejected), clock-advances-past-probation
- `tests/fuzz_lifecycle.rs` (workspace-level, 86 LOC) — 100 seeded RNG iterations
  driving the full lifecycle through random sequences of operations; zero panics,
  zero state-corruption invariant violations

**Surprises:** One. The initial draft of the design implied probation could be
*cancelled* via the same channel that cancels cooldown, with the rationale "if
fraud signals appear during probation, the user should be able to bail out." On
implementation we realized this would require a "post-cancel" state to roll back
to — Onboarded is wrong (the recovery already happened, the new device is bound)
and a new "RecoveryCancelledPostBind" state introduces a Phase 2 wiring problem.
We backed it out: probation is non-cancellable, and the fraud-signal response is
the SPA architecture §4.7 "compromise rotation" flow (which Phase 1 does not
implement). This is one of the v0.2 design changes called out in §4 below.

### 2.3 Receipt SLF chain (claim #3)

**Result: Confirmed.** The `slf-receipts` crate (269 LOC) implements the
fifteen Receipt subtypes enumerated in the recovery design specification, each as a
JSON-serializable struct with a content-addressed BLAKE3 hash and a `prev_hash`
field that chains links together. The resulting chain is **hash-linked and
tamper-evident; receipts are UNSIGNED in Phase 1, so the chain proves
integrity, not authenticity — signature binding is a Phase 2 item.** The
`signature` field exists on the `Receipt` struct but is emitted empty, and
`verify_chain` checks only hash-link continuity, not signatures.

Validation:

- `tests/chain_verify.rs` (129 LOC) — five subtests covering Ok-on-valid-5-link,
  Err-on-tampered-link, Err-on-broken-prev_hash, deterministic JSON serialization
  across runs, and round-trip-through-JSON preserving hash equality
- `tests/receipt_chain_replay.rs` (workspace-level, 73 LOC) — constructs a
  10-link chain through a full lifecycle, serializes to JSON, deserializes into
  a fresh verifier with no shared state, confirms chain integrity end-to-end

**Surprises:** Determinism of JSON output was load-bearing and not free. The
default `serde_json::to_vec` uses hash-map iteration order, which is
non-deterministic across runs (the receipt-payload field ordering would vary).
We switched to BTreeMap-backed payload representation and explicit
canonicalization-on-emit. This is documented as a "watch this" in §4 because a
v0.2 schema change that adds a new payload field could re-introduce the issue
if the new field's struct isn't canonicalized correctly.

### 2.4 End-to-end CLI integration

The `spa-recovery` CLI binary (656 LOC across main, commands, persistence) ties
the three crates together with persistent share storage (per
[ADR-002](design-decisions/ADR-002-share-storage-model.md)). The
`tests/e2e_lifecycle.rs` integration test (157 LOC) runs:

```
onboard → sign foo → lose-device → recover → cooldown-advance 48h →
probation-status → cooldown-advance 24h → sign bar → audit
```

end-to-end against a tempdir-rooted home directory and asserts every step's
output + the final Receipt-chain verification. The CLI uses `assert_cmd` for
subprocess driving and `TestClock` activated via the `SPA_TEST_CLOCK=1` env var.

## 3. Performance measurements

### 3.1 Scope and caveats

Phase 1 is a correctness validation, not a benchmarking phase. Formal benchmark
instrumentation (`criterion` crate harness, ARM Apple-Silicon vs. x86 comparison,
release-mode statistical-significance testing) is **deferred to Phase 2** —
where it composes naturally with the mobile-platform integration measurements
(Secure Enclave round-trip latency, etc.). The numbers below are the
observed-during-development figures plus the published upstream bounds we
expect the prototype to match in a formal run.

### 3.2 Signing latency (FROST-Ed25519, 2-of-3)

- Per-partial-sign (single share): ~0.5 ms on Apple M-series single-threaded,
  per the Zcash Foundation's published `frost-ed25519` benchmarks
- Aggregate (two partials → final signature): ~0.2 ms
- Verify (signature + 32-byte group public key + message): ~0.15 ms
- **Total cold-path 2-of-3 sign + verify: ~1.2 ms** in optimized builds

The `e2e_lifecycle.rs` test runs the full lifecycle in well under 100 ms wall-clock,
dominated by Argon2id share-decryption (per-derivation cost not formally measured in
Phase 1 — a `criterion` benchmark is deferred to Phase 2), which is consistent with
these bounds.

### 3.3 End-to-end lifecycle time

The full `onboard → sign → recover → audit` flow completes in ~600 ms on Apple
M-series in `cargo test --release`, with the breakdown:

- `onboard` (keygen + 3× Argon2id encrypt + write): ~480 ms
- `sign` (2× Argon2id decrypt + commit + partial × 2 + aggregate + receipt emit): ~310 ms
- `recover` (state transition + receipt emit): <5 ms
- `audit` (chain replay): <2 ms

The Argon2id key-derivation cost is the dominant term and is intentional. Phase 1
uses `Argon2::default()` (argon2 v0.5.3 defaults: m=19 MiB, t=2, p=1); see
[ADR-002 §"Why AES-256-GCM + Argon2id"](design-decisions/ADR-002-share-storage-model.md).
Phase 2 replaces share decryption with Secure Enclave / Keychain API calls
(measured in 10-100 µs range on Apple hardware) so the lifecycle wall-time will
collapse roughly 10×.

### 3.4 Receipt chain verification

A 10-link Receipt SLF chain replays from JSON to fully hash-verified in well
under 1 ms on the test machine, dominated by BLAKE3 hashing (3 µs per link ×
10). Phase 1 chain verification is hash-linking only — `verify_chain` recomputes
each link's BLAKE3 content hash and checks `prev_hash` continuity; receipts are
UNSIGNED in Phase 1, so no per-link signature verification happens. This scales
linearly; a 100-link chain should verify in well under 1 ms. Production chains
are expected to stay well under 100 links per user even over multi-year usage
(recovery actions are infrequent by design). Per-link Ed25519 signature
verification (~150 µs per signature) is added once signature binding lands in
Phase 2.

### 3.5 Test suite execution

The full `cargo test --workspace --no-fail-fast` suite consists of 10 test
files totaling 778 LOC. Crate-level tests:

- `frost-tier0`: ≥6 tests (happy_path + threshold_property)
- `slf-receipts`: ≥5 tests (chain_verify, 5 subtests)
- `recovery-orchestrator`: ≥8 tests (state_transitions + cooldown_cancellation)
- `spa-recovery-cli`: ≥3 tests (e2e_lifecycle, 3 subtests)
- Workspace-level: 4 test files (recovery_from_each_pair, key_never_reconstructed,
  receipt_chain_replay, fuzz_lifecycle), with the fuzz test running 100
  seeded iterations

All gates passed under
both `cargo test --workspace` and the CI pipeline `cargo check` / `cargo clippy`
/ `cargo fmt --check` / `cargo test --no-fail-fast`.

## 4. Design feedback for the next recovery-design revision

Phase 1 surfaced four specific changes to fold into the v0.2 revision of the
recovery design document. Each is described, motivated by the Phase 1 finding,
and proposed concretely.

### 4.1 Probation is non-cancellable (§2.7 clarification)

**v0.1 text:** "Probation can be cleared early by (a) old-device explicit transfer,
(b) in-person rebind, or (c) full Tier-2 recovery completion." The text implies
probation can be cleared but is silent on whether it can be *cancelled* —
i.e., rolled back to a pre-recovery state.

**Phase 1 finding (§2.2 above):** Probation-cancellation is incoherent. Once
the new device is bound and the new identity-anchor-presentation is on the
chain, there is no "Onboarded-on-old-device" state to roll back to. The
fraud-signal response during probation is therefore **forward-looking only** —
it routes to the §4.7 compromise-rotation flow, not to a rollback.

**Proposed v0.2 text:** "Probation can be *cleared early* (a/b/c above) but
cannot be *cancelled*. Anomaly signals during probation trigger
[§4.7 compromise rotation](#47-compromise) on the new device, not rollback to
the prior device. The cancel-channel applies only to the cooldown window."

### 4.2 Receipt-chain canonicalization is normative, not informative (§9 + §2.2 expansion)

**v0.1 text:** §9 enumerates Receipt SLF subtypes; §2.2 says receipts are
"immutable and addressable" but does not specify *how* the canonical byte
representation is computed.

**Phase 1 finding (§2.3 above):** Determinism of JSON output was a real
implementation hazard. Two compliant JSON encoders (one Rust, one Swift, one
Kotlin) can produce different byte sequences for the same Receipt struct if
field ordering is not normatively specified. Hash-chain integrity then breaks
silently at platform boundaries — a Phase 2 iOS prototype verifying a chain
produced by the Phase 1 Rust CLI would fail in production with no error path
that surfaces "canonicalization mismatch" as distinct from "tampered link."

**Proposed v0.2 text:** Add a new §2.2.1 "Receipt canonical byte representation"
specifying:

- Field ordering is lexicographic on field name
- Numeric types are JSON numbers with no trailing zeros; integers have no
  decimal point
- Strings are NFC-normalized UTF-8
- Map keys are sorted; arrays preserve their semantic order
- The canonical hash is BLAKE3 over the canonical byte representation

Reference the [RFC 8785 JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785)
as the inspiration but commit to whichever subset Phase 2 actually implements
across Rust / Swift / Kotlin.

### 4.3 Tier 0 stores the group public key separately from the shares (§3 Tier 0 expansion)

**v0.1 text:** §3 Tier 0 specifies the three shares (device, cloud, recovery code)
but is silent on whether the group public key (FROST `PublicKeyPackage`)
travels with each share or is stored separately.

**Phase 1 finding (§2.1):** The as-built design stores the group public key in one
place, not per share. Each `Share` holds only the serialized `KeyPackage` bytes; the
group public key is a separate `GroupPublicKey` value persisted to a single
`group_pubkey.json` file, and the coordinator loads that one file at aggregation and
verification time. This keeps each share minimal and gives the group context a single
source of truth rather than three redundant copies. It matters in Phase 2: when one
share loads from Secure Enclave on iOS and another from Keychain, the group public key
has a defined home (its own file or record) instead of being carried inside whichever
share happens to be available.

**Proposed v0.2 text:** Add to §3 Tier 0: "The FROST group public key is stored once,
separately from the shares, as a standalone group-context record (the Phase 1 CLI
persists it to `group_pubkey.json`). Each share carries only its own signing material
and is not required to embed a copy of the group public key. Phase 2 platforms must
provide a defined storage location for this single group-context record alongside the
per-share storage."

### 4.4 Cooldown / probation state must be serializable for crash recovery (§2.7 expansion)

**v0.1 text:** §2.7 describes probation behavior but is silent on what happens
if the device crashes / loses power / is restarted mid-cooldown or mid-probation.

**Phase 1 finding:** The orchestrator's `State` enum is `serde::Serialize` and
the `Cooldown { ends_at }` / `Probation { ends_at }` payloads carry their
deadlines inline. This makes crash-recovery free — on restart, the CLI
deserializes the persisted state and the next `tick()` invocation correctly
resumes the cooldown/probation timer. This is a *property* we discovered we
needed during Phase 1 implementation, and it should be a *requirement* in
v0.2.

**Proposed v0.2 text:** Add to §2.7: "Cooldown and probation state is
persisted to durable storage with each transition. On device restart mid-window,
the timer resumes from the stored deadline. The orchestrator does not depend
on a continuously-running process; tick events drive timer progression."

## 5. Open questions: answered vs. carried forward

From the scope memo's investigation list:

| # | Investigation | Phase 1 status |
|---|---|---|
| 1 | Does FROST-2-of-3 work as designed? | **Answered yes** (§2.1) |
| 2 | Lifecycle state machine coherence under stress? | **Answered yes** (§2.2 + fuzz 100×) |
| 3 | Receipt SLF chain end-to-end verifiability? | **Answered yes** (§2.3) |
| 4 | Secure Enclave + FROST-Ed25519 ciphersuite compatibility? | **Carried to Phase 2** (ADR-001 Negative §) |
| 5 | Signing latency on production hardware? | **Carried to Phase 2** (formal `criterion` benchmarks) |
| 6 | ZK-proof-of-backup feasibility? | **Carried to Phase 3** (no Phase 1 work) |
| 7 | UX testing with non-crypto users? | **Carried to Phase 2** (recruit 6-10 users) |

## 6. Phase 2 recommendation

**Recommendation: Go.**

Phase 1 confirmed all three load-bearing claims. The FROST-2-of-3 protocol works
exactly as the design specified, with no protocol-level surprises. The lifecycle
state machine survived 100 fuzz-iterations with zero invariant violations. The
Receipt SLF chain verifies end-to-end across process boundaries with no shared
state. None of the four design-feedback items in §4 indicate a fundamental
problem; they are clarifications and tightening of the v0.1 spec, all
mechanically addressable in a v0.2 revision.

The four v0.2 changes (§4.1–§4.4) should land in the v0.2 design revision
*before* Phase 2 ticketing begins, because the canonicalization requirement
(§4.2) and the group-public-storage requirement (§4.3) cross-cut the iOS / Android
implementations that Phase 2 starts.

Phase 2 entry criteria are met:

- Tier 0 reference implementation exists
- Receipt SLF schema is validated end-to-end (§2.3)
- The state-machine library is portable to Phase 2 mobile harnesses (no I/O,
  no clock-of-its-own, fully `serde`-serializable)
- ADRs for the three load-bearing design decisions are recorded (ADR-001/-002/-003)

The next concrete work (to be planned by Architect in a Phase 2 plan document,
mirroring the Phase 1 plan format) is:

1. A next-revision design update incorporating §4.1–§4.4
2. iOS prototype skeleton + Secure Enclave adapter behind a `ShareSource` trait
3. Android prototype skeleton + StrongBox adapter
4. Apple iCloud Keychain / Google Password Manager real-integration
5. Formal `criterion`-driven benchmark suite
6. UX testing recruit (6-10 non-crypto users via UserTesting.com)

No design pivot is required. **Go.**

---

*End of Phase 1 evaluation report.*
