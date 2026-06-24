# ADR-004 — Phase 2 Hardware Key Custody (Secure Enclave + iCloud Keychain + P-256/Ed25519 bridge)

**Date:** 2026-06-23
**Status:** Proposed — gated on two design checkpoints (see §Design Checkpoints). Not yet implemented.
**Author:** alex (Architect)
**Scope:** SPA recovery-prototype, Phase 2 (KC-2). Tracks backlog PCC-3172.
**Related:** [ADR-001](ADR-001-frost-ciphersuite.md) (Ed25519 / P-256-only Enclave), [ADR-002 §"Phase 2 hardware migration"](ADR-002-share-storage-model.md) (the seam this fills in), [ADR-003](ADR-003-state-machine-shape.md). Workstream K2 of ADR-SLF-SPA-PHASE2-KEY-CUSTODY-2026-06-20.

---

## Context

PCC-3158 (KC-2 Phase 1.5, commit `51f9e09`) landed the [`ShareSource`] trait seam and a
device-bound stand-in, [`DeviceBoundSource`], in `apps/cli/src/persistence.rs`. The seam is:

```rust
pub trait ShareSource {
    fn wrapping_secret(&self, kind: &ShareKind) -> Result<Secret, PersistError>;
}
```

`save_share` / `load_share` ask the source for a `Secret`, then run the fixed
Argon2id → AES-256-GCM derivation around it (ADR-002). `DeviceBoundSource` returns
`root_key || domain_label`, where `root_key` is 32 bytes of OS entropy written once to
`<base>/.spa-device-key` at `0600`. That keyfile is the explicit prototype stand-in for a
non-exportable Secure-Enclave key: an attacker already running code as the user can still
read it. Phase 2 replaces the stand-in with real hardware backends behind the same trait,
with no change to any caller.

This ADR is the design pass for that replacement. It has to answer three questions before
any platform code is written:

1. **How does Rust reach Security.framework without `unsafe`?** The workspace sets
   `unsafe_code = "forbid"` in `SPA/Cargo.toml [workspace.lints.rust]`, inherited by every
   member crate via `[lints] workspace = true`. `forbid` is the strongest Rust lint level
   and cannot be relaxed by an inner `#[allow(unsafe_code)]`. Every Secure-Enclave and
   Keychain operation is a C-ABI call, which is `unsafe` in Rust. These two facts collide.

2. **What entitlements / code-signing does each backend require?** Secure-Enclave key
   generation and iCloud-Keychain synchronizable items have very different signing burdens.
   Mislabeling them sets a false expectation for what the macOS PoC can prove.

3. **How does the P-256-attests-Ed25519 bridge sit on the `ShareSource` seam?** The Enclave
   is P-256-only (ADR-001 §"Negative", line 145); FROST shares are Ed25519. The Ed25519
   share cannot live *inside* the Enclave. The bridge must be expressed as a `ShareSource`
   implementation that changes no caller and ideally no derivation code.

---

## Decision

### D0 — All three backends remain behind `ShareSource`; no caller changes

`save_share` / `load_share` and every CLI command stay byte-for-byte as PCC-3158 left them.
Phase 2 adds new `ShareSource` implementors and a small amount of source-selection wiring.
The `recovery_code` share, the one share intentionally **not** device-bound (ADR-002), moves
to a portable user-entered 28-character code source; it is a peer `ShareSource` impl, not a
regression of the device-binding the other two shares keep.

| Share | Phase 1.5 (today) | Phase 2 backend (this ADR) |
|-------|-------------------|----------------------------|
| `device` | device root key (`0600` file) | `SecureEnclaveSource`: SE P-256 key wraps the per-device root secret (ECIES); only this Enclave can unwrap it. |
| `cloud` | device root key (`0600` file) | `KeychainSource`: HSM-wrapped **synchronizable** Keychain item (`kSecAttrSynchronizable`), readable on the user's other iCloud-Keychain devices. |
| `recovery_code` | device root key (`0600` file) | `RecoveryCodeSource`: Argon2id over a user-entered 28-char printable code, intentionally portable. |

### D1 — FFI approach: `security-framework` crate first, quarantined raw-FFI shim as fallback (CHECKPOINT 1)

**Recommended:** depend on the `security-framework` crate (which wraps Apple's C API inside
`security-framework-sys`). The `forbid(unsafe_code)` lint is per-crate and does **not** apply
transitively to dependencies, so the `unsafe` that any Security.framework binding needs lives
in a third-party crate, and every SPA member crate keeps `forbid(unsafe_code)` intact. This is
the lowest-friction path and preserves the invariant verbatim.

**The risk that makes this a checkpoint, not a foregone conclusion:** the `security-framework`
crate's coverage of Secure-Enclave key generation (`kSecAttrTokenIDSecureEnclave`),
`SecAccessControlCreateWithFlags` (`.privateKeyUsage`), and ECIES
`SecKeyCreateEncryptedData` / `SecKeyCreateDecryptedData`
(`eciesEncryptionCofactorX963SHA256AESGCM`) has historically been partial. The first spike
task is a throwaway probe: generate an SE P-256 key, encrypt 32 bytes to its public key, and
decrypt them back, using only safe `security-framework` APIs. If that probe compiles and runs,
D1 is settled on the crate.

**Fallback if the crate's surface is insufficient:** introduce one new crate,
`crates/spa-se-bridge`, that **does not** inherit the workspace lints (it omits
`[lints] workspace = true` and sets its own `[lints] rust.unsafe_code = "allow"`). All raw
`security-framework-sys` FFI is quarantined there behind a safe Rust facade; the cli crate
depends on the facade and keeps `forbid`. This confines `unsafe` to one small, individually
auditable platform-shim crate rather than relaxing the invariant workspace-wide. We do **not**
relax `forbid` on any existing crate, and we do **not** shell out to a separate signed helper
binary (an out-of-process `security`-CLI helper was considered and rejected: it adds a second
build artifact and its own signing story for no security gain over the quarantined shim).

### D2 — Entitlements / code-signing, per backend (CHECKPOINT 1, second half)

The two backends have sharply different signing requirements, and conflating them
over-promises what the macOS PoC can demonstrate:

- **`device` / Secure Enclave (in scope for the PoC).** SE key generation requires the
  process to carry a valid code signature. On macOS an **ad-hoc** signature (`codesign -s -`)
  is sufficient to create and use a non-synchronizable SE key for the current user; a Developer
  ID signature is preferable for a stable key-access ACL but is not required to prove the
  off-device property. The access-control object is built with
  `SecAccessControlCreateWithFlags(.privateKeyUsage)` (add `.biometryCurrentSet` / `.userPresence`
  later for the biometric gate; the prototype PoC can omit it). This backend is achievable on a
  single Apple-silicon Mac.

- **`cloud` / iCloud Keychain (design-only here; deferred to a child ticket).** A
  synchronizable item (`kSecAttrSynchronizable = true`) needs a real Apple Developer Team: an
  `application-identifier`, a `keychain-access-groups` entitlement, the Keychain Sharing
  capability, and a provisioning profile. A bare `cargo`-built CLI cannot obtain these; it
  needs to be a signed `.app` bundle with an embedded entitlements plist, or to run on a
  provisioned device. **Finding:** the cloud-share PoC is gated on Apple Developer Team
  entitlements and is out of reach for a CLI proof. We document the design and defer the
  runnable PoC to its own child ticket.

This split is why PCC-3172's hardware AC (AC#4) is scoped to the **device / Secure Enclave**
share specifically.

### D3 — The bridge: ECIES-wrap-to-Enclave, mapped onto `ShareSource` (CHECKPOINT 2)

The Enclave never holds the Ed25519 FROST share. Instead the SE P-256 key wraps the
*wrapping secret*, exactly the libsignal / iMessage-identity-key shape ADR-001 and ADR-002
already name. Concretely, `SecureEnclaveSource` is a drop-in `ShareSource`:

**Onboarding (once):**
1. Generate a non-exportable SE P-256 key; its private half lives in the Enclave forever.
2. Mint a random 32-byte `root_secret` in memory.
3. ECIES-encrypt `root_secret` to the SE **public** key →
   `<base>/.spa-se-wrapped-key` (ciphertext is safe to store in the clear: only this
   Enclave's private key can decrypt it).
4. Zeroize the in-memory `root_secret`.

**`wrapping_secret(kind)` (every save/load):**
1. Read `<base>/.spa-se-wrapped-key`.
2. `SecKeyCreateDecryptedData` → the Enclave unwraps `root_secret` into memory briefly
   (this is the operation an access-control flag can gate on presence/biometry).
3. Return `Secret::new(root_secret || kind.domain_label())`, identical in shape to
   `DeviceBoundSource`.

**Why this maps cleanly (the checkpoint-2 answer):**
- The Argon2id → AES-256-GCM derivation is **untouched**; the SE simply replaces the
  on-disk `0600` root key as the source of the same `root_secret` bytes.
- No caller changes; `SecureEnclaveSource` swaps in where `DeviceBoundSource::load_or_create`
  is constructed.
- **Off-device property (AC#4) falls out for free.** Copy the `.share` **and**
  `.spa-se-wrapped-key` to a second Mac: that machine's Enclave cannot decrypt a blob
  encrypted to *this* Enclave's public key (the private key is non-exportable), so
  `wrapping_secret` fails and `load_share` fails. This is strictly stronger than today's
  `0600` keyfile, which an attacker with user-level read access can copy and reuse.
- "Attestation" in the ticket title is the optional second leg: the SE key can additionally
  **sign** a statement binding the software Ed25519 share's public verifying key to this
  device. That attestation is a receipt-binding concern that composes with PCC-3157's
  FROST-signed receipts and is **not** load-bearing for share-at-rest confidentiality, which
  the ECIES wrap already provides. Keeping the two legs separate avoids over-scoping the PoC.

### D4 — Decomposition into child tickets

Per the PCC-3172 note, the work decomposes after this spike. Recommended children:

| Child | Scope | Gating |
|-------|-------|--------|
| KC-2.1 (PCC-3188, filed) | `security-framework` SE/ECIES probe; settles D1 (crate vs shim) | none — pure spike |
| KC-2.2 | `SecureEnclaveSource` impl + the `device.share` hardware PoC (AC#2, AC#4) | gated on KC-2.1 outcome + Checkpoint 2 sign-off |
| KC-2.3 | `RecoveryCodeSource` (28-char user code) | independent; no FFI |
| KC-2.4 | `KeychainSource` (`cloud.share`, synchronizable) + `.app`/entitlements harness | gated on a provisioned Apple Developer Team (D2) |

KC-2.2–2.4 are deliberately left unfiled until KC-2.1 (PCC-3188) returns the crate-vs-shim
verdict: their `file_scope` and ACs depend on whether the `spa-se-bridge` shim crate exists.

`SecureEnclaveSource` is macOS/iOS-gated (`#[cfg(target_os = ...)]`); non-Apple targets keep a
compile-time fallback so the workspace still builds and `cargo test --workspace` stays green on
CI that is not Apple-silicon.

---

## Open questions / spike probes (resolve in KC-2.1 before KC-2.2 code)

1. Does `security-framework` expose SE key gen + `SecAccessControl` + ECIES encrypt/decrypt
   with safe APIs? (Decides D1.) 
2. Is ad-hoc `codesign -s -` enough for SE key creation under `cargo test`, or does the test
   binary need a Developer ID signature / a wrapper `.app`? (Decides whether AC#4 is a manual
   run or a CI step; manual is the safe assumption.)
3. ECIES algorithm pin: `eciesEncryptionCofactorX963SHA256AESGCM` vs
   `...StandardX963...`. Pin one and record it like the other load-bearing crypto pins
   (ADR-001 §Neutral).

### KC-2.1 verdict (PCC-3188) — Checkpoint 1 settled on the crate

Probe: `apps/cli/examples/se_probe.rs`, `security-framework = "3"` (resolved 3.7.0,
`security-framework-sys 2.17.0`). It generated a non-exportable SE P-256 key, ECIES-encrypted a
random 32-byte secret to its public half, and decrypted it back through the Enclave, using only
safe `security-framework` APIs (the example contains zero `unsafe`; the cli crate keeps
`[lints] workspace = true` → `forbid(unsafe_code)`). It ran on Apple-silicon under an ad-hoc
signature and round-tripped the 32 bytes (113-byte ciphertext: 65-byte ephemeral P-256 point +
16-byte GCM tag + 32-byte payload), exit 0.

1. **Resolved: YES. `security-framework` is sufficient; the `spa-se-bridge` raw-FFI shim is
   NOT needed.** SE key generation is `GenerateKeyOptions` + `SecKey::new` with
   `Token::SecureEnclave` and `KeyType::ec()`; access control is
   `SecAccessControl::create_with_flags(kSecAccessControlPrivateKeyUsage)`; ECIES is
   `SecKey::encrypt_data` / `SecKey::decrypt_data`. Two naming gaps to carry into KC-2.2 (both
   safe, neither needs `unsafe`): the wrappers are `encrypt_data` / `decrypt_data`, not Apple's
   `SecKeyCreateEncryptedData` / `SecKeyCreateDecryptedData`; and `kSecAccessControlPrivateKeyUsage`
   is not re-exported by the safe crate (value `1 << 30`, restated locally). **D1 is settled on
   the crate. KC-2.2 builds on `security-framework`; the shim fallback is dropped.**
2. **Resolved for key creation: ad-hoc `codesign -s -` is enough.** The probe key is
   *non-permanent* (no keychain location → `kSecAttrIsPermanent = false`), so it needs no
   keychain-access-group and produced no prompt. Open sub-question for KC-2.2: the
   `SecureEnclaveSource` flow needs the SE key to *persist across process restarts*, which means
   a permanent key in the data-protection keychain; whether ad-hoc signing still suffices for a
   *permanent* SE key or whether a `keychain-access-groups` entitlement (and thus an
   `.app` / provisioning) is required is the next thing KC-2.2 must measure. AC#4's off-device
   test stays a manual two-Mac run.
3. **Resolved: pin `ECIESEncryptionCofactorX963SHA256AESGCM`** (the cofactor X9.63 / SHA-256 /
   AES-GCM variant). Confirmed present in `security-framework-sys 2.17.0` and exercised by the
   probe. Record alongside the ADR-001 §Neutral crypto pins.

The probe is throwaway: nothing in `src/` depends on it and `persistence.rs` is untouched.

---

## KC-2.2 implementation design (`SecureEnclaveSource`)

Tracks the next child after the KC-2.1 verdict. Carries PCC-3172's AC#2 (a `SecureEnclaveSource`
implements `ShareSource`) and AC#4 (the off-device hardware proof). Built on `security-framework`
"3" per the settled D1; no shim.

### The one thing the probe did not prove: key persistence

The probe key was **non-permanent** (no keychain location → regenerated per process, ad-hoc
signing sufficed). `SecureEnclaveSource` cannot work that way: the CLI runs `onboard`, then
`sign`, then `recover` as **separate processes**, and each must unwrap the same `.spa-se-wrapped-key`
blob. That requires the **same SE private key across process restarts**, i.e. a **permanent** SE
key in the data-protection keychain, retrieved by a stable application tag. Whether ad-hoc
`codesign -s -` still suffices for a *permanent* SE key, or whether a `keychain-access-groups`
entitlement (and therefore an `.app` bundle + provisioning) is required, is **unmeasured**. It is
the gating risk of this ticket and the subject of KC-2.2's first design checkpoint.

### Design (grounded in the probe's API surface)

```rust
// apps/cli/src/persistence.rs — Apple-gated, additive. DeviceBoundSource stays for non-device
// kinds and non-Apple targets until KC-2.3 / KC-2.4 land.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub struct SecureEnclaveSource { se_key: security_framework::key::SecKey }

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl SecureEnclaveSource {
    const KEY_TAG: &str = "com.lexenne.spa.device-se-key";   // application tag, stable across runs
    const WRAPPED_FILE: &str = ".spa-se-wrapped-key";        // ECIES blob, safe in the clear
    const ECIES: Algorithm = Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM; // ADR pin

    // Fetch the PERMANENT SE key by tag (ItemSearchOptions, class=key, load_refs). If absent:
    // generate a permanent SE key (set_token(SecureEnclave) + a data-protection-keychain
    // location + application_tag + access_control(1<<30)), mint a random 32-byte root_secret,
    // ECIES-wrap it to the key's public half, write <base>/.spa-se-wrapped-key, zeroize secret.
    pub fn load_or_create(base: &Path) -> Result<Self, PersistError> { /* … */ }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl ShareSource for SecureEnclaveSource {
    fn wrapping_secret(&self, kind: &ShareKind) -> Result<Secret, PersistError> {
        let blob = fs::read(base.join(Self::WRAPPED_FILE))?;
        let root = self.se_key.decrypt_data(Self::ECIES, &blob)?; // unwrap THROUGH the Enclave
        let mut material = root;                                   // root_secret …
        material.extend_from_slice(kind.domain_label().as_bytes()); // … || domain_label
        Ok(Secret::new(material))                                  // identical shape to DeviceBoundSource
    }
}
```

`save_share` / `load_share` gain a tiny per-kind **source factory** (the "small source-selection
wiring" of D0): `ShareKind::Device` on Apple → `SecureEnclaveSource`; everything else →
`DeviceBoundSource` (interim). The CLI commands above the persistence layer do not change.

### TDD plan (what is machine-verifiable vs hardware-manual)

SE calls cannot run in CI (`cargo test` is unsigned, non-Apple runners have no Enclave). So:
- **Machine-green everywhere:** `SecureEnclaveSource` is `#[cfg(target_os = …)]`-gated so
  `cargo test --workspace` compiles and passes on non-Apple CI (PCC-3172 AC#3 stays green). A
  software-only unit test still covers the kind→`domain_label` concatenation and the blob file
  shape via the existing `DeviceBoundSource` path.
- **Hardware-gated, `#[ignore]` by default:** an `se_roundtrip` test that creates the permanent
  SE key, wraps/unwraps a secret, and asserts round-trip. Run manually on signed Apple-silicon
  (`cargo test -- --ignored se_roundtrip`).
- **Manual two-Mac (AC#4):** `onboard` on Mac A; copy the user dir's `.share` **and**
  `.spa-se-wrapped-key` to Mac B; `recover`/`load_share` on Mac B must fail (B's keychain holds
  no SE key under `KEY_TAG`).

### Cargo wiring

```toml
[target.'cfg(any(target_os = "macos", target_os = "ios"))'.dependencies]
security-framework = "3"
core-foundation = "0.10"
```

### Smoke + rollback

- **Smoke:** `cargo build`; `codesign -s - target/debug/recovery`; `recovery onboard <user>`;
  confirm `.spa-se-wrapped-key` materializes and `recovery sign` round-trips on one Mac.
- **Rollback:** `SecureEnclaveSource` is additive behind `#[cfg]`; reverting the `save_share` /
  `load_share` factory back to `DeviceBoundSource` restores Phase-1.5 behavior with no data
  migration (the `.share` blobs are source-agnostic; only the wrapping secret's origin changes).

### KC-2.2 design checkpoints (human approval)

1. **Permanent-key entitlement measurement.** Before writing `SecureEnclaveSource`, confirm
   whether a *permanent* SE key (data-protection keychain + application tag) can be created and
   retrieved across processes under ad-hoc signing, or whether it needs a `keychain-access-groups`
   entitlement + `.app`. If the latter, decide: ship an `.app` PoC harness, or record the
   constraint and scope the PoC to a signed bundle.
2. **Pre-submit.** Confirm `cargo test --workspace` is green on a non-Apple target (cfg-gating
   holds) and that the off-device two-Mac result is recorded before close.

---

## Consequences

### Positive
- The seam holds: three real backends slot in with zero caller changes and an unchanged
  Argon2id → AES-GCM path. The device backend is a genuine hardware security boundary, not a
  `0600` convention.
- `forbid(unsafe_code)` survives on every existing crate under both D1 outcomes.
- AC#4's off-device guarantee is a direct consequence of SE key non-exportability, provable on
  two Macs.

### Negative / accepted costs
- The cloud / iCloud-Keychain PoC cannot run from a CLI; it is design-only here and needs a
  provisioned `.app` (KC-2.4). We state this rather than implying the PoC covers all three.
- A new platform-shim crate (the D1 fallback) adds one `unsafe`-bearing crate to audit. It is
  small and isolated by construction.
- Each SE decrypt is an Enclave round-trip per share read. This amortizes the Argon2id cost
  ADR-002 flagged; net latency is a KC-2.2 measurement, not a Phase-1 regression.

### Out of scope for this ADR
- `recovery_code` portability UX (TUI vs stdin vs share-sheet) — KC-2.3.
- Biometric / presence gating of the SE decrypt — a later hardening flag on the access-control
  object, not required to prove off-device binding.
- Updating `recovery-prototype/SECURITY.md` and `README.md`: both are **outside** PCC-3172's
  `file_scope` (docs/design-decisions/ + persistence.rs only). Their Phase-2 wording update is
  deferred to a closeout doc ticket so the file_scope gate stays honest.

---

## Design Checkpoints (human approval required before KC-2.2 code)

1. **FFI approach + entitlements (D1, D2).** Confirm: `security-framework` crate first, with a
   quarantined `spa-se-bridge` raw-FFI crate as the fallback that preserves `forbid` everywhere
   else; PoC scoped to the SE `device` share under ad-hoc codesign, with cloud/Keychain
   design-only pending an Apple Developer Team.
2. **The bridge maps onto the seam (D3).** Confirm: `SecureEnclaveSource` returns an
   SE-unwrapped `root_secret || domain_label`, leaving the Argon2id → AES-GCM derivation and
   all callers untouched, before `DeviceBoundSource` is replaced.

Until both are confirmed, `persistence.rs` is not modified and `DeviceBoundSource` is not
replaced.
