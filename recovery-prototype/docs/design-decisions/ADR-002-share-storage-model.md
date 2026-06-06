# ADR-002 — Phase 1 Share Storage Model

**Date:** 2026-05-25
**Status:** Accepted (Phase 1 only — explicit replacement in Phase 2)
**Author:** alex (Architect)
**Scope:** SPA recovery-prototype, Phase 1 (Tier 0)
**Related:** [ADR-001](ADR-001-frost-ciphersuite.md), [ADR-003](ADR-003-state-machine-shape.md), Sovereign Personal Agent architecture (design companion) — see `spec/SPA-ARCHITECTURE.md` in the [SLF repo](https://github.com/andrewcrenshaw/slf)

---

## Context

The SPA recovery design (v0.1, §3 Tier 0) commits to a FROST-2-of-3 share split across:

1. **Device share** — eventually Secure Enclave / StrongBox-backed, biometric-gated
2. **Cloud share** — eventually wrapped by iCloud Keychain / Google Password Manager HSM
3. **Recovery code share** — eventually a 28-character printable code presented at setup

In Phase 1 ("kick the tires"), none of those three production substrates are
integrated. The goal of Phase 1 is to validate the FROST protocol, the state-machine
lifecycle, and the Receipt SLF chain — not the hardware-backed share storage. We
therefore need an interim share-storage model that:

- Lets the CLI persist all three shares to disk so the lifecycle is exercisable
  across multiple process invocations (`onboard`, then `sign`, then `recover` in
  separate processes)
- Encrypts shares at rest so we are not normalizing plaintext-key-on-disk patterns
  even in a prototype
- Makes the Phase-2 substitution mechanical (one trait, three new implementations)
- Refuses to compile if a share is constructible from public types — the
  "no-key-reconstruction" invariant is enforced structurally, not by convention

## Decision

**Phase 1 stores each share as a file at `~/.spa-recovery/<user-id>/{device,cloud,recovery_code}.share`,
encrypted with AES-256-GCM using a key derived via Argon2id from a per-share-type
stub passphrase.**

Three stub passphrases are baked into the CLI binary for Phase 1:

| Share type | Stub passphrase (constant) | Phase 2 replacement |
|------------|----------------------------|---------------------|
| `device` | `"spa-device-stub"` | Secure Enclave / StrongBox-derived KEK |
| `cloud` | `"spa-cloud-stub"` | iCloud Keychain / Google Password Manager wrap |
| `recovery_code` | `"spa-recovery-code-stub"` | User-entered 28-char printable code |

Each stub is fed through Argon2id with a per-file random salt written into the
file header. The code calls `Argon2::default()` (argon2 crate v0.5.3), whose
default parameters are **m=19456 KiB (19 MiB), t=2, p=1** — the OWASP/RFC 9106
second-recommended profile. The resulting 32-byte key is used as the AES-256-GCM
key; the nonce is 96 bits of `getrandom`-sourced randomness per encrypt.

In-memory share representation is the `Share` opaque type defined in
`recovery-prototype/crates/frost-tier0/src/dkg.rs`. As built, the share holds
the serialized upstream `KeyPackage` inside a zeroizing buffer rather than the
individual FROST sub-fields:

```rust
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    key_package_bytes: Zeroizing<Vec<u8>>,
}
```

The single field is private (no `pub`/`pub(crate)` visibility), and the only
public methods are `participant_id()`, `to_bytes()` / `from_bytes()` (for
encrypted-at-rest round-tripping), and the crate-internal `to_key_package()` —
none of which expose the underlying `SigningShare`. `Display` and `Debug` are
not derived; the type is opaque even at the panic-message layer. The buffer is
wrapped in `Zeroizing`, and `Share` derives both `Zeroize` and `ZeroizeOnDrop`,
so the serialized key material is overwritten when the value is dropped. Because the serialized `KeyPackage` inside `Share` carries the FROST group
verifying key, the group public key travels with each share. The full
public-key package - every participant's verifying share plus the group
verifying key - is additionally held as a separate `GroupPublicKey` (persisted
to `group_pubkey.json`) and used for signature verification.

## Rationale

### Why AES-256-GCM + Argon2id rather than ChaCha20-Poly1305 or libsodium secretbox

- AES-NI hardware acceleration is universal on the M-series and Snapdragon hardware
  the Phase 2 mobile prototype targets. ChaCha20 is faster only when AES-NI is
  unavailable (older ARM cores, some embedded), which is not Phase 1 or Phase 2.
- AES-256-GCM is the same AEAD called out in §2.5 of the recovery design specification for
  substrate vault content. Using one AEAD across the prototype reduces the audit
  surface.
- Argon2id is the OWASP-recommended password-hashing function (RFC 9106) and the
  one most likely to survive a future "the stub passphrases were committed to git"
  forensic review — a fast hash like PBKDF2 would not survive that scenario,
  Argon2id's memory-hard derivation (the crate-default 19 MiB profile) makes it
  tractable. Raising the memory cost toward the 64 MiB first-recommended profile is
  a Phase-2 hardening knob, not a Phase-1 requirement.
- We considered libsodium `secretbox` (XSalsa20-Poly1305). Same security; less
  hardware acceleration; one more native dependency to vendor. Net negative.

### Why a stub passphrase rather than real user input in Phase 1

Phase 1 is automatable end-to-end testing: the e2e_lifecycle integration test runs
`onboard → sign → lose-device → recover → audit` as a single deterministic shell
script. Interactive user input would block automation. The stub passphrase is the
minimum mechanism that exercises the encryption-at-rest path without coupling Phase 1
to a real keystore.

The stub passphrases are not secrets in the threat-model sense — they are constants
visible in the binary. A reader who has the share file *also* has the passphrase.
The encryption is therefore protecting against:

- Casual filesystem grep (the encrypted shares are not greppable plaintext)
- Backup-tool exfiltration of `~/.spa-recovery/` to a non-encrypted cloud
- The reflexive "do not normalize plaintext keys on disk" property — Phase 2
  drops the stub and uses real key sources without changing the surrounding code

The threat model that *matters* — a real attacker on a real device — is not
addressed by Phase 1 storage. It is addressed by Phase 2's hardware-backed
replacement. This is intentional and is documented at the top of
`apps/cli/src/persistence.rs`.

### Why one share per file rather than a combined keystore

- Loss of one file = loss of one share. The FROST 2-of-3 invariant means losing
  any single share is recoverable. A combined keystore would make a single corrupt
  file a 3-of-3 loss.
- The Phase 2 substitution is share-type-specific: the device share moves to
  Secure Enclave, the cloud share moves to iCloud, the recovery-code share moves
  to user-entered input. Each substitution touches one file's persistence path,
  not a unified store.
- Receipt SLFs in `slf-receipts` reference shares by participant ID
  (`ParticipantId(1)` = device, `ParticipantId(2)` = cloud, `ParticipantId(3)` =
  recovery_code). The one-share-per-file layout matches that addressability
  directly.

### Why `~/.spa-recovery/<user-id>/` rather than `$XDG_CONFIG_HOME` or platform-specific paths

- Phase 1 is macOS-only in practice (the dev environment). Cross-platform path
  resolution (`dirs` crate) is wired in but the canonical layout is
  `~/.spa-recovery/`. Phase 2 platforms (iOS, Android) bypass the filesystem
  entirely — shares move into Secure Enclave / StrongBox / Keychain, so XDG
  conventions never become load-bearing.
- The `<user-id>` subdirectory is a UUID generated at `onboard`, allowing multiple
  recovery contexts on the same machine for testing (e.g., simulating multiple
  users in the e2e suite).

## Status

**Accepted** for Phase 1 with explicit replacement in Phase 2. This ADR's
"Consequences → Phase 2 hardware migration" section is the entry point for the
Phase 2 design pass.

## Consequences

### Positive

- The CLI lifecycle (`onboard → sign → recover → audit`) runs end-to-end across
  multiple process invocations with no manual key input, enabling deterministic
  CI testing
- Shares are encrypted-at-rest, satisfying the "no plaintext keys on disk" property
  without requiring a Phase 1 keystore integration
- The `Share` opaque type provides compile-time enforcement that no caller can
  reconstruct the underlying signing key — the `key_never_reconstructed.rs`
  workspace test verifies this structurally (`ZeroizeOnDrop` implementation +
  grep for absence of `combine_to_secret` / `reconstruct_full_key` symbols)
- One trait swap (a hypothetical `ShareSource` adapter) replaces the entire
  storage mechanism in Phase 2 — there is no schema migration

### Negative / accepted costs

- Phase 1 storage is **not a real security boundary.** The stub passphrases are
  binary-embedded constants. Any reader of the share file is implicitly a reader
  of the share. This is acknowledged explicitly in the Phase 1 evaluation report
  and at the top of `persistence.rs`.
- The `.share` file format is Phase-1-specific. Phase 2 emits no `.share` files
  on iOS/Android (Secure Enclave + Keychain own the storage). A migration tool
  for users who somehow ended up with Phase-1 `.share` files in production is
  *not provided* — Phase 1 is explicitly not for production users (the README
  says "early prototype; nothing here is production-ready").
- Argon2id key derivation runs on every share decrypt, so each `sign` invocation
  pays the derivation cost twice (two shares). The per-derivation cost has not been
  formally measured in Phase 1; the crate-default 19 MiB profile is cheaper than the
  64 MiB first-recommended profile, and a `criterion` benchmark is deferred to Phase 2.
  Either way the cost would be unacceptable on a per-signature basis in production —
  Phase 2's Secure Enclave / Keychain calls amortize this away.

### Phase 2 hardware migration (forward-looking)

Phase 2 replaces share storage with three implementations of a forthcoming
`ShareSource` trait:

| Phase 1 file path | Phase 2 source | iOS API | Android API |
|-------------------|----------------|---------|-------------|
| `device.share` | Secure Enclave–attested keystore | `SecureEnclave.P256.KeyAgreement` (attests software Ed25519 key) | `KeyStore "AndroidKeyStore"` + `StrongBox` flag |
| `cloud.share` | iCloud Keychain HSM-wrapped item | `kSecAttrSynchronizable=true` + `kSecAttrAccessibleAfterFirstUnlock` | Google Password Manager Wrapped Sync |
| `recovery_code.share` | User-entered 28-char printable code | Stdin / TUI / share-sheet | Stdin / TUI / share-sheet |

The Ed25519 / Secure Enclave gap (Secure Enclave is P-256-only) is bridged by the
Signal-Foundation libsignal-protocol pattern: a Secure-Enclave-resident P-256 key
attests a software Ed25519 key, and the recovery FROST share lives behind the
attestation gate. This is the same shape as iMessage's Ed25519-identity-key
storage and is documented in [ADR-001 §"Consequences → Negative"](ADR-001-frost-ciphersuite.md).
