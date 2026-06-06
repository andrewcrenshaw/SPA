# Security Policy

## Status: research prototype - NOT security-audited

This repository contains the SPA **recovery-prototype**, a **Phase 1 / Tier-0
research prototype**. It exists to demonstrate the SPA recovery design
(FROST-Ed25519 threshold recovery + SLF receipts), not to protect real keys,
identity, or funds. **Do not deploy it for production key custody.** It has not
undergone an independent security audit.

## Phase-1 threat model and known limitations

Phase 1 validates the protocol and lifecycle, not the production security
boundary. The following are intentional Phase-1 limitations, not bugs:

- **Receipts are unsigned.** The receipt chain is hash-linked (BLAKE3 `prev_hash`)
  and tamper-evident, so it shows *integrity*, not *authenticity*. No FROST
  signature is bound into receipts yet; that is Phase-2 work.
- **Share-at-rest encryption is not a real boundary.** Shares are encrypted with
  AES-256-GCM keys derived (via Argon2id) from compile-time **stub passphrases**
  embedded in the binary. Anyone who can read a share file can also read the
  passphrase, so this protects only against casual disclosure, not a real
  attacker. Hardware-backed key sources (Secure Enclave / Keychain / StrongBox)
  replace the stubs in Phase 2.
- **Cooldown / probation is a lifecycle UX safety window, not a cryptographic
  guarantee.** The 48-hour cooldown and 24-hour probation are time-driven
  lifecycle gates intended to give multi-channel veto and a fraud-signal window.
  They are enforced by the orchestrator state machine and emitted as receipts by
  the CLI by convention; they are not a cryptographic property and do not bind an
  attacker who controls the host.
- **Keygen uses a trusted dealer.** The 2-of-3 split is generated with
  trusted-dealer keygen, so the dealer transiently holds the full signing key in
  memory at onboarding before splitting it into shares. The "key is never
  reconstructed" property holds for *signing* and *recovery* (which combine
  partial signatures and never reassemble shares), not for *keygen*. Interactive
  DKG that removes the trusted-dealer assumption is later-phase work.

## Reporting a vulnerability

Despite the prototype status, responsible-disclosure reports are welcome. Please
email **security@lexenne.com** with a description, reproduction steps, and impact.
Do not open a public issue for a suspected vulnerability.
