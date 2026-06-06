# recovery-prototype

Prototype implementation of the **SPA recovery protocol**: threshold
recovery of a sovereign identity using FROST-Ed25519 + verifiable SLF
receipts.

> ⚠️ **Research prototype. NOT security-audited.** Do not use to protect real keys, identity, or funds. It exists to demonstrate the recovery design, not for production key custody.
>
> Status: Phase 1 / Tier-0 complete. DKG, FROST threshold signing, receipt
> encoding + hash-chain verification, and the orchestrator are implemented and
> tested. Later phases harden share storage and add receipt signature binding.

### Known Phase-1 limitations

- **Receipts are unsigned.** The receipt chain is hash-linked (BLAKE3
  `prev_hash`) and tamper-evident, but receipts carry no cryptographic
  signature in Phase 1 — the chain proves integrity, not authenticity. Binding
  a FROST-Ed25519 signature into each receipt is a Phase 2 item.
- **Share-at-rest encryption is not a real security boundary.** Shares are
  encrypted with AES-256-GCM keys derived from compile-time stub passphrases
  embedded in the binary. Anyone with the share file also has the passphrase,
  so Phase 1 storage protects against casual disclosure only, not a real
  attacker. Hardware-backed key sources replace the stubs in Phase 2.
- **Keygen uses a trusted dealer.** Phase 1 generates the 2-of-3 split with
  trusted-dealer keygen (`dealer_keygen` → `frost-ed25519`'s
  `generate_with_dealer`), so the dealer transiently holds the full signing key
  in memory at onboarding before splitting it into shares. The "key is never
  reconstructed" property holds for *signing* and *recovery* — both combine
  partial signatures and never reassemble shares — but not for *keygen*.
  Interactive DKG that removes the trusted-dealer assumption (so the full key
  never exists in one place, even at onboarding) is later-phase work.

## Crates

| Crate | Role |
|-------|------|
| [`frost-tier0`](crates/frost-tier0) | Tier-0 FROST-Ed25519 DKG + sign + verify primitives |
| [`slf-receipts`](crates/slf-receipts) | SLF receipt data model, canonical encoding, and verification |
| [`recovery-orchestrator`](crates/recovery-orchestrator) | Coordinates participants through a recovery session |

## Apps

| App | Role |
|-----|------|
| [`apps/cli`](apps/cli) | `recovery` binary — drives the orchestrator from the command line |

## Workspace

This sub-tree does NOT define its own Cargo workspace. All crates and
apps are members of the workspace at the SPA repository root. Run all
`cargo` commands from the repository root, not from this directory.

## Design references

- Substrate-Lens-Frame protocol + reference implementation: https://github.com/andrewcrenshaw/slf
- Sovereign Personal Agent architecture (design companion): see `spec/SPA-ARCHITECTURE.md` in that repo
- Position paper: "The Governance Gap in Agentic Memory" (Crenshaw, 2026) - Zenodo DOI added on deposit
- External crypto dep: [`frost-ed25519`](https://crates.io/crates/frost-ed25519) (Zcash Foundation, RFC 9591, Least Authority audit Q1 2025)
