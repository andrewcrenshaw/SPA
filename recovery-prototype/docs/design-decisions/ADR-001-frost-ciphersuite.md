# ADR-001 — FROST Ciphersuite Selection (Ed25519)

**Date:** 2026-05-25
**Status:** Accepted
**Author:** alex (Architect)
**Scope:** SPA recovery-prototype, Phase 1 (Tier 0)
**Supersedes:** none
**Related:** Sovereign Personal Agent architecture (design companion) — see `spec/SPA-ARCHITECTURE.md` in the [SLF repo](https://github.com/andrewcrenshaw/slf)

---

## Context

The SPA recovery design (v0.1, §3 Tier 0) calls for a FROST 2-of-3 threshold signature
scheme as the cryptographic substrate for splitting the substrate-vault KEK across
(device, cloud, recovery code) shares. FROST is the only threshold Schnorr family that
is RFC-published (RFC 9591, June 2024), has multiple independent implementations, and
has received third-party cryptographic audit at production scale.

RFC 9591 specifies five concrete ciphersuites:

| Ciphersuite | Group | Hash | Signature output |
|-------------|-------|------|------------------|
| `frost-ed25519-sha512` | edwards25519 | SHA-512 | 64 bytes (Ed25519-compatible) |
| `frost-ristretto255-sha512` | ristretto255 | SHA-512 | 64 bytes (Ristretto-specific) |
| `frost-p256-sha256` | NIST P-256 | SHA-256 | 64 bytes |
| `frost-secp256k1-sha256` | secp256k1 | SHA-256 | 64 bytes (Bitcoin BIP-340-compatible) |
| `frost-ed448-shake256` | edwards448 | SHAKE256 | 114 bytes |

Phase 1 must commit to exactly one ciphersuite. The choice constrains:

- Which Rust implementation the `frost-tier0` crate wraps
- Verification ergonomics for downstream Receipt-SLF consumers
- Hardware-backed share storage options in Phase 2 (Secure Enclave / StrongBox curve support)
- Post-quantum migration path (different ciphersuites have different upgrade roadmaps)

## Decision

**Phase 1 adopts `frost-ed25519-sha512`** (FROST over edwards25519 with SHA-512),
implemented via the `frost-ed25519` crate (Zcash Foundation, version 2.2.0) which is
the RFC 9591 reference implementation in Rust.

The crate is pinned exactly in `recovery-prototype/crates/frost-tier0/Cargo.toml`:

```toml
frost-ed25519 = "=2.2.0"
zeroize = { version = "1.8", features = ["derive"] }
```

The exact pin (`=2.2.0`) is intentional — minor version drift in a load-bearing
cryptographic primitive is treated as an explicit ADR-update event, not a routine
dependency bump.

## Rationale

### Why FROST-Ed25519 over the four alternatives

**vs. `frost-p256-sha256`.** P-256 is the curve mandated by FIPS 186-5 / NIST SP 800-186
and is the curve every iOS Secure Enclave and Android StrongBox supports natively.
This would matter enormously in Phase 2. The disqualifier is RFC 6979 / SP 800-186
deterministic-nonce semantics interact awkwardly with FROST's two-round protocol:
the threshold-signer-aggregated nonce cannot reuse the deterministic-nonce trick, so
the per-signer RNG quality requirement is identical to Ed25519's anyway. P-256
keeps the FIPS lineage but adds NIST-curve patent-and-provenance baggage (Dual_EC
historical taint, lingering distrust in the Snowden-era constant selection) without
any compensating engineering benefit at the FROST layer. We accept that Phase 2 will
have to bridge Ed25519 ↔ Secure Enclave via a separate trust-attestation pathway
(see ADR-002 §"Phase 2 hardware migration").

**vs. `frost-secp256k1-sha256`.** secp256k1 is the Bitcoin/Ethereum curve. Choosing it
buys us BIP-340 Schnorr-signature compatibility for free, which is genuinely useful
if SPA grants ever consume on-chain anchors. The disqualifier: secp256k1 is a Koblitz
curve with a small embedding degree, and the broader cryptographic-research community
has converged on Edwards-form curves (Ed25519, Ed448, Ristretto) for forward design.
Choosing secp256k1 in 2026 is a posture decision ("we are blockchain-aligned") that
the SPA architecture explicitly avoids — SPA's anchor model is identity-anchor-led
(passport ZK-PoP, EUDIW WUA), not chain-led. We should not bake the chain coupling
into the recovery substrate.

**vs. `frost-ristretto255-sha512`.** Ristretto255 is the cleanest abstraction (no
cofactor, no malleability concerns at the group-element level) and is what we would
choose in a vacuum. The disqualifier is ecosystem fit: every existing Ed25519-aware
tool — passport ICAO PKD ECDSA-over-p256 + Ed25519 hybrid PoP libraries, EUDIW SD-JWT
Ed25519 issuer keys, multi-anchor ZK-PoP libraries that produce Ed25519 group elements
— is Ed25519-shaped. Choosing Ristretto-only means writing or maintaining adapters
for every external consumer. The engineering cost is real and the cryptographic gain
is theoretical at the FROST-aggregate level (Ristretto-255 and Ed25519 deliver
the same ~128-bit classical / ~64-bit Grover-quantum security).

**vs. `frost-ed448-shake256`.** Ed448 gives ~224-bit classical security vs. Ed25519's
~128-bit, which is the only meaningful technical lever any of the alternatives offers.
The disqualifier: signature size (114 bytes vs. 64 bytes) propagates through every
Receipt SLF in the chain, the verification cost is 4-5× higher, and the threat model
that demands 224-bit security is incompatible with Ed25519 at the message-layer
already (the SPA architecture issues Ed25519 message signatures in many places).
We would be paying the Ed448 cost only at the recovery layer for no compound
security gain. If long-term post-quantum migration becomes urgent before Phase 5,
the answer is ML-DSA-threshold (Eurocrypt 2024+) rather than Ed448 — see
"Consequences" below.

### Why the Zcash Foundation `frost-ed25519` crate specifically

- **RFC 9591 reference implementation.** Direct lineage to the IRTF CFRG specification.
- **Audited (upstream).** The Zcash Foundation FROST crates were audited by NCC Group
  (public report, *Zcash FROST Security Assessment*, v0.6.0 - covering trusted-dealer and
  DKG key generation and FROST signing); all identified issues were addressed. (Separately,
  Least Authority audited the FROST *demo* tools - `frost-client`/`frostd` - in Q1 2025, with
  no high-severity findings.) Note the NCC audit covered v0.6.0, not the v2.2.0 pinned here:
  upstream assurance is on the audited *line*, not this exact version.
- **Active adoption for Zcash.** FROST is the Zcash Foundation's threshold-Schnorr line of
  work for Zcash wallets and custody; a v1.0.0 stable reference release shipped in 2025
  (see "The State of FROST for Zcash").
- **Permissive license.** Dual MIT / Apache-2.0; we elect Apache-2.0 to match the
  SPA repository (see [LICENSE](../../../LICENSE)).
- **Active maintenance.** Release cadence ~monthly; the Zcash Foundation is a 501(c)(3)
  with a multi-year recovery-and-threshold roadmap.
- **Zeroize support.** Internal `SigningShare` types already `impl ZeroizeOnDrop`.

## Status

**Accepted** for Phase 1. Reviewable as a design-checkpoint event for Phase 2 if any of
the following triggers:

- Threshold Raccoon (Eurocrypt 2024) lands a production-ready Rust implementation
- ML-DSA-threshold (ePrint 2025/1166) reaches a peer-reviewed Rust crate
- The Zcash Foundation deprecates the `frost-ed25519` crate (no signal as of 2026-05-25)

## Consequences

### Positive

- Smallest, fastest signatures of the five RFC 9591 ciphersuites (64 bytes, ~1.2 ms
  full aggregate-and-verify on Apple M-series at single-threaded baseline per the
  Zcash Foundation's published benchmarks)
- Direct ecosystem fit with EUDIW issuer-signature flows and ICAO passport ZK-PoP
  Ed25519 group elements
- The `frost-tier0` crate stays a thin wrapper (~410 LOC including tests) — RFC 9591
  compliance is inherited rather than re-implemented
- Receipt SLF signatures (per [ADR-003](ADR-003-state-machine-shape.md) and the SLF
  schema in `slf-receipts/src/schema.rs`) are Ed25519-typed end-to-end, eliminating
  cross-curve marshalling

### Negative / accepted costs

- **No native Secure Enclave Ed25519 storage on iOS (as of iOS 19).** The Secure
  Enclave exposes only NIST P-256 keys. Phase 2 will therefore use the Secure Enclave
  to attest a *separate* device key whose role is to authenticate to the on-device
  software keystore that holds the actual Ed25519 share. The shape is the same as
  what Signal Foundation does for its libsignal-protocol Ed25519 identity keys.
  This is documented as an explicit Phase 2 design checkpoint in
  [ADR-002 §"Phase 2 hardware migration"](ADR-002-share-storage-model.md).
- **PQ migration is non-trivial.** When the time comes, ML-DSA-threshold (Lyubashevsky
  et al. 2024) replaces FROST-Ed25519 wholesale; signature sizes grow from 64 bytes
  to ~2.4 kB and Receipt SLF storage costs grow proportionally. We accept this as
  the cost of shipping today rather than waiting for PQ-threshold maturity.
- **No BIP-340 compatibility.** SPA grants cannot directly anchor to Bitcoin/Ethereum
  Schnorr-compatible chains. If on-chain anchoring becomes load-bearing in Phase 4+,
  a separate `frost-secp256k1` parallel ciphersuite would be added rather than
  migrating.

### Neutral

- 128-bit classical security is the same as TLS 1.3's default ECDHE-X25519. We are
  not under-protecting; we are matching the prevailing transport-layer threshold.
- The dependency on `frost-ed25519 = "=2.2.0"` is one of three load-bearing exact
  pins in the workspace (the others are `blake3` and `aes-gcm`). All three are
  documented in this ADR set so that any future upgrade triggers an explicit
  decision-record review.
