# SPA — Sovereign Personal Agent

Umbrella repository for the **Sovereign Personal Agent** initiative. Hosts
multiple Rust prototype sub-trees that explore primitives for sovereign
identity, threshold recovery, and verifiable receipts.

> ⚠️ **Research prototype. NOT security-audited.** Do not use to protect real keys, identity, or funds. It exists to demonstrate the recovery design, not for production key custody.
>
> Status: early prototype. Nothing here is production-ready.

## Layout

```
SPA/
├── Cargo.toml                      ← Cargo workspace root
├── recovery-prototype/             ← T1+ recovery prototype sub-tree
│   ├── crates/
│   │   ├── frost-tier0/            ← FROST-Ed25519 threshold signing
│   │   ├── slf-receipts/           ← SLF receipt encoding + verification
│   │   └── recovery-orchestrator/  ← session coordinator
│   └── apps/
│       └── cli/                    ← `recovery` CLI binary
├── .github/workflows/ci.yml        ← check / clippy / fmt / test on push
├── LICENSE                         ← Apache-2.0
└── README.md                       ← this file
```

Additional prototype sub-trees may be added later; they become workspace
members via the `[workspace] members` glob in the root `Cargo.toml`.

## Developing

```bash
# from the SPA root
cargo check --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
cargo test --workspace --no-fail-fast
```

The CI workflow at [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
runs the same four gates on every push.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Related

- Substrate-Lens-Frame protocol + reference implementation: https://github.com/andrewcrenshaw/slf
- Sovereign Personal Agent architecture (design companion): see `spec/SPA-ARCHITECTURE.md` in that repo
- Position paper: "The Governance Gap in Agentic Memory" (Crenshaw, 2026) - Zenodo DOI added on deposit
