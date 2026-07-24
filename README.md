# Beacon

**Beacon** is the BitVM3-style dispute layer for Cube.

Target cryptographic backend: [BitVM/garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier)
(imported via Cargo `git` dependency — not vendored).

## Quick start

```bash
cargo test
cargo run --example gsv_link                    # prove GSV crate is linked
cargo run --example phase_a_driver              # claim-mini
cargo run --example phase_a_driver -- --gsv     # GSV-backed backend
cargo run --example phase_a_driver -- --gsv --cheat

# Without GSV (Claim Mini only)
cargo test --no-default-features
```

## Circuit backends

```text
CircuitBackend
├── ClaimMiniBackend          ← Phase A (works today)
└── GarbledSnarkBackend       ← git-depends on garbled-snark-verifier
```

Assert / Disprove / Timeout stay the same across backends.  
`H(L_invalid) = SHA256(L*)` for the Taproot hashlock.

```toml
# Cargo.toml
garbled-snark-verifier = { git = "https://github.com/BitVM/garbled-snark-verifier", default-features = false, features = ["test-utils"], optional = true }
```

Upstream is **GPL-3.0-only**. Default `gsv` builds that into Beacon binaries.

See [`docs/14-circuit-backend.md`](docs/14-circuit-backend.md).

## Status

- [x] Phase A logical flow (Assert → Evaluate → Disprove / Timeout)
- [x] Claim Mini circuit + `L*` fraud secret
- [x] Pluggable `CircuitBackend` + `--gsv` driver switch
- [x] Hashlock-correct `SHA256(L*)` commitment
- [x] Taproot Assert / Disprove / Timeout tx builders (unsigned placeholders)
- [x] Real `garbled-snark-verifier` linked via git dependency
- [ ] Full Taproot signing + regtest broadcast
- [ ] Phase B – adaptor signatures
- [ ] Phase C – VSSS + full garbled Groth16 Evaluate

## Docs

See [`docs/`](docs/) — especially [`07-garbled-snark-verifier.md`](docs/07-garbled-snark-verifier.md)
and [`docs/14-circuit-backend.md`](docs/14-circuit-backend.md).

## License

MIT — see [`LICENSE`](LICENSE).  
Note: the optional GSV dependency is GPL-3.0-only.
