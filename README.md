# Beacon

**Beacon** is the BitVM3-style dispute layer for Cube.

Target cryptographic backend: [BitVM/garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier)
(imported via Cargo `git` dependency — not vendored).

## Quick start

```bash
cargo test --no-default-features
cargo run --example phase_a_driver              # simulation
cargo run --example phase_a_driver -- --cheat

# Live Phase A on regtest (Docker Desktop — see docs/12-regtest-guide.md)
cp docker-compose.example.yml docker-compose.yml   # gitignored local copy
docker compose up -d
export BEACON_RPC_URL=http://127.0.0.1:18443 BEACON_RPC_USER=beacon BEACON_RPC_PASS=beacon
cargo run --example phase_a_driver --no-default-features -- --regtest
cargo run --example phase_a_driver --no-default-features -- --regtest --cheat

# Phase B – Schnorr adaptor opening (same Taproot graph)
cargo run --example phase_a_driver --no-default-features -- --adaptor
cargo run --example phase_a_driver --no-default-features -- --adaptor --regtest --cheat

# Phase C – VSSS reconstruct + garbled Evaluate (tiny AND MVP)
cargo run --example phase_a_driver --no-default-features -- --phase-c --cheat
cargo run --example phase_a_driver --no-default-features -- --phase-c --regtest --cheat
# Real GSV Evaluate (use stock ./target — see docs/16-phase-c-status.md)
CARGO_TARGET_DIR=./target cargo run --example phase_c_garble --features gsv --no-default-features

# Phase C+ – full garbled Groth16 verify (heavy; --release)
CARGO_TARGET_DIR=./target cargo run --release --example phase_c_plus --features gsv --no-default-features -- --k 4
CARGO_TARGET_DIR=./target cargo run --release --example phase_c_plus --features gsv --no-default-features -- --cheat

# Optional: GSV-linked backend (git dep; heavier build)
cargo run --example gsv_link
cargo run --example phase_a_driver -- --gsv --cheat
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
- [x] Taproot Assert / Disprove / Timeout with real Schnorr signatures
- [x] Live regtest runner (`--regtest` / `--regtest --cheat`)
- [x] Real `garbled-snark-verifier` linked via git dependency
- [x] Phase B – Schnorr adaptor extractable opening (`--adaptor`)
- [x] Phase C – VSSS reconstruct + tiny garbled Evaluate (`--phase-c`)
- [x] Phase C+ – garbled Groth16 Evaluate (`phase_c_plus`, `--release`)

## Docs

See [`docs/`](docs/) — especially [`07-garbled-snark-verifier.md`](docs/07-garbled-snark-verifier.md)
and [`docs/14-circuit-backend.md`](docs/14-circuit-backend.md).

## License

MIT — see [`LICENSE`](LICENSE).  
Note: the optional GSV dependency is GPL-3.0-only.
