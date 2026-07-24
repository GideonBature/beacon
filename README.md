# Beacon

**Beacon** is the BitVM3-style **dispute layer** for [Cube](https://github.com/BitVM):  
Assert → off-chain Evaluate → **Timeout** (honest) or **Disprove** (fraud) on Bitcoin Taproot.

Cryptographic backend: [BitVM/garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier)  
(Cargo `git` dependency — not vendored).

```text
Engine posts Assert (adaptor opening + hashlock H(L*))
        │
        ▼
Challenger evaluates garbled verifier off-chain
        │
   ┌────┴────┐
   │ Valid   │ Invalid → reveal L* → Disprove
   ▼         ▼
 Timeout   Connector spent (Engine cannot withdraw)
```

## What works today

| Phase | What | Regtest |
|-------|------|---------|
| **A** | Direct-seed opening + Claim Mini + signed Taproot | Yes |
| **B** | Schnorr adaptor extractable opening | Yes |
| **C** | Share-bundle reconstruct + tiny garbled Evaluate | Yes |
| **C+** | Real `garbled_groth16::verify` Garble → Evaluate | Off-chain smoke (`--release`) |

Verified end-to-end: honest → **Accepted**; cheat → **Rejected** with `L*`.  
Phase C+ on a laptop at `--k 4` is ~15–35 minutes per run (BN254 verifier gadget).

## Cube vs Beacon — who owns what?

**Not everything waits on Cube.** Beacon already owns the Bitcoin dispute graph and the GSV glue. Cube supplies the *statement being proved*.

| Owned by Beacon (can continue now) | Needs Cube (or a Cube-shaped SNARK) |
|------------------------------------|-------------------------------------|
| Taproot Assert / Disprove / Timeout | Real CubeVM state-transition circuit / VK |
| Adaptor opening + hashlock contract | Public inputs that bind to Cube state |
| GSV link, tiny Evaluate, Groth16 smoke | Production proof artifacts from Cube |
| Regtest / Docker driver | Mainnet policy, bonds, watchtowers |
| Assert witness layout, C&C packaging | Wire-compat with Cube’s proving pipeline |

Until Cube exposes a Groth16 (or equivalent) verifier key + proofs, Beacon keeps using **Claim Mini** and GSV’s **DummyCircuit** as stand-ins. Swapping those in is the main integration step — not redesigning Disprove.

## Quick start

```bash
# Fast tests (no GSV)
cargo test --no-default-features

# Phase A / B / C simulation
cargo run --example phase_a_driver --no-default-features
cargo run --example phase_a_driver --no-default-features -- --cheat
cargo run --example phase_a_driver --no-default-features -- --adaptor --cheat
cargo run --example phase_a_driver --no-default-features -- --phase-c --cheat
```

### Regtest (Docker)

```bash
cp docker-compose.example.yml docker-compose.yml   # gitignored
docker compose up -d
export BEACON_RPC_URL=http://127.0.0.1:18443 BEACON_RPC_USER=beacon BEACON_RPC_PASS=beacon

cargo run --example phase_a_driver --no-default-features -- --regtest
cargo run --example phase_a_driver --no-default-features -- --adaptor --regtest --cheat
cargo run --example phase_a_driver --no-default-features -- --phase-c --regtest --cheat
```

See [`docs/12-regtest-guide.md`](docs/12-regtest-guide.md).

### GSV / Phase C+ (heavier)

Use a directory literally named `target` (SP1 build-script quirk):

```bash
export CARGO_TARGET_DIR=./target

# Tiny garbled Evaluate
cargo run --example phase_c_garble --features gsv --no-default-features

# Full garbled Groth16 (prefer --release; expect many minutes)
cargo run --release --example phase_c_plus --features gsv --no-default-features -- --k 4
cargo run --release --example phase_c_plus --features gsv --no-default-features -- --k 4 --cheat
```

## Architecture

```text
CircuitBackend
├── ClaimMiniBackend       ← Phase A–C stand-in (fast)
└── GarbledSnarkBackend    ← GSV-linked path

Opening
├── DirectSeedOpening      ← Phase A
└── AdaptorOpening         ← Phase B / C / C+

phase_c/
├── reconstruct + evaluate ← tiny AND (Phase C)
├── ciphertext_store       ← off-chain CT + hash verify
└── groth16 + plus         ← garbled Groth16 (Phase C+)
```

On-chain rule (unchanged across phases):

```text
H(L_invalid) = SHA256(L*)     # Disprove leaf: OP_SHA256 <H> OP_EQUALVERIFY
```

## Features

| Feature | Purpose |
|---------|---------|
| *(default `gsv`)* | Link garbled-snark-verifier (GPL-3.0-only) |
| `--no-default-features` | Fast Claim Mini / regtest without GSV |
| `gsv-vsss` | Upstream VSSS lagrange reconstruct |
| `gsv-groth16` | Alias for Phase C+ (`gsv`) |

## Roadmap

- [x] Phase A – Assert → Evaluate → Disprove / Timeout (regtest)
- [x] Phase B – Adaptor extractable opening
- [x] Phase C – Tiny garbled Evaluate + share bundle
- [x] Phase C+ – Garbled Groth16 Evaluate smoke
- [x] Assert witness packing v1 (OP_RETURN + chain round-trip)
- [x] Ciphertext store MVP (disk CT + hash verify + Evaluate-from-store)
- [x] Cut-and-choose schedule MVP + Assert `ciphertext_hash`
- [ ] Mainnet policy for large datacarrier / alternate reveal-tx carrier
- [ ] C+ proof/VK sidecar + check-set re-garble consistency
- [ ] Wire GSV `AdaptorInfo` (Fr shares) to Beacon opening
- [ ] Swap DummyCircuit / Claim Mini for **Cube** VK + proofs

## Docs

| Doc | Topic |
|-----|--------|
| [`docs/01-design-overview.md`](docs/01-design-overview.md) | Design |
| [`docs/11-phase-a-status.md`](docs/11-phase-a-status.md) | Phase A |
| [`docs/15-phase-b-status.md`](docs/15-phase-b-status.md) | Phase B |
| [`docs/16-phase-c-status.md`](docs/16-phase-c-status.md) | Phase C |
| [`docs/17-phase-c-plus-status.md`](docs/17-phase-c-plus-status.md) | Phase C+ |
| [`docs/18-assert-witness.md`](docs/18-assert-witness.md) | Assert witness packing + Cube alignment |
| [`docs/19-ciphertext-store.md`](docs/19-ciphertext-store.md) | Off-chain CT persist |
| [`docs/20-cut-and-choose-schedule.md`](docs/20-cut-and-choose-schedule.md) | C&C schedule + Assert CT hash |
| [`docs/12-regtest-guide.md`](docs/12-regtest-guide.md) | Docker / bitcoind |
| [`docs/14-circuit-backend.md`](docs/14-circuit-backend.md) | Backends + GSV |

## License

MIT — see [`LICENSE`](LICENSE).  

Binaries built with `--features gsv` (the default) link **GPL-3.0-only** garbled-snark-verifier; distribute accordingly. Use `--no-default-features` for MIT-only Claim Mini builds.
