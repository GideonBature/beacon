# Beacon

**Beacon** is the BitVM3-style **dispute layer** for [Cube](https://github.com/BitVM):  
Assert → off-chain Evaluate → **Timeout** (honest) or **Disprove** (fraud) on Bitcoin Taproot.

Cryptographic backend: [BitVM/garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier)  
(Cargo `git` dependency — not vendored). Upstream GSV owns gate/gadget/Groth16 GC correctness; Beacon owns the Bitcoin dispute graph and Cube-shaped glue.

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

Also in-tree:

- **AssertWitnessV1** — packed statement + claim + opening + optional `ShareBundle` / `ciphertext_hash` (OP_RETURN carrier; annex helper for research)
- **CiphertextStore** — off-chain `gc_{id}.bin` + meta, hash verify, Evaluate-from-store
- **Cut-and-choose schedule** — sample/fixed partition, check-set open, eval commit + re-garble consistency
- **GSV adaptor wire** (`gsv-vsss`) — Fr-share opening tag `3` (distinct from Phase B Cube adaptor)
- **C+ eval sidecar** — disk package for Evaluate without keeping the Engine bundle in RAM

Verified end-to-end (A/B/C): honest → **Accepted**; cheat → **Rejected** with `L*`.  
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

## Requirements

- Rust **1.90+** (`rust-version` in `Cargo.toml`)
- For GSV features: network to fetch the git dependency; build dir named `target` (see below)
- For regtest: Docker + `docker-compose.example.yml` (see [docs/12-regtest-guide.md](docs/12-regtest-guide.md))

## Quick start

```bash
# Fast Claim Mini path (no GSV link)
cargo test --no-default-features

# Phase A / B / C simulation
cargo run --example phase_a_driver --no-default-features
cargo run --example phase_a_driver --no-default-features -- --cheat
cargo run --example phase_a_driver --no-default-features -- --adaptor --cheat
cargo run --example phase_a_driver --no-default-features -- --phase-c --cheat
```

### Contrib scripts

```bash
chmod +x contrib/*.sh   # once
```

| Script | What it does | Typical time |
|--------|----------------|--------------|
| [`contrib/run-tests.sh`](contrib/run-tests.sh) | Default unit + integration matrix | seconds–couple minutes |
| [`contrib/run-phase-c-plus.sh`](contrib/run-phase-c-plus.sh) | Full garbled Groth16 honest + cheat | **~15–35+ min per run** at `--k 4` |

#### Fast test matrix

```bash
./contrib/run-tests.sh

# Also run #[ignore] suites (Docker regtest + slow Phase C+ Groth16 *test*)
./contrib/run-tests.sh --with-ignored --release
```

| Flag | Effect |
|------|--------|
| *(none)* | Default suites only (CI-friendly; skips `#[ignore]`) |
| `--with-ignored` / `-i` | Regtest + Phase C+ ignored tests |
| `--release` / `-r` | `cargo test --release` (strongly recommended with `--with-ignored`) |
| `--help` | Usage |

#### Phase C+ heavy path (minutes)

Runs the real `phase_c_plus` example in **release** (honest, then cheat):

```bash
./contrib/run-phase-c-plus.sh                 # --k 4 honest + cheat
./contrib/run-phase-c-plus.sh --k 6           # heavier
./contrib/run-phase-c-plus.sh --honest-only
./contrib/run-phase-c-plus.sh --cheat-only
./contrib/run-phase-c-plus.sh --with-test     # also ignored integration_gsv C+ test
```

Both scripts set `CARGO_TARGET_DIR=./target` by default (SP1 / GSV build-script quirk: the directory name must be `target`).

Details and coverage stance: [docs/23-integration-tests.md](docs/23-integration-tests.md).

### Integration suites (manual)

```bash
# Core — Claim Mini, Phase A/B/C stand-in, witness, Taproot, store, C&C
cargo test --test integration_core --no-default-features

# GSV AND persist / evaluate-from-store / C&C re-garble
export CARGO_TARGET_DIR=./target
cargo test --test integration_gsv --features gsv --no-default-features

# GSV Fr-share adaptor (tag 3) + AssertWitness round-trip
cargo test --test integration_gsv_vsss --features gsv-vsss --no-default-features

# Optional (ignored by default)
cargo test --test integration_regtest --no-default-features -- --ignored
cargo test --test integration_gsv --features gsv --release -- --ignored
```

| Suite | Features | Covers |
|-------|----------|--------|
| `integration_core` | none | Claim Mini, A/B/C stand-in, AssertWitness, Taproot builders, store (SHA256), C&C schedule |
| `integration_gsv` | `gsv` | Linked backend, AND persist/eval-from-store, check-set re-garble; C+ `#[ignore]` |
| `integration_gsv_vsss` | `gsv-vsss` | Tag-3 `GsvAdaptorOpening`, Fr extract, ShareBundle, witness |
| `integration_regtest` | none | Docker Assert → Timeout/Disprove for A/B/C (`#[ignore]`) |

These aim for **behavioral coverage of Beacon-owned public APIs**, not LLVM line coverage of upstream GSV or a multi-minute C+ garble in the default run.

### Regtest (Docker)

```bash
cp docker-compose.example.yml docker-compose.yml   # gitignored
docker compose up -d
export BEACON_RPC_URL=http://127.0.0.1:18443 BEACON_RPC_USER=beacon BEACON_RPC_PASS=beacon

cargo run --example phase_a_driver --no-default-features -- --regtest
cargo run --example phase_a_driver --no-default-features -- --adaptor --regtest --cheat
cargo run --example phase_a_driver --no-default-features -- --phase-c --regtest --cheat

# Or via the ignored integration suite
./contrib/run-tests.sh --with-ignored
```

See [docs/12-regtest-guide.md](docs/12-regtest-guide.md). Bitcoind needs a large enough `-datacarriersize` for AssertWitness OP_RETURN (set in `docker-compose.example.yml`).

### GSV / Phase C+ (heavier)

Prefer the dedicated runner for the minutes-long Groth16 path:

```bash
./contrib/run-phase-c-plus.sh
```

Or manually (directory must be named `target`):

```bash
export CARGO_TARGET_DIR=./target

cargo run --example phase_c_garble --features gsv --no-default-features
cargo run --example phase_c_persist --features gsv --no-default-features
cargo run --example phase_c_cnc --features gsv --no-default-features
cargo run --example gsv_adaptor --features gsv-vsss --no-default-features

cargo run --release --example phase_c_plus --features gsv --no-default-features -- --k 4
cargo run --release --example phase_c_plus --features gsv --no-default-features -- --k 4 --cheat
```

## Architecture

```text
CircuitBackend
├── ClaimMiniBackend       ← Phase A–C stand-in (fast)
└── GarbledSnarkBackend    ← GSV-linked path

Opening / AssertOpening
├── DirectSeedOpening      ← Phase A
├── AdaptorOpening         ← Phase B / C / C+ (Cube Phase B labels)
└── GsvAdaptorOpening      ← tag 3 Fr-share (`gsv-vsss`)

phase_c/
├── reconstruct + evaluate ← tiny AND (Phase C)
├── ciphertext_store       ← off-chain CT + hash verify
├── schedule               ← cut-and-choose partition
├── persist                ← garble-to-store / evaluate-from-store
├── sidecar                ← C+ eval package on disk
└── groth16 + plus         ← garbled Groth16 (Phase C+)

witness/
└── AssertWitnessV1        ← BEAC magic, claim, opening, H(L*), optional CT hash
```

On-chain rule (unchanged across phases):

```text
H(L_invalid) = SHA256(L*)     # Disprove leaf: OP_SHA256 <H> OP_EQUALVERIFY
```

Ciphertexts and evaluation sidecars stay **off-chain**; Assert only needs the commitment, extractable opening, and `H(L*)` (plus optional `ciphertext_hash` for C&C binding).

## Features

| Feature | Purpose |
|---------|---------|
| *(default `gsv`)* | Link garbled-snark-verifier (GPL-3.0-only) |
| `--no-default-features` | Fast Claim Mini / regtest without GSV |
| `gsv-vsss` | Upstream VSSS lagrange + GSV Fr-share adaptor (tag 3) |
| `gsv-groth16` | Alias for Phase C+ (`gsv`) |

## Examples

| Example | Features | Purpose |
|---------|----------|---------|
| `phase_a_driver` | none | Phase A/B/C sim + optional `--regtest` |
| `gsv_link` | `gsv` | Smoke that GSV links |
| `phase_c_garble` | `gsv` | Tiny garbled Evaluate |
| `phase_c_persist` | `gsv` | CT store + evaluate-from-store |
| `phase_c_cnc` | `gsv` | C&C schedule + Assert CT hash |
| `gsv_adaptor` | `gsv-vsss` | Tag-3 Fr-share adaptor wire |
| `phase_c_plus` | `gsv` | Full garbled Groth16 (`--release`, `--k`) |

## Roadmap

- [x] Phase A – Assert → Evaluate → Disprove / Timeout (regtest)
- [x] Phase B – Adaptor extractable opening
- [x] Phase C – Tiny garbled Evaluate + share bundle
- [x] Phase C+ – Garbled Groth16 Evaluate smoke
- [x] Assert witness packing v1 (OP_RETURN + chain round-trip)
- [x] Ciphertext store MVP (disk CT + hash verify + Evaluate-from-store)
- [x] Cut-and-choose schedule MVP + Assert `ciphertext_hash`
- [x] GSV adaptor wire-compat (Fr-share opening tag 3, `gsv-vsss`)
- [x] C+ eval sidecar + check-set re-garble consistency
- [x] Integration test suites + `contrib/run-tests.sh` / `contrib/run-phase-c-plus.sh`
- [ ] Mainnet policy for large datacarrier / alternate reveal-tx carrier
- [ ] Swap DummyCircuit / Claim Mini for **Cube** VK + proofs

## Docs

| Doc | Topic |
|-----|--------|
| [docs/01-design-overview.md](docs/01-design-overview.md) | Design |
| [docs/11-phase-a-status.md](docs/11-phase-a-status.md) | Phase A |
| [docs/15-phase-b-status.md](docs/15-phase-b-status.md) | Phase B |
| [docs/16-phase-c-status.md](docs/16-phase-c-status.md) | Phase C |
| [docs/17-phase-c-plus-status.md](docs/17-phase-c-plus-status.md) | Phase C+ |
| [docs/18-assert-witness.md](docs/18-assert-witness.md) | Assert witness packing + Cube alignment |
| [docs/19-ciphertext-store.md](docs/19-ciphertext-store.md) | Off-chain CT persist |
| [docs/20-cut-and-choose-schedule.md](docs/20-cut-and-choose-schedule.md) | C&C schedule + Assert CT hash |
| [docs/21-gsv-adaptor-wire.md](docs/21-gsv-adaptor-wire.md) | GSV Fr-share adaptor (tag 3) |
| [docs/22-eval-sidecar.md](docs/22-eval-sidecar.md) | C+ sidecar + check-set re-garble |
| [docs/23-integration-tests.md](docs/23-integration-tests.md) | Integration suites + coverage stance |
| [docs/12-regtest-guide.md](docs/12-regtest-guide.md) | Docker / bitcoind |
| [docs/14-circuit-backend.md](docs/14-circuit-backend.md) | Backends + GSV |

## License

MIT — see [`LICENSE`](LICENSE).

Binaries built with `--features gsv` (the default) link **GPL-3.0-only** garbled-snark-verifier; distribute accordingly. Use `--no-default-features` for MIT-only Claim Mini builds.
