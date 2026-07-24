# Pluggable Circuit Backend

**Status**: `garbled-snark-verifier` linked via Cargo **git** dependency (`gsv` feature, default on)

## Shape

```text
CircuitBackend trait
├── ClaimMiniBackend          ← Phase A (works today)
└── GarbledSnarkBackend       ← BitVM3 path (git-depends on GSV)
```

On-chain Assert / Disprove / Timeout templates do **not** change when the
backend switches. Only `commit_l_invalid` and `evaluate` do.

## Dependency (no vendoring)

```toml
garbled-snark-verifier = {
  git = "https://github.com/BitVM/garbled-snark-verifier",
  default-features = false,
  features = ["test-utils"],
  optional = true,
}
```

Cargo caches the git checkout under `~/.cargo/git`. Updating Beacon’s lockfile
picks up new upstream commits without copying the tree into this repo.

## Hashlock rule

```text
H(L_invalid) = SHA256(L*)
```

## What “linked” means today

| Piece | Status |
|-------|--------|
| Git dependency on upstream GSV | Done |
| `CircuitBuilder::streaming_execute` smoke circuit | Done |
| Claim Mini validity → Accept / Disprove | Done |
| Full garbled Groth16 Garble + Evaluate | **Not yet** (Phase C) |

## CLI

```bash
cargo run --example gsv_link
cargo run --example phase_a_driver -- --gsv --cheat
cargo test --no-default-features   # without GSV
```

## License note

Upstream GSV is **GPL-3.0-only**. Distributing Beacon binaries built with
`--features gsv` (the default) requires complying with GPL for the combined work.

## Upstream caveat

GSV’s `Cargo.toml` currently lists `sp1-build` / `sp1-sdk` as unconditional
**build-dependencies**, so the first resolve/build may still download SP1 even
with `default-features = false`. Ideal fix is an upstream PR making those
optional (Beacon previously patched a local vendor for this; git import is
preferred long-term).
