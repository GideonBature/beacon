# Phase A – Regtest Guide

This guide shows how to run the Phase A flow against a local Bitcoin regtest node.

## Prerequisites

- Bitcoin Core (bitcoind + bitcoin-cli) with regtest support
- Rust toolchain
- This repository

## 1. Start regtest

```bash
bitcoind -regtest -daemon -fallbackfee=0.0001
bitcoin-cli -regtest createwallet "cube"
bitcoin-cli -regtest -generate 101          # mature coinbase
```

## 2. Build the project

```bash
cd cube-pseudo-bitvm3
cargo build --release
```

(If you hit dependency issues, run `cargo update` first.)

## 3. Logical flow that the code implements

```
1. Engine creates a ClaimMini (valid or invalid)
2. Engine builds Assert transaction
   - Connector output = Taproot with two leaves
     • Disprove leaf  = SHA256(L_invalid) check
     • Timeout leaf   = relative timelock + Engine key
   - Witness contains DirectSeedOpening
3. Assert is broadcast and confirmed
4. Challenger evaluates the claim off-chain
   - If invalid → obtains L_invalid → builds & broadcasts Disprove
   - If valid   → does nothing
5. After the relative timelock (DEFAULT_DISPUTE_WINDOW blocks)
   Engine can build & broadcast Timeout (only if connector still unspent)
```

## 4. Code entry points

| Function | File | Purpose |
|----------|------|---------|
| `build_assert_tx` | `src/phase_a/regtest_tx.rs` | Create the Assert transaction |
| `build_disprove_tx` | same | Spend connector with L_invalid |
| `build_timeout_tx` | same | Spend connector after CSV |
| `PhaseAFlow::engine_create_assert` | `src/phase_a/flow.rs` | High-level helper that also produces the opening |
| `PhaseAFlow::challenger_evaluate` | same | Decide Valid vs Invalid{L*} |

## 5. Minimal driver sketch (pseudo-Rust)

```rust
// 1. Create keys and a funding UTXO (from bitcoin-cli or the bitcoin crate RPC)
// 2. Build a ClaimMini (valid or cheating)
// 3. let result = build_assert_tx(...);
// 4. Broadcast result.tx
// 5. let eval = PhaseAFlow::challenger_evaluate(...);
// 6. match eval {
//        Invalid { l_invalid } => broadcast build_disprove_tx(..., l_invalid, ...)
//        Valid => wait DEFAULT_DISPUTE_WINDOW blocks, then broadcast build_timeout_tx(...)
//    }
```

## 6. What is still placeholder

- The Assert input is not yet signed (caller must sign with the funding key).
- The Timeout signature is a placeholder (zeros); a real Schnorr signature over the Taproot script-path sighash is required before broadcast.
- No RPC client is included yet; you can use `bitcoincore-rpc` or shell out to `bitcoin-cli`.

These are deliberately left open so the first integration can be done with the tools you already use for regtest.

## 7. Upgrade path remains intact

Once the regtest flow works with the direct seed opening (Phase A):

- Phase B only changes how the opening is constructed (adaptor signatures).
- Phase C adds VSSS share reconstruction.
- The Taproot leaves and the Disprove / Timeout transactions stay the same.

## 8. Next engineering tasks after this guide

1. Add a small binary or example that drives the full flow against regtest (including signing).
2. Replace the placeholder Timeout signature with a real script-path Schnorr signature.
3. Optionally add a thin RPC wrapper so the example can be run with a single command.
