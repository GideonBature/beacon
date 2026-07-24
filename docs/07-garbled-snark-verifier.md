# Real BitVM3 Core: BitVM/garbled-snark-verifier

**Repository**: https://github.com/BitVM/garbled-snark-verifier  
**Status as of July 2026**: Actively developed reference implementation (204+ commits)

This is the concrete implementation of the cryptographic heart of BitVM3.

## What it provides

A high-performance, streaming **garbled-circuit Groth16 verifier** over BN254, written in Rust.

It turns the statement “this Groth16 proof is valid” into a garbled circuit that a challenger can evaluate entirely off-chain. If the proof is invalid, evaluation yields a distinguished label (`L_invalid` / `L*`) that can be used on-chain as a fraud proof.

This is exactly the mechanism described in:

- The BitVM3 paper
- The Cube whitepaper (“BitVM3-style execution model”)

## Three Protocol Variants

| Protocol                    | Description                                      | Bitcoin relevance                  | Feature flag      |
|-----------------------------|--------------------------------------------------|------------------------------------|-------------------|
| Vanilla cut-and-choose      | All input labels revealed                        | Lowest complexity                  | (default)         |
| Soldering (SP1)             | One base input + SP1 proof of deltas             | Good for large instances           | `sp1-soldering`   |
| **VSSS + adaptor signatures** | Secret-shared labels + Bitcoin adaptor sigs    | **Most relevant for Cube**         | `vsss`            |

The **VSSS + adaptor signatures** variant is the one closest to what we need for a Bitcoin-native dispute layer.

## Performance (reported)

- ~57 million gates per second
- Can garble an 11.2 billion gate circuit in ~3 min 20 s
- Memory stays low (< 200 MB RSS per task) thanks to streaming
- AES-NI recommended (software fallback exists)

## Current Limitations (important for Cube)

- The **core garbled verifier** is solid and usable.
- The pure **Bitcoin transaction integration** (Assert / Disprove scripts, connectors, full adaptor-signature transaction graph) is still incomplete.
- You still need to build (or finish) the on-chain glue: the Taproot leaves, relative timelocks, covenant emulation, bond handling, etc.

In other words: this repository solves the hard cryptographic part. The Bitcoin protocol engineering part is still largely our responsibility (which is why the design work we already did remains valuable).

## How it maps to our Cube design

```
Cube Assert transaction
        │
        ▼
Engine supplies extractable commitment / adaptor signatures
        │
        ▼
Challenger recovers input labels
        │
        ▼
Feeds them into garbled-snark-verifier (Evaluate mode)
        │
        ▼
If invalid → obtains L* (false / invalid label)
        │
        ▼
Publishes Disprove with L*  (exactly as we designed)
```

Our existing Assert / Disprove / Timeout transaction templates remain valid.  
We simply replace the “tiny Claim Mini circuit” with a call into this library when we are ready for the full CubeVM Groth16 path.

## Recommended Strategy for Cube

**Short term (v1)**  
Keep Claim Mini (or a slightly richer limited claim) as a fast, low-cost dispute layer while we gain experience.

**Medium term**  
Integrate `garbled-snark-verifier` (especially the VSSS + adaptor path) as the real backend for asserting full CubeVM state transitions. This brings us into direct alignment with the Cube whitepaper.

**Long term**  
The same transaction graph can support both the lightweight claims and the full garbled Groth16 verifier.

## Next Engineering Actions

1. Clone and run the three examples locally to understand the API.
2. Study `docs/gsv_vsss.md` carefully (the Bitcoin-relevant protocol).
3. Map the output labels of the garbled verifier onto our `Hashlock(H(L*))` construction.
4. Design the exact adaptor-signature / VSSS opening that will appear in the Assert witness.
5. Keep our existing transaction templates; only the circuit backend changes.

---

**Bottom line**: BitVM3 is no longer pure research. The core engine exists and is usable. Cube can now treat `garbled-snark-verifier` as the intended production backend for the BitVM3-style dispute layer described in its own whitepaper.
