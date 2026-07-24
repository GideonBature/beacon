# Beacon Architecture

> **Applications depend on Beacon.**
> **Beacon never depends on applications.**

Cube imports Beacon. Beacon never imports Cube. This rule must not be broken.

---

- **Status:** Draft
- **Related:** [RFC-0001](../rfcs/0001-assertion-protocol.md), [Traits](traits.md)

## Engineering standard

Beacon is built like mature infrastructure (Bitcoin Core, Tokio, libp2p, Rust):

> **Every commit must leave the project compilable, documented, and testable.**

No “we’ll clean it up later.”

## Protocol-first

```text
                 RFCs
                   │
                   ▼
          Reference Protocol
                   │
                   ▼
       Reference Rust Implementation
                   │
                   ▼
           Applications (Cube, …)
```

The RFCs define the protocol. Rust is the first implementation. Compatible
implementations in other languages MUST follow the same RFCs.

## Problem statement

> **Beacon is a framework for asserting, challenging, and settling
> cryptographic claims in a backend-agnostic manner.**

That is the *definition*. It is not a mandate to support every claim, proof
system, or application on day one.

## Strategy: Cube-driven, then extract

1. **Design to satisfy Cube completely.**
2. **Keep Cube-specific mechanism out of Beacon** (see boundary test below).
3. **Implement one vertical slice** (mock → Groth16 software → Bitcoin later).
4. **Only then** ask what else fits—bridges, DLCs, rollups.

We do **not** start by supporting every proof system. We start with what Cube
needs, behind a `Verifiable` boundary so we are not structurally stuck.

```text
                Bitcoin
                    ▲
            Bitcoin Backend
                    ▲
              Beacon
                    ▲
        ┌───────────┼───────────┐
        │           │           │
      Cube     BitVM Bridge   Future …
```

## Milestone 1 (current engineering focus)

> Can someone create an assertion and drive it through its lifecycle entirely
> in memory?

Crates for that milestone:

```text
beacon-core      # protocol domain + traits (no Bitcoin)
beacon-events    # lifecycle events
beacon-mock      # in-memory backend
beacon-cli       # developer tooling
```

Same lifecycle tests MUST later pass on `BitcoinBackend`.

## The “remove Cube” test

A component belongs in Beacon only if it still makes sense after Cube is
deleted. CubeVM, shadowing, Projector, APE, exits stay in Cube. Assert →
challenge → settle stays in Beacon.

## Six concepts

1. Statement  
2. Proof (evidence; boundary: Verifiable)  
3. Assertion  
4. Challenger  
5. Challenge  
6. Settlement  

See [RFC-0001](../rfcs/0001-assertion-protocol.md). Normative statuses:
[RFC-0004](../rfcs/0004-state-machine.md) (`Asserted`, `Disputing`, `Accepted`,
`Rejected` — Draft is local-only; Settled is finalization).

## Crate layout

```text
crates/
  beacon-core
  beacon-events
  beacon-mock
  beacon-cli
  beacon-groth16
  beacon-bitcoin   # simulated journal skeleton (RFC-0006)
```

## Phase plan

| Phase | Deliverable |
|-------|-------------|
| **0** | RFCs / architecture (done) |
| **1** | Domain types, mock lifecycle, events, CLI |
| **2** | Groth16 `Verifiable` + VK registry |
| **3** | `beacon-bitcoin` skeleton (same lifecycle, tx journal) |
| **4+** | Real Bitcoin / BitVM3-style dispute behind the same API |
