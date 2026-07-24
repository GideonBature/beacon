# Beacon

**Assertion Engine** — a protocol for asserting, challenging, and settling
cryptographic claims in a backend-agnostic manner.

> **Beacon is protocol-first.**
>
> The RFCs define the protocol.  
> The Rust code is the reference implementation.  
> Every backend MUST implement the protocol defined in RFC-0001.  
> Applications MUST depend only on the protocol, not backend-specific behavior.

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

**Architectural rule:** Applications depend on Beacon. Beacon never depends on
applications. See [`docs/architecture.md`](docs/architecture.md).

## Status: Phase 1 — Foundation

Milestone 1: drive an assertion through its lifecycle **entirely in memory**
(`MockBackend`). Not Bitcoin. Not Groth16. The heart of Beacon.

| Doc | |
|-----|---|
| [`rfcs/0001-assertion-protocol.md`](rfcs/0001-assertion-protocol.md) | Assertion protocol |
| [`docs/architecture.md`](docs/architecture.md) | Layers, dependency rule, milestones |
| [`docs/traits.md`](docs/traits.md) | Intended trait hierarchy |
| [`docs/naming.md`](docs/naming.md) | Why “Beacon” |

## Workspace

```text
beacon/
├── rfcs/
├── docs/
├── crates/
│   ├── beacon-core      # protocol types/traits + Engine
│   ├── beacon-events    # RFC-0003 lifecycle events
│   ├── beacon-mock      # in-memory backend + examples
│   ├── beacon-cli       # developer CLI
│   ├── beacon-groth16   # Groth16 Verifiable adapter (verify-only)
│   └── beacon-bitcoin   # Bitcoin-shaped backend skeleton (sim journal)
└── examples/
```

```bash
cargo test --workspace
cargo run -p beacon-cli -- demo mock accept
cargo run -p beacon-cli -- demo mock reject
cargo run -p beacon-cli -- demo bitcoin accept
cargo run -p beacon-cli -- demo bitcoin reject
cargo run -p beacon-cli -- demo groth16 accept
cargo run -p beacon-cli -- demo groth16 accept --bitcoin
cargo run -p beacon-cli -- demo groth16 reject --bitcoin
cargo run -p beacon-mock --example lifecycle
cargo run -p beacon-groth16 --example lifecycle_groth16
cargo run -p beacon-bitcoin --example groth16_lifecycle
```

No Cube in this repository. Cube will import Beacon.

**Every commit must leave the project compilable, documented, and testable.**

## License

MIT — see [`LICENSE`](LICENSE).
