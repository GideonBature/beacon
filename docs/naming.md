# Naming

- **Status:** Working decision (pre-public release; revisable)
- **Current project / crate identity:** **Beacon**

## Criteria

The name should:

* Be short (ideally one word)
* Be memorable
* Relate to claims / observation / dispute (not to Cube as a brand)
* Be crate- and GitHub-friendly (`beacon`, `use beacon::…`)
* Be able to grow beyond Cube
* Still sound natural *inside* Cube

Rule of thumb (Tokio / Tower / SQLx / libp2p): name **what it does**, not **who uses it first**.

## Working decision

**Beacon** — assertions are public signals others can observe and challenge.

```text
Statement → evidence → Beacon (assert) → Challenge → Settlement
```

```rust
use beacon::{Assertion, Challenge, Backend};
```

Inside Cube:

```text
CubeVM → Groth16 → Beacon → Bitcoin Backend
```

## Shortlist (ranked)

| Rank | Name | Notes |
|------|------|-------|
| 1 | **Beacon** | Current choice; observe-and-react imagery; neutral |
| 2 | Verdict | Lifecycle-accurate; very strong runner-up |
| 3 | Arbiter | Decision-maker imagery; slightly personifying |
| 4 | Airlock | Fits Cube’s conceptual naming style; “gate before Bitcoin” |
| 5 | Tribunal | Bitcoin-as-court metaphor; a bit heavy |
| — | Dispute / Challenge / Relay | Too generic or overloaded |
| — | cube-proof / cube-dispute | Only if forever Cube-internal |

## Rejected as primary

| Name | Why |
|------|-----|
| `cube-proof` | Signals Cube ownership; hurts “can I use this for my bridge?” |
| `cube-verifier` / `cube-dispute` | Better than cube-proof if internal-only; still Cube-branded |
| Proof Engine | Centers proof, not assertion |
| Projector | Already Cube’s covenant-emulation concept |
| VerdictVM | Implies a VM; wrong layer |

## Two naming surfaces

| Surface | Name |
|---------|------|
| Repository / crates | `beacon` |
| Role in prose | Assertion Engine (what it *is*) |
| Inside Cube tree | dependency on `beacon`, not a `cube/proof` identity leak |

## Policy until public release

Do not rush a permanent public brand. Architecture and RFC-0001 matter more.
Renaming is cheap before external dependents exist. If a stronger name wins
later (e.g. Verdict), rename before v0.1 announce—not after.
