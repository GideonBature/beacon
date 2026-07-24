# Glossary

Normative definitions: [RFC-0001](../rfcs/0001-assertion-protocol.md).

## Six core concepts

| Term | See |
|------|-----|
| Statement | RFC-0001 |
| Proof (evidence) | RFC-0001, RFC-0002 |
| Assertion | RFC-0001 |
| Challenger | RFC-0001 |
| Challenge | RFC-0001 |
| Settlement | RFC-0001 |

## Related protocol terms

| Term | See |
|------|-----|
| Verifiable | RFC-0002, [traits.md](traits.md) |
| Commitment | RFC-0001 |
| Witness | RFC-0002 |
| Backend | RFC-0005 |
| Timeout | RFC-0001, RFC-0004 |
| Status | RFC-0004 |
| Assertion Engine | RFC-0001 (what Beacon is) |

## Naming guidance

| Prefer | Avoid as primary |
|--------|------------------|
| Beacon | cube-proof, cube-dispute |
| Assertion Engine | Proof Engine |
| Assertion wins / Challenger wins | vague “success” without subject |
| Disproven / Upheld (challenge result) | ChallengeSucceeded / Failed |

## Non-normative

| Term | Note |
|------|------|
| BitVM3-core | Candidate RFC-0006 backend technique |
| BitVM3-bridge | Application of BitVM3-core |
| Cube | First planned Beacon consumer |
| Tokio analogy | Runtime-over-capability metaphor only |
