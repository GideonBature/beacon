# RFC-0003: Events

- **Status:** Draft
- **Authors:** TBD
- **Created:** 2026-07-23
- **Depends on:** RFC-0001, RFC-0004

## Abstract

Applications subscribe to Assertion lifecycle events. This RFC names the v1
event set and ties each event to RFC-0004 transitions.

## v1 events

| Event | When | Key fields |
|-------|------|------------|
| `AssertionCreated` | T1 `assert` | `assertion_id`, `statement_commitment`, `challenge_deadline` |
| `ChallengeOpened` | T3 | `assertion_id`, `challenge_id` |
| `ChallengeResolved` | T4 / T5 (and mock sync resolve) | `assertion_id`, `result: Disproven \| Upheld` |
| `AssertionFinalized` | Terminal settle | `assertion_id`, `outcome: Accepted \| Rejected` |

Deprecated informal names (do not use):

- `ChallengeSucceeded` / `ChallengeFailed` — ambiguous subject

## Non-goals (v1)

- Stable wire encoding (future canonical-encoding RFC)
- Guaranteed delivery / persistence (host concern)
- Application-level topics (Cube exits, shadowing, …)

## Subscriber sketch

```text
on_event(Event) -> ()
```

Backends SHOULD emit events in transition order. Re-delivery semantics are
implementation-defined until a wire RFC exists.

## Open questions

1. Include full Statement in `AssertionCreated` or only commitments?
2. Separate `DisputeTimeout` event for T6 vs fold into `AssertionFinalized`?
