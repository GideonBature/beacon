# Assert Witness Packing (v1)

**Status**: Implemented — versioned blob + regtest round-trip from chain (OP_RETURN)

## Cube whitepaper alignment

These improvements stay inside the Cube / BitVM3 dispute shape. Beacon does **not**
replace Cube’s architecture; it freezes the Bitcoin-facing interface Cube needs:

```text
Assert (open material + commit H(L*))
   → off-chain Evaluate (garbled verifier)
   → Timeout (valid)  or  Disprove reveal L* (invalid)
```

| Whitepaper / docs concept | Beacon `AssertWitnessV1` |
|---------------------------|---------------------------|
| Public statement / public inputs | `claim_bytes` + `public_inputs_hash` |
| Extractable opening of instance `a` | `AssertOpening` (direct or adaptor) |
| Instance id (cut-and-choose) | `statement.instance_id` |
| Disprove secret commitment | `statement.h_l_invalid` (= connector leaf) |
| Optional VSSS check-set | `share_bundle` |
| Later Cube Groth16 publics | Same `claim_bytes` slot (format stays) |

**What stays fixed for Cube:** Taproot leaves (Disprove `OP_SHA256 <H(L*)>` /
Timeout CSV+sig), hashlock semantics, adaptor/extractable opening role.

**What is swappable later:** meaning of `claim_bytes` (Claim Mini → Cube
publics), carrier policy (OP_RETURN → reveal-tx / inscription if mainnet needs
it). Ciphertext streams stay off-chain in [`CiphertextStore`](19-ciphertext-store.md)
(optional later: put `ciphertext_hash` in the statement). Schema version stays
`FORMAT_V1` until fields change.

## Wire format

```text
MAGIC "BEAC" | FORMAT_V1=1
| protocol_version u8 | instance_id u32 LE
| public_inputs_hash[32] | claim_id[32] | h_l_invalid[32]
| claim_bytes (u32 LE length + bytes)
| opening_tag (1=direct | 2=adaptor) + opening fields
| share_flag (0|1) + optional ShareBundle
| ct_hash_flag (0|1) + optional ciphertext_hash[32]   // eval instance a
```

`ciphertext_hash` binds the off-chain garbled stream for `instance_id`
([`CiphertextStore`](19-ciphertext-store.md)). Older blobs without the trailing
flag still decode (`ciphertext_hash = None`).

Module: [`src/witness.rs`](../src/witness.rs).

## On-chain carrier (v1)

Published as a chunked **`OP_RETURN`** output on the Assert tx (attach **before**
signing):

```text
vout: … | OP_RETURN <push≤520>…  (concatenated data = BEAC-blob)
```

Regtest bitcoind needs `-datacarriersize` large enough (see
`docker-compose.example.yml`). The blob schema is independent of the carrier; a
reveal-tx / script-path / annex carrier can replace this later without changing
`AssertWitnessV1`. (BIP341 annex was tried; Core rejects it as non-standard.)

## Regtest

```bash
cp docker-compose.example.yml docker-compose.yml   # if needed; includes datacarriersize
docker compose up -d

export BEACON_RPC_URL=http://127.0.0.1:18443 BEACON_RPC_USER=beacon BEACON_RPC_PASS=beacon
cargo run --example phase_a_driver --no-default-features -- --regtest --cheat
cargo run --example phase_a_driver --no-default-features -- --adaptor --regtest --cheat
cargo run --example phase_a_driver --no-default-features -- --phase-c --regtest --cheat
```

Logs should include `assert_witness_v1 OP_RETURN attached` and
`recovered assert_witness_v1 from chain (round-trip OK)`. Evaluation uses only
the recovered blob, not in-memory Engine state.
