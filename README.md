# Beacon

**Beacon** is the BitVM3-style dispute layer for Cube.

Target cryptographic backend: [BitVM/garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier).  
Phase A runs today with a pluggable circuit backend.

## Quick start

```bash
cargo test
cargo run --example phase_a_driver              # claim-mini
cargo run --example phase_a_driver -- --gsv     # garbled-snark-verifier stand-in
cargo run --example phase_a_driver -- --gsv --cheat
```

## Circuit backends

```text
CircuitBackend
├── ClaimMiniBackend          ← Phase A (works today)
└── GarbledSnarkBackend       ← BitVM3 path (stand-in; ready for real crate)
```

Assert / Disprove / Timeout stay the same across backends.  
`H(L_invalid) = SHA256(L*)` for the Taproot hashlock.

See [`docs/14-circuit-backend.md`](docs/14-circuit-backend.md).

## Status

- [x] Phase A logical flow (Assert → Evaluate → Disprove / Timeout)
- [x] Claim Mini circuit + `L*` fraud secret
- [x] Pluggable `CircuitBackend` + `--gsv` driver switch
- [x] Hashlock-correct `SHA256(L*)` commitment
- [x] Taproot Assert / Disprove / Timeout tx builders (unsigned placeholders)
- [ ] Real `garbled-snark-verifier` crate linked
- [ ] Full Taproot signing + regtest broadcast
- [ ] Phase B – adaptor signatures
- [ ] Phase C – VSSS + real GSV Evaluate

## Docs

See [`docs/`](docs/) — especially [`07-garbled-snark-verifier.md`](docs/07-garbled-snark-verifier.md)
and [`14-circuit-backend.md`](docs/14-circuit-backend.md).

## License

MIT — see [`LICENSE`](LICENSE).
