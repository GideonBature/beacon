# Examples

```bash
cargo run -p beacon-cli -- demo mock accept
cargo run -p beacon-cli -- demo mock reject
cargo run -p beacon-cli -- demo bitcoin accept
cargo run -p beacon-cli -- demo bitcoin reject
cargo run -p beacon-cli -- demo groth16 accept --bitcoin
cargo run -p beacon-cli -- demo groth16 reject --bitcoin
cargo run -p beacon-mock --example lifecycle
cargo run -p beacon-mock --example challenge
cargo run -p beacon-groth16 --example lifecycle_groth16
cargo run -p beacon-bitcoin --example lifecycle
cargo run -p beacon-bitcoin --example groth16_lifecycle
```
