# Phase A – Regtest Guide

Preferred: **Docker Desktop** + Compose. Native `bitcoind` also works.

## Option A — Docker (recommended)

`docker-compose.yml` is **gitignored** (local only). Use the tracked example:

```bash
cp docker-compose.example.yml docker-compose.yml
docker compose up -d
docker compose ps   # wait until healthy
```

RPC defaults match the Compose file:

```bash
export BEACON_RPC_URL=http://127.0.0.1:18443
export BEACON_RPC_USER=beacon
export BEACON_RPC_PASS=beacon

# Phase A / B Claim Mini does not need GSV (avoids heavy SP1 build-deps)
cargo run --example phase_a_driver --no-default-features -- --regtest
cargo run --example phase_a_driver --no-default-features -- --regtest --cheat
cargo run --example phase_a_driver --no-default-features -- --adaptor --regtest
cargo run --example phase_a_driver --no-default-features -- --adaptor --regtest --cheat
```


Useful:

```bash
docker compose logs -f bitcoind
docker compose exec bitcoind bitcoin-cli -regtest -rpcuser=beacon -rpcpassword=beacon getblockchaininfo
docker compose down          # stop
docker compose down -v       # stop + wipe docker/bitcoin-data (also gitignored)
```

## Option B — Native bitcoind

```bash
DATADIR=/tmp/beacon-regtest
mkdir -p "$DATADIR"
bitcoind -regtest -datadir="$DATADIR" -daemon \
  -fallbackfee=0.0002 -server=1 \
  -rpcuser=beacon -rpcpassword=beacon -rpcport=18443

export BEACON_RPC_URL=http://127.0.0.1:18443
export BEACON_RPC_USER=beacon
export BEACON_RPC_PASS=beacon
cargo run --example phase_a_driver -- --regtest
```

## What the runner does

1. Creates/loads wallet `beacon`
2. Mines coins if needed
3. Funds a fresh P2TR address
4. Signs + broadcasts Assert
5. Off-chain evaluate (Claim Mini)
6. **Valid** → mine CSV → signed Timeout  
   **Invalid** → Disprove with `L*`

## Simulation (no node)

```bash
cargo run --example phase_a_driver
cargo run --example phase_a_driver -- --cheat
```
