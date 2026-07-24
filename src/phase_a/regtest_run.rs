//! End-to-end Phase A against Bitcoin Core regtest.
//!
//! Requires a running `bitcoind -regtest` (cookie auth). See `docs/12-regtest-guide.md`.

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use bitcoin::consensus::encode::deserialize;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::transaction::{OutPoint, Transaction};
use bitcoin::{Address, Amount, Network, TxOut, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use rand::thread_rng;

use crate::backend::{CircuitBackend, ClaimMiniBackend, EvaluationResult};
use crate::claim_mini::ClaimMini;
use crate::opening::AssertOpening;
use crate::phase_a::flow::{serialize_claim, PhaseAFlow};
use crate::phase_a::regtest_tx::{
    build_assert_tx_with_opening, build_disprove_tx, build_timeout_tx, p2tr_address,
    sign_assert_keypath, OpeningMode, REGTEST_DISPUTE_WINDOW,
};
use crate::phase_b::flow::PhaseBFlow;

/// Outcome of a regtest Phase A run.
#[derive(Debug)]
pub enum RegtestOutcome {
    /// Valid claim: Assert + Timeout mined.
    Accepted {
        assert_txid: Txid,
        timeout_txid: Txid,
    },
    /// Invalid claim: Assert + Disprove mined.
    Rejected {
        assert_txid: Txid,
        disprove_txid: Txid,
    },
}

/// Connect to local regtest (cookie file or `BEACON_RPC_USER` / `BEACON_RPC_PASS`).
pub fn connect_regtest() -> Result<Client, Box<dyn std::error::Error>> {
    let url = std::env::var("BEACON_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:18443".into());
    if let (Ok(user), Ok(pass)) = (
        std::env::var("BEACON_RPC_USER"),
        std::env::var("BEACON_RPC_PASS"),
    ) {
        return Ok(Client::new(&url, Auth::UserPass(user, pass))?);
    }
    let cookie = std::env::var("BEACON_RPC_COOKIE").map(PathBuf::from).unwrap_or_else(|_| {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".bitcoin/regtest/.cookie")
    });
    Ok(Client::new(&url, Auth::CookieFile(cookie))?)
}

fn ensure_wallet(rpc: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let wallets = rpc.list_wallets()?;
    if wallets.iter().any(|w| w == "beacon") {
        return Ok(());
    }
    match rpc.load_wallet("beacon") {
        Ok(_) => Ok(()),
        Err(_) => {
            let _ = rpc.create_wallet("beacon", None, None, None, None)?;
            Ok(())
        }
    }
}

fn mine(rpc: &Client, n: u64, dest: &Address) -> Result<(), Box<dyn std::error::Error>> {
    rpc.generate_to_address(n, dest)?;
    Ok(())
}

/// Fund `addr` with `amount` from the wallet; return outpoint + prevout.
fn fund_address(
    rpc: &Client,
    addr: &Address,
    amount: Amount,
    mine_to: &Address,
) -> Result<(OutPoint, TxOut), Box<dyn std::error::Error>> {
    let bal = rpc.get_balance(None, None)?;
    if bal < amount + Amount::from_sat(50_000) {
        mine(rpc, 101, mine_to)?;
    }
    let txid = rpc.send_to_address(addr, amount, None, None, None, None, None, None)?;
    mine(rpc, 1, mine_to)?;

    // Wallet knows this send; decode hex (works without -txindex / without importing addr).
    let wtx = rpc.get_transaction(&txid, None)?;
    let raw: Transaction = deserialize(&wtx.hex)?;
    let vout = raw
        .output
        .iter()
        .position(|o| o.script_pubkey == addr.script_pubkey() && o.value == amount)
        .ok_or("funding output not found in send tx")? as u32;

    Ok((
        OutPoint { txid, vout },
        TxOut {
            value: amount,
            script_pubkey: addr.script_pubkey(),
        },
    ))
}

/// Run Assert → Evaluate → Disprove|Timeout on regtest with [`ClaimMiniBackend`].
pub fn run_phase_a_regtest(cheat: bool) -> Result<RegtestOutcome, Box<dyn std::error::Error>> {
    run_regtest(cheat, OpeningMode::DirectSeed)
}

/// Phase B regtest: same Taproot path with adaptor opening.
pub fn run_phase_b_regtest(cheat: bool) -> Result<RegtestOutcome, Box<dyn std::error::Error>> {
    run_regtest(cheat, OpeningMode::Adaptor)
}

fn run_regtest(
    cheat: bool,
    opening_mode: OpeningMode,
) -> Result<RegtestOutcome, Box<dyn std::error::Error>> {
    let rpc = connect_regtest()?;
    for _ in 0..30 {
        if rpc.get_blockchain_info().is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }
    let _ = rpc.get_blockchain_info().map_err(|e| {
        format!(
            "cannot reach bitcoind regtest RPC ({e}). Start with:\n  \
             bitcoind -regtest -daemon -fallbackfee=0.0002"
        )
    })?;
    ensure_wallet(&rpc)?;

    let secp = Secp256k1::new();
    let funding_kp = Keypair::new(&secp, &mut thread_rng());
    let engine_kp = Keypair::new(&secp, &mut thread_rng());
    let slash_kp = Keypair::new(&secp, &mut thread_rng());

    let network = Network::Regtest;
    let funding_addr = p2tr_address(&funding_kp, network);
    let engine_addr = p2tr_address(&engine_kp, network);
    let slash_addr = p2tr_address(&slash_kp, network);
    let mine_addr = rpc
        .get_new_address(None, None)?
        .require_network(network)?;

    println!("regtest: funding={funding_addr}");
    let fund_amt = Amount::from_sat(200_000);
    let (funding_outpoint, funding_prev) =
        fund_address(&rpc, &funding_addr, fund_amt, &mine_addr)?;
    println!(
        "regtest: funded {} sats at {}:{}",
        fund_amt.to_sat(),
        funding_outpoint.txid,
        funding_outpoint.vout
    );

    let mut claim = ClaimMini::make_valid(
        [0x01; 32],
        100_000,
        40_000,
        [0x10; 32],
        [0x11; 32],
        [0x12; 32],
        [0x13; 32],
    );
    if cheat {
        claim.total_out = 250_000;
        println!("regtest: Engine cheating (inflated total_out)");
    }

    let claim_bytes = serialize_claim(&claim);
    let backend = ClaimMiniBackend;
    let h_l_invalid = backend.commit_l_invalid(&claim);

    let fee = Amount::from_sat(1_000);
    let connector_amt = Amount::from_sat(100_000);
    let mode_label = match opening_mode {
        OpeningMode::DirectSeed => "phase-a/direct-seed",
        OpeningMode::Adaptor => "phase-b/adaptor",
    };
    println!("regtest: opening={mode_label}");

    let mut built = build_assert_tx_with_opening(
        funding_outpoint,
        fund_amt,
        &engine_kp,
        &claim_bytes,
        h_l_invalid,
        connector_amt,
        &engine_addr,
        REGTEST_DISPUTE_WINDOW,
        fee,
        opening_mode,
    )?;
    sign_assert_keypath(&mut built.tx, &funding_prev, &funding_kp)?;

    let assert_txid = rpc.send_raw_transaction(&built.tx)?;
    println!("regtest: Assert broadcast {assert_txid}");
    mine(&rpc, 1, &mine_addr)?;

    let eval = match &built.opening {
        AssertOpening::Direct(o) => {
            PhaseAFlow::new(ClaimMiniBackend).challenger_evaluate(&claim, o, &built.h_l_invalid)
        }
        AssertOpening::Adaptor(o) => {
            PhaseBFlow::new(ClaimMiniBackend).challenger_evaluate(&claim, o, &built.h_l_invalid)
        }
    };
    let connector_prev = built.tx.output[built.connector_vout as usize].clone();

    match eval {
        EvaluationResult::Valid => {
            println!(
                "regtest: evaluation VALID — mining {REGTEST_DISPUTE_WINDOW} blocks for CSV"
            );
            mine(&rpc, u64::from(REGTEST_DISPUTE_WINDOW), &mine_addr)?;
            let timeout = build_timeout_tx(
                assert_txid,
                built.connector_vout,
                &connector_prev,
                &engine_kp,
                &built.taproot_spend_info,
                &engine_addr,
                REGTEST_DISPUTE_WINDOW,
                fee,
            )?;
            let timeout_txid = rpc.send_raw_transaction(&timeout)?;
            println!("regtest: Timeout broadcast {timeout_txid}");
            mine(&rpc, 1, &mine_addr)?;
            Ok(RegtestOutcome::Accepted {
                assert_txid,
                timeout_txid,
            })
        }
        EvaluationResult::Invalid { l_invalid } => {
            println!("regtest: evaluation INVALID — Disprove with L*");
            let disprove = build_disprove_tx(
                assert_txid,
                built.connector_vout,
                connector_amt,
                l_invalid,
                built.h_l_invalid,
                &built.taproot_spend_info,
                &slash_addr,
                fee,
            )?;
            let disprove_txid = rpc.send_raw_transaction(&disprove)?;
            println!("regtest: Disprove broadcast {disprove_txid}");
            mine(&rpc, 1, &mine_addr)?;
            Ok(RegtestOutcome::Rejected {
                assert_txid,
                disprove_txid,
            })
        }
    }
}
