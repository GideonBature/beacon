//! Phase A – Taproot Assert / Disprove / Timeout builders with real signatures.
//!
//! Connector = Taproot (NUMS internal key) with two script leaves:
//! - Disprove: `OP_SHA256 <H(L*)> OP_EQUALVERIFY OP_TRUE`
//! - Timeout:  `<Δ> OP_CSV OP_DROP <engine_xonly> OP_CHECKSIG`

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::script::{Builder, PushBytesBuf, ScriptBuf};
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use bitcoin::{absolute, Address, Amount, Network, Sequence, Txid, Witness};

use crate::opening::AssertOpening;
use crate::phase_a::opening::DirectSeedOpening;
use crate::phase_b::opening::AdaptorOpening;
use crate::tx_templates::DEFAULT_DISPUTE_WINDOW;
use rand::thread_rng;

/// Short relative lock for regtest demos (mine this many blocks after Assert).
pub const REGTEST_DISPUTE_WINDOW: u32 = 2;

/// BIP-341 recommended nothing-up-my-sleeve x-only pubkey (script-path only).
const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Which extractable opening to attach to the Assert.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OpeningMode {
    #[default]
    DirectSeed,
    Adaptor,
}

/// Everything needed to build and later spend the Assert connector.
pub struct AssertBuildResult {
    pub tx: Transaction,
    pub connector_vout: u32,
    pub connector_amount: Amount,
    pub taproot_spend_info: TaprootSpendInfo,
    pub h_l_invalid: [u8; 32],
    pub opening: AssertOpening,
    pub dispute_window: u32,
    /// Engine key that can take the Timeout script path.
    pub engine_keypair: Keypair,
}

fn nums_internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&NUMS_H).expect("BIP-341 NUMS key")
}

/// Build an unsigned Assert transaction (caller signs the funding input).
pub fn build_assert_tx(
    funding_outpoint: OutPoint,
    funding_amount: Amount,
    engine_keypair: &Keypair,
    claim_bytes: &[u8],
    h_l_invalid: [u8; 32],
    connector_amount: Amount,
    change_address: &Address,
    dispute_window: u32,
    fee: Amount,
) -> Result<AssertBuildResult, Box<dyn std::error::Error>> {
    build_assert_tx_with_opening(
        funding_outpoint,
        funding_amount,
        engine_keypair,
        claim_bytes,
        h_l_invalid,
        connector_amount,
        change_address,
        dispute_window,
        fee,
        OpeningMode::DirectSeed,
    )
}

/// Build Assert with Phase A (direct seed) or Phase B (adaptor) opening.
pub fn build_assert_tx_with_opening(
    funding_outpoint: OutPoint,
    funding_amount: Amount,
    engine_keypair: &Keypair,
    claim_bytes: &[u8],
    h_l_invalid: [u8; 32],
    connector_amount: Amount,
    change_address: &Address,
    dispute_window: u32,
    fee: Amount,
    opening_mode: OpeningMode,
) -> Result<AssertBuildResult, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let disprove_script = disprove_leaf_script(&h_l_invalid)?;
    let timeout_script = timeout_leaf_script(engine_keypair, dispute_window)?;

    let internal_key = nums_internal_key();
    let builder = TaprootBuilder::new()
        .add_leaf(1, disprove_script)?
        .add_leaf(1, timeout_script)?;
    let spend_info = builder
        .finalize(&secp, internal_key)
        .map_err(|_| "taproot finalize failed")?;

    let connector_script_pubkey =
        ScriptBuf::new_p2tr(&secp, spend_info.internal_key(), spend_info.merkle_root());

    let change_amount = funding_amount
        .checked_sub(connector_amount)
        .ok_or("insufficient funds")?
        .checked_sub(fee)
        .ok_or("insufficient funds for fee")?;

    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: connector_amount,
                script_pubkey: connector_script_pubkey,
            },
            TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    };

    let opening = match opening_mode {
        OpeningMode::DirectSeed => {
            AssertOpening::Direct(DirectSeedOpening::from_claim_bytes(0, claim_bytes))
        }
        OpeningMode::Adaptor => AssertOpening::Adaptor(AdaptorOpening::create(
            0,
            claim_bytes,
            engine_keypair,
            &mut thread_rng(),
        )?),
    };

    Ok(AssertBuildResult {
        tx,
        connector_vout: 0,
        connector_amount,
        taproot_spend_info: spend_info,
        h_l_invalid,
        opening,
        dispute_window,
        engine_keypair: *engine_keypair,
    })
}

/// Build Assert with a caller-supplied opening (Phase C binds `h_l_invalid` to it).
pub fn build_assert_tx_with_assert_opening(
    funding_outpoint: OutPoint,
    funding_amount: Amount,
    engine_keypair: &Keypair,
    h_l_invalid: [u8; 32],
    connector_amount: Amount,
    change_address: &Address,
    dispute_window: u32,
    fee: Amount,
    opening: AssertOpening,
) -> Result<AssertBuildResult, Box<dyn std::error::Error>> {
    let mut built = build_assert_tx_with_opening(
        funding_outpoint,
        funding_amount,
        engine_keypair,
        &[],
        h_l_invalid,
        connector_amount,
        change_address,
        dispute_window,
        fee,
        OpeningMode::DirectSeed, // placeholder; overwritten below
    )?;
    built.opening = opening;
    Ok(built)
}

/// Sign Assert funding input (P2TR key-path, no script merkle root).
pub fn sign_assert_keypath(
    tx: &mut Transaction,
    funding_prevout: &TxOut,
    funding_keypair: &Keypair,
) -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let tweaked = funding_keypair.tap_tweak(&secp, None);
    let prevouts = Prevouts::All(std::slice::from_ref(funding_prevout));
    let sighash_type = TapSighashType::Default;
    let sighash = SighashCache::new(&*tx).taproot_key_spend_signature_hash(
        0,
        &prevouts,
        sighash_type,
    )?;
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    tx.input[0].witness = witness;
    Ok(())
}

/// Build Disprove (hashlock leaf — no signature required).
pub fn build_disprove_tx(
    assert_txid: Txid,
    assert_vout: u32,
    connector_amount: Amount,
    l_invalid: [u8; 32],
    h_l_invalid: [u8; 32],
    spend_info: &TaprootSpendInfo,
    slash_address: &Address,
    fee: Amount,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let disprove_script = disprove_leaf_script(&h_l_invalid)?;
    let control_block = spend_info
        .control_block(&(disprove_script.clone(), LeafVersion::TapScript))
        .ok_or("control block for disprove leaf not found")?;

    let output_amount = connector_amount.checked_sub(fee).ok_or("fee too high")?;

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: assert_txid,
                vout: assert_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: output_amount,
            script_pubkey: slash_address.script_pubkey(),
        }],
    };

    let mut witness = Witness::new();
    witness.push(l_invalid);
    witness.push(disprove_script.as_bytes());
    witness.push(control_block.serialize());
    tx.input[0].witness = witness;
    Ok(tx)
}

/// Build and Schnorr-sign the Timeout script-path spend.
pub fn build_timeout_tx(
    assert_txid: Txid,
    assert_vout: u32,
    connector_prevout: &TxOut,
    engine_keypair: &Keypair,
    spend_info: &TaprootSpendInfo,
    engine_address: &Address,
    dispute_window: u32,
    fee: Amount,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let timeout_script = timeout_leaf_script(engine_keypair, dispute_window)?;
    let control_block = spend_info
        .control_block(&(timeout_script.clone(), LeafVersion::TapScript))
        .ok_or("control block for timeout leaf not found")?;

    let output_amount = connector_prevout
        .value
        .checked_sub(fee)
        .ok_or("fee too high")?;

    let window_u16 =
        u16::try_from(dispute_window).map_err(|_| "dispute_window exceeds u16")?;

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: assert_txid,
                vout: assert_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(window_u16),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: output_amount,
            script_pubkey: engine_address.script_pubkey(),
        }],
    };

    let leaf_hash = TapLeafHash::from_script(&timeout_script, LeafVersion::TapScript);
    let prevouts = Prevouts::All(std::slice::from_ref(connector_prevout));
    let sighash_type = TapSighashType::Default;
    let sighash = SighashCache::new(&tx).taproot_script_spend_signature_hash(
        0,
        &prevouts,
        leaf_hash,
        sighash_type,
    )?;
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, engine_keypair);

    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    witness.push(timeout_script.as_bytes());
    witness.push(control_block.serialize());
    tx.input[0].witness = witness;
    Ok(tx)
}

/// Convenience: default dispute window (mainnet-ish).
#[must_use]
pub fn default_dispute_window() -> u32 {
    DEFAULT_DISPUTE_WINDOW
}

fn disprove_leaf_script(h_l_invalid: &[u8; 32]) -> Result<ScriptBuf, Box<dyn std::error::Error>> {
    let push = PushBytesBuf::try_from(h_l_invalid.to_vec()).map_err(|_| "hash push")?;
    Ok(Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_SHA256)
        .push_slice(push)
        .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
        .push_opcode(bitcoin::opcodes::OP_TRUE)
        .into_script())
}

fn timeout_leaf_script(
    engine_keypair: &Keypair,
    dispute_window: u32,
) -> Result<ScriptBuf, Box<dyn std::error::Error>> {
    if dispute_window == 0 {
        return Err("dispute_window must be > 0".into());
    }
    let engine_xonly = engine_keypair.x_only_public_key().0;
    let pk_push =
        PushBytesBuf::try_from(engine_xonly.serialize().to_vec()).map_err(|_| "pk push")?;
    Ok(Builder::new()
        .push_int(i64::from(dispute_window))
        .push_opcode(bitcoin::opcodes::all::OP_CSV)
        .push_opcode(bitcoin::opcodes::all::OP_DROP)
        .push_slice(pk_push)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script())
}

/// P2TR address for a keypair (key-path only).
#[must_use]
pub fn p2tr_address(keypair: &Keypair, network: Network) -> Address {
    let secp = Secp256k1::new();
    let (xonly, _parity) = keypair.x_only_public_key();
    Address::p2tr(&secp, xonly, None, network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::Keypair;
    use bitcoin::Network;
    use rand::thread_rng;

    #[test]
    fn timeout_has_real_schnorr_sig() {
        let secp = Secp256k1::new();
        let engine = Keypair::new(&secp, &mut thread_rng());
        let funding = Keypair::new(&secp, &mut thread_rng());
        let change = p2tr_address(&funding, Network::Regtest);

        let mut assert_res = build_assert_tx(
            OutPoint::null(),
            Amount::from_sat(100_000),
            &engine,
            b"claim",
            [0x11; 32],
            Amount::from_sat(50_000),
            &change,
            REGTEST_DISPUTE_WINDOW,
            Amount::from_sat(500),
        )
        .unwrap();

        let funding_prev = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: p2tr_address(&funding, Network::Regtest).script_pubkey(),
        };
        sign_assert_keypath(&mut assert_res.tx, &funding_prev, &funding).unwrap();
        assert_eq!(assert_res.tx.input[0].witness.len(), 1);
        assert_eq!(assert_res.tx.input[0].witness.nth(0).unwrap().len(), 64);
        assert_ne!(assert_res.tx.input[0].witness.nth(0).unwrap(), &[0u8; 64]);

        let connector = &assert_res.tx.output[0];
        let timeout = build_timeout_tx(
            assert_res.tx.compute_txid(),
            0,
            connector,
            &engine,
            &assert_res.taproot_spend_info,
            &p2tr_address(&engine, Network::Regtest),
            REGTEST_DISPUTE_WINDOW,
            Amount::from_sat(500),
        )
        .unwrap();
        assert_eq!(timeout.input[0].witness.len(), 3);
        assert_eq!(timeout.input[0].witness.nth(0).unwrap().len(), 64);
        assert_ne!(timeout.input[0].witness.nth(0).unwrap(), &[0u8; 64]);
    }

    #[test]
    fn disprove_witness_is_hashlock_only() {
        let secp = Secp256k1::new();
        let engine = Keypair::new(&secp, &mut thread_rng());
        let funding = Keypair::new(&secp, &mut thread_rng());
        let l = [0xAB; 32];
        let h = {
            use sha2::{Digest, Sha256};
            Sha256::digest(l).into()
        };
        let assert_res = build_assert_tx(
            OutPoint::null(),
            Amount::from_sat(20_000),
            &engine,
            b"x",
            h,
            Amount::from_sat(10_000),
            &p2tr_address(&funding, Network::Regtest),
            REGTEST_DISPUTE_WINDOW,
            Amount::from_sat(500),
        )
        .unwrap();
        let d = build_disprove_tx(
            assert_res.tx.compute_txid(),
            0,
            Amount::from_sat(10_000),
            l,
            h,
            &assert_res.taproot_spend_info,
            &p2tr_address(&funding, Network::Regtest),
            Amount::from_sat(500),
        )
        .unwrap();
        assert_eq!(d.input[0].witness.len(), 3);
        assert_eq!(d.input[0].witness.nth(0).unwrap(), l);
    }
}
