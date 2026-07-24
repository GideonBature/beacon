//! Phase A – Real Bitcoin transaction builders (regtest-ready)
//!
//! These construct actual Taproot transactions for:
//!   - Assert   (connector with Disprove hashlock + Timeout CSV)
//!   - Disprove (spend connector with L_invalid)
//!   - Timeout  (spend connector after relative timelock)
//!
//! They do not talk to a node yet; they produce fully signed (or signable)
//! `bitcoin::Transaction` values that can be broadcast on regtest.

use bitcoin::key::Keypair;
use bitcoin::script::{Builder, PushBytesBuf, ScriptBuf};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use bitcoin::{absolute, Address, Amount, Network, Sequence, Txid, Witness};

use crate::phase_a::opening::DirectSeedOpening;
use crate::tx_templates::DEFAULT_DISPUTE_WINDOW;

/// Everything needed to build and later spend the Assert connector.
pub struct AssertBuildResult {
    pub tx: Transaction,
    pub connector_vout: u32,
    pub taproot_spend_info: TaprootSpendInfo,
    pub h_l_invalid: [u8; 32],
    pub opening: DirectSeedOpening,
    /// The internal key used for the Taproot (Engine’s key in this prototype).
    pub internal_keypair: Keypair,
}

/// Build the Assert transaction.
///
/// - `funding`: outpoint + amount + script_pubkey of the UTXO we are spending
/// - `engine_keypair`: key that will be able to take the Timeout path
/// - `claim_bytes`: serialized claim (used to derive the Phase A seed)
/// - `h_l_invalid`: the 32-byte commitment that goes into the Disprove leaf
/// - `connector_amount`: how many sats go into the connector output
/// - `change_address`: where to send the change
pub fn build_assert_tx(
    funding_outpoint: OutPoint,
    funding_amount: Amount,
    _funding_script_pubkey: ScriptBuf,
    engine_keypair: &Keypair,
    claim_bytes: &[u8],
    h_l_invalid: [u8; 32],
    connector_amount: Amount,
    change_address: &Address,
    _network: Network,
) -> Result<AssertBuildResult, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();

    let disprove_script = disprove_leaf_script(&h_l_invalid)?;
    let timeout_script = timeout_leaf_script(engine_keypair)?;

    let internal_keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let internal_key = internal_keypair.x_only_public_key().0;

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
        .checked_sub(Amount::from_sat(500)) // rough fee
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

    // For the prototype we leave the input unsigned; the caller can sign
    // with the funding key.  In a full implementation we would sign here.

    let opening = DirectSeedOpening::from_claim_bytes(0, claim_bytes);

    Ok(AssertBuildResult {
        tx,
        connector_vout: 0,
        taproot_spend_info: spend_info,
        h_l_invalid,
        opening,
        internal_keypair,
    })
}

/// Build the Disprove transaction that spends the Assert connector
/// with the hashlock leaf by revealing `l_invalid`.
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

    // Witness stack for script-path spend of the Disprove leaf:
    //   <L_invalid>  <disprove_script>  <control_block>
    let mut witness = Witness::new();
    witness.push(l_invalid);
    witness.push(disprove_script.as_bytes());
    witness.push(control_block.serialize());
    tx.input[0].witness = witness;

    Ok(tx)
}

/// Build the Timeout transaction (Engine spends after relative timelock).
pub fn build_timeout_tx(
    assert_txid: Txid,
    assert_vout: u32,
    connector_amount: Amount,
    engine_keypair: &Keypair,
    spend_info: &TaprootSpendInfo,
    engine_address: &Address,
    fee: Amount,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let timeout_script = timeout_leaf_script(engine_keypair)?;

    let control_block = spend_info
        .control_block(&(timeout_script.clone(), LeafVersion::TapScript))
        .ok_or("control block for timeout leaf not found")?;

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
            // Sequence must encode the relative timelock
            sequence: Sequence::from_height(DEFAULT_DISPUTE_WINDOW as u16),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: output_amount,
            script_pubkey: engine_address.script_pubkey(),
        }],
    };

    // For a real signature we would use SighashCache here.
    // In this prototype we leave a placeholder; the caller can sign.
    // Witness stack for the Timeout leaf:
    //   <signature>  <timeout_script>  <control_block>
    let mut witness = Witness::new();
    // placeholder signature (64 bytes of zeros) – replace with real sig
    witness.push([0u8; 64]);
    witness.push(timeout_script.as_bytes());
    witness.push(control_block.serialize());
    tx.input[0].witness = witness;

    Ok(tx)
}

/// Leaf 0: Disprove – `OP_SHA256 <H(L_invalid)> OP_EQUALVERIFY OP_TRUE`
fn disprove_leaf_script(h_l_invalid: &[u8; 32]) -> Result<ScriptBuf, Box<dyn std::error::Error>> {
    let push = PushBytesBuf::try_from(h_l_invalid.to_vec()).map_err(|_| "hash push")?;
    Ok(Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_SHA256)
        .push_slice(push)
        .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
        .push_opcode(bitcoin::opcodes::OP_TRUE)
        .into_script())
}

/// Leaf 1: Timeout – `<Δ> OP_CSV OP_DROP <pubkey> OP_CHECKSIG`
fn timeout_leaf_script(engine_keypair: &Keypair) -> Result<ScriptBuf, Box<dyn std::error::Error>> {
    let engine_xonly = engine_keypair.x_only_public_key().0;
    let pk_push = PushBytesBuf::try_from(engine_xonly.serialize().to_vec()).map_err(|_| "pk push")?;
    Ok(Builder::new()
        .push_int(i64::from(DEFAULT_DISPUTE_WINDOW))
        .push_opcode(bitcoin::opcodes::all::OP_CSV)
        .push_opcode(bitcoin::opcodes::all::OP_DROP)
        .push_slice(pk_push)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script())
}
