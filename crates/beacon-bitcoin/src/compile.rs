//! Compile [`TxTemplate`]s into real Bitcoin [`Script`](bitcoin::Script) /
//! [`Transaction`](bitcoin::Transaction) skeletons.
//!
//! This is still **offline**: no broadcasting, no wallet, no Taproot key setup.
//! Scripts use transparent CLTV / hashlock / `OP_TRUE` placeholders where a
//! production backend would put operator / challenger keys and `BitVM3` secrets.

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::{OP_CLTV, OP_DROP, OP_EQUAL, OP_HASH160, OP_RETURN};
use bitcoin::blockdata::script::{Builder, PushBytesBuf, ScriptBuf};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use bitcoin::Amount;
use bitcoin::Sequence;
use core::fmt;
use sha2::{Digest, Sha256};

use beacon_core::{AssertionId, ChallengerId};

use crate::template::{ScriptIntent, TxTemplate};
use crate::tx::{TxKind, Txid};

/// Tag prefix embedded in assert `OP_RETURN` payloads.
pub const ASSERT_COMMIT_TAG: &[u8] = b"BEACON/ASSERT/v1";

/// Tag prefix embedded in challenge `OP_RETURN` payloads.
pub const CHALLENGE_OPEN_TAG: &[u8] = b"BEACON/CHALLENGE/v1";

/// Tag prefix embedded in punish `OP_RETURN` payloads.
pub const PUNISH_BOND_TAG: &[u8] = b"BEACON/PUNISH/v1";

/// Domain separator for deterministic disprove hashlock preimage material.
const DISPROVE_DOMAIN: &[u8] = b"beacon-disprove-v1";

/// Domain separator for challenger identity commitments in `OP_RETURN` payloads.
const CHALLENGER_DOMAIN: &[u8] = b"beacon-challenger-v1";

/// Result of compiling a template to Bitcoin primitives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledTx {
    /// Protocol kind mirrored from the template.
    pub kind: TxKind,
    /// Primary scriptPubKey (commit, encumbrance, hashlock, or payout).
    pub script_pubkey: ScriptBuf,
    /// Minimal unsigned transaction skeleton (one input placeholder + outputs).
    pub tx: Transaction,
}

/// Errors compiling a template to Script / Transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileError {
    /// Locktime / value / payload could not be encoded.
    InvalidField(&'static str),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid field: {field}"),
        }
    }
}

impl std::error::Error for CompileError {}

/// Compile a [`TxTemplate`] into Bitcoin Script + a tx skeleton.
///
/// # Errors
///
/// Returns [`CompileError::InvalidField`] if amounts, locktimes, or push
/// payloads cannot be encoded.
pub fn compile(template: &TxTemplate) -> Result<CompiledTx, CompileError> {
    match &template.intent {
        ScriptIntent::AssertCommit { challenge_deadline } => {
            compile_assert(template, challenge_deadline.get())
        }
        ScriptIntent::WithdrawTimeout { unlocked_at } => {
            compile_withdraw(template, unlocked_at.get())
        }
        ScriptIntent::ChallengeOpen {
            challenger,
            challenge_deadline,
        } => compile_challenge(template, challenger, challenge_deadline.get()),
        ScriptIntent::DisproveHashlock { challenger } => compile_disprove(template, challenger),
        ScriptIntent::PunishBond { challenger } => compile_punish(template, challenger),
    }
}

fn compile_assert(template: &TxTemplate, deadline_height: u64) -> Result<CompiledTx, CompileError> {
    let height =
        u32::try_from(deadline_height).map_err(|_| CompileError::InvalidField("deadline"))?;
    let mut payload = Vec::with_capacity(ASSERT_COMMIT_TAG.len() + 16);
    payload.extend_from_slice(ASSERT_COMMIT_TAG);
    payload.extend_from_slice(template.assertion_id.as_uuid().as_bytes());
    let op_return = op_return_script(&payload)?;
    let bond_script = cltv_anyone_after(height)?;
    let tx = commit_plus_bond_tx(template, height, op_return.clone(), bond_script)?;

    Ok(CompiledTx {
        kind: TxKind::Assert,
        script_pubkey: op_return,
        tx,
    })
}

fn compile_challenge(
    template: &TxTemplate,
    challenger: &ChallengerId,
    deadline_height: u64,
) -> Result<CompiledTx, CompileError> {
    let height =
        u32::try_from(deadline_height).map_err(|_| CompileError::InvalidField("deadline"))?;
    let commit = challenger_commit(challenger);
    let mut payload = Vec::with_capacity(CHALLENGE_OPEN_TAG.len() + 16 + 32);
    payload.extend_from_slice(CHALLENGE_OPEN_TAG);
    payload.extend_from_slice(template.assertion_id.as_uuid().as_bytes());
    payload.extend_from_slice(&commit);
    let op_return = op_return_script(&payload)?;
    let bond_script = cltv_anyone_after(height)?;
    let tx = commit_plus_bond_tx(template, height, op_return.clone(), bond_script)?;

    Ok(CompiledTx {
        kind: TxKind::Challenge,
        script_pubkey: op_return,
        tx,
    })
}

fn compile_disprove(
    template: &TxTemplate,
    challenger: &ChallengerId,
) -> Result<CompiledTx, CompileError> {
    let script_pubkey = hashlock_script(template.assertion_id, challenger)?;
    let tx = skeleton_tx(
        template.spends,
        template.value_sats,
        script_pubkey.clone(),
        None,
    )?;
    Ok(CompiledTx {
        kind: TxKind::Disprove,
        script_pubkey,
        tx,
    })
}

fn compile_punish(
    template: &TxTemplate,
    challenger: &ChallengerId,
) -> Result<CompiledTx, CompileError> {
    let commit = challenger_commit(challenger);
    let mut payload = Vec::with_capacity(PUNISH_BOND_TAG.len() + 16 + 32);
    payload.extend_from_slice(PUNISH_BOND_TAG);
    payload.extend_from_slice(template.assertion_id.as_uuid().as_bytes());
    payload.extend_from_slice(&commit);
    let op_return = op_return_script(&payload)?;
    // Placeholder for "pay challenger": anyone-can-spend until real keys exist.
    let payout = Builder::new()
        .push_opcode(bitcoin::opcodes::OP_TRUE)
        .into_script();

    let txin = TxIn {
        previous_output: outpoint(template.spends),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
        witness: bitcoin::Witness::default(),
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: op_return.clone(),
            },
            TxOut {
                value: Amount::from_sat(template.value_sats),
                script_pubkey: payout,
            },
        ],
    };

    Ok(CompiledTx {
        kind: TxKind::Punish,
        script_pubkey: op_return,
        tx,
    })
}

fn compile_withdraw(
    template: &TxTemplate,
    unlocked_height: u64,
) -> Result<CompiledTx, CompileError> {
    let height =
        u32::try_from(unlocked_height).map_err(|_| CompileError::InvalidField("unlocked_at"))?;
    let script_pubkey = cltv_anyone_after(height)?;
    let tx = skeleton_tx(
        template.spends,
        template.value_sats,
        script_pubkey.clone(),
        Some(height),
    )?;
    Ok(CompiledTx {
        kind: TxKind::Withdraw,
        script_pubkey,
        tx,
    })
}

fn commit_plus_bond_tx(
    template: &TxTemplate,
    height: u32,
    op_return: ScriptBuf,
    bond_script: ScriptBuf,
) -> Result<Transaction, CompileError> {
    let txin = TxIn {
        previous_output: outpoint(template.spends),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
        witness: bitcoin::Witness::default(),
    };

    let lock_time =
        LockTime::from_height(height).map_err(|_| CompileError::InvalidField("lock_height"))?;

    Ok(Transaction {
        version: Version::TWO,
        lock_time,
        input: vec![txin],
        output: vec![
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: op_return,
            },
            TxOut {
                value: Amount::from_sat(template.value_sats),
                script_pubkey: bond_script,
            },
        ],
    })
}

fn op_return_script(payload: &[u8]) -> Result<ScriptBuf, CompileError> {
    let push = PushBytesBuf::try_from(payload.to_vec())
        .map_err(|_| CompileError::InvalidField("op_return_payload"))?;
    Ok(Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push)
        .into_script())
}

/// `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_TRUE`
fn cltv_anyone_after(height: u32) -> Result<ScriptBuf, CompileError> {
    if height == 0 {
        return Err(CompileError::InvalidField("locktime_zero"));
    }
    Ok(Builder::new()
        .push_int(i64::from(height))
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_opcode(bitcoin::opcodes::OP_TRUE)
        .into_script())
}

/// `OP_HASH160 <20-byte> OP_EQUAL` — stand-in for `BitVM3` / fraud preimage reveal.
fn hashlock_script(
    assertion_id: AssertionId,
    challenger: &ChallengerId,
) -> Result<ScriptBuf, CompileError> {
    let digest = disprove_hash160(assertion_id, challenger);
    let push = PushBytesBuf::try_from(digest.to_vec())
        .map_err(|_| CompileError::InvalidField("hashlock_digest"))?;
    Ok(Builder::new()
        .push_opcode(OP_HASH160)
        .push_slice(push)
        .push_opcode(OP_EQUAL)
        .into_script())
}

fn challenger_commit(challenger: &ChallengerId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGER_DOMAIN);
    hasher.update(challenger.as_str().as_bytes());
    hasher.finalize().into()
}

fn disprove_hash160(assertion_id: AssertionId, challenger: &ChallengerId) -> [u8; 20] {
    let mut preimage = Vec::with_capacity(DISPROVE_DOMAIN.len() + 16 + challenger.as_str().len());
    preimage.extend_from_slice(DISPROVE_DOMAIN);
    preimage.extend_from_slice(assertion_id.as_uuid().as_bytes());
    preimage.extend_from_slice(challenger.as_str().as_bytes());
    *hash160::Hash::hash(&preimage).as_byte_array()
}

fn skeleton_tx(
    spends: Option<Txid>,
    value_sats: u64,
    script_pubkey: ScriptBuf,
    lock_height: Option<u32>,
) -> Result<Transaction, CompileError> {
    let txin = TxIn {
        previous_output: outpoint(spends),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
        witness: bitcoin::Witness::default(),
    };

    let txout = TxOut {
        value: Amount::from_sat(value_sats),
        script_pubkey,
    };

    let lock_time = match lock_height {
        Some(h) => {
            LockTime::from_height(h).map_err(|_| CompileError::InvalidField("lock_height"))?
        }
        None => LockTime::ZERO,
    };

    Ok(Transaction {
        version: Version::TWO,
        lock_time,
        input: vec![txin],
        output: vec![txout],
    })
}

fn outpoint(spends: Option<Txid>) -> OutPoint {
    match spends {
        Some(txid) => {
            let hash = *txid.as_bytes();
            OutPoint {
                txid: bitcoin::Txid::from_byte_array(hash),
                vout: 0,
            }
        }
        None => OutPoint::null(),
    }
}

/// Compile every journal entry's template to Script / Transaction skeletons.
pub fn compile_journal<'a>(
    journal: impl IntoIterator<Item = &'a crate::tx::SimulatedTx>,
) -> Vec<(Txid, Result<CompiledTx, CompileError>)> {
    journal
        .into_iter()
        .map(|tx| (tx.txid, compile(&tx.template)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_core::{AssertionId, Instant};

    use crate::template::TxTemplate;

    #[test]
    fn compile_assert_commit_op_return() {
        let id = AssertionId::new();
        let template = TxTemplate::new(
            id,
            ScriptIntent::AssertCommit {
                challenge_deadline: Instant::new(100),
            },
            None,
            0,
        );
        let compiled = compile(&template).unwrap();
        assert_eq!(compiled.kind, TxKind::Assert);
        assert!(compiled.script_pubkey.is_op_return());
        let bytes = compiled.script_pubkey.as_bytes();
        assert!(bytes
            .windows(ASSERT_COMMIT_TAG.len())
            .any(|w| w == ASSERT_COMMIT_TAG));
        assert_eq!(compiled.tx.lock_time, LockTime::from_height(100).unwrap());
        assert_eq!(compiled.tx.output.len(), 2);
        assert_eq!(compiled.tx.output[0].value, Amount::from_sat(0));
    }

    #[test]
    fn compile_withdraw_cltv() {
        let id = AssertionId::new();
        let prev = Txid::derive(TxKind::Assert, id, 0, Some(Instant::new(50)), None);
        let template = TxTemplate::new(
            id,
            ScriptIntent::WithdrawTimeout {
                unlocked_at: Instant::new(50),
            },
            Some(prev),
            25_000,
        );
        let compiled = compile(&template).unwrap();
        assert_eq!(compiled.kind, TxKind::Withdraw);
        assert!(!compiled.script_pubkey.is_op_return());
        assert_eq!(compiled.tx.output[0].value, Amount::from_sat(25_000));
        assert_eq!(compiled.tx.input[0].previous_output.vout, 0);
        assert_ne!(
            compiled.tx.input[0].previous_output.txid,
            bitcoin::Txid::all_zeros()
        );
    }

    #[test]
    fn compile_challenge_open_op_return() {
        let id = AssertionId::new();
        let prev = Txid::derive(TxKind::Assert, id, 0, Some(Instant::new(10)), None);
        let template = TxTemplate::new(
            id,
            ScriptIntent::ChallengeOpen {
                challenger: ChallengerId::new("watcher"),
                challenge_deadline: Instant::new(10),
            },
            Some(prev),
            5_000,
        );
        let compiled = compile(&template).unwrap();
        assert_eq!(compiled.kind, TxKind::Challenge);
        assert!(compiled.script_pubkey.is_op_return());
        let bytes = compiled.script_pubkey.as_bytes();
        assert!(bytes
            .windows(CHALLENGE_OPEN_TAG.len())
            .any(|w| w == CHALLENGE_OPEN_TAG));
        assert_eq!(compiled.tx.output.len(), 2);
        assert_eq!(compiled.tx.output[1].value, Amount::from_sat(5_000));
        assert_eq!(compiled.tx.lock_time, LockTime::from_height(10).unwrap());
    }

    #[test]
    fn compile_disprove_hashlock() {
        let id = AssertionId::new();
        let challenger = ChallengerId::new("watcher");
        let template = TxTemplate::new(
            id,
            ScriptIntent::DisproveHashlock {
                challenger: challenger.clone(),
            },
            None,
            1_000,
        );
        let compiled = compile(&template).unwrap();
        assert_eq!(compiled.kind, TxKind::Disprove);
        assert!(!compiled.script_pubkey.is_op_return());
        let expected = hashlock_script(id, &challenger).unwrap();
        assert_eq!(compiled.script_pubkey, expected);
        assert_eq!(compiled.tx.output[0].value, Amount::from_sat(1_000));
    }

    #[test]
    fn compile_punish_bond_op_return() {
        let id = AssertionId::new();
        let template = TxTemplate::new(
            id,
            ScriptIntent::PunishBond {
                challenger: ChallengerId::new("watcher"),
            },
            None,
            50_000,
        );
        let compiled = compile(&template).unwrap();
        assert_eq!(compiled.kind, TxKind::Punish);
        assert!(compiled.script_pubkey.is_op_return());
        let bytes = compiled.script_pubkey.as_bytes();
        assert!(bytes
            .windows(PUNISH_BOND_TAG.len())
            .any(|w| w == PUNISH_BOND_TAG));
        assert_eq!(compiled.tx.output.len(), 2);
        assert_eq!(compiled.tx.output[1].value, Amount::from_sat(50_000));
        assert_eq!(
            compiled.tx.output[1].script_pubkey,
            Builder::new()
                .push_opcode(bitcoin::opcodes::OP_TRUE)
                .into_script()
        );
    }

    #[test]
    fn reject_journal_compiles_all_intents() {
        use beacon_core::{Deadline, Engine};
        use beacon_mock::MockEvidence;

        let mut engine = Engine::new(crate::BitcoinBackend::with_bond(
            beacon_mock::MockConfig::default(),
            10_000,
        ));
        let id = engine
            .assert(MockEvidence::invalid("bad"), Deadline::from_raw(100))
            .unwrap();
        engine
            .challenge(id, ChallengerId::new("cli-challenger"))
            .unwrap();
        let _ = engine.finalize(id).unwrap();

        let compiled = compile_journal(engine.backend().journal());
        assert_eq!(compiled.len(), 4);
        assert!(compiled.iter().all(|(_, r)| r.is_ok()));
        let kinds: Vec<_> = compiled
            .iter()
            .map(|(_, r)| r.as_ref().unwrap().kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                TxKind::Assert,
                TxKind::Challenge,
                TxKind::Disprove,
                TxKind::Punish
            ]
        );
    }
}
