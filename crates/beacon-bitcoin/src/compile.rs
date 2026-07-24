//! Compile [`TxTemplate`]s into real Bitcoin [`Script`](bitcoin::Script) /
//! [`Transaction`](bitcoin::Transaction) skeletons.
//!
//! This is still **offline**: no broadcasting, no wallet, no Taproot key setup.
//! Scripts use transparent CLTV + `OP_TRUE` placeholders where a production
//! backend would put operator / challenger keys. `BitVM3` artifacts are out of
//! scope — only Assert / Withdraw are compiled in v1.

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::{OP_CLTV, OP_DROP, OP_RETURN};
use bitcoin::blockdata::script::{Builder, PushBytesBuf, ScriptBuf};
use bitcoin::hashes::Hash;
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use bitcoin::Amount;
use bitcoin::Sequence;
use core::fmt;

use crate::template::{ScriptIntent, TxTemplate};
use crate::tx::{TxKind, Txid};

/// Tag prefix embedded in assert `OP_RETURN` payloads.
pub const ASSERT_COMMIT_TAG: &[u8] = b"BEACON/ASSERT/v1";

/// Result of compiling a template to Bitcoin primitives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledTx {
    /// Protocol kind mirrored from the template.
    pub kind: TxKind,
    /// Primary scriptPubKey (commit or encumbrance).
    pub script_pubkey: ScriptBuf,
    /// Minimal unsigned transaction skeleton (one input placeholder + one output).
    pub tx: Transaction,
}

/// Errors compiling a template to Script / Transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileError {
    /// Intent not yet mapped to Script (Challenge / Disprove / Punish in v1).
    UnsupportedIntent(TxKind),
    /// Locktime / value could not be encoded.
    InvalidField(&'static str),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedIntent(kind) => {
                write!(f, "script compilation not implemented for {kind:?}")
            }
            Self::InvalidField(field) => write!(f, "invalid field: {field}"),
        }
    }
}

impl std::error::Error for CompileError {}

/// Compile a [`TxTemplate`] into Bitcoin Script + a tx skeleton.
///
/// # Errors
///
/// Returns [`CompileError::UnsupportedIntent`] for Challenge / Disprove / Punish
/// until those policies are specified. Returns [`CompileError::InvalidField`]
/// if amounts or locktimes cannot be encoded.
pub fn compile(template: &TxTemplate) -> Result<CompiledTx, CompileError> {
    match &template.intent {
        ScriptIntent::AssertCommit { challenge_deadline } => {
            compile_assert(template, challenge_deadline.get())
        }
        ScriptIntent::WithdrawTimeout { unlocked_at } => {
            compile_withdraw(template, unlocked_at.get())
        }
        ScriptIntent::ChallengeOpen { .. } => {
            Err(CompileError::UnsupportedIntent(TxKind::Challenge))
        }
        ScriptIntent::DisproveHashlock { .. } => {
            Err(CompileError::UnsupportedIntent(TxKind::Disprove))
        }
        ScriptIntent::PunishBond { .. } => Err(CompileError::UnsupportedIntent(TxKind::Punish)),
    }
}

fn compile_assert(template: &TxTemplate, deadline_height: u64) -> Result<CompiledTx, CompileError> {
    let height =
        u32::try_from(deadline_height).map_err(|_| CompileError::InvalidField("deadline"))?;
    let mut payload = Vec::with_capacity(ASSERT_COMMIT_TAG.len() + 16);
    payload.extend_from_slice(ASSERT_COMMIT_TAG);
    payload.extend_from_slice(template.assertion_id.as_uuid().as_bytes());
    let push = PushBytesBuf::try_from(payload)
        .map_err(|_| CompileError::InvalidField("op_return_payload"))?;

    let op_return = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push)
        .into_script();

    let bond_script = cltv_anyone_after(height)?;

    let prev = outpoint(template.spends);
    let txin = TxIn {
        previous_output: prev,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
        witness: bitcoin::Witness::default(),
    };

    let lock_time =
        LockTime::from_height(height).map_err(|_| CompileError::InvalidField("lock_height"))?;

    let tx = Transaction {
        version: Version::TWO,
        lock_time,
        input: vec![txin],
        output: vec![
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: op_return.clone(),
            },
            TxOut {
                value: Amount::from_sat(template.value_sats),
                script_pubkey: bond_script,
            },
        ],
    };

    Ok(CompiledTx {
        kind: TxKind::Assert,
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

/// Compile every Assert/Withdraw entry in a journal; skip unsupported intents.
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
    fn challenge_not_yet_supported() {
        let id = AssertionId::new();
        let template = TxTemplate::new(
            id,
            ScriptIntent::ChallengeOpen {
                challenger: beacon_core::ChallengerId::new("c"),
                challenge_deadline: Instant::new(10),
            },
            None,
            0,
        );
        assert!(matches!(
            compile(&template),
            Err(CompileError::UnsupportedIntent(TxKind::Challenge))
        ));
    }
}
