//! Minimal cut-and-choose schedule (Cube / BitVM3 Steps 2–4).
//!
//! Selects check set `C` and evaluation set `E`, designates Assert instance
//! `a ∈ E`, and verifies check / eval ciphertext commitments against
//! [`CiphertextStore`]. Does **not** implement full VSSS, soldering, or
//! label-commit reopen — only schedule bookkeeping + store hash checks.

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::phase_c::ciphertext_store::{CiphertextMeta, CiphertextStore, StoreError};

/// Setup parameters (GSV `Config { total, finalized_count }` shape).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutAndChooseParams {
    /// Total garbled instances `n`.
    pub n: u32,
    /// Evaluation-set size `f` (MVP default: 1 → single Assert instance).
    pub eval_count: u32,
}

impl Default for CutAndChooseParams {
    fn default() -> Self {
        Self {
            n: 3,
            eval_count: 1,
        }
    }
}

/// Post-challenge partition of instances.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutAndChooseSchedule {
    pub n: u32,
    /// Check set `C` (sorted).
    pub check_set: Vec<u32>,
    /// Evaluation set `E` (sorted).
    pub eval_set: Vec<u32>,
    /// Assert evaluation instance `a ∈ E` (MVP: `eval_set[0]`).
    pub eval_instance: u32,
}

/// Published commitment for one garbled instance (epoch / bulletin board).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceCommit {
    pub instance_id: u32,
    pub ciphertext_hash: [u8; 32],
}

/// Engine opens a check-set instance (seed optional; hash verify is enough for MVP).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckOpening {
    pub instance_id: u32,
    pub seed: u64,
}

#[derive(Debug)]
pub enum ScheduleError {
    BadParams(&'static str),
    BadSchedule(&'static str),
    MissingCommit(u32),
    CommitMismatch(u32),
    Store(StoreError),
    CheckNotInSet(u32),
    EvalInCheckSet(u32),
}

impl std::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadParams(m) => write!(f, "cut-and-choose params: {m}"),
            Self::BadSchedule(m) => write!(f, "cut-and-choose schedule: {m}"),
            Self::MissingCommit(i) => write!(f, "cut-and-choose: missing commit for instance {i}"),
            Self::CommitMismatch(i) => {
                write!(f, "cut-and-choose: commit mismatch for instance {i}")
            }
            Self::Store(e) => write!(f, "cut-and-choose store: {e}"),
            Self::CheckNotInSet(i) => {
                write!(f, "cut-and-choose: opening {i} not in check set")
            }
            Self::EvalInCheckSet(i) => {
                write!(f, "cut-and-choose: eval instance {i} must not be opened as check")
            }
        }
    }
}

impl std::error::Error for ScheduleError {}

impl From<StoreError> for ScheduleError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl CutAndChooseParams {
    pub fn validate(self) -> Result<(), ScheduleError> {
        if self.n == 0 {
            return Err(ScheduleError::BadParams("n == 0"));
        }
        if self.eval_count == 0 || self.eval_count >= self.n {
            return Err(ScheduleError::BadParams(
                "need 0 < eval_count < n (at least one check instance)",
            ));
        }
        Ok(())
    }
}

/// Sample a random schedule: shuffle `0..n`, take `f` as eval set, rest check.
pub fn sample_schedule<R: Rng>(
    rng: &mut R,
    params: CutAndChooseParams,
) -> Result<CutAndChooseSchedule, ScheduleError> {
    params.validate()?;
    let n = params.n as usize;
    let f = params.eval_count as usize;
    let mut idxs: Vec<u32> = (0..params.n).collect();
    // Fisher–Yates
    for i in (1..n).rev() {
        let j = rng.gen_range(0..=i);
        idxs.swap(i, j);
    }
    let mut eval_set = idxs[..f].to_vec();
    let mut check_set = idxs[f..].to_vec();
    eval_set.sort_unstable();
    check_set.sort_unstable();
    let eval_instance = eval_set[0];
    let schedule = CutAndChooseSchedule {
        n: params.n,
        check_set,
        eval_set,
        eval_instance,
    };
    validate_schedule(&schedule, params)?;
    Ok(schedule)
}

/// Deterministic schedule for tests: eval = `{n-1}`, check = `{0..n-2}`.
pub fn fixed_schedule(params: CutAndChooseParams) -> Result<CutAndChooseSchedule, ScheduleError> {
    params.validate()?;
    let f = params.eval_count;
    let mut eval_set: Vec<u32> = ((params.n - f)..params.n).collect();
    let mut check_set: Vec<u32> = (0..(params.n - f)).collect();
    eval_set.sort_unstable();
    check_set.sort_unstable();
    let schedule = CutAndChooseSchedule {
        n: params.n,
        check_set,
        eval_set: eval_set.clone(),
        eval_instance: eval_set[0],
    };
    validate_schedule(&schedule, params)?;
    Ok(schedule)
}

pub fn validate_schedule(
    schedule: &CutAndChooseSchedule,
    params: CutAndChooseParams,
) -> Result<(), ScheduleError> {
    params.validate()?;
    if schedule.n != params.n {
        return Err(ScheduleError::BadSchedule("n mismatch"));
    }
    if schedule.eval_set.len() as u32 != params.eval_count {
        return Err(ScheduleError::BadSchedule("eval_set size"));
    }
    if schedule.check_set.len() as u32 != params.n - params.eval_count {
        return Err(ScheduleError::BadSchedule("check_set size"));
    }
    if !schedule.eval_set.contains(&schedule.eval_instance) {
        return Err(ScheduleError::BadSchedule("eval_instance ∉ E"));
    }
    let mut all = schedule.check_set.clone();
    all.extend_from_slice(&schedule.eval_set);
    all.sort_unstable();
    all.dedup();
    if all.len() != params.n as usize {
        return Err(ScheduleError::BadSchedule("sets not a partition of 0..n"));
    }
    for (i, &v) in all.iter().enumerate() {
        if v != i as u32 {
            return Err(ScheduleError::BadSchedule("sets not a partition of 0..n"));
        }
    }
    Ok(())
}

/// Verify every check-set opening against published commits + store files.
pub fn open_check_instances(
    store: &CiphertextStore,
    schedule: &CutAndChooseSchedule,
    commits: &[InstanceCommit],
    openings: &[CheckOpening],
) -> Result<(), ScheduleError> {
    if openings.len() != schedule.check_set.len() {
        return Err(ScheduleError::BadSchedule("opening count ≠ |C|"));
    }
    for op in openings {
        if schedule.eval_set.contains(&op.instance_id) {
            return Err(ScheduleError::EvalInCheckSet(op.instance_id));
        }
        if !schedule.check_set.contains(&op.instance_id) {
            return Err(ScheduleError::CheckNotInSet(op.instance_id));
        }
        let commit = commits
            .iter()
            .find(|c| c.instance_id == op.instance_id)
            .ok_or(ScheduleError::MissingCommit(op.instance_id))?;
        let meta = store.verify(op.instance_id)?;
        if meta.ciphertext_hash != commit.ciphertext_hash {
            return Err(ScheduleError::CommitMismatch(op.instance_id));
        }
        if meta.seed != op.seed {
            return Err(ScheduleError::CommitMismatch(op.instance_id));
        }
    }
    // Ensure every check index was opened.
    for &i in &schedule.check_set {
        if !openings.iter().any(|o| o.instance_id == i) {
            return Err(ScheduleError::CheckNotInSet(i));
        }
    }
    Ok(())
}

/// Confirm eval instance CT is present and matches the published commit.
pub fn require_eval_committed(
    store: &CiphertextStore,
    schedule: &CutAndChooseSchedule,
    commits: &[InstanceCommit],
) -> Result<CiphertextMeta, ScheduleError> {
    let a = schedule.eval_instance;
    let commit = commits
        .iter()
        .find(|c| c.instance_id == a)
        .ok_or(ScheduleError::MissingCommit(a))?;
    let meta = store.verify(a)?;
    if meta.ciphertext_hash != commit.ciphertext_hash {
        return Err(ScheduleError::CommitMismatch(a));
    }
    Ok(meta)
}

/// Build commit table from store metas for `0..n`.
pub fn commits_from_store(
    store: &CiphertextStore,
    n: u32,
) -> Result<Vec<InstanceCommit>, ScheduleError> {
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let meta = store.load_meta(i)?;
        out.push(InstanceCommit {
            instance_id: i,
            ciphertext_hash: meta.ciphertext_hash,
        });
    }
    Ok(out)
}

/// Openings for the whole check set (seeds from store meta).
pub fn check_openings_from_store(
    store: &CiphertextStore,
    schedule: &CutAndChooseSchedule,
) -> Result<Vec<CheckOpening>, ScheduleError> {
    let mut out = Vec::with_capacity(schedule.check_set.len());
    for &i in &schedule.check_set {
        let meta = store.load_meta(i)?;
        out.push(CheckOpening {
            instance_id: i,
            seed: meta.seed,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phase_c::ciphertext_store::CiphertextStore;
    use rand::thread_rng;

    #[test]
    fn sample_is_valid_partition() {
        let params = CutAndChooseParams {
            n: 5,
            eval_count: 2,
        };
        let s = sample_schedule(&mut thread_rng(), params).unwrap();
        validate_schedule(&s, params).unwrap();
        assert_eq!(s.eval_set.len(), 2);
        assert_eq!(s.check_set.len(), 3);
    }

    #[test]
    fn open_check_and_require_eval() {
        let dir = std::env::temp_dir().join(format!(
            "beacon-cnc-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = CiphertextStore::open(&dir).unwrap();
        let params = CutAndChooseParams::default(); // n=3, f=1
        let schedule = fixed_schedule(params).unwrap();
        assert_eq!(schedule.eval_instance, 2);
        assert_eq!(schedule.check_set, vec![0, 1]);

        for i in 0..3 {
            store
                .persist_bytes_sha256(
                    i,
                    &[i as u8; 16],
                    100 + i as u64,
                    1,
                    0,
                    [0x11; 32],
                    [0x22; 32],
                )
                .unwrap();
        }
        let commits = commits_from_store(&store, 3).unwrap();
        let openings = check_openings_from_store(&store, &schedule).unwrap();
        open_check_instances(&store, &schedule, &commits, &openings).unwrap();
        let meta = require_eval_committed(&store, &schedule, &commits).unwrap();
        assert_eq!(meta.instance_id, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
