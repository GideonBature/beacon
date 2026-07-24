//! Optional Docker regtest integration (`#[ignore]` by default).
//!
//! Requires bitcoind from `docker-compose.example.yml` and:
//! ```bash
//! export BEACON_RPC_URL=http://127.0.0.1:18443
//! export BEACON_RPC_USER=beacon BEACON_RPC_PASS=beacon
//! cargo test --test integration_regtest --no-default-features -- --ignored --nocapture
//! ```

use beacon::{run_phase_a_regtest, run_phase_b_regtest, run_phase_c_regtest, RegtestOutcome};

#[test]
#[ignore = "needs local bitcoind regtest (Docker); see docs/12-regtest-guide.md"]
fn regtest_phase_a_timeout_and_disprove() {
    assert!(matches!(
        run_phase_a_regtest(false).expect("phase a honest"),
        RegtestOutcome::Accepted { .. }
    ));
    assert!(matches!(
        run_phase_a_regtest(true).expect("phase a cheat"),
        RegtestOutcome::Rejected { .. }
    ));
}

#[test]
#[ignore = "needs local bitcoind regtest (Docker); see docs/12-regtest-guide.md"]
fn regtest_phase_b_timeout_and_disprove() {
    assert!(matches!(
        run_phase_b_regtest(false).expect("phase b honest"),
        RegtestOutcome::Accepted { .. }
    ));
    assert!(matches!(
        run_phase_b_regtest(true).expect("phase b cheat"),
        RegtestOutcome::Rejected { .. }
    ));
}

#[test]
#[ignore = "needs local bitcoind regtest (Docker); see docs/12-regtest-guide.md"]
fn regtest_phase_c_timeout_and_disprove() {
    assert!(matches!(
        run_phase_c_regtest(false).expect("phase c honest"),
        RegtestOutcome::Accepted { .. }
    ));
    assert!(matches!(
        run_phase_c_regtest(true).expect("phase c cheat"),
        RegtestOutcome::Rejected { .. }
    ));
}
