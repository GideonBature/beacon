//! Lifecycle demos across mock, bitcoin-sim, and groth16 evidence.

use ark_bn254::Fr;
use beacon_bitcoin::{BitcoinBackend, TxKind};
use beacon_core::{ChallengerId, Deadline, Engine, Instant, Verifiable};
use beacon_groth16::testing::{prove_product_parts, with_public_inputs, ProductWitness};
use beacon_groth16::{Groth16Statement, VerifyingKeyRegistry};
use beacon_mock::{MockBackend, MockEvidence};
use clap::Subcommand;

use crate::print::{print_compiled, print_events, print_journal, print_settlement};

#[derive(Debug, Subcommand)]
pub(crate) enum DemoCommand {
    /// In-memory mock backend (`MockEvidence`).
    Mock {
        #[command(subcommand)]
        scenario: OutcomeScenario,
    },
    /// Simulated Bitcoin journal backend.
    Bitcoin {
        #[command(subcommand)]
        scenario: OutcomeScenario,
    },
    /// Groth16 evidence (toy circuit) through mock or bitcoin-sim.
    Groth16 {
        #[command(subcommand)]
        scenario: Groth16Scenario,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum OutcomeScenario {
    /// Valid evidence → timeout → Accepted.
    Accept {
        #[arg(long, default_value_t = 5)]
        deadline: u64,
        #[arg(long, default_value = "demo-state-root")]
        statement: String,
    },
    /// Invalid evidence → challenge → Rejected.
    Reject {
        #[arg(long, default_value_t = 100)]
        deadline: u64,
        #[arg(long, default_value = "demo-bad-root")]
        statement: String,
        #[arg(long, default_value = "cli-challenger")]
        challenger: String,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum Groth16Scenario {
    /// Prove toy product, assert on mock, accept after deadline.
    Accept {
        #[arg(long, default_value_t = 5)]
        deadline: u64,
        #[arg(long, default_value_t = 7)]
        a: u64,
        #[arg(long, default_value_t = 11)]
        b: u64,
        /// Use simulated Bitcoin journal instead of plain mock.
        #[arg(long)]
        bitcoin: bool,
    },
    /// Tamper public input, challenge, reject (optionally on bitcoin-sim).
    Reject {
        #[arg(long, default_value_t = 100)]
        deadline: u64,
        #[arg(long, default_value_t = 6)]
        a: u64,
        #[arg(long, default_value_t = 7)]
        b: u64,
        #[arg(long, default_value = "cli-challenger")]
        challenger: String,
        #[arg(long)]
        bitcoin: bool,
    },
}

pub(crate) fn run(command: DemoCommand) -> Result<(), String> {
    match command {
        DemoCommand::Mock { scenario } => run_mock(scenario),
        DemoCommand::Bitcoin { scenario } => run_bitcoin(scenario),
        DemoCommand::Groth16 { scenario } => run_groth16(scenario),
    }
}

fn run_mock(scenario: OutcomeScenario) -> Result<(), String> {
    let mut engine = Engine::new(MockBackend::default());
    match scenario {
        OutcomeScenario::Accept {
            deadline,
            statement,
        } => {
            let id = engine
                .assert(MockEvidence::valid(statement), Deadline::from_raw(deadline))
                .map_err(|e| e.to_string())?;
            println!("backend=mock");
            println!("asserted {id}");
            engine.backend_mut().set_now(Instant::new(deadline));
            let settlement = engine.finalize(id).map_err(|e| e.to_string())?;
            print_settlement(settlement.outcome);
        }
        OutcomeScenario::Reject {
            deadline,
            statement,
            challenger,
        } => {
            let id = engine
                .assert(
                    MockEvidence::invalid(statement),
                    Deadline::from_raw(deadline),
                )
                .map_err(|e| e.to_string())?;
            println!("backend=mock");
            println!("asserted {id}");
            engine
                .challenge(id, ChallengerId::new(challenger))
                .map_err(|e| e.to_string())?;
            println!("challenged");
            let settlement = engine.finalize(id).map_err(|e| e.to_string())?;
            print_settlement(settlement.outcome);
        }
    }
    print_events(engine.backend().events());
    Ok(())
}

fn run_bitcoin(scenario: OutcomeScenario) -> Result<(), String> {
    let mut engine = Engine::new(BitcoinBackend::default());
    match scenario {
        OutcomeScenario::Accept {
            deadline,
            statement,
        } => {
            let id = engine
                .assert(MockEvidence::valid(statement), Deadline::from_raw(deadline))
                .map_err(|e| e.to_string())?;
            println!("backend=bitcoin-sim");
            println!("asserted {id}");
            engine.backend_mut().set_now(Instant::new(deadline));
            let settlement = engine.finalize(id).map_err(|e| e.to_string())?;
            print_settlement(settlement.outcome);
        }
        OutcomeScenario::Reject {
            deadline,
            statement,
            challenger,
        } => {
            let id = engine
                .assert(
                    MockEvidence::invalid(statement),
                    Deadline::from_raw(deadline),
                )
                .map_err(|e| e.to_string())?;
            println!("backend=bitcoin-sim");
            println!("asserted {id}");
            engine
                .challenge(id, ChallengerId::new(challenger))
                .map_err(|e| e.to_string())?;
            println!("challenged");
            let settlement = engine.finalize(id).map_err(|e| e.to_string())?;
            print_settlement(settlement.outcome);
        }
    }
    print_events(engine.backend().events());
    print_journal(engine.backend().journal());
    print_compiled(engine.backend().journal());
    Ok(())
}

fn run_groth16(scenario: Groth16Scenario) -> Result<(), String> {
    match scenario {
        Groth16Scenario::Accept {
            deadline,
            a,
            b,
            bitcoin,
        } => {
            let (vk, proof, product) = prove_product_parts(ProductWitness { a, b });
            let mut registry = VerifyingKeyRegistry::new();
            registry.register("cli-toy-v1", vk);
            let evidence = registry
                .evidence("cli-toy-v1", Groth16Statement::new(vec![product]), proof)
                .map_err(|e| e.to_string())?;
            assert!(evidence.check(), "toy proof must verify");
            println!("evidence=groth16 product={product} vk_id=cli-toy-v1");

            if bitcoin {
                let mut engine = Engine::new(BitcoinBackend::default());
                let id = engine
                    .assert(evidence, Deadline::from_raw(deadline))
                    .map_err(|e| e.to_string())?;
                println!("backend=bitcoin-sim");
                println!("asserted {id}");
                engine.backend_mut().set_now(Instant::new(deadline));
                let settlement = engine.finalize(id).map_err(|e| e.to_string())?;
                print_settlement(settlement.outcome);
                print_events(engine.backend().events());
                print_journal(engine.backend().journal());
                print_compiled(engine.backend().journal());
                let kinds: Vec<_> = engine.backend().journal().iter().map(|t| t.kind).collect();
                if kinds != [TxKind::Assert, TxKind::Withdraw] {
                    return Err(format!("unexpected journal: {kinds:?}"));
                }
            } else {
                let mut engine = Engine::new(MockBackend::default());
                let id = engine
                    .assert(evidence, Deadline::from_raw(deadline))
                    .map_err(|e| e.to_string())?;
                println!("backend=mock");
                println!("asserted {id}");
                engine.backend_mut().set_now(Instant::new(deadline));
                let settlement = engine.finalize(id).map_err(|e| e.to_string())?;
                print_settlement(settlement.outcome);
                print_events(engine.backend().events());
            }
        }
        Groth16Scenario::Reject {
            deadline,
            a,
            b,
            challenger,
            bitcoin,
        } => {
            let (vk, proof, product) = prove_product_parts(ProductWitness { a, b });
            let mut registry = VerifyingKeyRegistry::new();
            registry.register("cli-toy-v1", vk);
            let evidence = registry
                .evidence("cli-toy-v1", Groth16Statement::new(vec![product]), proof)
                .map_err(|e| e.to_string())?;
            let bad = with_public_inputs(&evidence, vec![product + Fr::from(1u64)]);
            assert!(!bad.check(), "tampered proof must fail verify");
            println!("evidence=groth16 (tampered public input) vk_id=cli-toy-v1");

            if bitcoin {
                let mut engine = Engine::new(BitcoinBackend::default());
                let id = engine
                    .assert(bad, Deadline::from_raw(deadline))
                    .map_err(|e| e.to_string())?;
                println!("backend=bitcoin-sim");
                println!("asserted {id}");
                engine
                    .challenge(id, ChallengerId::new(challenger))
                    .map_err(|e| e.to_string())?;
                println!("challenged");
                let settlement = engine.finalize(id).map_err(|e| e.to_string())?;
                print_settlement(settlement.outcome);
                print_events(engine.backend().events());
                print_journal(engine.backend().journal());
                print_compiled(engine.backend().journal());
            } else {
                let mut engine = Engine::new(MockBackend::default());
                let id = engine
                    .assert(bad, Deadline::from_raw(deadline))
                    .map_err(|e| e.to_string())?;
                println!("backend=mock");
                println!("asserted {id}");
                engine
                    .challenge(id, ChallengerId::new(challenger))
                    .map_err(|e| e.to_string())?;
                println!("challenged");
                let settlement = engine.finalize(id).map_err(|e| e.to_string())?;
                print_settlement(settlement.outcome);
                print_events(engine.backend().events());
            }
        }
    }
    Ok(())
}
