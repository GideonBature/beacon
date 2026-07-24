//! Beacon developer CLI — drive the in-memory mock lifecycle from the terminal.

use std::process::ExitCode;

use beacon_core::{ChallengerId, Deadline, Engine, Instant, Outcome};
use beacon_events::Event;
use beacon_mock::{MockBackend, MockEvidence};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "beacon")]
#[command(about = "Beacon assertion engine (mock backend)", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print version information.
    Version,
    /// Run an in-memory lifecycle demonstration.
    Demo {
        #[command(subcommand)]
        scenario: DemoScenario,
    },
}

#[derive(Debug, Subcommand)]
enum DemoScenario {
    /// Assert valid evidence, wait out the window, accept (no challenge).
    Accept {
        /// Challenge-window deadline (logical time).
        #[arg(long, default_value_t = 5)]
        deadline: u64,
        /// Statement text embedded in mock evidence.
        #[arg(long, default_value = "demo-state-root")]
        statement: String,
    },
    /// Assert invalid evidence, challenge, reject.
    Reject {
        /// Challenge-window deadline (logical time).
        #[arg(long, default_value_t = 100)]
        deadline: u64,
        /// Statement text embedded in mock evidence.
        #[arg(long, default_value = "demo-bad-root")]
        statement: String,
        /// Challenger id.
        #[arg(long, default_value = "cli-challenger")]
        challenger: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Version => {
            println!("beacon {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Commands::Demo { scenario } => {
            if let Err(err) = run_demo(scenario) {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

fn run_demo(scenario: DemoScenario) -> Result<(), String> {
    let mut engine = Engine::new(MockBackend::default());

    match scenario {
        DemoScenario::Accept {
            deadline,
            statement,
        } => {
            let id = engine
                .assert(MockEvidence::valid(statement), Deadline::from_raw(deadline))
                .map_err(|e| e.to_string())?;
            println!("asserted {id}");

            engine.backend_mut().set_now(Instant::new(deadline));
            let settlement = engine.finalize(id).map_err(|e| e.to_string())?;
            print_settlement(settlement.outcome);
        }
        DemoScenario::Reject {
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
            println!("asserted {id}");

            engine
                .challenge(id, ChallengerId::new(challenger))
                .map_err(|e| e.to_string())?;
            println!("challenged");

            let settlement = engine.finalize(id).map_err(|e| e.to_string())?;
            print_settlement(settlement.outcome);
        }
    }

    println!("\nevents:");
    for event in engine.backend().events() {
        print_event(event);
    }
    Ok(())
}

fn print_settlement(outcome: Outcome) {
    match outcome {
        Outcome::Accepted => println!("settled: Accepted (assertion wins)"),
        Outcome::Rejected => println!("settled: Rejected (challenger wins)"),
    }
}

fn print_event(event: &Event) {
    match event {
        Event::AssertionCreated {
            assertion_id,
            challenge_deadline,
        } => {
            println!("  AssertionCreated {assertion_id} deadline={challenge_deadline:?}");
        }
        Event::ChallengeOpened {
            assertion_id,
            challenge_id,
            challenger,
        } => {
            println!(
                "  ChallengeOpened assertion={assertion_id} challenge={challenge_id} by={challenger}"
            );
        }
        Event::ChallengeResolved {
            assertion_id,
            challenge_id,
            result,
        } => {
            println!(
                "  ChallengeResolved assertion={assertion_id} challenge={challenge_id} result={result:?}"
            );
        }
        Event::AssertionFinalized {
            assertion_id,
            outcome,
        } => {
            println!("  AssertionFinalized {assertion_id} outcome={outcome:?}");
        }
    }
}
