//! Beacon developer CLI — drive mock, bitcoin-sim, and Groth16 demos.

mod demo;
mod print;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::demo::DemoCommand;

#[derive(Debug, Parser)]
#[command(name = "beacon")]
#[command(
    about = "Beacon assertion engine developer CLI",
    long_about = "Drive assertion lifecycles against mock or simulated Bitcoin backends,\noptionally with Groth16 toy evidence."
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print version information.
    Version,
    /// Run a lifecycle demonstration.
    Demo {
        #[command(subcommand)]
        command: DemoCommand,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Version => {
            println!("beacon {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Commands::Demo { command } => {
            if let Err(err) = demo::run(command) {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}
