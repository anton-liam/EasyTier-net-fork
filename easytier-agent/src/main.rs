use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use easytier_agent::{DevicePolicy, dry_run_plan};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Plan {
        #[arg(long)]
        policy: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Plan { policy } => {
            let raw = fs::read_to_string(policy)?;
            let policy: DevicePolicy = serde_json::from_str(&raw)?;
            for action in dry_run_plan(&policy)? {
                println!("{}: {}", action.kind, action.description);
            }
        }
    }

    Ok(())
}

