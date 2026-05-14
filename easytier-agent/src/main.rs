use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use easytier_agent::{
    CommandExecutionMode, DevicePolicy, PlatformBackend, SystemCommandExecutor, apply_command_plan,
    dry_run_plan, platform::linux::LinuxBackend,
};

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
    Apply {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        execute: bool,
    },
    Cleanup {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        execute: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Plan { policy } => {
            let policy = read_policy(policy)?;
            for action in dry_run_plan(&policy)? {
                println!("{}: {}", action.kind, action.description);
            }
        }
        Command::Apply { policy, execute } => {
            let policy = read_policy(policy)?;
            let backend = LinuxBackend::default();
            let commands = backend.plan_apply(&policy)?;
            run_command_plan(commands, execute)?;
        }
        Command::Cleanup { policy, execute } => {
            let policy = read_policy(policy)?;
            let backend = LinuxBackend::default();
            let commands = backend.plan_cleanup(&policy)?;
            run_command_plan(commands, execute)?;
        }
    }

    Ok(())
}

fn read_policy(path: PathBuf) -> anyhow::Result<DevicePolicy> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn run_command_plan(
    commands: Vec<easytier_agent::CommandPlan>,
    execute: bool,
) -> anyhow::Result<()> {
    let mode = if execute {
        CommandExecutionMode::Execute
    } else {
        CommandExecutionMode::DryRun
    };
    let mut executor = SystemCommandExecutor;
    let report = apply_command_plan(commands, mode, &mut executor)?;

    for command in &report.commands {
        println!("{} {}", command.program, command.args.join(" "));
    }
    if report.dry_run {
        println!("dry_run: true");
    } else {
        println!("executed_count: {}", report.executed_count);
    }
    Ok(())
}
