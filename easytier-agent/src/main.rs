use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use easytier_agent::{
    AgentRuntimeReport, CommandExecutionMode, DevicePolicy, PlatformBackend, SystemCommandExecutor,
    apply_command_plan, build_runtime_report, build_runtime_report_from_failure,
    derive_policy_status, dry_run_plan, platform::linux::LinuxBackend,
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
            let report = run_command_plan("localhost", &policy, commands, execute);
            println!("{}", serde_json::to_string(&report)?);
        }
        Command::Cleanup { policy, execute } => {
            let policy = read_policy(policy)?;
            let backend = LinuxBackend::default();
            let commands = backend.plan_cleanup(&policy)?;
            let report = run_command_plan("localhost", &policy, commands, execute);
            println!("{}", serde_json::to_string(&report)?);
        }
    }

    Ok(())
}

fn read_policy(path: PathBuf) -> anyhow::Result<DevicePolicy> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn run_command_plan(
    machine_id: impl Into<String>,
    policy: &DevicePolicy,
    commands: Vec<easytier_agent::CommandPlan>,
    execute: bool,
) -> AgentRuntimeReport {
    let mode = if execute {
        CommandExecutionMode::Execute
    } else {
        CommandExecutionMode::DryRun
    };
    let mut executor = SystemCommandExecutor;
    match apply_command_plan(commands, mode, &mut executor) {
        Ok(command_report) => {
            for command in &command_report.commands {
                println!("{} {}", command.program, command.args.join(" "));
            }
            if command_report.dry_run {
                println!("dry_run: true");
            } else {
                println!("executed_count: {}", command_report.executed_count);
            }
            let status = derive_policy_status(&command_report, None, false);
            build_runtime_report(machine_id, policy, status, &command_report, None)
        }
        Err(failure) => {
            for command in &failure.report.commands {
                println!("{} {}", command.program, command.args.join(" "));
            }
            println!("executed_count: {}", failure.report.executed_count);
            build_runtime_report_from_failure(machine_id, policy, &failure)
        }
    }
}
