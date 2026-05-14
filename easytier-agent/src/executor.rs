use std::process::Command;

use crate::platform::CommandPlan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandExecutionMode {
    DryRun,
    Execute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExecutionReport {
    pub dry_run: bool,
    pub commands: Vec<CommandPlan>,
    pub executed_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExecutionFailure {
    pub report: CommandExecutionReport,
    pub error: String,
}

impl std::fmt::Display for CommandExecutionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for CommandExecutionFailure {}

pub trait CommandExecutor {
    fn execute(&mut self, command: &CommandPlan) -> anyhow::Result<()>;
}

#[derive(Debug, Default)]
pub struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn execute(&mut self, command: &CommandPlan) -> anyhow::Result<()> {
        let status = Command::new(&command.program)
            .args(&command.args)
            .status()?;
        if !status.success() {
            anyhow::bail!(
                "command failed with status {status}: {} {}",
                command.program,
                command.args.join(" ")
            );
        }
        Ok(())
    }
}

pub fn apply_command_plan<E>(
    commands: Vec<CommandPlan>,
    mode: CommandExecutionMode,
    executor: &mut E,
) -> Result<CommandExecutionReport, CommandExecutionFailure>
where
    E: CommandExecutor,
{
    if mode == CommandExecutionMode::DryRun {
        return Ok(CommandExecutionReport {
            dry_run: true,
            commands,
            executed_count: 0,
        });
    }

    let mut executed_count = 0;
    for command in &commands {
        if let Err(error) = executor.execute(command) {
            return Err(CommandExecutionFailure {
                report: CommandExecutionReport {
                    dry_run: false,
                    commands,
                    executed_count,
                },
                error: error.to_string(),
            });
        }
        executed_count += 1;
    }

    Ok(CommandExecutionReport {
        dry_run: false,
        commands,
        executed_count,
    })
}

#[cfg(test)]
mod tests {
    use anyhow::bail;

    use super::*;

    #[derive(Default)]
    struct RecordingExecutor {
        commands: Vec<CommandPlan>,
        fail_after: Option<usize>,
    }

    impl CommandExecutor for RecordingExecutor {
        fn execute(&mut self, command: &CommandPlan) -> anyhow::Result<()> {
            if self.fail_after == Some(self.commands.len()) {
                bail!("synthetic command failure");
            }
            self.commands.push(command.clone());
            Ok(())
        }
    }

    #[test]
    fn dry_run_returns_commands_without_executing_them() {
        let commands = vec![CommandPlan::new("ip", ["route", "show", "default"])];
        let mut executor = RecordingExecutor::default();

        let report = apply_command_plan(
            commands.clone(),
            CommandExecutionMode::DryRun,
            &mut executor,
        )
        .unwrap();

        assert!(report.dry_run);
        assert_eq!(report.commands, commands);
        assert_eq!(report.executed_count, 0);
        assert!(executor.commands.is_empty());
    }

    #[test]
    fn execute_mode_runs_commands_in_order() {
        let commands = vec![
            CommandPlan::new("ip", ["route", "show", "default"]),
            CommandPlan::new("sysctl", ["-w", "net.ipv4.ip_forward=1"]),
        ];
        let mut executor = RecordingExecutor::default();

        let report = apply_command_plan(
            commands.clone(),
            CommandExecutionMode::Execute,
            &mut executor,
        )
        .unwrap();

        assert!(!report.dry_run);
        assert_eq!(report.executed_count, 2);
        assert_eq!(executor.commands, commands);
    }

    #[test]
    fn execute_mode_stops_on_first_command_failure() {
        let commands = vec![
            CommandPlan::new("ip", ["route", "show", "default"]),
            CommandPlan::new("sysctl", ["-w", "net.ipv4.ip_forward=1"]),
        ];
        let mut executor = RecordingExecutor {
            fail_after: Some(1),
            ..RecordingExecutor::default()
        };

        let err =
            apply_command_plan(commands, CommandExecutionMode::Execute, &mut executor).unwrap_err();

        assert!(err.to_string().contains("synthetic command failure"));
        assert_eq!(executor.commands.len(), 1);
        assert_eq!(err.report.executed_count, 1);
    }
}
