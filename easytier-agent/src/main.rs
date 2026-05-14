use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use easytier_agent::{
    AgentRuntimeReport, CommandExecutionMode, CommandPlan, ControlPlaneEndpoint, ControlPlaneGuard,
    DevicePolicy, PlatformBackend, ReportTarget, SystemCommandExecutor, apply_command_plan,
    build_runtime_report, build_runtime_report_from_failure, derive_policy_status_for_policy,
    dry_run_plan, platform::linux::LinuxBackend, post_runtime_report,
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
        #[arg(long, default_value = "localhost")]
        machine_id: String,
        #[arg(long)]
        easytier_ipv4: Option<String>,
        #[arg(long)]
        web_base_url: Option<String>,
        #[arg(long)]
        user_id: Option<i32>,
        #[arg(long)]
        internal_auth_token: Option<String>,
        #[arg(long)]
        execute: bool,
    },
    Cleanup {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, default_value = "localhost")]
        machine_id: String,
        #[arg(long)]
        easytier_ipv4: Option<String>,
        #[arg(long)]
        web_base_url: Option<String>,
        #[arg(long)]
        user_id: Option<i32>,
        #[arg(long)]
        internal_auth_token: Option<String>,
        #[arg(long)]
        execute: bool,
    },
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command};

    #[test]
    fn apply_accepts_machine_identity_for_web_report() {
        let cli = Cli::parse_from([
            "easytier-agent",
            "apply",
            "--policy",
            "/tmp/policy.json",
            "--machine-id",
            "00000000-0000-0000-0000-000000000001",
            "--easytier-ipv4",
            "10.126.126.2",
        ]);

        let Command::Apply {
            machine_id,
            easytier_ipv4,
            web_base_url,
            user_id,
            internal_auth_token,
            ..
        } = cli.command
        else {
            panic!("expected apply command");
        };

        assert_eq!(machine_id, "00000000-0000-0000-0000-000000000001");
        assert_eq!(easytier_ipv4.as_deref(), Some("10.126.126.2"));
        assert!(web_base_url.is_none());
        assert!(user_id.is_none());
        assert!(internal_auth_token.is_none());
    }

    #[test]
    fn report_target_requires_all_web_report_flags() {
        let err = super::report_target_from_flags(
            Some("http://127.0.0.1:11211".to_string()),
            None,
            Some("secret".to_string()),
            "00000000-0000-0000-0000-000000000001".to_string(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("all web report flags"));
    }

    #[test]
    fn apply_plan_protects_web_control_plane_before_gateway_rules() {
        let policy: easytier_agent::DevicePolicy = serde_json::from_str(&format!(
            r#"{{
              "policy_id": "p1",
              "device_policy_id": "p1/source",
              "version": 1,
              "role": "client_gateway_via_peer",
              "network_instance_id": "{}",
              "source_machine_id": "node-a",
              "managed_cidrs": ["192.168.10.0/24"],
              "ingress_ifaces": ["br-lan"],
              "include_device_traffic": true,
              "exit_machine_id": "node-b",
              "exit_peer_ipv4": "10.126.126.3",
              "protect_control_plane": true,
              "rollback_enabled": true
            }}"#,
            uuid::Uuid::nil()
        ))
        .unwrap();

        let commands = super::apply_commands_for_policy(
            &policy,
            Some("http://192.168.64.4:11211".to_string()),
        )
        .unwrap();

        assert_eq!(commands[0].program, "sh");
        assert!(commands[0].args.join(" ").contains("host='192.168.64.4'"));
        assert!(
            commands[0]
                .args
                .join(" ")
                .contains("ip route get \"$host\"")
        );
        assert!(
            commands[0]
                .args
                .join(" ")
                .contains("ip route replace \"$host/32\"")
        );
        assert!(commands.iter().skip(1).any(|command| {
            command.program == "ip"
                && command
                    .args
                    .starts_with(&["route".to_string(), "replace".to_string()])
        }));
    }
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
        Command::Apply {
            policy,
            machine_id,
            easytier_ipv4,
            web_base_url,
            user_id,
            internal_auth_token,
            execute,
        } => {
            let policy = read_policy(policy)?;
            let commands = apply_commands_for_policy(&policy, web_base_url.clone())?;
            let report_target = report_target_from_flags(
                web_base_url,
                user_id,
                internal_auth_token,
                machine_id.clone(),
            )?;
            let report = run_command_plan(machine_id, easytier_ipv4, &policy, commands, execute);
            if let Some(target) = report_target {
                post_runtime_report(&target, &report)?;
            }
            println!("{}", serde_json::to_string(&report)?);
        }
        Command::Cleanup {
            policy,
            machine_id,
            easytier_ipv4,
            web_base_url,
            user_id,
            internal_auth_token,
            execute,
        } => {
            let policy = read_policy(policy)?;
            let backend = LinuxBackend::default();
            let commands = backend.plan_cleanup(&policy)?;
            let report_target = report_target_from_flags(
                web_base_url,
                user_id,
                internal_auth_token,
                machine_id.clone(),
            )?;
            let report = run_command_plan(machine_id, easytier_ipv4, &policy, commands, execute);
            if let Some(target) = report_target {
                post_runtime_report(&target, &report)?;
            }
            println!("{}", serde_json::to_string(&report)?);
        }
    }

    Ok(())
}

fn read_policy(path: PathBuf) -> anyhow::Result<DevicePolicy> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn report_target_from_flags(
    web_base_url: Option<String>,
    user_id: Option<i32>,
    internal_auth_token: Option<String>,
    machine_id: String,
) -> anyhow::Result<Option<ReportTarget>> {
    match (web_base_url, user_id, internal_auth_token) {
        (None, None, None) => Ok(None),
        (Some(web_base_url), Some(user_id), Some(internal_auth_token)) => Ok(Some(ReportTarget {
            web_base_url,
            user_id,
            machine_id,
            internal_auth_token,
        })),
        _ => anyhow::bail!(
            "all web report flags are required together: --web-base-url, --user-id, --internal-auth-token"
        ),
    }
}

fn apply_commands_for_policy(
    policy: &DevicePolicy,
    web_base_url: Option<String>,
) -> anyhow::Result<Vec<CommandPlan>> {
    let backend = LinuxBackend::default();
    let mut commands = control_plane_commands(policy, web_base_url)?;
    commands.extend(backend.plan_apply(policy)?);
    Ok(commands)
}

fn control_plane_commands(
    policy: &DevicePolicy,
    web_base_url: Option<String>,
) -> anyhow::Result<Vec<CommandPlan>> {
    if !policy.protect_control_plane {
        return Ok(Vec::new());
    }
    let Some(web_base_url) = web_base_url else {
        return Ok(Vec::new());
    };
    let Some(host) = host_from_url_like(&web_base_url) else {
        anyhow::bail!("invalid --web-base-url: missing host");
    };
    let backend = LinuxBackend::default();
    Ok(
        ControlPlaneGuard::new(vec![ControlPlaneEndpoint::new("web", host)])
            .protected_route_plan_for_table(Some(backend.table_id())),
    )
}

fn host_from_url_like(value: &str) -> Option<String> {
    let without_scheme = value.split_once("://").map_or(value, |(_, rest)| rest);
    let authority = without_scheme.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
        .split(':')
        .next()?
        .trim();
    (!host.is_empty()).then(|| host.to_string())
}

fn run_command_plan(
    machine_id: impl Into<String>,
    easytier_ipv4: Option<String>,
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
            let status = derive_policy_status_for_policy(policy, &command_report, None, false);
            let mut report =
                build_runtime_report(machine_id, policy, status, &command_report, None);
            report.easytier_ipv4 = easytier_ipv4;
            report
        }
        Err(failure) => {
            for command in &failure.report.commands {
                println!("{} {}", command.program, command.args.join(" "));
            }
            println!("executed_count: {}", failure.report.executed_count);
            let mut report = build_runtime_report_from_failure(machine_id, policy, &failure);
            report.easytier_ipv4 = easytier_ipv4;
            report
        }
    }
}
