use std::{
    fs,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand, ValueEnum};
use easytier_agent::{
    AgentApiAuth, AgentRuntimeReport, CommandExecutionMode, CommandPlan, ControlPlaneEndpoint,
    ControlPlaneGuard, DevicePolicy, PlatformBackend, PolicyReconciler, ReportTarget,
    SystemCommandExecutor, apply_command_plan, build_runtime_report,
    build_runtime_report_from_failure, derive_policy_status_for_policy, dry_run_plan,
    enroll_and_store_agent, fetch_device_policies, platform::linux::LinuxBackend,
    platform::openwrt::OpenWrtBackend, post_runtime_report, rotate_and_confirm_credential,
};

const DEFAULT_REAPPLY_INTERVAL: Duration = Duration::from_secs(60);

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
        #[arg(long, value_enum, default_value_t = PlatformKind::Linux)]
        platform: PlatformKind,
        #[arg(long, default_value = "localhost")]
        machine_id: String,
        #[arg(long)]
        easytier_ipv4: Option<String>,
        #[arg(long)]
        easytier_iface: Option<String>,
        #[arg(long)]
        web_base_url: Option<String>,
        #[arg(long)]
        user_id: Option<i32>,
        #[arg(long)]
        internal_auth_token: Option<String>,
        #[arg(long)]
        credential_file: Option<PathBuf>,
        #[arg(long)]
        execute: bool,
    },
    Cleanup {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, value_enum, default_value_t = PlatformKind::Linux)]
        platform: PlatformKind,
        #[arg(long, default_value = "localhost")]
        machine_id: String,
        #[arg(long)]
        easytier_ipv4: Option<String>,
        #[arg(long)]
        easytier_iface: Option<String>,
        #[arg(long)]
        web_base_url: Option<String>,
        #[arg(long)]
        user_id: Option<i32>,
        #[arg(long)]
        internal_auth_token: Option<String>,
        #[arg(long)]
        credential_file: Option<PathBuf>,
        #[arg(long)]
        execute: bool,
    },
    RunOnce {
        #[arg(long, value_enum, default_value_t = PlatformKind::Linux)]
        platform: PlatformKind,
        #[arg(long)]
        web_base_url: String,
        #[arg(long)]
        user_id: i32,
        #[arg(long)]
        machine_id: String,
        #[arg(long)]
        internal_auth_token: Option<String>,
        #[arg(long)]
        credential_file: Option<PathBuf>,
        #[arg(long)]
        bootstrap_token: Option<String>,
        #[arg(long)]
        easytier_ipv4: Option<String>,
        #[arg(long)]
        easytier_iface: Option<String>,
        #[arg(long)]
        execute: bool,
    },
    Run {
        #[arg(long, value_enum, default_value_t = PlatformKind::Linux)]
        platform: PlatformKind,
        #[arg(long)]
        web_base_url: String,
        #[arg(long)]
        user_id: i32,
        #[arg(long)]
        machine_id: String,
        #[arg(long)]
        internal_auth_token: Option<String>,
        #[arg(long)]
        credential_file: Option<PathBuf>,
        #[arg(long)]
        bootstrap_token: Option<String>,
        #[arg(long)]
        easytier_ipv4: Option<String>,
        #[arg(long)]
        easytier_iface: Option<String>,
        #[arg(long, default_value_t = 10)]
        interval_seconds: u64,
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PlatformKind {
    Linux,
    OpenWrt,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;

    use super::{Cli, Command, PlatformKind};

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
            easytier_iface,
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
        assert!(easytier_iface.is_none());
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
            None,
            "00000000-0000-0000-0000-000000000001".to_string(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("all web report flags"));
    }

    #[test]
    fn apply_accepts_openwrt_platform() {
        let cli = Cli::parse_from([
            "easytier-agent",
            "apply",
            "--policy",
            "/tmp/policy.json",
            "--platform",
            "open-wrt",
        ]);

        let Command::Apply { platform, .. } = cli.command else {
            panic!("expected apply command");
        };

        assert_eq!(platform, PlatformKind::OpenWrt);
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
            PlatformKind::Linux,
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

    #[test]
    fn openwrt_apply_plan_uses_fw4_backend() {
        let policy: easytier_agent::DevicePolicy = serde_json::from_str(&format!(
            r#"{{
              "policy_id": "p1",
              "device_policy_id": "p1/exit",
              "version": 1,
              "role": "provide_exit_for_gateway",
              "network_instance_id": "{}",
              "source_machine_id": "node-a",
              "managed_cidrs": ["192.168.10.0/24"],
              "exit_machine_id": "node-b",
              "source_peer_ipv4": "10.126.126.2",
              "protect_control_plane": true,
              "rollback_enabled": true
            }}"#,
            uuid::Uuid::nil()
        ))
        .unwrap();

        let commands =
            super::apply_commands_for_policy(&policy, None, PlatformKind::OpenWrt).unwrap();

        assert!(
            commands
                .iter()
                .any(|cmd| cmd.program == "fw4" && cmd.args == ["reload"])
        );
        assert!(!commands.iter().any(|cmd| cmd.program == "nft"));
    }

    #[test]
    fn run_once_requires_web_identity_flags() {
        let cli = Cli::parse_from([
            "easytier-agent",
            "run-once",
            "--web-base-url",
            "http://127.0.0.1:11211",
            "--user-id",
            "1",
            "--machine-id",
            "00000000-0000-0000-0000-000000000001",
            "--internal-auth-token",
            "secret",
            "--platform",
            "open-wrt",
        ]);

        let Command::RunOnce {
            platform,
            web_base_url,
            user_id,
            machine_id,
            internal_auth_token,
            ..
        } = cli.command
        else {
            panic!("expected run-once command");
        };

        assert_eq!(platform, PlatformKind::OpenWrt);
        assert_eq!(web_base_url, "http://127.0.0.1:11211");
        assert_eq!(user_id, 1);
        assert_eq!(
            machine_id,
            "00000000-0000-0000-0000-000000000001".to_string()
        );
        assert_eq!(internal_auth_token.as_deref(), Some("secret"));
    }

    #[test]
    fn run_accepts_interval_and_web_identity_flags() {
        let cli = Cli::parse_from([
            "easytier-agent",
            "run",
            "--web-base-url",
            "http://127.0.0.1:11211",
            "--user-id",
            "1",
            "--machine-id",
            "00000000-0000-0000-0000-000000000001",
            "--internal-auth-token",
            "secret",
            "--interval-seconds",
            "3",
            "--platform",
            "open-wrt",
        ]);

        let Command::Run {
            platform,
            interval_seconds,
            web_base_url,
            ..
        } = cli.command
        else {
            panic!("expected run command");
        };

        assert_eq!(platform, PlatformKind::OpenWrt);
        assert_eq!(interval_seconds, 3);
        assert_eq!(web_base_url, "http://127.0.0.1:11211");
    }

    #[test]
    fn report_target_prefers_credential_api_base_url() {
        let dir =
            std::env::temp_dir().join(format!("easytier-agent-main-{}", uuid::Uuid::new_v4()));
        let path = dir.join("credential.json");
        easytier_agent::write_credential_atomic(
            &path,
            &easytier_agent::MachineCredentialFile {
                machine_id: "00000000-0000-0000-0000-000000000001".to_string(),
                credential_version: 1,
                current_token: "machine-token".to_string(),
                next_token: None,
                next_token_status: None,
                api_base_url: Some("http://10.126.126.1:11212".to_string()),
                updated_at: "2026-05-20T10:00:00Z".to_string(),
            },
        )
        .unwrap();

        let target = super::report_target_from_flags(
            Some("http://137.220.194.19:11212".to_string()),
            Some(2),
            None,
            Some(path),
            "00000000-0000-0000-0000-000000000001".to_string(),
        )
        .unwrap()
        .unwrap();

        assert_eq!(target.web_base_url, "http://10.126.126.1:11212");
    }

    #[test]
    fn run_loop_continues_after_iteration_error() {
        let mut attempts = 0usize;
        let mut slept = 0usize;

        super::run_loop_with_iteration(
            Duration::from_secs(1),
            Some(3),
            || {
                attempts += 1;
                if attempts == 1 {
                    anyhow::bail!("web temporarily unreachable");
                }
                Ok(())
            },
            |_| {
                slept += 1;
            },
        )
        .unwrap();

        assert_eq!(attempts, 3);
        assert_eq!(slept, 2);
    }

    #[test]
    fn managed_loop_keeps_retrying_when_control_plane_identity_is_not_ready() {
        let mut attempts = 0usize;
        let mut slept = 0usize;

        super::run_loop_with_iteration(
            Duration::from_secs(1),
            Some(2),
            || {
                attempts += 1;
                if attempts == 1 {
                    anyhow::bail!("machine_not_connected");
                }
                Ok(())
            },
            |_| {
                slept += 1;
            },
        )
        .unwrap();

        assert_eq!(attempts, 2);
        assert_eq!(slept, 1);
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
            easytier_iface,
            web_base_url,
            user_id,
            internal_auth_token,
            credential_file,
            execute,
            platform,
        } => {
            let mut policy = read_policy(policy)?;
            apply_easytier_iface_override(&mut policy, easytier_iface);
            let commands = apply_commands_for_policy(&policy, web_base_url.clone(), platform)?;
            let report_target = report_target_from_flags(
                web_base_url,
                user_id,
                internal_auth_token,
                credential_file,
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
            easytier_iface,
            web_base_url,
            user_id,
            internal_auth_token,
            credential_file,
            execute,
            platform,
        } => {
            let mut policy = read_policy(policy)?;
            apply_easytier_iface_override(&mut policy, easytier_iface);
            let commands = cleanup_commands_for_policy(&policy, platform)?;
            let report_target = report_target_from_flags(
                web_base_url,
                user_id,
                internal_auth_token,
                credential_file,
                machine_id.clone(),
            )?;
            let report = run_command_plan(machine_id, easytier_ipv4, &policy, commands, execute);
            if let Some(target) = report_target {
                post_runtime_report(&target, &report)?;
            }
            println!("{}", serde_json::to_string(&report)?);
        }
        Command::RunOnce {
            platform,
            web_base_url,
            user_id,
            machine_id,
            internal_auth_token,
            credential_file,
            bootstrap_token,
            easytier_ipv4,
            easytier_iface,
            execute,
        } => {
            let target = report_target_from_flags(
                Some(web_base_url.clone()),
                Some(user_id),
                internal_auth_token,
                ensure_credential_file(
                    &web_base_url,
                    bootstrap_token,
                    credential_file,
                    user_id,
                    &machine_id,
                )?,
                machine_id.clone(),
            )?
            .ok_or_else(|| anyhow::anyhow!("web report target is required"))?;
            run_once(target, platform, easytier_ipv4, easytier_iface, execute)?;
        }
        Command::Run {
            platform,
            web_base_url,
            user_id,
            machine_id,
            internal_auth_token,
            credential_file,
            bootstrap_token,
            easytier_ipv4,
            easytier_iface,
            interval_seconds,
            execute,
        } => {
            run_managed_loop(
                web_base_url,
                user_id,
                machine_id,
                internal_auth_token,
                credential_file,
                bootstrap_token,
                platform,
                easytier_ipv4,
                easytier_iface,
                execute,
                Duration::from_secs(interval_seconds),
                None,
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_managed_loop(
    web_base_url: String,
    user_id: i32,
    machine_id: String,
    internal_auth_token: Option<String>,
    credential_file: Option<PathBuf>,
    bootstrap_token: Option<String>,
    platform: PlatformKind,
    easytier_ipv4: Option<String>,
    easytier_iface: Option<String>,
    execute: bool,
    interval: Duration,
    max_iterations: Option<usize>,
) -> anyhow::Result<()> {
    let mut reconciler = PolicyReconciler::default();
    run_loop_with_iteration(
        interval,
        max_iterations,
        || {
            let target = managed_report_target(
                &web_base_url,
                user_id,
                &machine_id,
                internal_auth_token.clone(),
                credential_file.clone(),
                bootstrap_token.clone(),
            )?;
            run_reconcile_iteration(
                &target,
                platform,
                easytier_ipv4.clone(),
                easytier_iface.clone(),
                execute,
                &mut reconciler,
            )
        },
        thread::sleep,
    )
}

fn managed_report_target(
    web_base_url: &str,
    user_id: i32,
    machine_id: &str,
    internal_auth_token: Option<String>,
    credential_file: Option<PathBuf>,
    bootstrap_token: Option<String>,
) -> anyhow::Result<ReportTarget> {
    report_target_from_flags(
        Some(web_base_url.to_string()),
        Some(user_id),
        internal_auth_token,
        ensure_credential_file(
            web_base_url,
            bootstrap_token,
            credential_file,
            user_id,
            machine_id,
        )?,
        machine_id.to_string(),
    )?
    .ok_or_else(|| anyhow::anyhow!("web report target is required"))
}

fn run_loop_with_iteration<I, S>(
    interval: Duration,
    max_iterations: Option<usize>,
    mut iteration: I,
    mut sleep: S,
) -> anyhow::Result<()>
where
    I: FnMut() -> anyhow::Result<()>,
    S: FnMut(Duration),
{
    let mut iterations = 0;
    loop {
        if let Err(error) = iteration() {
            eprintln!("reconcile iteration failed: {error:#}");
        }
        iterations += 1;
        if max_iterations.is_some_and(|max| iterations >= max) {
            return Ok(());
        }
        sleep(interval);
    }
}

fn run_reconcile_iteration(
    target: &ReportTarget,
    platform: PlatformKind,
    easytier_ipv4: Option<String>,
    easytier_iface: Option<String>,
    execute: bool,
    reconciler: &mut PolicyReconciler,
) -> anyhow::Result<()> {
    let policies = fetch_device_policies(target)?;
    let policies_to_apply = reconciler.policies_to_apply_at(
        &policies,
        Instant::now(),
        Some(DEFAULT_REAPPLY_INTERVAL),
    )?;
    for mut policy in policies_to_apply {
        apply_easytier_iface_override(&mut policy, easytier_iface.clone());
        println!(
            "reconcile: {:?}",
            easytier_agent::ReconcileEvent::Apply(policy.device_policy_id.clone(), policy.version)
        );
        let commands =
            apply_commands_for_policy(&policy, Some(target.web_base_url.clone()), platform)?;
        let report = run_command_plan(
            target.machine_id.clone(),
            easytier_ipv4.clone(),
            &policy,
            commands,
            execute,
        );
        post_runtime_report(target, &report)?;
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(())
}

fn run_once(
    target: ReportTarget,
    platform: PlatformKind,
    easytier_ipv4: Option<String>,
    easytier_iface: Option<String>,
    execute: bool,
) -> anyhow::Result<()> {
    let mut policies = fetch_device_policies(&target)?;
    for policy in &mut policies {
        apply_easytier_iface_override(policy, easytier_iface.clone());
    }
    let mut reconciler = PolicyReconciler::default();
    for event in reconciler.reconcile(&policies)? {
        println!("reconcile: {event:?}");
    }
    for policy in policies {
        let commands =
            apply_commands_for_policy(&policy, Some(target.web_base_url.clone()), platform)?;
        let report = run_command_plan(
            target.machine_id.clone(),
            easytier_ipv4.clone(),
            &policy,
            commands,
            execute,
        );
        post_runtime_report(&target, &report)?;
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(())
}

fn read_policy(path: PathBuf) -> anyhow::Result<DevicePolicy> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn apply_easytier_iface_override(policy: &mut DevicePolicy, easytier_iface: Option<String>) {
    if let Some(easytier_iface) = easytier_iface {
        if !easytier_iface.trim().is_empty() {
            policy.easytier_iface = easytier_iface;
        }
    }
}

fn ensure_credential_file(
    web_base_url: &str,
    bootstrap_token: Option<String>,
    credential_file: Option<PathBuf>,
    user_id: i32,
    machine_id: &str,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(credential_file) = credential_file else {
        return Ok(None);
    };
    if credential_file.exists() {
        let runtime_base_url = credential_runtime_base_url(&credential_file, web_base_url)?;
        rotate_and_confirm_credential(&runtime_base_url, user_id, &credential_file)?;
        return Ok(Some(credential_file));
    }
    let Some(bootstrap_token) = bootstrap_token else {
        return Ok(Some(credential_file));
    };

    enroll_and_store_agent(
        web_base_url,
        &bootstrap_token,
        user_id,
        machine_id,
        &credential_file,
    )?;
    let runtime_base_url = credential_runtime_base_url(&credential_file, web_base_url)?;
    rotate_and_confirm_credential(&runtime_base_url, user_id, &credential_file)?;
    Ok(Some(credential_file))
}

fn credential_runtime_base_url(
    credential_file: &PathBuf,
    fallback_web_base_url: &str,
) -> anyhow::Result<String> {
    let credential = easytier_agent::read_credential(credential_file)?;
    Ok(credential
        .api_base_url
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback_web_base_url.to_string()))
}

fn report_target_from_flags(
    web_base_url: Option<String>,
    user_id: Option<i32>,
    internal_auth_token: Option<String>,
    credential_file: Option<PathBuf>,
    machine_id: String,
) -> anyhow::Result<Option<ReportTarget>> {
    let has_any = web_base_url.is_some()
        || user_id.is_some()
        || internal_auth_token.is_some()
        || credential_file.is_some();
    if !has_any {
        return Ok(None);
    }

    let (Some(web_base_url), Some(user_id)) = (web_base_url, user_id) else {
        anyhow::bail!(
            "all web report flags are required together: --web-base-url, --user-id, and either --credential-file or --internal-auth-token"
        );
    };

    let mut runtime_web_base_url = web_base_url;
    let auth = match (credential_file, internal_auth_token) {
        (Some(credential_file), _) => {
            let credential = easytier_agent::read_credential(credential_file)?;
            if credential.machine_id != machine_id {
                anyhow::bail!("credential file machine_id does not match --machine-id");
            }
            runtime_web_base_url = credential
                .api_base_url
                .as_ref()
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .unwrap_or(runtime_web_base_url);
            AgentApiAuth::MachineToken {
                token: credential.current_token,
                credential_version: credential.credential_version,
            }
        }
        (None, Some(internal_auth_token)) => AgentApiAuth::LegacyInternalToken(internal_auth_token),
        (None, None) => anyhow::bail!(
            "all web report flags are required together: --web-base-url, --user-id, and either --credential-file or --internal-auth-token"
        ),
    };

    Ok(Some(ReportTarget {
        web_base_url: runtime_web_base_url,
        user_id,
        machine_id,
        auth,
    }))
}

fn apply_commands_for_policy(
    policy: &DevicePolicy,
    web_base_url: Option<String>,
    platform: PlatformKind,
) -> anyhow::Result<Vec<CommandPlan>> {
    let mut commands = control_plane_commands(policy, web_base_url, platform)?;
    commands.extend(plan_apply_for_platform(policy, platform)?);
    Ok(commands)
}

fn control_plane_commands(
    policy: &DevicePolicy,
    web_base_url: Option<String>,
    platform: PlatformKind,
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
    Ok(
        ControlPlaneGuard::new(vec![ControlPlaneEndpoint::new("web", host)])
            .protected_route_plan_for_table(Some(platform.table_id())),
    )
}

fn plan_apply_for_platform(
    policy: &DevicePolicy,
    platform: PlatformKind,
) -> anyhow::Result<Vec<CommandPlan>> {
    match platform {
        PlatformKind::Linux => LinuxBackend::default().plan_apply(policy),
        PlatformKind::OpenWrt => OpenWrtBackend::default().plan_apply(policy),
    }
}

fn cleanup_commands_for_policy(
    policy: &DevicePolicy,
    platform: PlatformKind,
) -> anyhow::Result<Vec<CommandPlan>> {
    match platform {
        PlatformKind::Linux => LinuxBackend::default().plan_cleanup(policy),
        PlatformKind::OpenWrt => OpenWrtBackend::default().plan_cleanup(policy),
    }
}

impl PlatformKind {
    fn table_id(self) -> u32 {
        match self {
            PlatformKind::Linux => LinuxBackend::default().table_id(),
            PlatformKind::OpenWrt => 126,
        }
    }
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
