use serde::{Deserialize, Serialize};

use crate::{
    CommandExecutionReport, DevicePolicy, DevicePolicyRole, PolicyStatus,
    executor::CommandExecutionFailure,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRuntimeReport {
    pub machine_id: String,
    pub agent_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub easytier_ipv4: Option<String>,
    pub policy_id: String,
    pub device_policy_id: String,
    pub version: u64,
    pub role: String,
    pub status: PolicyStatus,
    pub observed_policy_id: String,
    pub observed_policy_version: u64,
    pub observed_policy_status: PolicyStatus,
    pub dry_run: bool,
    pub executed_count: usize,
    pub last_error: Option<String>,
}

pub fn build_runtime_report(
    machine_id: impl Into<String>,
    policy: &DevicePolicy,
    status: PolicyStatus,
    command_report: &CommandExecutionReport,
    last_error: Option<String>,
) -> AgentRuntimeReport {
    AgentRuntimeReport {
        machine_id: machine_id.into(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        easytier_ipv4: None,
        policy_id: policy.policy_id.clone(),
        device_policy_id: policy.device_policy_id.clone(),
        version: policy.version,
        role: policy.role.to_string(),
        status,
        observed_policy_id: policy.policy_id.clone(),
        observed_policy_version: policy.version,
        observed_policy_status: status,
        dry_run: command_report.dry_run,
        executed_count: command_report.executed_count,
        last_error,
    }
}

pub fn build_runtime_report_from_failure(
    machine_id: impl Into<String>,
    policy: &DevicePolicy,
    failure: &CommandExecutionFailure,
) -> AgentRuntimeReport {
    build_runtime_report(
        machine_id,
        policy,
        derive_policy_status(&failure.report, Some(&failure.error), false),
        &failure.report,
        Some(failure.error.clone()),
    )
}

pub fn derive_policy_status(
    command_report: &CommandExecutionReport,
    last_error: Option<&str>,
    rollbacked: bool,
) -> PolicyStatus {
    if rollbacked {
        return PolicyStatus::Rollbacked;
    }
    if last_error.is_some() {
        return PolicyStatus::Degraded;
    }
    if command_report.dry_run {
        return PolicyStatus::Planned;
    }
    if command_report.executed_count > 0 {
        return PolicyStatus::Active;
    }
    PolicyStatus::Prepared
}

pub fn derive_policy_status_for_policy(
    policy: &DevicePolicy,
    command_report: &CommandExecutionReport,
    last_error: Option<&str>,
    rollbacked: bool,
) -> PolicyStatus {
    let status = derive_policy_status(command_report, last_error, rollbacked);
    if status == PolicyStatus::Active && policy.role == DevicePolicyRole::ProvideExitForGateway {
        return PolicyStatus::Prepared;
    }
    status
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::{
        CommandExecutionMode, CommandPlan, DevicePolicyRole, ExitEgress, apply_command_plan,
    };

    struct NoopExecutor;

    impl crate::CommandExecutor for NoopExecutor {
        fn execute(&mut self, _command: &CommandPlan) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn policy() -> DevicePolicy {
        DevicePolicy {
            policy_id: "p1".to_string(),
            device_policy_id: "p1/source".to_string(),
            version: 2,
            role: DevicePolicyRole::ClientGatewayViaPeer,
            network_instance_id: Uuid::nil(),
            source_machine_id: "node-a".to_string(),
            managed_cidrs: vec!["192.168.10.0/24".to_string()],
            ingress_ifaces: vec!["br-lan".to_string()],
            include_device_traffic: true,
            exit_machine_id: "node-b".to_string(),
            exit_peer_ipv4: Some("10.126.126.3".to_string()),
            source_peer_ipv4: None,
            easytier_iface: "easytier0".to_string(),
            exit_egress: ExitEgress::default(),
            protect_control_plane: true,
            rollback_enabled: true,
        }
    }

    #[test]
    fn builds_runtime_report_from_command_result() {
        let policy = policy();
        let commands = vec![CommandPlan::new("ip", ["route", "show", "default"])];
        let mut executor = NoopExecutor;
        let command_report =
            apply_command_plan(commands, CommandExecutionMode::DryRun, &mut executor).unwrap();

        let report = build_runtime_report(
            "node-a",
            &policy,
            PolicyStatus::Active,
            &command_report,
            None,
        );

        assert_eq!(report.machine_id, "node-a");
        assert_eq!(report.policy_id, "p1");
        assert_eq!(report.device_policy_id, "p1/source");
        assert_eq!(report.version, 2);
        assert_eq!(report.role, "client_gateway_via_peer");
        assert!(report.dry_run);
        assert_eq!(report.executed_count, 0);
        assert_eq!(report.status, PolicyStatus::Active);
    }

    #[test]
    fn serializes_web_observed_state_fields() {
        let policy = policy();
        let commands = vec![CommandPlan::new("ip", ["route", "show", "default"])];
        let mut executor = NoopExecutor;
        let command_report =
            apply_command_plan(commands, CommandExecutionMode::Execute, &mut executor).unwrap();

        let report = build_runtime_report(
            "00000000-0000-0000-0000-000000000001",
            &policy,
            PolicyStatus::Active,
            &command_report,
            None,
        );
        let json = serde_json::to_value(report).unwrap();

        assert_eq!(json["observed_policy_id"], "p1");
        assert_eq!(json["observed_policy_version"], 2);
        assert_eq!(json["observed_policy_status"], "active");
    }

    #[test]
    fn derives_planned_for_dry_run() {
        let commands = vec![CommandPlan::new("ip", ["route", "show", "default"])];
        let mut executor = NoopExecutor;
        let command_report =
            apply_command_plan(commands, CommandExecutionMode::DryRun, &mut executor).unwrap();

        assert_eq!(
            derive_policy_status(&command_report, None, false),
            PolicyStatus::Planned
        );
    }

    #[test]
    fn derives_active_for_executed_commands() {
        let commands = vec![CommandPlan::new("ip", ["route", "show", "default"])];
        let mut executor = NoopExecutor;
        let command_report =
            apply_command_plan(commands, CommandExecutionMode::Execute, &mut executor).unwrap();

        assert_eq!(
            derive_policy_status(&command_report, None, false),
            PolicyStatus::Active
        );
    }

    #[test]
    fn derives_prepared_for_successful_exit_provider() {
        let mut policy = policy();
        policy.role = DevicePolicyRole::ProvideExitForGateway;
        policy.source_peer_ipv4 = Some("10.126.126.2".to_string());
        policy.exit_peer_ipv4 = None;
        let commands = vec![CommandPlan::new("sysctl", ["-w", "net.ipv4.ip_forward=1"])];
        let mut executor = NoopExecutor;
        let command_report =
            apply_command_plan(commands, CommandExecutionMode::Execute, &mut executor).unwrap();

        assert_eq!(
            derive_policy_status_for_policy(&policy, &command_report, None, false),
            PolicyStatus::Prepared
        );
    }

    #[test]
    fn derives_degraded_when_last_error_exists() {
        let commands = vec![CommandPlan::new("ip", ["route", "show", "default"])];
        let mut executor = NoopExecutor;
        let command_report =
            apply_command_plan(commands, CommandExecutionMode::DryRun, &mut executor).unwrap();

        assert_eq!(
            derive_policy_status(&command_report, Some("control plane failed"), false),
            PolicyStatus::Degraded
        );
    }

    #[test]
    fn derives_rollbacked_when_rollback_flag_is_set() {
        let commands = vec![CommandPlan::new("ip", ["route", "show", "default"])];
        let mut executor = NoopExecutor;
        let command_report =
            apply_command_plan(commands, CommandExecutionMode::DryRun, &mut executor).unwrap();

        assert_eq!(
            derive_policy_status(&command_report, None, true),
            PolicyStatus::Rollbacked
        );
    }

    #[test]
    fn builds_runtime_report_from_failure() {
        let policy = policy();
        let failure = CommandExecutionFailure {
            report: CommandExecutionReport {
                dry_run: false,
                commands: vec![CommandPlan::new("ip", ["route", "show", "default"])],
                executed_count: 1,
            },
            error: "synthetic command failure".to_string(),
        };

        let report = build_runtime_report_from_failure("node-a", &policy, &failure);

        assert_eq!(report.status, PolicyStatus::Degraded);
        assert_eq!(report.executed_count, 1);
        assert_eq!(
            report.last_error.as_deref(),
            Some("synthetic command failure")
        );
    }
}
