use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use easytier::launcher::NetworkConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayFullTunnelPolicy {
    pub policy_id: Uuid,
    pub enabled: bool,
    pub network_instance_id: Uuid,
    pub source_machine_id: Uuid,
    pub managed_cidrs: Vec<String>,
    #[serde(default)]
    pub ingress_ifaces: Vec<String>,
    #[serde(default)]
    pub include_device_traffic: bool,
    pub exit_machine_id: Uuid,
    #[serde(default)]
    pub exit_egress: ExitEgress,
    pub desired_version: u64,
    #[serde(default = "default_true")]
    pub protect_control_plane: bool,
    #[serde(default)]
    pub healthcheck: HealthcheckConfig,
    #[serde(default)]
    pub rollback: RollbackConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevicePolicy {
    pub policy_id: Uuid,
    pub device_policy_id: String,
    pub version: u64,
    pub role: DevicePolicyRole,
    pub machine_id: Uuid,
    pub network_instance_id: Uuid,
    pub source_machine_id: Uuid,
    pub managed_cidrs: Vec<String>,
    #[serde(default)]
    pub ingress_ifaces: Vec<String>,
    #[serde(default)]
    pub include_device_traffic: bool,
    pub exit_machine_id: Uuid,
    #[serde(default)]
    pub exit_peer_ipv4: Option<String>,
    #[serde(default)]
    pub source_peer_ipv4: Option<String>,
    #[serde(default = "default_easytier_iface")]
    pub easytier_iface: String,
    #[serde(default)]
    pub exit_egress: ExitEgress,
    #[serde(default = "default_true")]
    pub protect_control_plane: bool,
    #[serde(default = "default_true")]
    pub rollback_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeReport {
    pub machine_id: Uuid,
    pub agent_version: String,
    #[serde(default)]
    pub easytier_ipv4: Option<String>,
    #[serde(default)]
    pub last_report_at: Option<String>,
    #[serde(default)]
    pub policy_id: Option<Uuid>,
    #[serde(default)]
    pub device_policy_id: Option<String>,
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub role: Option<DevicePolicyRole>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub observed_policy_id: Option<Uuid>,
    #[serde(default)]
    pub observed_policy_version: Option<u64>,
    #[serde(default)]
    pub observed_policy_status: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayPolicySnapshot {
    pub desired: GatewayFullTunnelPolicy,
    pub observed: GatewayPolicyObservedState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayPolicyObservedState {
    #[serde(default)]
    pub source: Option<GatewayPolicyObservedNode>,
    #[serde(default)]
    pub exit: Option<GatewayPolicyObservedNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayPolicyObservedNode {
    pub machine_id: Uuid,
    pub agent_version: String,
    #[serde(default)]
    pub easytier_ipv4: Option<String>,
    #[serde(default)]
    pub last_report_at: Option<String>,
    #[serde(default)]
    pub policy_id: Option<Uuid>,
    #[serde(default)]
    pub version: Option<u64>,
    pub status: String,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayPolicyNode {
    pub machine_id: Uuid,
    pub agent_version: String,
    #[serde(default)]
    pub easytier_ipv4: Option<String>,
    #[serde(default)]
    pub last_report_at: Option<String>,
    pub status: String,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Default)]
pub struct PolicyStore {
    policies: HashMap<(i32, Uuid), GatewayFullTunnelPolicy>,
    reports: HashMap<(i32, Uuid), RuntimeReport>,
    policy_reports: HashMap<(i32, Uuid, DevicePolicyRole, Uuid), RuntimeReport>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DevicePolicyRole {
    ClientGatewayViaPeer,
    ProvideExitForGateway,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitEgress {
    pub mode: ExitEgressMode,
    #[serde(default)]
    pub iface: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitEgressMode {
    Auto,
    Interface,
}

impl Default for ExitEgress {
    fn default() -> Self {
        Self {
            mode: ExitEgressMode::Auto,
            iface: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthcheckConfig {
    pub control_plane_timeout_seconds: u64,
    pub exit_timeout_seconds: u64,
}

impl Default for HealthcheckConfig {
    fn default() -> Self {
        Self {
            control_plane_timeout_seconds: 5,
            exit_timeout_seconds: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackConfig {
    pub enabled: bool,
    pub max_fail_seconds: u64,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_fail_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("source and exit machine must be different")]
    SourceEqualsExit,
    #[error("policy does not define any managed traffic")]
    NoManagedTraffic,
    #[error("source already has an enabled gateway full tunnel policy")]
    SourceAlreadyHasEnabledPolicy,
    #[error("missing peer ipv4")]
    MissingPeerIpv4,
    #[error("machine report is not ready")]
    MachineReportNotReady,
}

impl GatewayFullTunnelPolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.source_machine_id == self.exit_machine_id {
            return Err(PolicyError::SourceEqualsExit);
        }
        if self.managed_cidrs.is_empty() && !self.include_device_traffic {
            return Err(PolicyError::NoManagedTraffic);
        }
        Ok(())
    }

    pub fn source_device_policy(
        &self,
        exit_peer_ipv4: String,
    ) -> Result<DevicePolicy, PolicyError> {
        if exit_peer_ipv4.trim().is_empty() {
            return Err(PolicyError::MissingPeerIpv4);
        }
        Ok(DevicePolicy {
            policy_id: self.policy_id,
            device_policy_id: format!("{}/source", self.policy_id),
            version: self.desired_version,
            role: DevicePolicyRole::ClientGatewayViaPeer,
            machine_id: self.source_machine_id,
            network_instance_id: self.network_instance_id,
            source_machine_id: self.source_machine_id,
            managed_cidrs: self.managed_cidrs.clone(),
            ingress_ifaces: self.ingress_ifaces.clone(),
            include_device_traffic: self.include_device_traffic,
            exit_machine_id: self.exit_machine_id,
            exit_peer_ipv4: Some(exit_peer_ipv4),
            source_peer_ipv4: None,
            easytier_iface: default_easytier_iface(),
            exit_egress: self.exit_egress.clone(),
            protect_control_plane: self.protect_control_plane,
            rollback_enabled: self.rollback.enabled,
        })
    }

    pub fn exit_device_policy(
        &self,
        source_peer_ipv4: String,
    ) -> Result<DevicePolicy, PolicyError> {
        if source_peer_ipv4.trim().is_empty() {
            return Err(PolicyError::MissingPeerIpv4);
        }
        Ok(DevicePolicy {
            policy_id: self.policy_id,
            device_policy_id: format!("{}/exit", self.policy_id),
            version: self.desired_version,
            role: DevicePolicyRole::ProvideExitForGateway,
            machine_id: self.exit_machine_id,
            network_instance_id: self.network_instance_id,
            source_machine_id: self.source_machine_id,
            managed_cidrs: self.managed_cidrs.clone(),
            ingress_ifaces: Vec::new(),
            include_device_traffic: self.include_device_traffic,
            exit_machine_id: self.exit_machine_id,
            exit_peer_ipv4: None,
            source_peer_ipv4: Some(source_peer_ipv4),
            easytier_iface: default_easytier_iface(),
            exit_egress: self.exit_egress.clone(),
            protect_control_plane: self.protect_control_plane,
            rollback_enabled: self.rollback.enabled,
        })
    }
}

pub fn validate_policy_conflicts(
    existing: &[GatewayFullTunnelPolicy],
    candidate: &GatewayFullTunnelPolicy,
) -> Result<(), PolicyError> {
    candidate.validate()?;
    if !candidate.enabled {
        return Ok(());
    }
    if existing.iter().any(|policy| {
        policy.enabled
            && policy.policy_id != candidate.policy_id
            && policy.source_machine_id == candidate.source_machine_id
    }) {
        return Err(PolicyError::SourceAlreadyHasEnabledPolicy);
    }
    Ok(())
}

pub fn apply_gateway_policy_to_native_network_configs(
    policy: &GatewayFullTunnelPolicy,
    source_config: &mut NetworkConfig,
    exit_config: &mut NetworkConfig,
    exit_peer_ipv4: &str,
) {
    for cidr in &policy.managed_cidrs {
        if !source_config.proxy_cidrs.contains(cidr) {
            source_config.proxy_cidrs.push(cidr.clone());
        }
    }
    if !source_config
        .exit_nodes
        .contains(&exit_peer_ipv4.to_string())
    {
        source_config.exit_nodes = vec![exit_peer_ipv4.to_string()];
    }
    exit_config.enable_exit_node = Some(true);
    exit_config.proxy_forward_by_system = Some(true);
}

impl PolicyStore {
    pub fn upsert_policy(
        &mut self,
        user_id: i32,
        policy: GatewayFullTunnelPolicy,
    ) -> Result<(), PolicyError> {
        let existing = self
            .policies
            .iter()
            .filter_map(|((stored_user_id, _), policy)| {
                (*stored_user_id == user_id).then_some(policy.clone())
            })
            .collect::<Vec<_>>();
        validate_policy_conflicts(&existing, &policy)?;
        self.policies.insert((user_id, policy.policy_id), policy);
        Ok(())
    }

    pub fn update_report(&mut self, user_id: i32, report: RuntimeReport) {
        if let Some((policy_id, role)) = self.report_policy_role(user_id, &report) {
            self.policy_reports.insert(
                (user_id, policy_id, role, report.machine_id),
                report.clone(),
            );
        }
        self.reports.insert((user_id, report.machine_id), report);
    }

    fn report_policy_role(
        &self,
        user_id: i32,
        report: &RuntimeReport,
    ) -> Option<(Uuid, DevicePolicyRole)> {
        let policy_id = report.observed_policy_id.or(report.policy_id)?;
        if let Some(role) = report.role {
            return Some((policy_id, role));
        }

        let policy = self.policies.get(&(user_id, policy_id))?;
        if report.machine_id == policy.source_machine_id {
            return Some((policy_id, DevicePolicyRole::ClientGatewayViaPeer));
        }
        if report.machine_id == policy.exit_machine_id {
            return Some((policy_id, DevicePolicyRole::ProvideExitForGateway));
        }
        None
    }

    pub fn list_policies(&self, user_id: i32) -> Vec<GatewayFullTunnelPolicy> {
        let mut policies = self
            .policies
            .iter()
            .filter_map(|((stored_user_id, _), policy)| {
                (*stored_user_id == user_id).then_some(policy.clone())
            })
            .collect::<Vec<_>>();
        policies.sort_by_key(|policy| policy.policy_id);
        policies
    }

    pub fn list_policy_snapshots(&self, user_id: i32) -> Vec<GatewayPolicySnapshot> {
        self.list_policies(user_id)
            .into_iter()
            .filter_map(|policy| self.policy_snapshot(user_id, policy.policy_id))
            .collect()
    }

    pub fn list_nodes(&self, user_id: i32) -> Vec<GatewayPolicyNode> {
        let mut nodes = self
            .reports
            .iter()
            .filter_map(|((stored_user_id, _), report)| {
                (*stored_user_id == user_id).then_some(GatewayPolicyNode::from(report))
            })
            .collect::<Vec<_>>();
        nodes.sort_by_key(|node| node.machine_id);
        nodes
    }

    pub fn policy_snapshot(&self, user_id: i32, policy_id: Uuid) -> Option<GatewayPolicySnapshot> {
        let desired = self.policies.get(&(user_id, policy_id))?.clone();
        let source = self
            .policy_reports
            .get(&(
                user_id,
                policy_id,
                DevicePolicyRole::ClientGatewayViaPeer,
                desired.source_machine_id,
            ))
            .map(GatewayPolicyObservedNode::from);
        let exit = self
            .policy_reports
            .get(&(
                user_id,
                policy_id,
                DevicePolicyRole::ProvideExitForGateway,
                desired.exit_machine_id,
            ))
            .map(GatewayPolicyObservedNode::from);

        Some(GatewayPolicySnapshot {
            desired,
            observed: GatewayPolicyObservedState { source, exit },
        })
    }

    pub fn device_policies_for_machine(
        &self,
        user_id: i32,
        machine_id: Uuid,
    ) -> Result<Vec<DevicePolicy>, PolicyError> {
        let mut policies = Vec::new();
        for policy in self
            .policies
            .iter()
            .filter_map(|((stored_user_id, _), policy)| {
                (*stored_user_id == user_id && policy.enabled).then_some(policy)
            })
        {
            if policy.source_machine_id == machine_id {
                let exit_peer_ipv4 = self
                    .reports
                    .get(&(user_id, policy.exit_machine_id))
                    .and_then(|report| report.easytier_ipv4.clone())
                    .ok_or(PolicyError::MachineReportNotReady)?;
                policies.push(policy.source_device_policy(exit_peer_ipv4)?);
            }
            if policy.exit_machine_id == machine_id {
                let source_peer_ipv4 = self
                    .reports
                    .get(&(user_id, policy.source_machine_id))
                    .and_then(|report| report.easytier_ipv4.clone())
                    .ok_or(PolicyError::MachineReportNotReady)?;
                policies.push(policy.exit_device_policy(source_peer_ipv4)?);
            }
        }
        Ok(policies)
    }
}

impl From<&RuntimeReport> for GatewayPolicyObservedNode {
    fn from(report: &RuntimeReport) -> Self {
        Self {
            machine_id: report.machine_id,
            agent_version: report.agent_version.clone(),
            easytier_ipv4: report.easytier_ipv4.clone(),
            last_report_at: report.last_report_at.clone(),
            policy_id: report.observed_policy_id.or(report.policy_id),
            version: report.observed_policy_version.or(report.version),
            status: report
                .observed_policy_status
                .clone()
                .or_else(|| report.status.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            last_error: report.last_error.clone(),
        }
    }
}

impl From<&RuntimeReport> for GatewayPolicyNode {
    fn from(report: &RuntimeReport) -> Self {
        Self {
            machine_id: report.machine_id,
            agent_version: report.agent_version.clone(),
            easytier_ipv4: report.easytier_ipv4.clone(),
            last_report_at: report.last_report_at.clone(),
            status: report
                .observed_policy_status
                .clone()
                .or_else(|| report.status.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            last_error: report.last_error.clone(),
        }
    }
}

impl DevicePolicyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            DevicePolicyRole::ClientGatewayViaPeer => "client_gateway_via_peer",
            DevicePolicyRole::ProvideExitForGateway => "provide_exit_for_gateway",
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_easytier_iface() -> String {
    "easytier0".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_policy(source: Uuid, exit: Uuid) -> GatewayFullTunnelPolicy {
        GatewayFullTunnelPolicy {
            policy_id: Uuid::new_v4(),
            enabled: true,
            network_instance_id: Uuid::new_v4(),
            source_machine_id: source,
            managed_cidrs: vec!["192.168.10.0/24".to_string()],
            ingress_ifaces: vec!["br-lan".to_string()],
            include_device_traffic: true,
            exit_machine_id: exit,
            exit_egress: ExitEgress::default(),
            desired_version: 1,
            protect_control_plane: true,
            healthcheck: HealthcheckConfig::default(),
            rollback: RollbackConfig::default(),
        }
    }

    #[test]
    fn rejects_source_equal_to_exit() {
        let machine_id = Uuid::new_v4();
        let policy = base_policy(machine_id, machine_id);

        assert_eq!(policy.validate(), Err(PolicyError::SourceEqualsExit));
    }

    #[test]
    fn rejects_policy_without_managed_traffic() {
        let mut policy = base_policy(Uuid::new_v4(), Uuid::new_v4());
        policy.managed_cidrs.clear();
        policy.include_device_traffic = false;

        assert_eq!(policy.validate(), Err(PolicyError::NoManagedTraffic));
    }

    #[test]
    fn source_can_have_only_one_enabled_policy() {
        let source = Uuid::new_v4();
        let existing = vec![base_policy(source, Uuid::new_v4())];
        let candidate = base_policy(source, Uuid::new_v4());

        assert_eq!(
            validate_policy_conflicts(&existing, &candidate),
            Err(PolicyError::SourceAlreadyHasEnabledPolicy)
        );
    }

    #[test]
    fn exit_can_serve_multiple_sources() {
        let exit = Uuid::new_v4();
        let existing = vec![base_policy(Uuid::new_v4(), exit)];
        let candidate = base_policy(Uuid::new_v4(), exit);

        validate_policy_conflicts(&existing, &candidate).unwrap();
    }

    #[test]
    fn builds_source_and_exit_device_policies() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let policy = base_policy(source, exit);

        let source_policy = policy
            .source_device_policy("10.126.126.3".to_string())
            .unwrap();
        let exit_policy = policy
            .exit_device_policy("10.126.126.2".to_string())
            .unwrap();

        assert_eq!(source_policy.role, DevicePolicyRole::ClientGatewayViaPeer);
        assert_eq!(source_policy.machine_id, source);
        assert_eq!(
            source_policy.exit_peer_ipv4.as_deref(),
            Some("10.126.126.3")
        );
        assert_eq!(exit_policy.role, DevicePolicyRole::ProvideExitForGateway);
        assert_eq!(exit_policy.machine_id, exit);
        assert_eq!(
            exit_policy.source_peer_ipv4.as_deref(),
            Some("10.126.126.2")
        );
    }

    #[test]
    fn native_network_config_sync_announces_source_cidrs_and_prepares_exit() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let policy = base_policy(source, exit);
        let mut source_config = NetworkConfig {
            proxy_cidrs: vec!["10.10.0.0/24".to_string()],
            exit_nodes: vec!["10.126.126.9".to_string()],
            ..Default::default()
        };
        let mut exit_config = NetworkConfig::default();

        apply_gateway_policy_to_native_network_configs(
            &policy,
            &mut source_config,
            &mut exit_config,
            "10.126.126.3",
        );

        assert!(
            source_config
                .proxy_cidrs
                .contains(&"192.168.10.0/24".to_string())
        );
        assert_eq!(source_config.exit_nodes, vec!["10.126.126.3"]);
        assert_eq!(exit_config.enable_exit_node, Some(true));
        assert_eq!(exit_config.proxy_forward_by_system, Some(true));
    }

    #[test]
    fn store_returns_device_policies_after_reports_are_ready() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let mut store = PolicyStore::default();
        store.upsert_policy(1, base_policy(source, exit)).unwrap();

        assert_eq!(
            store.device_policies_for_machine(1, source),
            Err(PolicyError::MachineReportNotReady)
        );

        store.update_report(
            1,
            RuntimeReport {
                machine_id: source,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.2".to_string()),
                last_report_at: Some("2026-05-16T10:00:00+00:00".to_string()),
                policy_id: None,
                device_policy_id: None,
                version: None,
                role: None,
                status: None,
                observed_policy_id: None,
                observed_policy_version: None,
                observed_policy_status: None,
                last_error: None,
            },
        );
        store.update_report(
            1,
            RuntimeReport {
                machine_id: exit,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.3".to_string()),
                last_report_at: Some("2026-05-16T10:00:00+00:00".to_string()),
                policy_id: None,
                device_policy_id: None,
                version: None,
                role: None,
                status: None,
                observed_policy_id: None,
                observed_policy_version: None,
                observed_policy_status: None,
                last_error: None,
            },
        );

        let source_policies = store.device_policies_for_machine(1, source).unwrap();
        let exit_policies = store.device_policies_for_machine(1, exit).unwrap();

        assert_eq!(source_policies.len(), 1);
        assert_eq!(
            source_policies[0].role,
            DevicePolicyRole::ClientGatewayViaPeer
        );
        assert_eq!(
            source_policies[0].exit_peer_ipv4.as_deref(),
            Some("10.126.126.3")
        );
        assert_eq!(exit_policies.len(), 1);
        assert_eq!(
            exit_policies[0].role,
            DevicePolicyRole::ProvideExitForGateway
        );
        assert_eq!(
            exit_policies[0].source_peer_ipv4.as_deref(),
            Some("10.126.126.2")
        );
    }

    #[test]
    fn store_scopes_policies_by_user() {
        let source = Uuid::new_v4();
        let mut store = PolicyStore::default();
        store
            .upsert_policy(1, base_policy(source, Uuid::new_v4()))
            .unwrap();
        store
            .upsert_policy(2, base_policy(source, Uuid::new_v4()))
            .unwrap();

        assert_eq!(store.list_policies(1).len(), 1);
        assert_eq!(store.list_policies(2).len(), 1);
    }

    #[test]
    fn store_returns_policy_snapshot_with_observed_state() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let policy = base_policy(source, exit);
        let mut store = PolicyStore::default();
        store.upsert_policy(1, policy.clone()).unwrap();
        store.update_report(
            1,
            RuntimeReport {
                machine_id: source,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.2".to_string()),
                last_report_at: Some("2026-05-16T10:00:00+00:00".to_string()),
                policy_id: Some(policy.policy_id),
                device_policy_id: Some(format!("{}/source", policy.policy_id)),
                version: Some(policy.desired_version),
                role: Some(DevicePolicyRole::ClientGatewayViaPeer),
                status: Some("active".to_string()),
                observed_policy_id: Some(policy.policy_id),
                observed_policy_version: Some(policy.desired_version),
                observed_policy_status: Some("active".to_string()),
                last_error: None,
            },
        );
        store.update_report(
            1,
            RuntimeReport {
                machine_id: exit,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.3".to_string()),
                last_report_at: Some("2026-05-16T10:00:00+00:00".to_string()),
                policy_id: Some(policy.policy_id),
                device_policy_id: Some(format!("{}/exit", policy.policy_id)),
                version: Some(policy.desired_version),
                role: Some(DevicePolicyRole::ProvideExitForGateway),
                status: Some("prepared".to_string()),
                observed_policy_id: Some(policy.policy_id),
                observed_policy_version: Some(policy.desired_version),
                observed_policy_status: Some("prepared".to_string()),
                last_error: None,
            },
        );

        let snapshot = store.policy_snapshot(1, policy.policy_id).unwrap();

        assert_eq!(snapshot.desired, policy);
        assert_eq!(
            snapshot
                .observed
                .source
                .as_ref()
                .map(|node| node.status.as_str()),
            Some("active")
        );
        assert_eq!(
            snapshot
                .observed
                .exit
                .as_ref()
                .map(|node| node.status.as_str()),
            Some("prepared")
        );
    }

    #[test]
    fn store_keeps_observed_state_per_policy_role_when_machine_has_multiple_roles() {
        let node_a = Uuid::new_v4();
        let node_b = Uuid::new_v4();
        let policy_a_to_b = base_policy(node_a, node_b);
        let policy_b_to_a = base_policy(node_b, node_a);
        let mut store = PolicyStore::default();
        store.upsert_policy(1, policy_a_to_b.clone()).unwrap();
        store.upsert_policy(1, policy_b_to_a.clone()).unwrap();

        store.update_report(
            1,
            RuntimeReport {
                machine_id: node_a,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.77.77.2".to_string()),
                last_report_at: Some("2026-05-16T10:00:01+00:00".to_string()),
                policy_id: Some(policy_a_to_b.policy_id),
                device_policy_id: Some(format!("{}/source", policy_a_to_b.policy_id)),
                version: Some(policy_a_to_b.desired_version),
                role: Some(DevicePolicyRole::ClientGatewayViaPeer),
                status: Some("active".to_string()),
                observed_policy_id: Some(policy_a_to_b.policy_id),
                observed_policy_version: Some(policy_a_to_b.desired_version),
                observed_policy_status: Some("active".to_string()),
                last_error: None,
            },
        );
        store.update_report(
            1,
            RuntimeReport {
                machine_id: node_a,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.77.77.2".to_string()),
                last_report_at: Some("2026-05-16T10:00:02+00:00".to_string()),
                policy_id: Some(policy_b_to_a.policy_id),
                device_policy_id: Some(format!("{}/exit", policy_b_to_a.policy_id)),
                version: Some(policy_b_to_a.desired_version),
                role: Some(DevicePolicyRole::ProvideExitForGateway),
                status: Some("prepared".to_string()),
                observed_policy_id: Some(policy_b_to_a.policy_id),
                observed_policy_version: Some(policy_b_to_a.desired_version),
                observed_policy_status: Some("prepared".to_string()),
                last_error: None,
            },
        );
        store.update_report(
            1,
            RuntimeReport {
                machine_id: node_b,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.77.77.3".to_string()),
                last_report_at: Some("2026-05-16T10:00:03+00:00".to_string()),
                policy_id: Some(policy_a_to_b.policy_id),
                device_policy_id: Some(format!("{}/exit", policy_a_to_b.policy_id)),
                version: Some(policy_a_to_b.desired_version),
                role: Some(DevicePolicyRole::ProvideExitForGateway),
                status: Some("prepared".to_string()),
                observed_policy_id: Some(policy_a_to_b.policy_id),
                observed_policy_version: Some(policy_a_to_b.desired_version),
                observed_policy_status: Some("prepared".to_string()),
                last_error: None,
            },
        );

        let snapshot = store.policy_snapshot(1, policy_a_to_b.policy_id).unwrap();

        assert_eq!(
            snapshot
                .observed
                .source
                .as_ref()
                .and_then(|node| node.policy_id),
            Some(policy_a_to_b.policy_id)
        );
        assert_eq!(
            snapshot
                .observed
                .source
                .as_ref()
                .and_then(|node| node.version),
            Some(policy_a_to_b.desired_version)
        );
        assert_eq!(
            snapshot
                .observed
                .source
                .as_ref()
                .map(|node| node.status.as_str()),
            Some("active")
        );
    }
}
