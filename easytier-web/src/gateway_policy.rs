use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use easytier::launcher::NetworkConfig;

pub const GATEWAY_DEFAULT_NETWORK_NAME: &str = "gateway-default";

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
pub struct QuickApplyGatewayPolicyRequest {
    pub source_machine_id: Uuid,
    pub exit_machine_id: Uuid,
    #[serde(default)]
    pub network_instance_id: Option<Uuid>,
    #[serde(default)]
    pub managed_cidrs_mode: ManagedCidrsMode,
    #[serde(default)]
    pub managed_cidrs: Vec<String>,
    #[serde(default)]
    pub include_device_traffic: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedCidrsMode {
    #[default]
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuickApplyGatewayPolicyResponse {
    pub policy: GatewayPolicySnapshot,
    pub selected_network_instance_id: Uuid,
    pub managed_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevicePolicy {
    pub policy_id: Uuid,
    pub device_policy_id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeReport {
    pub machine_id: Uuid,
    pub agent_version: String,
    #[serde(default)]
    pub easytier_ipv4: Option<String>,
    #[serde(default)]
    pub last_report_at: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_uuid")]
    pub policy_id: Option<Uuid>,
    #[serde(default)]
    pub device_policy_id: Option<String>,
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_device_policy_role")]
    pub role: Option<DevicePolicyRole>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_uuid")]
    pub observed_policy_id: Option<Uuid>,
    #[serde(default)]
    pub observed_policy_version: Option<u64>,
    #[serde(default)]
    pub observed_policy_status: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub easytier_iface: Option<String>,
    #[serde(default)]
    pub lan_cidrs: Vec<String>,
    #[serde(default)]
    pub ingress_ifaces: Vec<String>,
    #[serde(default)]
    pub default_route: Option<String>,
    #[serde(default)]
    pub firewall_backend: Option<String>,
    #[serde(default)]
    pub protected_routes: Vec<String>,
}

fn deserialize_optional_uuid<'de, D>(deserializer: D) -> Result<Option<Uuid>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(value) => value.parse().map(Some).map_err(serde::de::Error::custom),
    }
}

fn deserialize_optional_device_policy_role<'de, D>(
    deserializer: D,
) -> Result<Option<DevicePolicyRole>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some("client_gateway_via_peer") => Ok(Some(DevicePolicyRole::ClientGatewayViaPeer)),
        Some("provide_exit_for_gateway") => Ok(Some(DevicePolicyRole::ProvideExitForGateway)),
        Some(value) => Err(serde::de::Error::custom(format!(
            "unknown device policy role: {value}"
        ))),
    }
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
pub struct GatewayNodeMachineSnapshot {
    pub machine_id: Uuid,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default)]
    pub running_network_instances: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayNodeView {
    pub machine_id: Uuid,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub public_ip: Option<String>,
    pub machine_online: bool,
    #[serde(default)]
    pub running_network_instances: Vec<Uuid>,
    pub agent: GatewayNodeAgentView,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayNodeAgentView {
    pub online: bool,
    #[serde(default)]
    pub last_report_at: Option<String>,
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub easytier_ipv4: Option<String>,
    #[serde(default)]
    pub easytier_iface: Option<String>,
    #[serde(default)]
    pub lan_cidrs: Vec<String>,
    #[serde(default)]
    pub ingress_ifaces: Vec<String>,
    #[serde(default)]
    pub default_route: Option<String>,
    #[serde(default)]
    pub firewall_backend: Option<String>,
    #[serde(default)]
    pub policy_status: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub protected_routes: Vec<String>,
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
    #[error("machine is offline: {0}")]
    MachineOffline(Uuid),
    #[error("agent report is stale or missing: {0}")]
    AgentReportStale(Uuid),
    #[error("source agent did not report any managed CIDR")]
    MissingManagedCidrs,
    #[error("source and exit do not share a running network instance")]
    NetworkInstanceNotReady,
    #[error("gateway policy not found")]
    PolicyNotFound,
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
            enabled: self.enabled,
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
            enabled: self.enabled,
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
    if !policy.enabled {
        source_config
            .proxy_cidrs
            .retain(|cidr| !policy.managed_cidrs.contains(cidr));
        source_config
            .exit_nodes
            .retain(|node| node != exit_peer_ipv4);
        exit_config.enable_exit_node = Some(false);
        exit_config.proxy_forward_by_system = Some(false);
        return;
    }

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
    source_config.enable_exit_node = Some(false);
    source_config.proxy_forward_by_system = Some(false);
    exit_config.proxy_cidrs.clear();
    exit_config.exit_nodes.clear();
    exit_config.enable_exit_node = Some(true);
    exit_config.proxy_forward_by_system = Some(true);
}

pub fn gateway_default_network_config(
    instance_id: Uuid,
    network_secret: String,
    hostname: Option<String>,
    peer_urls: Vec<String>,
) -> NetworkConfig {
    NetworkConfig {
        instance_id: Some(instance_id.to_string()),
        dhcp: Some(true),
        network_length: Some(24),
        hostname,
        network_name: Some(GATEWAY_DEFAULT_NETWORK_NAME.to_string()),
        network_secret: Some(network_secret),
        networking_method: Some(easytier::launcher::NetworkingMethod::Manual as i32),
        peer_urls,
        enable_vpn_portal: Some(false),
        vpn_portal_listen_port: Some(22022),
        vpn_portal_client_network_len: Some(24),
        advanced_settings: Some(false),
        listener_urls: vec![
            "tcp://0.0.0.0:11010".to_string(),
            "udp://0.0.0.0:11010".to_string(),
            "wg://0.0.0.0:11011".to_string(),
        ],
        latency_first: Some(false),
        use_smoltcp: Some(false),
        disable_ipv6: Some(false),
        enable_kcp_proxy: Some(false),
        disable_kcp_input: Some(false),
        disable_p2p: Some(false),
        bind_device: Some(true),
        no_tun: Some(false),
        enable_exit_node: Some(false),
        relay_all_peer_rpc: Some(false),
        multi_thread: Some(true),
        enable_relay_network_whitelist: Some(false),
        enable_manual_routes: Some(false),
        proxy_forward_by_system: Some(false),
        disable_encryption: Some(false),
        enable_socks5: Some(false),
        socks5_port: Some(1080),
        disable_udp_hole_punching: Some(false),
        enable_magic_dns: Some(false),
        enable_private_mode: Some(false),
        enable_quic_proxy: Some(false),
        disable_quic_input: Some(false),
        disable_sym_hole_punching: Some(false),
        p2p_only: Some(false),
        disable_tcp_hole_punching: Some(false),
        lazy_p2p: Some(false),
        need_p2p: Some(false),
        disable_upnp: Some(false),
        ipv6_public_addr_provider: Some(false),
        ipv6_public_addr_auto: Some(false),
        disable_relay_data: Some(false),
        enable_udp_broadcast_relay: Some(false),
        ..Default::default()
    }
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
        let mut report = report;
        if report.easytier_ipv4.is_none() {
            report.easytier_ipv4 = self
                .reports
                .get(&(user_id, report.machine_id))
                .and_then(|existing| existing.easytier_ipv4.clone());
        }
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

    pub fn native_sync_ready_policies_for_machine(
        &self,
        user_id: i32,
        machine_id: Uuid,
    ) -> Vec<GatewayFullTunnelPolicy> {
        let mut policies = self
            .policies
            .iter()
            .filter_map(|((stored_user_id, _), policy)| {
                if *stored_user_id != user_id || !policy.enabled {
                    return None;
                }
                if policy.source_machine_id != machine_id && policy.exit_machine_id != machine_id {
                    return None;
                }
                let source_ready = self
                    .reports
                    .get(&(user_id, policy.source_machine_id))
                    .and_then(|report| report.easytier_ipv4.as_ref())
                    .is_some();
                let exit_ready = self
                    .reports
                    .get(&(user_id, policy.exit_machine_id))
                    .and_then(|report| report.easytier_ipv4.as_ref())
                    .is_some();
                (source_ready && exit_ready).then_some(policy.clone())
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
                (*stored_user_id == user_id).then_some(policy)
            })
        {
            if policy.source_machine_id == machine_id {
                let Some(exit_peer_ipv4) = self
                    .reports
                    .get(&(user_id, policy.exit_machine_id))
                    .and_then(|report| report.easytier_ipv4.clone())
                else {
                    continue;
                };
                policies.push(policy.source_device_policy(exit_peer_ipv4)?);
            }
            if policy.exit_machine_id == machine_id {
                let Some(source_peer_ipv4) = self
                    .reports
                    .get(&(user_id, policy.source_machine_id))
                    .and_then(|report| report.easytier_ipv4.clone())
                else {
                    continue;
                };
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

pub fn build_gateway_node_views(
    machines: Vec<GatewayNodeMachineSnapshot>,
    reports: Vec<RuntimeReport>,
    now: chrono::DateTime<chrono::Utc>,
    fresh_after: chrono::Duration,
) -> Vec<GatewayNodeView> {
    let mut report_by_machine: HashMap<Uuid, RuntimeReport> = HashMap::new();
    for report in reports {
        let replace = report_by_machine
            .get(&report.machine_id)
            .map(|existing| report_is_newer(&report, existing))
            .unwrap_or(true);
        if replace {
            report_by_machine.insert(report.machine_id, report);
        }
    }

    let mut views = machines
        .into_iter()
        .map(|machine| {
            let report = report_by_machine.get(&machine.machine_id);
            GatewayNodeView {
                machine_id: machine.machine_id,
                hostname: machine.hostname,
                public_ip: machine.public_ip,
                machine_online: true,
                running_network_instances: machine.running_network_instances,
                agent: report
                    .map(|report| GatewayNodeAgentView::from_report(report, now, fresh_after))
                    .unwrap_or_default(),
            }
        })
        .collect::<Vec<_>>();
    views.sort_by_key(|node| node.machine_id);
    views
}

pub fn build_quick_apply_gateway_policy(
    request: &QuickApplyGatewayPolicyRequest,
    nodes: &[GatewayNodeView],
    policy_id: Uuid,
    desired_version: u64,
) -> Result<GatewayFullTunnelPolicy, PolicyError> {
    if request.source_machine_id == request.exit_machine_id {
        return Err(PolicyError::SourceEqualsExit);
    }
    let network_instance_id = select_quick_apply_network_instance(request, nodes)?;
    build_quick_apply_gateway_policy_for_network(
        request,
        nodes,
        policy_id,
        desired_version,
        network_instance_id,
    )
}

pub fn build_quick_apply_gateway_policy_for_network(
    request: &QuickApplyGatewayPolicyRequest,
    nodes: &[GatewayNodeView],
    policy_id: Uuid,
    desired_version: u64,
    network_instance_id: Uuid,
) -> Result<GatewayFullTunnelPolicy, PolicyError> {
    if request.source_machine_id == request.exit_machine_id {
        return Err(PolicyError::SourceEqualsExit);
    }

    let source = nodes
        .iter()
        .find(|node| node.machine_id == request.source_machine_id)
        .ok_or(PolicyError::MachineOffline(request.source_machine_id))?;
    let exit = nodes
        .iter()
        .find(|node| node.machine_id == request.exit_machine_id)
        .ok_or(PolicyError::MachineOffline(request.exit_machine_id))?;

    if !source.machine_online {
        return Err(PolicyError::MachineOffline(source.machine_id));
    }
    if !exit.machine_online {
        return Err(PolicyError::MachineOffline(exit.machine_id));
    }
    if !source.agent.online {
        return Err(PolicyError::AgentReportStale(source.machine_id));
    }
    if !exit.agent.online {
        return Err(PolicyError::AgentReportStale(exit.machine_id));
    }

    let managed_cidrs = if request.managed_cidrs.is_empty() {
        match request.managed_cidrs_mode {
            ManagedCidrsMode::Auto => source.agent.lan_cidrs.clone(),
        }
    } else {
        request.managed_cidrs.clone()
    };
    if managed_cidrs.is_empty() {
        return Err(PolicyError::MissingManagedCidrs);
    }

    let policy = GatewayFullTunnelPolicy {
        policy_id,
        enabled: true,
        network_instance_id,
        source_machine_id: source.machine_id,
        managed_cidrs,
        ingress_ifaces: source.agent.ingress_ifaces.clone(),
        include_device_traffic: request.include_device_traffic,
        exit_machine_id: exit.machine_id,
        exit_egress: ExitEgress::default(),
        desired_version,
        protect_control_plane: true,
        healthcheck: HealthcheckConfig::default(),
        rollback: RollbackConfig::default(),
    };
    policy.validate()?;
    Ok(policy)
}

fn select_quick_apply_network_instance(
    request: &QuickApplyGatewayPolicyRequest,
    nodes: &[GatewayNodeView],
) -> Result<Uuid, PolicyError> {
    let source = nodes
        .iter()
        .find(|node| node.machine_id == request.source_machine_id)
        .ok_or(PolicyError::MachineOffline(request.source_machine_id))?;
    let exit = nodes
        .iter()
        .find(|node| node.machine_id == request.exit_machine_id)
        .ok_or(PolicyError::MachineOffline(request.exit_machine_id))?;

    if let Some(network_instance_id) = request.network_instance_id {
        let source_has_network = source
            .running_network_instances
            .contains(&network_instance_id);
        let exit_has_network = exit
            .running_network_instances
            .contains(&network_instance_id);
        return (source_has_network && exit_has_network)
            .then_some(network_instance_id)
            .ok_or(PolicyError::NetworkInstanceNotReady);
    }

    let mut source_networks = source.running_network_instances.clone();
    source_networks.sort();
    source_networks
        .into_iter()
        .find(|network_id| exit.running_network_instances.contains(network_id))
        .ok_or(PolicyError::NetworkInstanceNotReady)
}

impl GatewayNodeAgentView {
    fn from_report(
        report: &RuntimeReport,
        now: chrono::DateTime<chrono::Utc>,
        fresh_after: chrono::Duration,
    ) -> Self {
        Self {
            online: report_is_fresh(report, now, fresh_after),
            last_report_at: report.last_report_at.clone(),
            agent_version: Some(report.agent_version.clone()),
            easytier_ipv4: report.easytier_ipv4.clone(),
            easytier_iface: report.easytier_iface.clone(),
            lan_cidrs: report.lan_cidrs.clone(),
            ingress_ifaces: report.ingress_ifaces.clone(),
            default_route: report.default_route.clone(),
            firewall_backend: report.firewall_backend.clone(),
            policy_status: report
                .observed_policy_status
                .clone()
                .or_else(|| report.status.clone()),
            last_error: report.last_error.clone(),
            protected_routes: report.protected_routes.clone(),
        }
    }
}

fn report_is_fresh(
    report: &RuntimeReport,
    now: chrono::DateTime<chrono::Utc>,
    fresh_after: chrono::Duration,
) -> bool {
    let Some(last_report_at) = parse_report_time(report.last_report_at.as_deref()) else {
        return false;
    };
    now.signed_duration_since(last_report_at) <= fresh_after
}

fn report_is_newer(left: &RuntimeReport, right: &RuntimeReport) -> bool {
    match (
        parse_report_time(left.last_report_at.as_deref()),
        parse_report_time(right.last_report_at.as_deref()),
    ) {
        (Some(left), Some(right)) => left >= right,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => true,
    }
}

fn parse_report_time(value: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value?)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
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
    "tun0".to_string()
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
    fn device_policy_defaults_to_tun0() {
        let policy: DevicePolicy = serde_json::from_str(&format!(
            r#"{{
              "policy_id": "{}",
              "device_policy_id": "p1/source",
              "enabled": true,
              "version": 1,
              "role": "client_gateway_via_peer",
              "machine_id": "{}",
              "network_instance_id": "{}",
              "source_machine_id": "{}",
              "managed_cidrs": ["192.168.10.0/24"],
              "ingress_ifaces": ["br-lan"],
              "include_device_traffic": true,
              "exit_machine_id": "{}",
              "exit_peer_ipv4": "10.126.126.3",
              "protect_control_plane": true,
              "rollback_enabled": true
            }}"#,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::nil(),
            Uuid::new_v4(),
            Uuid::new_v4()
        ))
        .unwrap();

        assert_eq!(policy.easytier_iface, "tun0");
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
            enable_exit_node: Some(true),
            proxy_forward_by_system: Some(true),
            ..Default::default()
        };
        let mut exit_config = NetworkConfig {
            proxy_cidrs: vec!["192.168.10.0/24".to_string()],
            exit_nodes: vec!["10.126.126.2".to_string()],
            ..Default::default()
        };

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
        assert_eq!(source_config.enable_exit_node, Some(false));
        assert_eq!(source_config.proxy_forward_by_system, Some(false));
        assert!(exit_config.proxy_cidrs.is_empty());
        assert!(exit_config.exit_nodes.is_empty());
        assert_eq!(exit_config.enable_exit_node, Some(true));
        assert_eq!(exit_config.proxy_forward_by_system, Some(true));
    }

    #[test]
    fn native_network_config_sync_cleans_gateway_settings_when_policy_disabled() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let mut policy = base_policy(source, exit);
        policy.enabled = false;
        let mut source_config = NetworkConfig {
            proxy_cidrs: vec!["192.168.10.0/24".to_string(), "10.10.0.0/24".to_string()],
            exit_nodes: vec!["10.126.126.3".to_string()],
            ..Default::default()
        };
        let mut exit_config = NetworkConfig {
            enable_exit_node: Some(true),
            proxy_forward_by_system: Some(true),
            ..Default::default()
        };

        apply_gateway_policy_to_native_network_configs(
            &policy,
            &mut source_config,
            &mut exit_config,
            "10.126.126.3",
        );

        assert_eq!(source_config.proxy_cidrs, vec!["10.10.0.0/24"]);
        assert!(source_config.exit_nodes.is_empty());
        assert_eq!(exit_config.enable_exit_node, Some(false));
        assert_eq!(exit_config.proxy_forward_by_system, Some(false));
    }

    #[test]
    fn node_list_uses_native_machines_as_primary_source() {
        let machine = Uuid::new_v4();
        let orphan = Uuid::new_v4();
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-22T10:00:00+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let views = build_gateway_node_views(
            vec![GatewayNodeMachineSnapshot {
                machine_id: machine,
                hostname: Some("r3s-a".to_string()),
                public_ip: Some("182.105.22.12".to_string()),
                running_network_instances: vec![Uuid::nil()],
            }],
            vec![
                RuntimeReport {
                    machine_id: machine,
                    agent_version: "0.1.0".to_string(),
                    easytier_ipv4: Some("10.126.126.2".to_string()),
                    last_report_at: Some("2026-05-22T09:59:50+00:00".to_string()),
                    policy_id: None,
                    device_policy_id: None,
                    version: None,
                    role: None,
                    status: Some("prepared".to_string()),
                    observed_policy_id: None,
                    observed_policy_version: None,
                    observed_policy_status: Some("prepared".to_string()),
                    last_error: None,
                    easytier_iface: Some("easytier0".to_string()),
                    lan_cidrs: vec!["192.168.100.0/24".to_string()],
                    ingress_ifaces: vec!["br-lan".to_string()],
                    default_route: Some("default via 192.168.64.1 dev eth0".to_string()),
                    firewall_backend: Some("fw4-nftables".to_string()),
                    protected_routes: vec![],
                },
                RuntimeReport {
                    machine_id: orphan,
                    agent_version: "0.1.0".to_string(),
                    easytier_ipv4: Some("10.126.126.9".to_string()),
                    last_report_at: Some("2026-05-22T09:59:50+00:00".to_string()),
                    policy_id: None,
                    device_policy_id: None,
                    version: None,
                    role: None,
                    status: Some("prepared".to_string()),
                    observed_policy_id: None,
                    observed_policy_version: None,
                    observed_policy_status: Some("prepared".to_string()),
                    last_error: None,
                    easytier_iface: Some("easytier0".to_string()),
                    lan_cidrs: vec!["192.168.200.0/24".to_string()],
                    ingress_ifaces: vec!["br-lan".to_string()],
                    default_route: None,
                    firewall_backend: Some("fw4-nftables".to_string()),
                    protected_routes: vec![],
                },
            ],
            now,
            chrono::Duration::seconds(30),
        );

        assert_eq!(views.len(), 1);
        assert_eq!(views[0].machine_id, machine);
        assert!(views[0].machine_online);
        assert!(views[0].agent.online);
        assert_eq!(
            views[0].agent.easytier_ipv4.as_deref(),
            Some("10.126.126.2")
        );
        assert_eq!(views[0].agent.lan_cidrs, vec!["192.168.100.0/24"]);
    }

    #[test]
    fn node_list_marks_agent_report_stale() {
        let machine = Uuid::new_v4();
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-22T10:00:00+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let views = build_gateway_node_views(
            vec![GatewayNodeMachineSnapshot {
                machine_id: machine,
                hostname: Some("r3s-a".to_string()),
                public_ip: Some("182.105.22.12".to_string()),
                running_network_instances: vec![],
            }],
            vec![RuntimeReport {
                machine_id: machine,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.2".to_string()),
                last_report_at: Some("2026-05-22T09:58:00+00:00".to_string()),
                policy_id: None,
                device_policy_id: None,
                version: None,
                role: None,
                status: Some("prepared".to_string()),
                observed_policy_id: None,
                observed_policy_version: None,
                observed_policy_status: Some("prepared".to_string()),
                last_error: None,
                easytier_iface: Some("easytier0".to_string()),
                lan_cidrs: vec!["192.168.100.0/24".to_string()],
                ingress_ifaces: vec!["br-lan".to_string()],
                default_route: Some("default via 192.168.64.1 dev eth0".to_string()),
                firewall_backend: Some("fw4-nftables".to_string()),
                protected_routes: vec![],
            }],
            now,
            chrono::Duration::seconds(30),
        );

        assert_eq!(views.len(), 1);
        assert!(views[0].machine_online);
        assert!(!views[0].agent.online);
        assert_eq!(views[0].agent.policy_status.as_deref(), Some("prepared"));
    }

    fn gateway_node_view(
        machine_id: Uuid,
        network_instance_id: Uuid,
        online: bool,
        lan_cidrs: Vec<&str>,
    ) -> GatewayNodeView {
        GatewayNodeView {
            machine_id,
            hostname: Some(machine_id.to_string()),
            public_ip: None,
            machine_online: true,
            running_network_instances: vec![network_instance_id],
            agent: GatewayNodeAgentView {
                online,
                last_report_at: Some("2026-05-22T10:00:00+00:00".to_string()),
                agent_version: Some("0.1.0".to_string()),
                easytier_ipv4: Some("10.126.126.2".to_string()),
                easytier_iface: Some("easytier0".to_string()),
                lan_cidrs: lan_cidrs.into_iter().map(str::to_string).collect(),
                ingress_ifaces: vec!["br-lan".to_string()],
                default_route: None,
                firewall_backend: Some("fw4-nftables".to_string()),
                policy_status: Some("prepared".to_string()),
                last_error: None,
                protected_routes: vec![],
            },
        }
    }

    #[test]
    fn quick_apply_rejects_same_source_exit() {
        let machine = Uuid::new_v4();
        let request = QuickApplyGatewayPolicyRequest {
            source_machine_id: machine,
            exit_machine_id: machine,
            network_instance_id: None,
            managed_cidrs_mode: ManagedCidrsMode::Auto,
            managed_cidrs: vec![],
            include_device_traffic: false,
        };

        assert_eq!(
            build_quick_apply_gateway_policy(&request, &[], Uuid::new_v4(), 1),
            Err(PolicyError::SourceEqualsExit)
        );
    }

    #[test]
    fn quick_apply_rejects_stale_agent_report() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let network = Uuid::new_v4();
        let request = QuickApplyGatewayPolicyRequest {
            source_machine_id: source,
            exit_machine_id: exit,
            network_instance_id: None,
            managed_cidrs_mode: ManagedCidrsMode::Auto,
            managed_cidrs: vec![],
            include_device_traffic: false,
        };
        let nodes = vec![
            gateway_node_view(source, network, false, vec!["192.168.100.0/24"]),
            gateway_node_view(exit, network, true, vec!["192.168.200.0/24"]),
        ];

        assert_eq!(
            build_quick_apply_gateway_policy(&request, &nodes, Uuid::new_v4(), 1),
            Err(PolicyError::AgentReportStale(source))
        );
    }

    #[test]
    fn quick_apply_builds_default_gateway_policy_from_node_reports() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let network = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let request = QuickApplyGatewayPolicyRequest {
            source_machine_id: source,
            exit_machine_id: exit,
            network_instance_id: None,
            managed_cidrs_mode: ManagedCidrsMode::Auto,
            managed_cidrs: vec![],
            include_device_traffic: false,
        };
        let nodes = vec![
            gateway_node_view(source, network, true, vec!["192.168.100.0/24"]),
            gateway_node_view(exit, network, true, vec!["192.168.200.0/24"]),
        ];

        let policy = build_quick_apply_gateway_policy(&request, &nodes, policy_id, 7).unwrap();

        assert_eq!(policy.policy_id, policy_id);
        assert_eq!(policy.network_instance_id, network);
        assert_eq!(policy.source_machine_id, source);
        assert_eq!(policy.exit_machine_id, exit);
        assert_eq!(policy.managed_cidrs, vec!["192.168.100.0/24"]);
        assert_eq!(policy.ingress_ifaces, vec!["br-lan"]);
        assert!(!policy.include_device_traffic);
        assert!(policy.enabled);
        assert_eq!(policy.desired_version, 7);
    }

    #[test]
    fn quick_apply_prefers_explicit_managed_cidrs_override() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let network = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let request = QuickApplyGatewayPolicyRequest {
            source_machine_id: source,
            exit_machine_id: exit,
            network_instance_id: None,
            managed_cidrs_mode: ManagedCidrsMode::Auto,
            managed_cidrs: vec!["192.168.100.0/24".to_string()],
            include_device_traffic: false,
        };
        let nodes = vec![
            gateway_node_view(source, network, true, vec!["192.168.64.2/24"]),
            gateway_node_view(exit, network, true, vec!["192.168.64.3/24"]),
        ];

        let policy = build_quick_apply_gateway_policy(&request, &nodes, policy_id, 11).unwrap();

        assert_eq!(policy.managed_cidrs, vec!["192.168.100.0/24"]);
        assert_eq!(policy.ingress_ifaces, vec!["br-lan"]);
    }

    #[test]
    fn quick_apply_can_build_policy_for_prepared_gateway_default_network() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let prepared_network = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let request = QuickApplyGatewayPolicyRequest {
            source_machine_id: source,
            exit_machine_id: exit,
            network_instance_id: None,
            managed_cidrs_mode: ManagedCidrsMode::Auto,
            managed_cidrs: vec![],
            include_device_traffic: false,
        };
        let mut source_node =
            gateway_node_view(source, Uuid::new_v4(), true, vec!["192.168.100.0/24"]);
        let mut exit_node = gateway_node_view(exit, Uuid::new_v4(), true, vec!["192.168.200.0/24"]);
        source_node.running_network_instances.clear();
        exit_node.running_network_instances.clear();
        source_node.agent.easytier_ipv4 = None;
        exit_node.agent.easytier_ipv4 = None;
        let nodes = vec![source_node, exit_node];

        let policy = build_quick_apply_gateway_policy_for_network(
            &request,
            &nodes,
            policy_id,
            3,
            prepared_network,
        )
        .unwrap();

        assert_eq!(policy.network_instance_id, prepared_network);
        assert_eq!(policy.source_machine_id, source);
        assert_eq!(policy.exit_machine_id, exit);
        assert_eq!(policy.managed_cidrs, vec!["192.168.100.0/24"]);
        assert!(!policy.include_device_traffic);
    }

    #[test]
    fn gateway_default_network_config_sets_manual_peer_config() {
        let network_id = Uuid::new_v4();
        let config = gateway_default_network_config(
            network_id,
            "secret-1".to_string(),
            Some("r3s-a".to_string()),
            vec!["udp://137.220.194.19:11010".to_string()],
        );

        assert_eq!(
            config.instance_id.as_deref(),
            Some(network_id.to_string().as_str())
        );
        assert_eq!(
            config.network_name.as_deref(),
            Some(GATEWAY_DEFAULT_NETWORK_NAME)
        );
        assert_eq!(config.network_secret.as_deref(), Some("secret-1"));
        assert_eq!(config.hostname.as_deref(), Some("r3s-a"));
        assert_eq!(config.peer_urls, vec!["udp://137.220.194.19:11010"]);
        assert_eq!(
            config.networking_method,
            Some(easytier::launcher::NetworkingMethod::Manual as i32)
        );
        assert_eq!(config.dhcp, Some(true));
        assert_eq!(config.enable_exit_node, Some(false));
        assert_eq!(config.proxy_forward_by_system, Some(false));
    }

    #[test]
    fn store_returns_native_sync_ready_policies_when_both_peer_ips_are_known() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let policy = base_policy(source, exit);
        let policy_id = policy.policy_id;
        let mut store = PolicyStore::default();
        store.upsert_policy(1, policy).unwrap();

        store.update_report(
            1,
            RuntimeReport {
                machine_id: source,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.2".to_string()),
                last_report_at: None,
                policy_id: None,
                device_policy_id: None,
                version: None,
                role: None,
                status: None,
                observed_policy_id: None,
                observed_policy_version: None,
                observed_policy_status: None,
                last_error: None,
                ..Default::default()
            },
        );
        assert!(
            store
                .native_sync_ready_policies_for_machine(1, source)
                .is_empty()
        );

        store.update_report(
            1,
            RuntimeReport {
                machine_id: exit,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.3".to_string()),
                last_report_at: None,
                policy_id: None,
                device_policy_id: None,
                version: None,
                role: None,
                status: None,
                observed_policy_id: None,
                observed_policy_version: None,
                observed_policy_status: None,
                last_error: None,
                ..Default::default()
            },
        );

        let ready = store.native_sync_ready_policies_for_machine(1, source);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].policy_id, policy_id);
        assert_eq!(
            store.native_sync_ready_policies_for_machine(1, exit)[0].policy_id,
            policy_id
        );
    }

    #[test]
    fn store_returns_no_device_policy_until_peer_ips_are_known() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let policy = base_policy(source, exit);
        let mut store = PolicyStore::default();
        store.upsert_policy(1, policy).unwrap();

        store.update_report(
            1,
            RuntimeReport {
                machine_id: source,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.2".to_string()),
                ..Default::default()
            },
        );

        assert_eq!(store.device_policies_for_machine(1, source), Ok(vec![]));
        assert_eq!(store.device_policies_for_machine(1, exit).unwrap().len(), 1);
    }

    #[test]
    fn store_returns_device_policies_after_reports_are_ready() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let mut store = PolicyStore::default();
        store.upsert_policy(1, base_policy(source, exit)).unwrap();

        assert_eq!(store.device_policies_for_machine(1, source), Ok(vec![]));

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
                ..Default::default()
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
                ..Default::default()
            },
        );

        let source_policies = store.device_policies_for_machine(1, source).unwrap();
        let exit_policies = store.device_policies_for_machine(1, exit).unwrap();

        assert_eq!(source_policies.len(), 1);
        assert!(source_policies[0].enabled);
        assert_eq!(
            source_policies[0].role,
            DevicePolicyRole::ClientGatewayViaPeer
        );
        assert_eq!(
            source_policies[0].exit_peer_ipv4.as_deref(),
            Some("10.126.126.3")
        );
        assert_eq!(exit_policies.len(), 1);
        assert!(exit_policies[0].enabled);
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
    fn disabled_policy_still_returns_cleanup_device_policies() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let mut policy = base_policy(source, exit);
        policy.enabled = false;
        let mut store = PolicyStore::default();
        store.upsert_policy(1, policy).unwrap();

        for (machine_id, easytier_ipv4) in [(source, "10.126.126.2"), (exit, "10.126.126.3")] {
            store.update_report(
                1,
                RuntimeReport {
                    machine_id,
                    agent_version: "0.1.0".to_string(),
                    easytier_ipv4: Some(easytier_ipv4.to_string()),
                    last_report_at: None,
                    policy_id: None,
                    device_policy_id: None,
                    version: None,
                    role: None,
                    status: None,
                    observed_policy_id: None,
                    observed_policy_version: None,
                    observed_policy_status: None,
                    last_error: None,
                    ..Default::default()
                },
            );
        }

        let source_policies = store.device_policies_for_machine(1, source).unwrap();
        let exit_policies = store.device_policies_for_machine(1, exit).unwrap();

        assert_eq!(source_policies.len(), 1);
        assert_eq!(exit_policies.len(), 1);
        assert!(!source_policies[0].enabled);
        assert!(!exit_policies[0].enabled);
    }

    #[test]
    fn store_keeps_machine_easytier_ip_when_policy_report_omits_it() {
        let source = Uuid::new_v4();
        let exit = Uuid::new_v4();
        let policy = base_policy(source, exit);
        let policy_id = policy.policy_id;
        let mut store = PolicyStore::default();
        store.upsert_policy(1, policy).unwrap();

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
                ..Default::default()
            },
        );
        store.update_report(
            1,
            RuntimeReport {
                machine_id: exit,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: None,
                last_report_at: Some("2026-05-16T10:01:00+00:00".to_string()),
                policy_id: Some(policy_id),
                device_policy_id: Some(format!("{policy_id}/exit")),
                version: Some(1),
                role: Some(DevicePolicyRole::ProvideExitForGateway),
                status: Some("prepared".to_string()),
                observed_policy_id: Some(policy_id),
                observed_policy_version: Some(1),
                observed_policy_status: Some("prepared".to_string()),
                last_error: None,
                ..Default::default()
            },
        );

        let source_policies = store.device_policies_for_machine(1, source).unwrap();

        assert_eq!(
            source_policies[0].exit_peer_ipv4.as_deref(),
            Some("10.126.126.3")
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
    fn runtime_report_accepts_empty_policy_fields_from_idle_agent() {
        let raw = r#"{
            "machine_id":"9e466b97-623f-4cea-b072-d5f7b002d446",
            "agent_version":"0.1.0",
            "easytier_ipv4":"10.126.126.20",
            "policy_id":"",
            "device_policy_id":"",
            "version":0,
            "role":"",
            "status":"prepared",
            "observed_policy_id":"",
            "observed_policy_version":0,
            "observed_policy_status":"prepared",
            "dry_run":false,
            "executed_count":0,
            "last_error":null
        }"#;

        let report: RuntimeReport = serde_json::from_str(raw).unwrap();

        assert_eq!(
            report.machine_id,
            Uuid::parse_str("9e466b97-623f-4cea-b072-d5f7b002d446").unwrap()
        );
        assert_eq!(report.policy_id, None);
        assert_eq!(report.role, None);
        assert_eq!(report.observed_policy_id, None);
        assert_eq!(report.status.as_deref(), Some("prepared"));
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
