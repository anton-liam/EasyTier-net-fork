use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

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
    pub observed_policy_id: Option<Uuid>,
    #[serde(default)]
    pub observed_policy_version: Option<u64>,
    #[serde(default)]
    pub observed_policy_status: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Default)]
pub struct PolicyStore {
    policies: HashMap<(i32, Uuid), GatewayFullTunnelPolicy>,
    reports: HashMap<(i32, Uuid), RuntimeReport>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
            include_device_traffic: false,
            exit_machine_id: self.exit_machine_id,
            exit_peer_ipv4: None,
            source_peer_ipv4: Some(source_peer_ipv4),
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
        self.reports.insert((user_id, report.machine_id), report);
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

fn default_true() -> bool {
    true
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
}
