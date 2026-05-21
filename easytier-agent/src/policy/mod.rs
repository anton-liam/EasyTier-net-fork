use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayFullTunnelPolicy {
    pub policy_id: String,
    #[serde(rename = "type")]
    pub policy_type: String,
    pub enabled: bool,
    pub network_instance_id: Uuid,
    pub source_machine_id: String,
    pub managed_cidrs: Vec<String>,
    #[serde(default)]
    pub ingress_ifaces: Vec<String>,
    #[serde(default)]
    pub include_device_traffic: bool,
    pub exit_machine_id: String,
    pub exit_egress: ExitEgress,
    pub desired_version: u64,
    #[serde(default = "default_true")]
    pub protect_control_plane: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevicePolicy {
    pub policy_id: String,
    pub device_policy_id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub version: u64,
    pub role: DevicePolicyRole,
    pub network_instance_id: Uuid,
    pub source_machine_id: String,
    pub managed_cidrs: Vec<String>,
    #[serde(default)]
    pub ingress_ifaces: Vec<String>,
    #[serde(default)]
    pub include_device_traffic: bool,
    pub exit_machine_id: String,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DevicePolicyRole {
    ClientGatewayViaPeer,
    ProvideExitForGateway,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Pending,
    Validating,
    Planned,
    Prepared,
    Applying,
    VerifyingControlPlane,
    VerifyingExit,
    Active,
    Degraded,
    Rollbacking,
    Rollbacked,
    Disabled,
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

impl DevicePolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.policy_id.trim().is_empty() {
            return Err(PolicyError::MissingField("policy_id"));
        }
        if self.device_policy_id.trim().is_empty() {
            return Err(PolicyError::MissingField("device_policy_id"));
        }
        if self.source_machine_id.trim().is_empty() {
            return Err(PolicyError::MissingField("source_machine_id"));
        }
        if self.exit_machine_id.trim().is_empty() {
            return Err(PolicyError::MissingField("exit_machine_id"));
        }
        if self.source_machine_id == self.exit_machine_id {
            return Err(PolicyError::SourceEqualsExit);
        }
        if self.managed_cidrs.is_empty() && !self.include_device_traffic {
            return Err(PolicyError::NoManagedTraffic);
        }
        for cidr in &self.managed_cidrs {
            if cidr.trim().is_empty() {
                return Err(PolicyError::InvalidManagedCidr(cidr.clone()));
            }
        }
        if self.easytier_iface.trim().is_empty() {
            return Err(PolicyError::MissingField("easytier_iface"));
        }
        match self.role {
            DevicePolicyRole::ClientGatewayViaPeer => {
                require_ip(self.exit_peer_ipv4.as_deref(), "exit_peer_ipv4")?;
            }
            DevicePolicyRole::ProvideExitForGateway => {
                require_ip(self.source_peer_ipv4.as_deref(), "source_peer_ipv4")?;
            }
        }
        if matches!(self.exit_egress.mode, ExitEgressMode::Interface)
            && self
                .exit_egress
                .iface
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            return Err(PolicyError::MissingField("exit_egress.iface"));
        }
        Ok(())
    }
}

fn require_ip(value: Option<&str>, field: &'static str) -> Result<(), PolicyError> {
    match value {
        Some(ip) if !ip.trim().is_empty() => Ok(()),
        _ => Err(PolicyError::MissingField(field)),
    }
}

fn default_true() -> bool {
    true
}

pub fn default_easytier_iface() -> String {
    "easytier0".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("source and exit machine must be different")]
    SourceEqualsExit,
    #[error("policy does not define any managed traffic")]
    NoManagedTraffic,
    #[error("invalid managed CIDR: {0}")]
    InvalidManagedCidr(String),
}

impl fmt::Display for DevicePolicyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DevicePolicyRole::ClientGatewayViaPeer => write!(f, "client_gateway_via_peer"),
            DevicePolicyRole::ProvideExitForGateway => write!(f, "provide_exit_for_gateway"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_policy_json() -> String {
        format!(
            r#"{{
              "policy_id": "p1",
              "device_policy_id": "p1/source",
              "enabled": true,
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
            Uuid::nil()
        )
    }

    #[test]
    fn parses_source_device_policy() {
        let policy: DevicePolicy = serde_json::from_str(&source_policy_json()).unwrap();
        assert_eq!(policy.role, DevicePolicyRole::ClientGatewayViaPeer);
        assert_eq!(policy.managed_cidrs, vec!["192.168.10.0/24"]);
        policy.validate().unwrap();
        assert_eq!(policy.easytier_iface, "easytier0");
    }

    #[test]
    fn rejects_source_equals_exit() {
        let mut policy: DevicePolicy = serde_json::from_str(&source_policy_json()).unwrap();
        policy.exit_machine_id = policy.source_machine_id.clone();
        assert_eq!(policy.validate(), Err(PolicyError::SourceEqualsExit));
    }

    #[test]
    fn rejects_policy_without_managed_traffic() {
        let mut policy: DevicePolicy = serde_json::from_str(&source_policy_json()).unwrap();
        policy.managed_cidrs.clear();
        policy.include_device_traffic = false;
        assert_eq!(policy.validate(), Err(PolicyError::NoManagedTraffic));
    }

    #[test]
    fn accepts_exit_policy_for_source_device_traffic_only() {
        let mut policy: DevicePolicy = serde_json::from_str(&source_policy_json()).unwrap();
        policy.role = DevicePolicyRole::ProvideExitForGateway;
        policy.device_policy_id = "p1/exit".to_string();
        policy.managed_cidrs.clear();
        policy.include_device_traffic = true;
        policy.exit_peer_ipv4 = None;
        policy.source_peer_ipv4 = Some("10.126.126.2".to_string());

        policy.validate().unwrap();
    }

    #[test]
    fn rejects_source_policy_without_exit_peer() {
        let mut policy: DevicePolicy = serde_json::from_str(&source_policy_json()).unwrap();
        policy.exit_peer_ipv4 = None;
        assert_eq!(
            policy.validate(),
            Err(PolicyError::MissingField("exit_peer_ipv4"))
        );
    }
}
