use std::fmt;

use crate::policy::{DevicePolicy, DevicePolicyRole, PolicyError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanAction {
    pub kind: PlanActionKind,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanActionKind {
    ProtectControlPlane,
    RouteManagedTraffic,
    PrepareForwarding,
    PrepareNat,
    Verify,
}

impl fmt::Display for PlanActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanActionKind::ProtectControlPlane => write!(f, "protect_control_plane"),
            PlanActionKind::RouteManagedTraffic => write!(f, "route_managed_traffic"),
            PlanActionKind::PrepareForwarding => write!(f, "prepare_forwarding"),
            PlanActionKind::PrepareNat => write!(f, "prepare_nat"),
            PlanActionKind::Verify => write!(f, "verify"),
        }
    }
}

pub fn dry_run_plan(policy: &DevicePolicy) -> Result<Vec<PlanAction>, PlanError> {
    policy.validate()?;
    let actions = match policy.role {
        DevicePolicyRole::ClientGatewayViaPeer => source_plan(policy),
        DevicePolicyRole::ProvideExitForGateway => exit_plan(policy),
    };
    Ok(actions)
}

fn source_plan(policy: &DevicePolicy) -> Vec<PlanAction> {
    let exit_peer = policy.exit_peer_ipv4.as_deref().unwrap_or_default();
    let traffic = describe_managed_traffic(policy);
    vec![
        PlanAction {
            kind: PlanActionKind::ProtectControlPlane,
            description:
                "ensure Web/config-server/relay/SSH underlay routes stay outside the tunnel"
                    .to_string(),
        },
        PlanAction {
            kind: PlanActionKind::RouteManagedTraffic,
            description: format!("route {traffic} to {exit_peer} via EasyTier"),
        },
        PlanAction {
            kind: PlanActionKind::Verify,
            description: "verify control-plane reachability and managed traffic exit health"
                .to_string(),
        },
    ]
}

fn exit_plan(policy: &DevicePolicy) -> Vec<PlanAction> {
    let source_peer = policy.source_peer_ipv4.as_deref().unwrap_or_default();
    let traffic = describe_managed_traffic(policy);
    vec![
        PlanAction {
            kind: PlanActionKind::PrepareForwarding,
            description: format!("allow {traffic} from source peer {source_peer} to exit egress"),
        },
        PlanAction {
            kind: PlanActionKind::PrepareNat,
            description: "ensure managed traffic is masqueraded on exit egress".to_string(),
        },
        PlanAction {
            kind: PlanActionKind::Verify,
            description: "verify forwarding and NAT are prepared without affecting other sources"
                .to_string(),
        },
    ]
}

fn describe_managed_traffic(policy: &DevicePolicy) -> String {
    let mut parts = Vec::new();
    if !policy.managed_cidrs.is_empty() {
        parts.push(format!("managed_cidrs={}", policy.managed_cidrs.join(",")));
    }
    if !policy.ingress_ifaces.is_empty() {
        parts.push(format!(
            "ingress_ifaces={}",
            policy.ingress_ifaces.join(",")
        ));
    }
    if policy.include_device_traffic {
        parts.push("include_device_traffic=true".to_string());
    }
    parts.join(" ")
}

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::policy::{DevicePolicy, DevicePolicyRole, ExitEgress};

    fn policy(role: DevicePolicyRole) -> DevicePolicy {
        DevicePolicy {
            policy_id: "p1".to_string(),
            device_policy_id: "p1/device".to_string(),
            version: 1,
            role,
            network_instance_id: Uuid::nil(),
            source_machine_id: "node-a".to_string(),
            managed_cidrs: vec!["192.168.10.0/24".to_string()],
            ingress_ifaces: vec!["br-lan".to_string()],
            include_device_traffic: true,
            exit_machine_id: "node-b".to_string(),
            exit_peer_ipv4: Some("10.126.126.3".to_string()),
            source_peer_ipv4: Some("10.126.126.2".to_string()),
            easytier_iface: "easytier0".to_string(),
            exit_egress: ExitEgress::default(),
            protect_control_plane: true,
            rollback_enabled: true,
        }
    }

    #[test]
    fn source_plan_routes_managed_traffic_after_control_plane_protection() {
        let actions = dry_run_plan(&policy(DevicePolicyRole::ClientGatewayViaPeer)).unwrap();
        assert_eq!(actions[0].kind, PlanActionKind::ProtectControlPlane);
        assert_eq!(actions[1].kind, PlanActionKind::RouteManagedTraffic);
        assert!(actions[1].description.contains("10.126.126.3"));
    }

    #[test]
    fn exit_plan_prepares_forwarding_and_nat() {
        let actions = dry_run_plan(&policy(DevicePolicyRole::ProvideExitForGateway)).unwrap();
        assert_eq!(actions[0].kind, PlanActionKind::PrepareForwarding);
        assert_eq!(actions[1].kind, PlanActionKind::PrepareNat);
        assert!(actions[0].description.contains("10.126.126.2"));
    }
}
