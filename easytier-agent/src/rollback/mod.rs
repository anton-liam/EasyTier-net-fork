use crate::{
    control_plane::{ControlPlaneError, ControlPlaneGuard, ControlPlaneProbe},
    platform::{CommandPlan, PlatformBackend},
    policy::{DevicePolicy, PolicyStatus},
    state::{RouteSnapshot, StateStore},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub status: PolicyStatus,
    pub apply_plan: Vec<CommandPlan>,
    pub rollback_plan: Vec<CommandPlan>,
}

pub fn apply_with_control_plane_guard<B, P, S>(
    backend: &B,
    probe: &P,
    state: &mut S,
    guard: &ControlPlaneGuard,
    policy: &DevicePolicy,
) -> Result<ApplyOutcome, ApplyError>
where
    B: PlatformBackend,
    P: ControlPlaneProbe,
    S: StateStore,
{
    guard.verify(probe).map_err(ApplyError::Preflight)?;

    let mut apply_plan = guard.protected_route_plan();
    apply_plan.extend(backend.plan_apply(policy)?);

    state.save_last_known_good(RouteSnapshot::new(
        policy.policy_id.clone(),
        policy.version,
        apply_plan
            .iter()
            .map(|cmd| format!("{} {}", cmd.program, cmd.args.join(" ")))
            .collect(),
    ));

    match guard.verify(probe) {
        Ok(()) => Ok(ApplyOutcome {
            status: PolicyStatus::Active,
            apply_plan,
            rollback_plan: Vec::new(),
        }),
        Err(_) => Ok(ApplyOutcome {
            status: PolicyStatus::Rollbacked,
            apply_plan,
            rollback_plan: backend.plan_cleanup(policy)?,
        }),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("preflight control-plane check failed: {0}")]
    Preflight(ControlPlaneError),
    #[error("post-apply control-plane check failed: {0}")]
    PostApply(ControlPlaneError),
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::HashSet};

    use uuid::Uuid;

    use super::*;
    use crate::{
        control_plane::ControlPlaneEndpoint,
        platform::linux::LinuxBackend,
        policy::{DevicePolicyRole, ExitEgress},
        state::MemoryStateStore,
    };

    struct StaticProbe {
        reachable: HashSet<String>,
    }

    impl ControlPlaneProbe for StaticProbe {
        fn is_reachable(&self, endpoint: &ControlPlaneEndpoint) -> bool {
            self.reachable.contains(&endpoint.name)
        }
    }

    struct FlakyProbe {
        first: Cell<bool>,
    }

    impl ControlPlaneProbe for FlakyProbe {
        fn is_reachable(&self, _endpoint: &ControlPlaneEndpoint) -> bool {
            if self.first.replace(false) {
                true
            } else {
                false
            }
        }
    }

    fn policy() -> DevicePolicy {
        DevicePolicy {
            policy_id: "p1".to_string(),
            device_policy_id: "p1/source".to_string(),
            enabled: true,
            version: 1,
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

    fn guard() -> ControlPlaneGuard {
        ControlPlaneGuard::new(vec![ControlPlaneEndpoint::new("web", "192.168.64.4/32")])
    }

    #[test]
    fn refuses_to_apply_when_preflight_fails() {
        let backend = LinuxBackend::default();
        let probe = StaticProbe {
            reachable: HashSet::new(),
        };
        let mut state = MemoryStateStore::default();
        let err = apply_with_control_plane_guard(&backend, &probe, &mut state, &guard(), &policy())
            .unwrap_err();
        assert!(matches!(err, ApplyError::Preflight(_)));
    }

    #[test]
    fn returns_active_when_control_plane_stays_reachable() {
        let backend = LinuxBackend::default();
        let probe = StaticProbe {
            reachable: ["web".to_string()].into_iter().collect(),
        };
        let mut state = MemoryStateStore::default();
        let outcome =
            apply_with_control_plane_guard(&backend, &probe, &mut state, &guard(), &policy())
                .unwrap();
        assert_eq!(outcome.status, PolicyStatus::Active);
        assert!(state.last_known_good().is_some());
    }

    #[test]
    fn returns_rollbacked_when_post_apply_check_fails() {
        let backend = LinuxBackend::default();
        let probe = FlakyProbe {
            first: Cell::new(true),
        };
        let mut state = MemoryStateStore::default();
        let outcome =
            apply_with_control_plane_guard(&backend, &probe, &mut state, &guard(), &policy())
                .unwrap();
        assert_eq!(outcome.status, PolicyStatus::Rollbacked);
        assert!(!outcome.rollback_plan.is_empty());
    }
}
