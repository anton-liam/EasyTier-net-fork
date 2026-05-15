use std::collections::HashMap;

use crate::DevicePolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileEvent {
    Apply(String, u64),
}

#[derive(Debug, Default)]
pub struct PolicyReconciler {
    observed_versions: HashMap<String, u64>,
}

impl PolicyReconciler {
    pub fn reconcile(&mut self, policies: &[DevicePolicy]) -> anyhow::Result<Vec<ReconcileEvent>> {
        let mut events = Vec::new();
        for policy in policies {
            policy.validate()?;
            let observed_version = self
                .observed_versions
                .get(&policy.device_policy_id)
                .copied();
            if observed_version != Some(policy.version) {
                self.observed_versions
                    .insert(policy.device_policy_id.clone(), policy.version);
                events.push(ReconcileEvent::Apply(
                    policy.device_policy_id.clone(),
                    policy.version,
                ));
            }
        }
        Ok(events)
    }

    pub fn observed_version(&self, device_policy_id: &str) -> Option<u64> {
        self.observed_versions.get(device_policy_id).copied()
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::{DevicePolicy, DevicePolicyRole, ExitEgress, PolicyReconciler, ReconcileEvent};

    fn policy(device_policy_id: &str, version: u64) -> DevicePolicy {
        DevicePolicy {
            policy_id: "p1".to_string(),
            device_policy_id: device_policy_id.to_string(),
            version,
            role: DevicePolicyRole::ClientGatewayViaPeer,
            network_instance_id: Uuid::nil(),
            source_machine_id: "node-a".to_string(),
            managed_cidrs: vec!["192.168.10.0/24".to_string()],
            ingress_ifaces: vec!["br-lan".to_string()],
            include_device_traffic: true,
            exit_machine_id: "node-b".to_string(),
            exit_peer_ipv4: Some("10.126.126.3".to_string()),
            source_peer_ipv4: None,
            exit_egress: ExitEgress::default(),
            protect_control_plane: true,
            rollback_enabled: true,
        }
    }

    #[test]
    fn reconcile_applies_new_policy_once() {
        let mut reconciler = PolicyReconciler::default();

        let first = reconciler.reconcile(&[policy("p1/source", 1)]).unwrap();
        let second = reconciler.reconcile(&[policy("p1/source", 1)]).unwrap();

        assert_eq!(
            first,
            vec![ReconcileEvent::Apply("p1/source".to_string(), 1)]
        );
        assert!(second.is_empty());
        assert_eq!(reconciler.observed_version("p1/source"), Some(1));
    }

    #[test]
    fn reconcile_reapplies_newer_version() {
        let mut reconciler = PolicyReconciler::default();
        reconciler.reconcile(&[policy("p1/source", 1)]).unwrap();

        let events = reconciler.reconcile(&[policy("p1/source", 2)]).unwrap();

        assert_eq!(
            events,
            vec![ReconcileEvent::Apply("p1/source".to_string(), 2)]
        );
        assert_eq!(reconciler.observed_version("p1/source"), Some(2));
    }
}
