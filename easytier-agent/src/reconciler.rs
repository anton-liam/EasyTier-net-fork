use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::DevicePolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileEvent {
    Apply(String, u64),
}

#[derive(Debug)]
struct ObservedPolicy {
    version: u64,
    applied_at: Instant,
}

#[derive(Debug, Default)]
pub struct PolicyReconciler {
    observed_versions: HashMap<String, ObservedPolicy>,
}

impl PolicyReconciler {
    pub fn reconcile(&mut self, policies: &[DevicePolicy]) -> anyhow::Result<Vec<ReconcileEvent>> {
        Ok(self
            .policies_to_apply(policies)?
            .into_iter()
            .map(|policy| ReconcileEvent::Apply(policy.device_policy_id, policy.version))
            .collect())
    }

    pub fn policies_to_apply(
        &mut self,
        policies: &[DevicePolicy],
    ) -> anyhow::Result<Vec<DevicePolicy>> {
        self.policies_to_apply_at(policies, Instant::now(), None)
    }

    pub fn policies_to_apply_at(
        &mut self,
        policies: &[DevicePolicy],
        now: Instant,
        reapply_interval: Option<Duration>,
    ) -> anyhow::Result<Vec<DevicePolicy>> {
        let mut policies_to_apply = Vec::new();
        for policy in policies {
            policy.validate()?;
            let observed = self.observed_versions.get(&policy.device_policy_id);
            let version_changed = observed.map(|observed| observed.version) != Some(policy.version);
            let reapply_due = observed.is_some_and(|observed| {
                reapply_interval.is_some_and(|interval| {
                    now.duration_since(observed.applied_at) >= interval
                })
            });
            if version_changed || reapply_due {
                self.observed_versions.insert(
                    policy.device_policy_id.clone(),
                    ObservedPolicy {
                        version: policy.version,
                        applied_at: now,
                    },
                );
                policies_to_apply.push(policy.clone());
            }
        }
        Ok(policies_to_apply)
    }

    pub fn observed_version(&self, device_policy_id: &str) -> Option<u64> {
        self.observed_versions
            .get(device_policy_id)
            .map(|observed| observed.version)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

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

    #[test]
    fn policies_to_apply_returns_only_new_versions() {
        let mut reconciler = PolicyReconciler::default();
        let first = policy("p1/source", 1);
        let second = policy("p1/source", 2);

        assert_eq!(
            reconciler.policies_to_apply(&[first.clone()]).unwrap(),
            vec![first.clone()]
        );
        assert!(reconciler.policies_to_apply(&[first]).unwrap().is_empty());
        assert_eq!(
            reconciler.policies_to_apply(&[second.clone()]).unwrap(),
            vec![second]
        );
    }

    #[test]
    fn policies_to_apply_reapplies_after_interval() {
        let mut reconciler = PolicyReconciler::default();
        let policy = policy("p1/source", 1);
        let started_at = Instant::now();

        assert_eq!(
            reconciler
                .policies_to_apply_at(&[policy.clone()], started_at, Some(Duration::from_secs(60)))
                .unwrap(),
            vec![policy.clone()]
        );
        assert!(
            reconciler
                .policies_to_apply_at(
                    &[policy.clone()],
                    started_at + Duration::from_secs(59),
                    Some(Duration::from_secs(60))
                )
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            reconciler
                .policies_to_apply_at(
                    &[policy.clone()],
                    started_at + Duration::from_secs(60),
                    Some(Duration::from_secs(60))
                )
                .unwrap(),
            vec![policy]
        );
    }
}
