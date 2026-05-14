use crate::platform::CommandPlan;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneEndpoint {
    pub name: String,
    pub host: String,
}

impl ControlPlaneEndpoint {
    pub fn new(name: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
        }
    }
}

pub trait ControlPlaneProbe {
    fn is_reachable(&self, endpoint: &ControlPlaneEndpoint) -> bool;
}

#[derive(Debug, Clone)]
pub struct ControlPlaneGuard {
    endpoints: Vec<ControlPlaneEndpoint>,
}

impl ControlPlaneGuard {
    pub fn new(endpoints: Vec<ControlPlaneEndpoint>) -> Self {
        Self { endpoints }
    }

    pub fn endpoints(&self) -> &[ControlPlaneEndpoint] {
        &self.endpoints
    }

    pub fn verify<P: ControlPlaneProbe>(&self, probe: &P) -> Result<(), ControlPlaneError> {
        for endpoint in &self.endpoints {
            if !probe.is_reachable(endpoint) {
                return Err(ControlPlaneError::Unreachable(endpoint.name.clone()));
            }
        }
        Ok(())
    }

    pub fn protected_route_plan(&self) -> Vec<CommandPlan> {
        self.protected_route_plan_for_table(None)
    }

    pub fn protected_route_plan_for_table(&self, table_id: Option<u32>) -> Vec<CommandPlan> {
        self.endpoints
            .iter()
            .map(|endpoint| {
                let host = endpoint.host.trim_end_matches("/32");
                let quoted_host = shell_single_quote(host);
                let table = table_id
                    .map(|id| format!(" table {id}"))
                    .unwrap_or_default();
                let script = format!(
                    "host={quoted_host}; route=\"$(ip route get \"$host\" | head -n1)\"; dev=\"$(printf '%s\\n' \"$route\" | awk '{{ for (i=1;i<=NF;i++) if ($i==\"dev\") {{ print $(i+1); exit }} }}')\"; via=\"$(printf '%s\\n' \"$route\" | awk '{{ for (i=1;i<=NF;i++) if ($i==\"via\") {{ print $(i+1); exit }} }}')\"; test -n \"$dev\"; if [ -n \"$via\" ]; then ip route replace \"$host/32\" via \"$via\" dev \"$dev\"{table}; else ip route replace \"$host/32\" dev \"$dev\"{table}; fi"
                );
                CommandPlan::new("sh", ["-c", &script])
            })
            .collect()
    }
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlPlaneError {
    #[error("control-plane endpoint is unreachable: {0}")]
    Unreachable(String),
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    struct Probe {
        reachable: HashSet<String>,
    }

    impl ControlPlaneProbe for Probe {
        fn is_reachable(&self, endpoint: &ControlPlaneEndpoint) -> bool {
            self.reachable.contains(&endpoint.name)
        }
    }

    #[test]
    fn verifies_all_control_plane_endpoints() {
        let guard = ControlPlaneGuard::new(vec![
            ControlPlaneEndpoint::new("web", "192.168.64.4/32"),
            ControlPlaneEndpoint::new("relay", "192.168.64.4/32"),
        ]);
        let probe = Probe {
            reachable: ["web".to_string(), "relay".to_string()]
                .into_iter()
                .collect(),
        };
        guard.verify(&probe).unwrap();
    }

    #[test]
    fn fails_when_endpoint_unreachable() {
        let guard =
            ControlPlaneGuard::new(vec![ControlPlaneEndpoint::new("web", "192.168.64.4/32")]);
        let probe = Probe {
            reachable: HashSet::new(),
        };
        assert_eq!(
            guard.verify(&probe),
            Err(ControlPlaneError::Unreachable("web".to_string()))
        );
    }
}
