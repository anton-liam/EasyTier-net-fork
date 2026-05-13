#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSnapshot {
    pub policy_id: String,
    pub version: u64,
    pub commands: Vec<String>,
}

impl RouteSnapshot {
    pub fn new(policy_id: impl Into<String>, version: u64, commands: Vec<String>) -> Self {
        Self {
            policy_id: policy_id.into(),
            version,
            commands,
        }
    }
}

pub trait StateStore {
    fn save_last_known_good(&mut self, snapshot: RouteSnapshot);

    fn last_known_good(&self) -> Option<&RouteSnapshot>;
}

#[derive(Debug, Default)]
pub struct MemoryStateStore {
    snapshot: Option<RouteSnapshot>,
}

impl StateStore for MemoryStateStore {
    fn save_last_known_good(&mut self, snapshot: RouteSnapshot) {
        self.snapshot = Some(snapshot);
    }

    fn last_known_good(&self) -> Option<&RouteSnapshot> {
        self.snapshot.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_last_known_good_snapshot() {
        let mut store = MemoryStateStore::default();
        store.save_last_known_good(RouteSnapshot::new(
            "p1",
            1,
            vec!["ip route show default".to_string()],
        ));
        assert_eq!(store.last_known_good().unwrap().policy_id, "p1");
    }
}

