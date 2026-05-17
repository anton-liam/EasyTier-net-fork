pub mod linux;
pub mod openwrt;

use crate::policy::DevicePolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPlan {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandPlan {
    pub fn new<I, S>(program: impl Into<String>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

pub trait PlatformBackend {
    fn plan_apply(&self, policy: &DevicePolicy) -> anyhow::Result<Vec<CommandPlan>>;

    fn plan_cleanup(&self, policy: &DevicePolicy) -> anyhow::Result<Vec<CommandPlan>>;
}
