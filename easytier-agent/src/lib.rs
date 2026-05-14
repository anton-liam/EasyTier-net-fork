pub mod control_plane;
pub mod executor;
pub mod planner;
pub mod platform;
pub mod policy;
pub mod report;
pub mod reporter;
pub mod rollback;
pub mod state;

pub use control_plane::{ControlPlaneEndpoint, ControlPlaneGuard, ControlPlaneProbe};
pub use executor::{
    CommandExecutionFailure, CommandExecutionMode, CommandExecutionReport, CommandExecutor,
    SystemCommandExecutor, apply_command_plan,
};
pub use planner::{PlanAction, PlanActionKind, PlanError, dry_run_plan};
pub use platform::{CommandPlan, PlatformBackend};
pub use policy::{
    DevicePolicy, DevicePolicyRole, ExitEgress, ExitEgressMode, GatewayFullTunnelPolicy,
    PolicyError, PolicyStatus,
};
pub use report::{
    AgentRuntimeReport, build_runtime_report, build_runtime_report_from_failure,
    derive_policy_status,
};
pub use reporter::{ReportTarget, post_runtime_report};
pub use rollback::{ApplyOutcome, apply_with_control_plane_guard};
pub use state::{RouteSnapshot, StateStore};
