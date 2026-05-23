pub mod control_plane;
pub mod credential;
pub mod executor;
pub mod planner;
pub mod platform;
pub mod policy;
pub mod reconciler;
pub mod report;
pub mod reporter;
pub mod rollback;
pub mod state;

pub use control_plane::{ControlPlaneEndpoint, ControlPlaneGuard, ControlPlaneProbe};
pub use credential::{MachineCredentialFile, read_credential, write_credential_atomic};
pub use credential::{
    confirm_credential, credential_status, enroll_agent, enroll_and_store_agent,
    rotate_and_confirm_credential, rotate_credential,
};
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
pub use reconciler::{PolicyReconciler, ReconcileEvent};
pub use report::{
    AgentRuntimeObservation, AgentRuntimeReport, build_idle_runtime_report, build_runtime_report,
    build_runtime_report_from_failure, derive_policy_status, derive_policy_status_for_policy,
};
pub use reporter::{AgentApiAuth, ReportTarget, fetch_device_policies, post_runtime_report};
pub use rollback::{ApplyOutcome, apply_with_control_plane_guard};
pub use state::{RouteSnapshot, StateStore};
