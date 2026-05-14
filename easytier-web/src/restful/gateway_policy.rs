use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router, extract::State};
use axum_login::AuthUser;

use crate::db::UserIdInDb;
use crate::gateway_policy::{
    GatewayFullTunnelPolicy, GatewayPolicySnapshot, PolicyError, RuntimeReport,
};

use super::users::AuthSession;
use super::{AppState, AppStateInner, Error, HttpHandleError, other_error};

fn convert_policy_error(e: PolicyError) -> (StatusCode, Json<Error>) {
    let status = match e {
        PolicyError::MachineReportNotReady => StatusCode::CONFLICT,
        _ => StatusCode::BAD_REQUEST,
    };
    (status, other_error(e.to_string()).into())
}

fn convert_anyhow_error(e: anyhow::Error) -> (StatusCode, Json<Error>) {
    if let Some(policy_error) = e.downcast_ref::<PolicyError>() {
        return convert_policy_error(policy_error.clone());
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        other_error(e.to_string()).into(),
    )
}

pub struct GatewayPolicyApi;

impl GatewayPolicyApi {
    fn get_user_id(auth_session: &AuthSession) -> Result<UserIdInDb, (StatusCode, Json<Error>)> {
        let Some(user_id) = auth_session.user.as_ref().map(|x| x.id()) else {
            return Err((
                StatusCode::UNAUTHORIZED,
                other_error("No user id found".to_string()).into(),
            ));
        };
        Ok(user_id)
    }

    async fn handle_upsert_policy(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Json(policy): Json<GatewayFullTunnelPolicy>,
    ) -> Result<StatusCode, HttpHandleError> {
        let user_id = Self::get_user_id(&auth_session)?;
        client_mgr
            .upsert_gateway_policy(user_id, policy)
            .await
            .map_err(convert_anyhow_error)?;
        Ok(StatusCode::NO_CONTENT)
    }

    async fn handle_list_policies(
        auth_session: AuthSession,
        State(client_mgr): AppState,
    ) -> Result<Json<Vec<GatewayFullTunnelPolicy>>, HttpHandleError> {
        let user_id = Self::get_user_id(&auth_session)?;
        Ok(Json(
            client_mgr
                .list_gateway_policies(user_id)
                .await
                .map_err(convert_anyhow_error)?,
        ))
    }

    async fn handle_get_policy(
        auth_session: AuthSession,
        State(client_mgr): AppState,
        Path(policy_id): Path<uuid::Uuid>,
    ) -> Result<Json<GatewayPolicySnapshot>, HttpHandleError> {
        let user_id = Self::get_user_id(&auth_session)?;
        let Some(snapshot) = client_mgr
            .get_gateway_policy_snapshot(user_id, policy_id)
            .await
            .map_err(convert_anyhow_error)?
        else {
            return Err((
                StatusCode::NOT_FOUND,
                other_error("gateway policy not found").into(),
            ));
        };
        Ok(Json(snapshot))
    }

    async fn handle_get_device_policies_internal(
        State(client_mgr): AppState,
        Path((user_id, machine_id)): Path<(UserIdInDb, uuid::Uuid)>,
    ) -> Result<Json<Vec<crate::gateway_policy::DevicePolicy>>, HttpHandleError> {
        Ok(Json(
            client_mgr
                .gateway_device_policies(user_id, machine_id)
                .await
                .map_err(convert_anyhow_error)?,
        ))
    }

    async fn handle_runtime_report_internal(
        State(client_mgr): AppState,
        Path((user_id, machine_id)): Path<(UserIdInDb, uuid::Uuid)>,
        Json(mut report): Json<RuntimeReport>,
    ) -> Result<StatusCode, HttpHandleError> {
        report.machine_id = machine_id;
        client_mgr
            .update_gateway_runtime_report(user_id, report)
            .await
            .map_err(convert_anyhow_error)?;
        Ok(StatusCode::NO_CONTENT)
    }

    pub fn build_route() -> Router<AppStateInner> {
        Router::new()
            .route(
                "/api/v1/gateway-policies",
                get(Self::handle_list_policies).post(Self::handle_upsert_policy),
            )
            .route(
                "/api/v1/gateway-policies/:policy-id",
                get(Self::handle_get_policy).put(Self::handle_upsert_policy),
            )
    }

    pub fn build_route_internal() -> Router<AppStateInner> {
        Router::new()
            .route(
                "/api/internal/users/:user-id/machines/:machine-id/gateway-policies",
                get(Self::handle_get_device_policies_internal),
            )
            .route(
                "/api/internal/users/:user-id/machines/:machine-id/gateway-report",
                post(Self::handle_runtime_report_internal),
            )
    }
}
