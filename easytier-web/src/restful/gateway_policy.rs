//! 网关策略 REST API
//!
//! 提供策略的 CRUD 操作，通过 proxy-rpc 下发到目标节点。
//! - POST   /api/v1/gateway-policy/:machine-id — 下发策略到指定节点
//! - GET    /api/v1/gateway-policy/:machine-id — 查询节点策略状态
//! - DELETE /api/v1/gateway-policy/:machine-id — 移除节点策略

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use axum_login::AuthUser as _;
use easytier::proto::common::Void;
use easytier::proto::gateway_policy::{GatewayPolicy, GatewayPolicyStatus, GatewayRole};
use easytier::proto::rpc_types::controller::BaseController;
use serde::Deserialize;
use std::sync::Arc;

use super::{AppState, HttpHandleError, other_error};
use crate::client_manager::{ClientManager, session::Session};
use crate::db::UserIdInDb;

/// 双节点网关策略编排请求，一次指定 Source 和 Exit
#[derive(Debug, Deserialize)]
struct GatewayPolicyPairRequest {
    policy_id: String,
    source_machine_id: uuid::Uuid,
    exit_machine_id: uuid::Uuid,
    managed_cidrs: Vec<String>,
    ingress_iface: String,
    exit_peer_tun_ip: String,
    exit_wan_iface: String,
    #[serde(default)]
    easytier_iface: String,
}

/// 双节点网关策略执行结果
#[derive(Debug, serde::Serialize)]
struct GatewayPolicyPairStatus {
    policy_id: String,
    source_machine_id: uuid::Uuid,
    exit_machine_id: uuid::Uuid,
    source_status: GatewayPolicyStatus,
    exit_status: GatewayPolicyStatus,
}

/// 获取当前登录用户 id
fn current_user_id(
    auth_session: &super::users::AuthSession,
) -> Result<UserIdInDb, HttpHandleError> {
    Ok(auth_session
        .user
        .as_ref()
        .ok_or((StatusCode::UNAUTHORIZED, other_error("Unauthorized").into()))?
        .id())
}

/// 获取节点当前在线会话
fn gateway_session(
    client_mgr: &ClientManager,
    user_id: UserIdInDb,
    machine_id: &uuid::Uuid,
) -> Result<Arc<Session>, HttpHandleError> {
    let session = client_mgr
        .get_session_by_machine_id(user_id, machine_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            other_error("Session not found").into(),
        ))?;

    Ok(session)
}

/// 调用指定节点应用策略
async fn apply_policy_to_machine(
    client_mgr: &ClientManager,
    user_id: UserIdInDb,
    machine_id: &uuid::Uuid,
    policy: GatewayPolicy,
) -> Result<GatewayPolicyStatus, HttpHandleError> {
    let session = gateway_session(client_mgr, user_id, machine_id)?;
    let client = session
        .scoped_client::<easytier::proto::gateway_policy::GatewayPolicyRpcClientFactory<BaseController>>();

    client
        .apply_policy(BaseController::default(), policy)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                other_error(format!("RPC Error: {:?}", e)).into(),
            )
        })
}

/// 调用指定节点移除策略
async fn remove_policy_from_machine(
    client_mgr: &ClientManager,
    user_id: UserIdInDb,
    machine_id: &uuid::Uuid,
) -> Result<(), HttpHandleError> {
    let session = gateway_session(client_mgr, user_id, machine_id)?;
    let client = session
        .scoped_client::<easytier::proto::gateway_policy::GatewayPolicyRpcClientFactory<BaseController>>();

    client
        .remove_policy(BaseController::default(), Void::default())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                other_error(format!("RPC Error: {:?}", e)).into(),
            )
        })?;

    Ok(())
}

/// 下发网关策略到指定节点
async fn handle_apply_policy(
    auth_session: super::users::AuthSession,
    State(client_mgr): AppState,
    Path(machine_id): Path<uuid::Uuid>,
    Json(policy): Json<GatewayPolicy>,
) -> Result<Json<GatewayPolicyStatus>, HttpHandleError> {
    let user_id = current_user_id(&auth_session)?;
    let status = apply_policy_to_machine(&client_mgr, user_id, &machine_id, policy).await?;

    Ok(Json(status))
}

/// 编排 Source/Exit 双节点策略，先下发 Exit，再下发 Source，失败时回滚已应用节点
async fn handle_apply_pair_policy(
    auth_session: super::users::AuthSession,
    State(client_mgr): AppState,
    Json(req): Json<GatewayPolicyPairRequest>,
) -> Result<Json<GatewayPolicyPairStatus>, HttpHandleError> {
    let user_id = current_user_id(&auth_session)?;

    let exit_policy = GatewayPolicy {
        policy_id: req.policy_id.clone(),
        enabled: true,
        role: GatewayRole::Exit.into(),
        source_machine_id: req.source_machine_id.to_string(),
        exit_machine_id: req.exit_machine_id.to_string(),
        managed_cidrs: req.managed_cidrs.clone(),
        exit_wan_iface: req.exit_wan_iface.clone(),
        easytier_iface: req.easytier_iface.clone(),
        ..Default::default()
    };

    let source_policy = GatewayPolicy {
        policy_id: req.policy_id.clone(),
        enabled: true,
        role: GatewayRole::Source.into(),
        source_machine_id: req.source_machine_id.to_string(),
        exit_machine_id: req.exit_machine_id.to_string(),
        managed_cidrs: req.managed_cidrs.clone(),
        ingress_iface: req.ingress_iface.clone(),
        exit_peer_tun_ip: req.exit_peer_tun_ip.clone(),
        easytier_iface: req.easytier_iface.clone(),
        ..Default::default()
    };

    let exit_status =
        apply_policy_to_machine(&client_mgr, user_id, &req.exit_machine_id, exit_policy).await?;

    let source_status =
        match apply_policy_to_machine(&client_mgr, user_id, &req.source_machine_id, source_policy)
            .await
        {
            Ok(status) => status,
            Err(err) => {
                let _ =
                    remove_policy_from_machine(&client_mgr, user_id, &req.exit_machine_id).await;
                return Err(err);
            }
        };

    Ok(Json(GatewayPolicyPairStatus {
        policy_id: req.policy_id,
        source_machine_id: req.source_machine_id,
        exit_machine_id: req.exit_machine_id,
        source_status,
        exit_status,
    }))
}

/// 同时移除 Source/Exit 双节点策略
async fn handle_remove_pair_policy(
    auth_session: super::users::AuthSession,
    State(client_mgr): AppState,
    Json(req): Json<GatewayPolicyPairRequest>,
) -> Result<StatusCode, HttpHandleError> {
    let user_id = current_user_id(&auth_session)?;

    let source_result =
        remove_policy_from_machine(&client_mgr, user_id, &req.source_machine_id).await;
    let exit_result = remove_policy_from_machine(&client_mgr, user_id, &req.exit_machine_id).await;

    source_result?;
    exit_result?;

    Ok(StatusCode::NO_CONTENT)
}

/// 查询节点网关策略状态
async fn handle_get_status(
    auth_session: super::users::AuthSession,
    State(client_mgr): AppState,
    Path(machine_id): Path<uuid::Uuid>,
) -> Result<Json<GatewayPolicyStatus>, HttpHandleError> {
    let user_id = current_user_id(&auth_session)?;
    let session = gateway_session(&client_mgr, user_id, &machine_id)?;
    let client = session
        .scoped_client::<easytier::proto::gateway_policy::GatewayPolicyRpcClientFactory<BaseController>>();

    let status = client
        .get_status(BaseController::default(), Void::default())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                other_error(format!("RPC Error: {:?}", e)).into(),
            )
        })?;

    Ok(Json(status))
}

/// 移除节点网关策略
async fn handle_remove_policy(
    auth_session: super::users::AuthSession,
    State(client_mgr): AppState,
    Path(machine_id): Path<uuid::Uuid>,
) -> Result<StatusCode, HttpHandleError> {
    let user_id = current_user_id(&auth_session)?;
    remove_policy_from_machine(&client_mgr, user_id, &machine_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// 构建网关策略路由
pub fn router() -> Router<super::AppStateInner> {
    Router::new()
        .route(
            "/api/v1/gateway-policy/pair",
            post(handle_apply_pair_policy),
        )
        .route(
            "/api/v1/gateway-policy/pair/remove",
            post(handle_remove_pair_policy),
        )
        .route(
            "/api/v1/gateway-policy/:machine-id",
            post(handle_apply_policy),
        )
        .route("/api/v1/gateway-policy/:machine-id", get(handle_get_status))
        .route(
            "/api/v1/gateway-policy/:machine-id",
            delete(handle_remove_policy),
        )
}
