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
use easytier::common::config::ConfigSource as RuntimeConfigSource;
use easytier::proto::api::config::{
    ConfigPatchAction, ExitNodePatch, InstanceConfigPatch, PatchConfigRequest, ProxyNetworkPatch,
};
use easytier::proto::api::instance::{
    InstanceIdentifier, instance_identifier::Selector as InstanceSelector,
};
use easytier::proto::api::manage::{NetworkConfig, NetworkingMethod, RunNetworkInstanceRequest};
use easytier::proto::common::{IpAddr, Ipv4Inet, Void};
use easytier::proto::gateway_policy::{GatewayPolicy, GatewayPolicyStatus, GatewayRole};
use easytier::proto::rpc_types::controller::BaseController;
use easytier::rpc_service::remote_client::{RemoteClientManager, Storage};
use serde::Deserialize;
use std::sync::Arc;

use super::{AppState, HttpHandleError, other_error};
use crate::client_manager::{ClientManager, session::Session};
use crate::db::UserIdInDb;

fn default_save_network() -> bool {
    true
}

/// 网关 pair 中需要提前下发基础 EasyTier 组网配置的节点角色
#[derive(Debug, Clone, Copy)]
enum GatewayNetworkRole {
    Source,
    Exit,
}

/// 为 pair 网络生成稳定实例 ID，避免重复下发时不断创建新 tun 实例
fn gateway_network_instance_id(
    req: &GatewayPolicyPairRequest,
    machine_id: &uuid::Uuid,
    role: GatewayNetworkRole,
) -> uuid::Uuid {
    let mut bytes = *machine_id.as_bytes();
    for (idx, byte) in req.policy_id.as_bytes().iter().enumerate() {
        bytes[idx % bytes.len()] ^= *byte;
    }
    bytes[15] ^= match role {
        GatewayNetworkRole::Source => 0x51,
        GatewayNetworkRole::Exit => 0x52,
    };
    uuid::Uuid::from_bytes(bytes)
}

/// 获取 pair 网络中某一角色对应的 machine id
fn gateway_network_machine_id(
    req: &GatewayPolicyPairRequest,
    role: GatewayNetworkRole,
) -> uuid::Uuid {
    match role {
        GatewayNetworkRole::Source => req.source_machine_id,
        GatewayNetworkRole::Exit => req.exit_machine_id,
    }
}

/// 生成指向稳定 pair 网络实例的 ConfigRpc instance selector
fn gateway_network_instance_selector(
    req: &GatewayPolicyPairRequest,
    role: GatewayNetworkRole,
) -> InstanceIdentifier {
    let machine_id = gateway_network_machine_id(req, role);
    InstanceIdentifier {
        selector: Some(InstanceSelector::Id(
            gateway_network_instance_id(req, &machine_id, role).into(),
        )),
    }
}

/// 生成 HTTP 400 错误，集中表达 pair 请求校验失败
fn bad_request(message: impl Into<String>) -> HttpHandleError {
    (StatusCode::BAD_REQUEST, other_error(message.into()).into())
}

/// 校验网关 pair 请求，确保不会在参数明显错误时先产生下发副作用
fn validate_pair_request(req: &GatewayPolicyPairRequest) -> Result<(), HttpHandleError> {
    if req.policy_id.trim().is_empty() {
        return Err(bad_request("policy_id is required"));
    }
    if req.source_machine_id == req.exit_machine_id {
        return Err(bad_request(
            "source_machine_id and exit_machine_id must be different",
        ));
    }
    if req.managed_cidrs.is_empty() {
        return Err(bad_request("managed_cidrs is required"));
    }
    for cidr in &req.managed_cidrs {
        cidr.parse::<Ipv4Inet>()
            .map_err(|e| bad_request(format!("Invalid managed CIDR {}: {}", cidr, e)))?;
    }
    validate_iface("ingress_iface", &req.ingress_iface)?;
    validate_iface("exit_wan_iface", &req.exit_wan_iface)?;
    if !req.easytier_iface.trim().is_empty() {
        validate_iface("easytier_iface", &req.easytier_iface)?;
    }
    req.exit_peer_tun_ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|e| {
            bad_request(format!(
                "Invalid exit_peer_tun_ip {}: {}",
                req.exit_peer_tun_ip, e
            ))
        })?;

    if let Some(length) = req.network_length
        && !(1..=32).contains(&length)
    {
        return Err(bad_request("network_length must be between 1 and 32"));
    }

    if !req.peer_urls.is_empty() {
        let network_name = req
            .network_name
            .as_deref()
            .ok_or_else(|| bad_request("network_name is required when peer_urls is set"))?;
        if network_name.trim().is_empty() {
            return Err(bad_request(
                "network_name is required when peer_urls is set",
            ));
        }
        let network_secret = req
            .network_secret
            .as_deref()
            .ok_or_else(|| bad_request("network_secret is required when peer_urls is set"))?;
        if network_secret.trim().is_empty() {
            return Err(bad_request(
                "network_secret is required when peer_urls is set",
            ));
        }
        let source_peer_tun_ip = req
            .source_peer_tun_ip
            .as_deref()
            .ok_or_else(|| bad_request("source_peer_tun_ip is required when peer_urls is set"))?;
        source_peer_tun_ip
            .parse::<std::net::Ipv4Addr>()
            .map_err(|e| {
                bad_request(format!(
                    "Invalid source_peer_tun_ip {}: {}",
                    source_peer_tun_ip, e
                ))
            })?;
        if source_peer_tun_ip == req.exit_peer_tun_ip {
            return Err(bad_request(
                "source_peer_tun_ip and exit_peer_tun_ip must be different",
            ));
        }
        for peer_url in &req.peer_urls {
            validate_peer_url(peer_url)?;
        }
    }

    Ok(())
}

/// 校验产品允许的 EasyTier peer URL；当前 C relay 只允许 tcp/udp
fn validate_peer_url(peer_url: &str) -> Result<(), HttpHandleError> {
    let url = url::Url::parse(peer_url)
        .map_err(|e| bad_request(format!("Invalid peer URL {}: {}", peer_url, e)))?;
    match url.scheme() {
        "tcp" | "udp" => Ok(()),
        scheme => Err(bad_request(format!(
            "Unsupported peer URL scheme {} in {}. Allowed schemes: tcp, udp",
            scheme, peer_url
        ))),
    }
}

/// 校验网关 pair 删除请求，确保还原策略不会在参数错误时留下半清理状态
fn validate_pair_remove_request(req: &GatewayPolicyPairRequest) -> Result<(), HttpHandleError> {
    validate_pair_request(req)
}

/// 校验 Linux 网口名，避免空值或明显非法参数进入命令执行
fn validate_iface(field: &str, iface: &str) -> Result<(), HttpHandleError> {
    if iface.trim().is_empty() {
        return Err(bad_request(format!("{} is required", field)));
    }

    let valid = iface
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'));
    if !valid {
        return Err(bad_request(format!(
            "{} contains invalid characters: {}",
            field, iface
        )));
    }

    Ok(())
}

/// 将网关 pair 请求转换成 EasyTier 原生配置补丁，用于补齐子网回程和出口 peer 选择
fn build_source_native_patch_request(
    req: &GatewayPolicyPairRequest,
    action: ConfigPatchAction,
    role: GatewayNetworkRole,
) -> Result<PatchConfigRequest, HttpHandleError> {
    let proxy_networks = req
        .managed_cidrs
        .iter()
        .map(|cidr| {
            let cidr = cidr.parse::<Ipv4Inet>().map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    other_error(format!("Invalid managed CIDR {}: {}", cidr, e)).into(),
                )
            })?;

            Ok(ProxyNetworkPatch {
                action: action.into(),
                cidr: Some(cidr),
                mapped_cidr: None,
            })
        })
        .collect::<Result<Vec<_>, HttpHandleError>>()?;

    let exit_node = req.exit_peer_tun_ip.parse::<IpAddr>().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            other_error(format!(
                "Invalid exit peer tunnel IP {}: {}",
                req.exit_peer_tun_ip, e
            ))
            .into(),
        )
    })?;

    Ok(PatchConfigRequest {
        instance: Some(gateway_network_instance_selector(req, role)),
        patch: Some(InstanceConfigPatch {
            proxy_networks,
            exit_nodes: vec![ExitNodePatch {
                action: action.into(),
                node: Some(exit_node),
            }],
            ..Default::default()
        }),
    })
}

/// 构造 A/B 的基础组网配置，让 Web 先下发 peer_urls，再下发出口策略
fn build_pair_network_config(
    req: &GatewayPolicyPairRequest,
    role: GatewayNetworkRole,
) -> Result<Option<NetworkConfig>, HttpHandleError> {
    if req.peer_urls.is_empty() {
        return Ok(None);
    }

    let network_name = req.network_name.clone().ok_or((
        StatusCode::BAD_REQUEST,
        other_error("network_name is required when peer_urls is set").into(),
    ))?;
    let network_secret = req.network_secret.clone().ok_or((
        StatusCode::BAD_REQUEST,
        other_error("network_secret is required when peer_urls is set").into(),
    ))?;

    let virtual_ipv4 = match role {
        GatewayNetworkRole::Source => req.source_peer_tun_ip.clone().ok_or((
            StatusCode::BAD_REQUEST,
            other_error("source_peer_tun_ip is required when peer_urls is set").into(),
        ))?,
        GatewayNetworkRole::Exit => req.exit_peer_tun_ip.clone(),
    };

    let dev_name = if req.easytier_iface.is_empty() {
        "tun0".to_string()
    } else {
        req.easytier_iface.clone()
    };

    Ok(Some(NetworkConfig {
        virtual_ipv4: Some(virtual_ipv4),
        network_length: Some(req.network_length.unwrap_or(24)),
        network_name: Some(network_name),
        network_secret: Some(network_secret),
        networking_method: Some(NetworkingMethod::Manual.into()),
        peer_urls: req.peer_urls.clone(),
        dev_name: Some(dev_name),
        proxy_forward_by_system: Some(true),
        disable_ipv6: Some(true),
        disable_p2p: req.disable_p2p,
        ..Default::default()
    }))
}

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
    #[serde(default)]
    network_name: Option<String>,
    #[serde(default)]
    network_secret: Option<String>,
    #[serde(default)]
    source_peer_tun_ip: Option<String>,
    #[serde(default)]
    network_length: Option<i32>,
    #[serde(default)]
    peer_urls: Vec<String>,
    #[serde(default)]
    disable_p2p: Option<bool>,
    #[serde(default = "default_save_network")]
    save_network: bool,
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

/// 通过 ConfigRpc 调整 Source 节点上的 EasyTier 原生子网代理和出口节点配置
async fn patch_source_native_config(
    client_mgr: &ClientManager,
    user_id: UserIdInDb,
    machine_id: &uuid::Uuid,
    req: &GatewayPolicyPairRequest,
    action: ConfigPatchAction,
) -> Result<(), HttpHandleError> {
    let session = gateway_session(client_mgr, user_id, machine_id)?;
    let client = session
        .scoped_client::<easytier::proto::api::config::ConfigRpcClientFactory<BaseController>>();
    let patch = build_source_native_patch_request(req, action, GatewayNetworkRole::Source)?;

    client
        .patch_config(BaseController::default(), patch)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                other_error(format!("RPC Error: {:?}", e)).into(),
            )
        })?;

    Ok(())
}

/// 通过 WebClient 原生能力下发基础组网配置，peer_urls 通常指向 C 的搭线节点
async fn ensure_pair_network_config(
    client_mgr: &ClientManager,
    user_id: UserIdInDb,
    machine_id: &uuid::Uuid,
    req: &GatewayPolicyPairRequest,
    role: GatewayNetworkRole,
) -> Result<(), HttpHandleError> {
    let Some(config) = build_pair_network_config(req, role)? else {
        return Ok(());
    };
    let inst_id = gateway_network_instance_id(req, machine_id, role);
    let session = gateway_session(client_mgr, user_id, machine_id)?;
    let client = session.scoped_rpc_client();

    client
        .run_network_instance(
            BaseController::default(),
            RunNetworkInstanceRequest {
                inst_id: Some(inst_id.to_string().into()),
                config: Some(config.clone()),
                overwrite: true,
                source: RuntimeConfigSource::User.to_rpc(),
            },
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                other_error(format!("Run network Error: {:?}", e)).into(),
            )
        })?;

    if req.save_network {
        client_mgr
            .get_storage()
            .insert_or_update_user_network_config(
                (user_id, *machine_id),
                inst_id,
                config,
                RuntimeConfigSource::User,
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    other_error(format!("Save network Error: {:?}", e)).into(),
                )
            })?;
    }

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
    validate_pair_request(&req)?;

    ensure_pair_network_config(
        &client_mgr,
        user_id,
        &req.source_machine_id,
        &req,
        GatewayNetworkRole::Source,
    )
    .await?;
    ensure_pair_network_config(
        &client_mgr,
        user_id,
        &req.exit_machine_id,
        &req,
        GatewayNetworkRole::Exit,
    )
    .await?;

    // 基础 EasyTier network instance 属于设备管理配置，失败时保留；
    // 下面只回滚 gateway policy 和 Source 原生 proxy/exit 补丁。
    patch_source_native_config(
        &client_mgr,
        user_id,
        &req.source_machine_id,
        &req,
        ConfigPatchAction::Add,
    )
    .await?;

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

    let exit_status = match apply_policy_to_machine(
        &client_mgr,
        user_id,
        &req.exit_machine_id,
        exit_policy,
    )
    .await
    {
        Ok(status) => status,
        Err(err) => {
            let _ = patch_source_native_config(
                &client_mgr,
                user_id,
                &req.source_machine_id,
                &req,
                ConfigPatchAction::Remove,
            )
            .await;
            return Err(err);
        }
    };

    let source_status =
        match apply_policy_to_machine(&client_mgr, user_id, &req.source_machine_id, source_policy)
            .await
        {
            Ok(status) => status,
            Err(err) => {
                let _ =
                    remove_policy_from_machine(&client_mgr, user_id, &req.exit_machine_id).await;
                let _ = patch_source_native_config(
                    &client_mgr,
                    user_id,
                    &req.source_machine_id,
                    &req,
                    ConfigPatchAction::Remove,
                )
                .await;
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
    validate_pair_remove_request(&req)?;

    let source_result =
        remove_policy_from_machine(&client_mgr, user_id, &req.source_machine_id).await;
    let exit_result = remove_policy_from_machine(&client_mgr, user_id, &req.exit_machine_id).await;
    let native_result = patch_source_native_config(
        &client_mgr,
        user_id,
        &req.source_machine_id,
        &req,
        ConfigPatchAction::Remove,
    )
    .await;

    source_result?;
    exit_result?;
    native_result?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use easytier::proto::api::config::ConfigPatchAction;
    use easytier::proto::api::instance::instance_identifier::Selector;
    use easytier::proto::api::manage::NetworkingMethod;

    fn pair_request() -> GatewayPolicyPairRequest {
        GatewayPolicyPairRequest {
            policy_id: "utm-gw-001".to_string(),
            source_machine_id: uuid::Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
                .unwrap(),
            exit_machine_id: uuid::Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap(),
            managed_cidrs: vec!["192.168.128.0/24".to_string()],
            ingress_iface: "br-lan".to_string(),
            exit_peer_tun_ip: "10.126.126.3".to_string(),
            exit_wan_iface: "eth0".to_string(),
            easytier_iface: "tun0".to_string(),
            network_name: Some("utm-gw".to_string()),
            network_secret: Some("utm-gw-secret".to_string()),
            source_peer_tun_ip: Some("10.126.126.2".to_string()),
            network_length: Some(24),
            peer_urls: vec!["udp://192.168.64.4:11010".to_string()],
            disable_p2p: Some(true),
            save_network: true,
        }
    }

    #[test]
    fn pair_network_config_uses_controller_peer_for_source_and_exit() {
        let req = pair_request();
        let source = build_pair_network_config(&req, GatewayNetworkRole::Source)
            .unwrap()
            .unwrap();
        let exit = build_pair_network_config(&req, GatewayNetworkRole::Exit)
            .unwrap()
            .unwrap();

        assert_eq!(source.network_name.as_deref(), Some("utm-gw"));
        assert_eq!(source.network_secret.as_deref(), Some("utm-gw-secret"));
        assert_eq!(source.peer_urls, vec!["udp://192.168.64.4:11010"]);
        assert_eq!(source.virtual_ipv4.as_deref(), Some("10.126.126.2"));
        assert_eq!(source.network_length, Some(24));
        assert_eq!(source.dev_name.as_deref(), Some("tun0"));
        assert_eq!(
            source.networking_method,
            Some(NetworkingMethod::Manual as i32)
        );
        assert_eq!(source.proxy_forward_by_system, Some(true));
        assert_eq!(source.disable_ipv6, Some(true));
        assert_eq!(source.disable_p2p, Some(true));

        assert_eq!(exit.peer_urls, vec!["udp://192.168.64.4:11010"]);
        assert_eq!(exit.virtual_ipv4.as_deref(), Some("10.126.126.3"));
    }

    #[test]
    fn native_patch_adds_proxy_cidrs_and_exit_node_to_source() {
        let request = build_source_native_patch_request(
            &pair_request(),
            ConfigPatchAction::Add,
            GatewayNetworkRole::Source,
        )
        .unwrap();
        let patch = request.patch.unwrap();

        assert_eq!(patch.proxy_networks.len(), 1);
        assert_eq!(
            patch.proxy_networks[0].action,
            ConfigPatchAction::Add as i32
        );
        assert_eq!(
            patch.proxy_networks[0].cidr.unwrap().to_string(),
            "192.168.128.0/24"
        );
        assert_eq!(patch.exit_nodes.len(), 1);
        assert_eq!(patch.exit_nodes[0].action, ConfigPatchAction::Add as i32);
        assert_eq!(
            patch.exit_nodes[0].node.unwrap().to_string(),
            "10.126.126.3"
        );
    }

    #[test]
    fn native_patch_removes_proxy_cidrs_and_exit_node_from_source() {
        let request = build_source_native_patch_request(
            &pair_request(),
            ConfigPatchAction::Remove,
            GatewayNetworkRole::Source,
        )
        .unwrap();
        let patch = request.patch.unwrap();

        assert_eq!(
            patch.proxy_networks[0].action,
            ConfigPatchAction::Remove as i32
        );
        assert_eq!(patch.exit_nodes[0].action, ConfigPatchAction::Remove as i32);
    }

    #[test]
    fn native_patch_rejects_invalid_cidr() {
        let mut req = pair_request();
        req.managed_cidrs = vec!["not-a-cidr".to_string()];

        let err = build_source_native_patch_request(
            &req,
            ConfigPatchAction::Add,
            GatewayNetworkRole::Source,
        )
        .unwrap_err()
        .0;

        assert_eq!(err, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn native_patch_rejects_invalid_exit_node() {
        let mut req = pair_request();
        req.exit_peer_tun_ip = "not-an-ip".to_string();

        let err = build_source_native_patch_request(
            &req,
            ConfigPatchAction::Add,
            GatewayNetworkRole::Source,
        )
        .unwrap_err()
        .0;

        assert_eq!(err, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn native_patch_targets_stable_pair_instance() {
        let req = pair_request();
        let request = build_source_native_patch_request(
            &req,
            ConfigPatchAction::Add,
            GatewayNetworkRole::Source,
        )
        .unwrap();
        let expected =
            gateway_network_instance_id(&req, &req.source_machine_id, GatewayNetworkRole::Source);

        let Some(instance) = request.instance else {
            panic!("native patch should target the pair network instance");
        };
        let Some(Selector::Id(id)) = instance.selector else {
            panic!("native patch should use an instance id selector");
        };

        assert_eq!(uuid::Uuid::from(id), expected);
    }

    #[test]
    fn pair_request_validation_rejects_invalid_network_length_before_side_effects() {
        let mut req = pair_request();
        req.network_length = Some(33);

        let err = validate_pair_request(&req).unwrap_err().0;

        assert_eq!(err, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn pair_request_validation_rejects_invalid_source_tunnel_ip() {
        let mut req = pair_request();
        req.source_peer_tun_ip = Some("not-an-ip".to_string());

        let err = validate_pair_request(&req).unwrap_err().0;

        assert_eq!(err, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn pair_request_validation_rejects_unsupported_peer_url_scheme() {
        let mut req = pair_request();
        req.peer_urls = vec!["http://192.168.64.4:11010".to_string()];

        let err = validate_pair_request(&req).unwrap_err().0;

        assert_eq!(err, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn pair_request_validation_allows_tcp_and_udp_peer_url_schemes() {
        let mut req = pair_request();
        req.peer_urls = vec![
            "udp://192.168.64.4:11010".to_string(),
            "tcp://192.168.64.4:11010".to_string(),
        ];

        validate_pair_request(&req).unwrap();
    }

    #[test]
    fn pair_remove_validation_accepts_request_without_network_bootstrap_fields() {
        let mut req = pair_request();
        req.network_name = None;
        req.network_secret = None;
        req.source_peer_tun_ip = None;
        req.peer_urls.clear();
        req.disable_p2p = None;

        validate_pair_remove_request(&req).unwrap();
    }

    #[test]
    fn pair_remove_validation_rejects_invalid_cidr_before_side_effects() {
        let mut req = pair_request();
        req.peer_urls.clear();
        req.managed_cidrs = vec!["not-a-cidr".to_string()];

        let err = validate_pair_remove_request(&req).unwrap_err().0;

        assert_eq!(err, StatusCode::BAD_REQUEST);
    }
}
