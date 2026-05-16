use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router, extract::State};
use axum_login::AuthUser;

use crate::db::UserIdInDb;
use crate::gateway_policy::{
    GatewayFullTunnelPolicy, GatewayPolicyNode, GatewayPolicySnapshot, PolicyError, RuntimeReport,
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
    ) -> Result<Json<Vec<GatewayPolicySnapshot>>, HttpHandleError> {
        let user_id = Self::get_user_id(&auth_session)?;
        Ok(Json(
            client_mgr
                .list_gateway_policy_snapshots(user_id)
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

    async fn handle_list_nodes(
        auth_session: AuthSession,
        State(client_mgr): AppState,
    ) -> Result<Json<Vec<GatewayPolicyNode>>, HttpHandleError> {
        let user_id = Self::get_user_id(&auth_session)?;
        Ok(Json(
            client_mgr
                .list_gateway_policy_nodes(user_id)
                .await
                .map_err(convert_anyhow_error)?,
        ))
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
            .route("/api/v1/gateway-nodes", get(Self::handle_list_nodes))
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

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use axum::http::header;
    use easytier::tunnel::udp::UdpTunnelListener;
    use reqwest::StatusCode;

    use crate::{
        FeatureFlags,
        client_manager::ClientManager,
        db::Db,
        gateway_policy::{
            ExitEgress, GatewayFullTunnelPolicy, HealthcheckConfig, RollbackConfig, RuntimeReport,
        },
        restful::{RestfulServer, oidc::OidcConfig, users::Credentials},
        webhook::WebhookConfig,
    };

    fn base_gateway_policy(source: uuid::Uuid, exit: uuid::Uuid) -> GatewayFullTunnelPolicy {
        GatewayFullTunnelPolicy {
            policy_id: uuid::Uuid::new_v4(),
            enabled: true,
            network_instance_id: uuid::Uuid::new_v4(),
            source_machine_id: source,
            managed_cidrs: vec!["192.168.10.0/24".to_string()],
            ingress_ifaces: vec!["br-lan".to_string()],
            include_device_traffic: true,
            exit_machine_id: exit,
            exit_egress: ExitEgress::default(),
            desired_version: 1,
            protect_control_plane: true,
            healthcheck: HealthcheckConfig::default(),
            rollback: RollbackConfig::default(),
        }
    }

    fn next_http_addr() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    fn cookie_header(response: &reqwest::Response) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split(';').next())
            .collect::<Vec<_>>()
            .join("; ")
    }

    async fn test_server() -> (String, Db, i32, tokio_util::task::AbortOnDropHandle<()>) {
        let db_path = std::env::temp_dir().join(format!(
            "easytier-web-gateway-policy-test-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db = Db::new(db_path.to_string_lossy()).await.unwrap();
        let user_id = db
            .create_user_and_join_users_group(
                "gateway-user",
                password_auth::generate_hash("secret"),
            )
            .await
            .unwrap()
            .id;

        let webhook_config = Arc::new(WebhookConfig::new(
            None,
            None,
            Some("internal-token".to_string()),
            None,
            None,
        ));
        let mut client_mgr = ClientManager::new(
            db.clone(),
            None,
            Arc::new(FeatureFlags::default()),
            webhook_config.clone(),
        );
        client_mgr
            .add_listener(Box::new(UdpTunnelListener::new(
                "udp://127.0.0.1:0".parse().unwrap(),
            )))
            .await
            .unwrap();
        let client_mgr = Arc::new(client_mgr);
        let http_addr = next_http_addr();
        let server = RestfulServer::new(
            http_addr,
            client_mgr,
            db.clone(),
            None,
            Arc::new(FeatureFlags::default()),
            OidcConfig::disabled(),
            webhook_config,
        )
        .await
        .unwrap();
        let (serve_task, _session_cleanup_task) = server.start().await.unwrap();

        (
            format!("http://{}", http_addr),
            db,
            user_id,
            serve_task,
        )
    }

    #[tokio::test]
    async fn gateway_policy_rest_round_trip_lists_observed_snapshots() {
        let (base_url, _db, user_id, _server) = test_server().await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let source = uuid::Uuid::new_v4();
        let exit = uuid::Uuid::new_v4();
        let policy = base_gateway_policy(source, exit);

        let login = client
            .post(format!("{}/api/v1/auth/login", base_url))
            .json(&Credentials {
                username: "gateway-user".to_string(),
                password: "secret".to_string(),
            })
            .send()
            .await
            .unwrap();
        let login_status = login.status();
        let cookie = cookie_header(&login);
        let login_headers = login.headers().clone();
        let login_body = login.text().await.unwrap();
        assert_eq!(
            login_status,
            StatusCode::OK,
            "login headers: {login_headers:?}, body: {login_body}"
        );

        let upsert = client
            .post(format!("{}/api/v1/gateway-policies", base_url))
            .header(header::COOKIE, cookie.clone())
            .json(&policy)
            .send()
            .await
            .unwrap();
        assert_eq!(upsert.status(), StatusCode::NO_CONTENT);

        for (machine_id, easytier_ipv4, status) in [
            (source, "10.126.126.2", "active"),
            (exit, "10.126.126.3", "prepared"),
        ] {
            let report = RuntimeReport {
                machine_id,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some(easytier_ipv4.to_string()),
                observed_policy_id: Some(policy.policy_id),
                observed_policy_version: Some(policy.desired_version),
                observed_policy_status: Some(status.to_string()),
                last_error: None,
            };
            let response = client
                .post(format!(
                    "{}/api/internal/users/{}/machines/{}/gateway-report",
                    base_url, user_id, machine_id
                ))
                .header("X-Internal-Auth", "internal-token")
                .json(&report)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        let snapshot = client
            .get(format!(
                "{}/api/v1/gateway-policies/{}",
                base_url, policy.policy_id
            ))
            .header(header::COOKIE, cookie.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(snapshot.status(), StatusCode::OK);
        let snapshot_body = snapshot.json::<serde_json::Value>().await.unwrap();
        assert_eq!(snapshot_body["desired"]["policy_id"], policy.policy_id.to_string());
        assert_eq!(snapshot_body["observed"]["source"]["status"], "active");
        assert_eq!(snapshot_body["observed"]["exit"]["status"], "prepared");

        let nodes = client
            .get(format!("{}/api/v1/gateway-nodes", base_url))
            .header(header::COOKIE, cookie.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(nodes.status(), StatusCode::OK);
        let nodes_body = nodes.json::<serde_json::Value>().await.unwrap();
        assert_eq!(nodes_body.as_array().unwrap().len(), 2);
        assert!(
            nodes_body
                .as_array()
                .unwrap()
                .iter()
                .any(|node| node["machine_id"] == source.to_string()
                    && node["easytier_ipv4"] == "10.126.126.2")
        );

        let list = client
            .get(format!("{}/api/v1/gateway-policies", base_url))
            .header(header::COOKIE, cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let list_body = list.json::<serde_json::Value>().await.unwrap();
        assert_eq!(list_body[0]["desired"]["policy_id"], policy.policy_id.to_string());
        assert_eq!(list_body[0]["observed"]["source"]["status"], "active");

        let source_device_policies = client
            .get(format!(
                "{}/api/internal/users/{}/machines/{}/gateway-policies",
                base_url, user_id, source
            ))
            .header("X-Internal-Auth", "internal-token")
            .send()
            .await
            .unwrap();
        assert_eq!(source_device_policies.status(), StatusCode::OK);
        let source_body = source_device_policies
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(source_body[0]["role"], "client_gateway_via_peer");
        assert_eq!(source_body[0]["exit_peer_ipv4"], "10.126.126.3");

        let exit_device_policies = client
            .get(format!(
                "{}/api/internal/users/{}/machines/{}/gateway-policies",
                base_url, user_id, exit
            ))
            .header("X-Internal-Auth", "internal-token")
            .send()
            .await
            .unwrap();
        assert_eq!(exit_device_policies.status(), StatusCode::OK);
        let exit_body = exit_device_policies
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(exit_body[0]["role"], "provide_exit_for_gateway");
        assert_eq!(exit_body[0]["source_peer_ipv4"], "10.126.126.2");
    }
}
