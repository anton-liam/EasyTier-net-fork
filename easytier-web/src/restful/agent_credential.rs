use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::agent_credential::{RotationStatus, TokenMatch};
use crate::db::{Db, UserIdInDb};

use super::{AppStateInner, HttpHandleError, other_error};

#[derive(Debug, Deserialize, Serialize)]
pub struct EnrollAgentRequest {
    pub user_id: UserIdInDb,
    pub machine_id: uuid::Uuid,
    pub machine_token_hash: String,
    pub hostname: Option<String>,
    pub agent_version: Option<String>,
    pub easytier_version: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EnrollAgentResponse {
    pub credential_version: i64,
    pub api_base_url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialStatusResponse {
    pub status: String,
    pub credential_version: i64,
    pub rotate_required: bool,
    pub grace_until: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RotateCredentialRequest {
    pub user_id: UserIdInDb,
    pub machine_id: uuid::Uuid,
    pub next_token_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RotateCredentialResponse {
    pub credential_version: i64,
    pub grace_until: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConfirmCredentialRequest {
    pub user_id: UserIdInDb,
    pub machine_id: uuid::Uuid,
    pub credential_version: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConfirmCredentialResponse {
    pub status: String,
    pub credential_version: i64,
}

pub struct AgentCredentialApi;

impl AgentCredentialApi {
    async fn handle_enroll_agent(
        State(client_mgr): State<AppStateInner>,
        headers: HeaderMap,
        Json(request): Json<EnrollAgentRequest>,
    ) -> Result<Json<EnrollAgentResponse>, HttpHandleError> {
        let Some(bootstrap_token) = bearer_token(&headers) else {
            return Err((
                StatusCode::UNAUTHORIZED,
                other_error("missing bearer token").into(),
            ));
        };

        let now = chrono::Utc::now();
        let Some(bootstrap) = client_mgr
            .db()
            .find_valid_agent_bootstrap_token(&bootstrap_token, now)
            .await
            .map_err(super::convert_db_error)?
        else {
            return Err((
                StatusCode::UNAUTHORIZED,
                other_error("invalid bootstrap token").into(),
            ));
        };

        if bootstrap.user_id != request.user_id {
            return Err((
                StatusCode::FORBIDDEN,
                other_error("bootstrap token does not match user").into(),
            ));
        }

        if !client_mgr.has_machine(request.user_id, &request.machine_id) {
            client_mgr
                .db()
                .append_agent_credential_audit_log(
                    request.user_id,
                    request.machine_id,
                    "enroll",
                    None,
                    "machine_not_connected",
                    Some("machine is not connected to EasyTier web"),
                )
                .await
                .map_err(super::convert_db_error)?;
            return Err((
                StatusCode::CONFLICT,
                other_error("machine_not_connected").into(),
            ));
        }

        if let Some(existing) = client_mgr
            .db()
            .get_agent_machine_credential(request.user_id, request.machine_id)
            .await
            .map_err(super::convert_db_error)?
        {
            return Ok(Json(EnrollAgentResponse {
                credential_version: existing.credential_version,
                api_base_url: client_mgr.agent_api_base_url(),
            }));
        }

        let credential = client_mgr
            .db()
            .create_active_agent_machine_credential_from_hash(
                request.user_id,
                request.machine_id,
                request.machine_token_hash,
            )
            .await
            .map_err(super::convert_db_error)?;

        client_mgr
            .db()
            .append_agent_credential_audit_log(
                request.user_id,
                request.machine_id,
                "enroll",
                Some(credential.credential_version),
                "success",
                None,
            )
            .await
            .map_err(super::convert_db_error)?;

        Ok(Json(EnrollAgentResponse {
            credential_version: credential.credential_version,
            api_base_url: client_mgr.agent_api_base_url(),
        }))
    }

    async fn handle_get_credential(
        State(client_mgr): State<AppStateInner>,
        headers: HeaderMap,
    ) -> Result<Json<CredentialStatusResponse>, HttpHandleError> {
        let credential = authenticated_machine_credential(client_mgr.db(), &headers).await?;
        Ok(Json(CredentialStatusResponse {
            status: credential.rotation_status.as_str().to_string(),
            credential_version: credential.credential_version,
            rotate_required: matches!(credential.rotation_status, RotationStatus::Rotating)
                && credential.next_token_hash.is_none(),
            grace_until: credential.grace_until.map(|value| value.to_rfc3339()),
        }))
    }

    async fn handle_rotate_credential(
        State(client_mgr): State<AppStateInner>,
        headers: HeaderMap,
        Json(request): Json<RotateCredentialRequest>,
    ) -> Result<Json<RotateCredentialResponse>, HttpHandleError> {
        let credential = authenticated_machine_credential(client_mgr.db(), &headers).await?;
        if credential.user_id != request.user_id || credential.machine_id != request.machine_id {
            return Err((
                StatusCode::FORBIDDEN,
                other_error("machine token does not match request").into(),
            ));
        }
        if !matches!(credential.rotation_status, RotationStatus::Rotating) {
            return Err((
                StatusCode::CONFLICT,
                other_error("credential rotation is not required").into(),
            ));
        }
        if credential.next_token_hash.is_some() {
            return Err((
                StatusCode::CONFLICT,
                other_error("credential rotation is already issued").into(),
            ));
        }

        let credential = client_mgr
            .db()
            .set_agent_machine_next_token_hash(
                request.user_id,
                request.machine_id,
                request.next_token_hash,
            )
            .await
            .map_err(super::convert_db_error)?;

        Ok(Json(RotateCredentialResponse {
            credential_version: credential.credential_version,
            grace_until: credential.grace_until.map(|value| value.to_rfc3339()),
        }))
    }

    async fn handle_confirm_credential(
        State(client_mgr): State<AppStateInner>,
        headers: HeaderMap,
        Json(request): Json<ConfirmCredentialRequest>,
    ) -> Result<Json<ConfirmCredentialResponse>, HttpHandleError> {
        let credential = authenticated_machine_credential(client_mgr.db(), &headers).await?;
        if credential.user_id != request.user_id || credential.machine_id != request.machine_id {
            return Err((
                StatusCode::FORBIDDEN,
                other_error("machine token does not match request").into(),
            ));
        }
        let Some(token) = bearer_token(&headers) else {
            return Err((
                StatusCode::UNAUTHORIZED,
                other_error("missing machine token").into(),
            ));
        };
        if credential.verify_machine_token(&token, chrono::Utc::now()) != TokenMatch::Next {
            return Err((
                StatusCode::UNAUTHORIZED,
                other_error("credential confirm requires next token").into(),
            ));
        }
        if credential.credential_version != request.credential_version {
            return Err((
                StatusCode::UNAUTHORIZED,
                other_error("credential version mismatch").into(),
            ));
        }

        let credential = client_mgr
            .db()
            .confirm_agent_machine_credential_rotation(request.user_id, request.machine_id)
            .await
            .map_err(super::convert_db_error)?;

        Ok(Json(ConfirmCredentialResponse {
            status: credential.rotation_status.as_str().to_string(),
            credential_version: credential.credential_version,
        }))
    }

    pub fn build_route_internal() -> Router<AppStateInner> {
        Router::new()
            .route(
                "/api/internal/agent/enroll",
                post(Self::handle_enroll_agent),
            )
            .route(
                "/api/internal/agent/credential",
                get(Self::handle_get_credential),
            )
            .route(
                "/api/internal/agent/credential/rotate",
                post(Self::handle_rotate_credential),
            )
            .route(
                "/api/internal/agent/credential/confirm",
                post(Self::handle_confirm_credential),
            )
    }
}

async fn authenticated_machine_credential(
    db: &Db,
    headers: &HeaderMap,
) -> Result<crate::agent_credential::MachineCredential, HttpHandleError> {
    let Some(machine_id) = headers
        .get("X-Machine-Id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<uuid::Uuid>().ok())
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            other_error("missing X-Machine-Id").into(),
        ));
    };
    let Some(user_id) = headers
        .get("X-User-Id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<UserIdInDb>().ok())
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            other_error("missing X-User-Id").into(),
        ));
    };
    let Some(version) = headers
        .get("X-Credential-Version")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            other_error("missing X-Credential-Version").into(),
        ));
    };
    let Some(token) = bearer_token(headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            other_error("missing machine token").into(),
        ));
    };
    let Some(credential) = db
        .get_agent_machine_credential(user_id, machine_id)
        .await
        .map_err(super::convert_db_error)?
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            other_error("credential not found").into(),
        ));
    };
    machine_auth_headers_match(&credential, &token, machine_id, version, chrono::Utc::now())
        .map_err(|status| (status, other_error("invalid machine token").into()))?;
    Ok(credential)
}

pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

pub fn machine_auth_headers_match(
    credential: &crate::agent_credential::MachineCredential,
    token: &str,
    machine_id: uuid::Uuid,
    credential_version: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<TokenMatch, StatusCode> {
    if credential.machine_id != machine_id {
        return Err(StatusCode::FORBIDDEN);
    }

    let accepts_previous_rotating_version = matches!(
        credential.rotation_status,
        crate::agent_credential::RotationStatus::Rotating
    ) && credential_version + 1
        == credential.credential_version
        && credential.verify_machine_token(token, now) == TokenMatch::Current;

    if credential.credential_version != credential_version && !accepts_previous_rotating_version {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match credential.verify_machine_token(token, now) {
        TokenMatch::None => Err(StatusCode::UNAUTHORIZED),
        matched => Ok(matched),
    }
}

pub async fn machine_auth_middleware(
    db: Db,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    machine_or_legacy_auth_middleware(db, None, req, next).await
}

pub async fn machine_or_legacy_auth_middleware(
    db: Db,
    legacy_internal_token: Option<String>,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    if let Some(expected_token) = legacy_internal_token.as_deref()
        && req
            .headers()
            .get("X-Internal-Auth")
            .and_then(|value| value.to_str().ok())
            == Some(expected_token)
    {
        return next.run(req).await;
    }

    let unauthorized = || {
        axum::response::Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"error":"unauthorized: invalid machine token"}"#,
            ))
            .unwrap()
    };
    let forbidden = || {
        axum::response::Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"error":"forbidden: machine token mismatch"}"#,
            ))
            .unwrap()
    };

    let Some(user_id) = user_id_from_internal_path(req.uri().path()) else {
        return forbidden();
    };
    let Some(machine_id) = machine_id_from_internal_path(req.uri().path()) else {
        return forbidden();
    };
    let Some(token) = bearer_token(req.headers()) else {
        return unauthorized();
    };
    let Some(version) = req
        .headers()
        .get("X-Credential-Version")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return unauthorized();
    };

    let credential = match db.get_agent_machine_credential(user_id, machine_id).await {
        Ok(Some(credential)) => credential,
        Ok(None) => return unauthorized(),
        Err(error) => {
            tracing::warn!(%error, ?user_id, ?machine_id, "failed to load machine credential");
            return unauthorized();
        }
    };

    match machine_auth_headers_match(&credential, &token, machine_id, version, chrono::Utc::now()) {
        Ok(_) => next.run(req).await,
        Err(StatusCode::FORBIDDEN) => forbidden(),
        Err(_) => unauthorized(),
    }
}

pub fn user_id_from_internal_path(path: &str) -> Option<UserIdInDb> {
    let mut parts = path.split('/');
    while let Some(part) = parts.next() {
        if part == "users" {
            return parts.next()?.parse().ok();
        }
    }
    None
}

pub fn machine_id_from_internal_path(path: &str) -> Option<uuid::Uuid> {
    let mut parts = path.split('/');
    while let Some(part) = parts.next() {
        if part == "machines" {
            return parts.next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use axum::http::StatusCode;
    use easytier::tunnel::udp::UdpTunnelListener;

    use crate::{
        FeatureFlags,
        agent_credential::verify_token,
        client_manager::ClientManager,
        client_manager::storage::StorageToken,
        db::Db,
        restful::{RestfulServer, oidc::OidcConfig},
        webhook::WebhookConfig,
    };

    use super::{
        ConfirmCredentialRequest, ConfirmCredentialResponse, CredentialStatusResponse,
        EnrollAgentRequest, EnrollAgentResponse, RotateCredentialRequest, RotateCredentialResponse,
    };

    fn plain_sha256(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(token.as_bytes());
        format!("plain-sha256:{digest:x}")
    }

    fn base_gateway_policy(
        source: uuid::Uuid,
        exit: uuid::Uuid,
    ) -> crate::gateway_policy::GatewayFullTunnelPolicy {
        crate::gateway_policy::GatewayFullTunnelPolicy {
            policy_id: uuid::Uuid::new_v4(),
            enabled: true,
            network_instance_id: uuid::Uuid::new_v4(),
            source_machine_id: source,
            managed_cidrs: vec!["192.168.10.0/24".to_string()],
            ingress_ifaces: vec!["br-lan".to_string()],
            include_device_traffic: true,
            exit_machine_id: exit,
            exit_egress: crate::gateway_policy::ExitEgress::default(),
            desired_version: 1,
            protect_control_plane: true,
            healthcheck: crate::gateway_policy::HealthcheckConfig::default(),
            rollback: crate::gateway_policy::RollbackConfig::default(),
        }
    }

    fn next_http_addr() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    async fn test_server() -> (
        String,
        Db,
        Arc<ClientManager>,
        i32,
        tokio_util::task::AbortOnDropHandle<()>,
    ) {
        test_server_with_agent_api_base_url(None).await
    }

    async fn test_server_with_agent_api_base_url(
        agent_api_base_url: Option<String>,
    ) -> (
        String,
        Db,
        Arc<ClientManager>,
        i32,
        tokio_util::task::AbortOnDropHandle<()>,
    ) {
        let db_path = std::env::temp_dir().join(format!(
            "easytier-web-agent-credential-test-{}.db",
            uuid::Uuid::new_v4()
        ));
        let db = Db::new(db_path.to_string_lossy()).await.unwrap();
        let user_id = db.auto_create_user("agent-enroll-user").await.unwrap().id;
        db.create_agent_bootstrap_token(
            user_id,
            "test-bootstrap",
            crate::agent_credential::hash_token("bootstrap-token"),
            None,
        )
        .await
        .unwrap();

        let webhook_config = Arc::new(WebhookConfig::new(
            None,
            None,
            None,
            None,
            agent_api_base_url,
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
            client_mgr.clone(),
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
            client_mgr,
            user_id,
            serve_task,
        )
    }

    #[tokio::test]
    async fn enroll_agent_requires_bootstrap_token() {
        let (base_url, _db, _client_mgr, user_id, _server) = test_server().await;
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("{}/api/internal/agent/enroll", base_url))
            .json(&EnrollAgentRequest {
                user_id,
                machine_id: uuid::Uuid::new_v4(),
                machine_token_hash: "plain-sha256:unused".to_string(),
                hostname: None,
                agent_version: None,
                easytier_version: None,
            })
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn enroll_agent_rejects_machine_before_easytier_heartbeat() {
        let (base_url, _db, _client_mgr, user_id, _server) = test_server().await;
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("{}/api/internal/agent/enroll", base_url))
            .bearer_auth("bootstrap-token")
            .json(&EnrollAgentRequest {
                user_id,
                machine_id: uuid::Uuid::new_v4(),
                machine_token_hash: "plain-sha256:unused".to_string(),
                hostname: None,
                agent_version: None,
                easytier_version: None,
            })
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["message"],
            "machine_not_connected"
        );
    }

    #[tokio::test]
    async fn enroll_agent_stores_agent_generated_machine_token_hash() {
        let (base_url, db, client_mgr, user_id, _server) = test_server().await;
        let machine_id = uuid::Uuid::new_v4();
        client_mgr.storage_for_tests().update_client(
            StorageToken {
                token: "native-user-token".to_string(),
                client_url: "tcp://127.0.0.1:12345".parse().unwrap(),
                machine_id,
                user_id,
            },
            chrono::Utc::now().timestamp(),
        );

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .post(format!("{}/api/internal/agent/enroll", base_url))
            .bearer_auth("bootstrap-token")
            .json(&EnrollAgentRequest {
                user_id,
                machine_id,
                machine_token_hash: plain_sha256("current-token"),
                hostname: Some("r3s-a".to_string()),
                agent_version: Some("0.1.0".to_string()),
                easytier_version: Some("2.6.4".to_string()),
            })
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let _body = response.json::<EnrollAgentResponse>().await.unwrap();
        let credential = db
            .get_agent_machine_credential(user_id, machine_id)
            .await
            .unwrap()
            .unwrap();
        assert!(verify_token(
            "current-token",
            &credential.current_token_hash
        ));

        let second = client
            .post(format!("{}/api/internal/agent/enroll", base_url))
            .bearer_auth("bootstrap-token")
            .json(&EnrollAgentRequest {
                user_id,
                machine_id,
                machine_token_hash: plain_sha256("other-token"),
                hostname: None,
                agent_version: None,
                easytier_version: None,
            })
            .send()
            .await
            .unwrap();
        let second_body = second.json::<EnrollAgentResponse>().await.unwrap();
        assert_eq!(second_body.credential_version, 1);
        let credential_after_retry = db
            .get_agent_machine_credential(user_id, machine_id)
            .await
            .unwrap()
            .unwrap();
        assert!(verify_token(
            "current-token",
            &credential_after_retry.current_token_hash
        ));
    }

    #[tokio::test]
    async fn enroll_agent_returns_configured_overlay_api_base_url() {
        let (base_url, _db, client_mgr, user_id, _server) =
            test_server_with_agent_api_base_url(Some("http://10.126.126.1:11211".to_string()))
                .await;
        let machine_id = uuid::Uuid::new_v4();
        client_mgr.storage_for_tests().update_client(
            StorageToken {
                token: "native-user-token".to_string(),
                client_url: "tcp://127.0.0.1:12347".parse().unwrap(),
                machine_id,
                user_id,
            },
            chrono::Utc::now().timestamp(),
        );

        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("{}/api/internal/agent/enroll", base_url))
            .bearer_auth("bootstrap-token")
            .json(&EnrollAgentRequest {
                user_id,
                machine_id,
                machine_token_hash: plain_sha256("current-token"),
                hostname: None,
                agent_version: None,
                easytier_version: None,
            })
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.json::<EnrollAgentResponse>().await.unwrap();
        assert_eq!(
            body.api_base_url.as_deref(),
            Some("http://10.126.126.1:11211")
        );
    }

    #[tokio::test]
    async fn machine_token_can_fetch_gateway_policies() {
        let (base_url, db, client_mgr, user_id, _server) = test_server().await;
        let source = uuid::Uuid::new_v4();
        let exit = uuid::Uuid::new_v4();
        let policy = base_gateway_policy(source, exit);
        client_mgr.storage_for_tests().update_client(
            StorageToken {
                token: "native-user-token".to_string(),
                client_url: "tcp://127.0.0.1:12345".parse().unwrap(),
                machine_id: source,
                user_id,
            },
            chrono::Utc::now().timestamp(),
        );
        db.upsert_gateway_policy(user_id, policy.clone())
            .await
            .unwrap();
        for (machine_id, easytier_ipv4, role) in [
            (
                source,
                "10.126.126.2",
                crate::gateway_policy::DevicePolicyRole::ClientGatewayViaPeer,
            ),
            (
                exit,
                "10.126.126.3",
                crate::gateway_policy::DevicePolicyRole::ProvideExitForGateway,
            ),
        ] {
            db.upsert_gateway_runtime_report(
                user_id,
                crate::gateway_policy::RuntimeReport {
                    machine_id,
                    agent_version: "0.1.0".to_string(),
                    easytier_ipv4: Some(easytier_ipv4.to_string()),
                    last_report_at: Some("2026-05-20T10:00:00+00:00".to_string()),
                    policy_id: Some(policy.policy_id),
                    device_policy_id: Some(format!("{}/{}", policy.policy_id, machine_id)),
                    version: Some(policy.desired_version),
                    role: Some(role),
                    status: Some("active".to_string()),
                    observed_policy_id: Some(policy.policy_id),
                    observed_policy_version: Some(policy.desired_version),
                    observed_policy_status: Some("active".to_string()),
                    last_error: None,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        db.create_active_agent_machine_credential(user_id, source, "machine-token")
            .await
            .unwrap();

        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!(
                "{}/api/internal/users/{}/machines/{}/gateway-policies",
                base_url, user_id, source
            ))
            .bearer_auth("machine-token")
            .header("X-Credential-Version", "1")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.json::<serde_json::Value>().await.unwrap();
        assert_eq!(body[0]["policy_id"], policy.policy_id.to_string());
    }

    #[tokio::test]
    async fn credential_rotation_returns_next_token_once_and_confirm_promotes_it() {
        let (base_url, db, client_mgr, user_id, _server) = test_server().await;
        let machine_id = uuid::Uuid::new_v4();
        client_mgr.storage_for_tests().update_client(
            StorageToken {
                token: "native-user-token".to_string(),
                client_url: "tcp://127.0.0.1:12346".parse().unwrap(),
                machine_id,
                user_id,
            },
            chrono::Utc::now().timestamp(),
        );
        db.create_active_agent_machine_credential(user_id, machine_id, "current-token")
            .await
            .unwrap();
        db.mark_agent_machine_credential_rotating(
            user_id,
            machine_id,
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let status = client
            .get(format!("{}/api/internal/agent/credential", base_url))
            .bearer_auth("current-token")
            .header("X-User-Id", user_id.to_string())
            .header("X-Machine-Id", machine_id.to_string())
            .header("X-Credential-Version", "2")
            .send()
            .await
            .unwrap();
        assert_eq!(status.status(), StatusCode::OK);
        let status = status.json::<CredentialStatusResponse>().await.unwrap();
        assert_eq!(status.status, "rotating");
        assert!(status.rotate_required);

        let rotate = client
            .post(format!("{}/api/internal/agent/credential/rotate", base_url))
            .bearer_auth("current-token")
            .header("X-User-Id", user_id.to_string())
            .header("X-Machine-Id", machine_id.to_string())
            .header("X-Credential-Version", "2")
            .json(&RotateCredentialRequest {
                user_id,
                machine_id,
                next_token_hash: plain_sha256("next-token"),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(rotate.status(), StatusCode::OK);
        let rotate = rotate.json::<RotateCredentialResponse>().await.unwrap();
        assert_eq!(rotate.credential_version, 2);

        let second_rotate = client
            .post(format!("{}/api/internal/agent/credential/rotate", base_url))
            .bearer_auth("current-token")
            .header("X-User-Id", user_id.to_string())
            .header("X-Machine-Id", machine_id.to_string())
            .header("X-Credential-Version", "2")
            .json(&RotateCredentialRequest {
                user_id,
                machine_id,
                next_token_hash: plain_sha256("other-next-token"),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(second_rotate.status(), StatusCode::CONFLICT);

        let confirm = client
            .post(format!(
                "{}/api/internal/agent/credential/confirm",
                base_url
            ))
            .bearer_auth("next-token")
            .header("X-User-Id", user_id.to_string())
            .header("X-Machine-Id", machine_id.to_string())
            .header("X-Credential-Version", "2")
            .json(&ConfirmCredentialRequest {
                user_id,
                machine_id,
                credential_version: 2,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(confirm.status(), StatusCode::OK);
        let confirm = confirm.json::<ConfirmCredentialResponse>().await.unwrap();
        assert_eq!(confirm.status, "confirmed");
        assert_eq!(confirm.credential_version, 2);

        let credential = db
            .get_agent_machine_credential(user_id, machine_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            credential.verify_machine_token("next-token", chrono::Utc::now()),
            crate::agent_credential::TokenMatch::Current
        );
        assert_eq!(
            credential.verify_machine_token("current-token", chrono::Utc::now()),
            crate::agent_credential::TokenMatch::Previous
        );
    }

    #[test]
    fn machine_auth_path_extracts_user_and_machine() {
        let machine_id = uuid::Uuid::new_v4();
        let path = format!("/api/internal/users/7/machines/{machine_id}/gateway-policies");

        assert_eq!(super::user_id_from_internal_path(&path), Some(7));
        assert_eq!(
            super::machine_id_from_internal_path(&path),
            Some(machine_id)
        );
    }

    #[test]
    fn rotating_machine_auth_accepts_current_token_with_previous_version() {
        let machine_id = uuid::Uuid::new_v4();
        let credential = crate::agent_credential::MachineCredential::rotating(
            7,
            machine_id,
            2,
            crate::agent_credential::hash_token("current-token"),
            crate::agent_credential::hash_token("next-token"),
            chrono::Utc::now() + chrono::Duration::hours(1),
        );

        assert_eq!(
            super::machine_auth_headers_match(
                &credential,
                "current-token",
                machine_id,
                1,
                chrono::Utc::now(),
            ),
            Ok(crate::agent_credential::TokenMatch::Current)
        );
    }
}
