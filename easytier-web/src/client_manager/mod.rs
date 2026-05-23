pub mod session;
pub mod storage;

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use dashmap::DashMap;
use easytier::{
    launcher::NetworkConfig,
    proto::{
        api::manage::WebClientService, rpc_types::controller::BaseController, web::HeartbeatRequest,
    },
    rpc_service::remote_client::{
        self, ListNetworkProps, PersistentConfig as _, RemoteClientManager, Storage as _,
    },
    tunnel::TunnelListener,
    web_client::security,
};
use maxminddb::geoip2;
use session::{Location, Session};
use storage::{Storage, StorageToken};
use tokio::sync::RwLock;

use crate::FeatureFlags;
use crate::gateway_policy::{
    DevicePolicy, GATEWAY_DEFAULT_NETWORK_NAME, GatewayFullTunnelPolicy,
    GatewayNodeMachineSnapshot, GatewayNodeView, GatewayPolicySnapshot, PolicyError, PolicyStore,
    QuickApplyGatewayPolicyRequest, QuickApplyGatewayPolicyResponse, RuntimeReport,
    apply_gateway_policy_to_native_network_configs, build_gateway_node_views,
    build_quick_apply_gateway_policy_for_network, gateway_default_network_config,
};
use crate::webhook::SharedWebhookConfig;
use tokio::task::JoinSet;

use crate::db::{Db, UserIdInDb, entity::user_running_network_configs};

const DEFAULT_GATEWAY_PEER_URL: &str = "udp://137.220.194.19:22020/admin";
const GATEWAY_DEFAULT_PEER_URLS_ENV: &str = "EASYTIER_GATEWAY_DEFAULT_PEER_URLS";

#[derive(Debug, Clone)]
struct GatewayDefaultNetworkTemplate {
    instance_id: uuid::Uuid,
    network_secret: String,
    peer_urls: Vec<String>,
}

fn gateway_default_peer_urls() -> Vec<String> {
    let raw = std::env::var(GATEWAY_DEFAULT_PEER_URLS_ENV)
        .unwrap_or_else(|_| DEFAULT_GATEWAY_PEER_URL.to_string());
    raw.split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(rust_embed::Embed)]
#[folder = "resources/"]
#[include = "geoip2-cn.mmdb"]
struct GeoipDb;

fn load_geoip_db(geoip_db: Option<String>) -> Option<maxminddb::Reader<Vec<u8>>> {
    if let Some(path) = geoip_db {
        match maxminddb::Reader::open_readfile(&path) {
            Ok(reader) => {
                tracing::info!("Successfully loaded GeoIP2 database from {}", path);
                Some(reader)
            }
            Err(err) => {
                tracing::debug!("Failed to load GeoIP2 database from {}: {}", path, err);
                None
            }
        }
    } else {
        let db = GeoipDb::get("geoip2-cn.mmdb").unwrap();
        let reader = maxminddb::Reader::from_source(db.data.to_vec()).ok()?;
        tracing::info!("Successfully loaded GeoIP2 database from embedded file");
        Some(reader)
    }
}

#[derive(Debug)]
pub struct ClientManager {
    tasks: JoinSet<()>,

    listeners_cnt: Arc<AtomicU32>,

    client_sessions: Arc<DashMap<url::Url, Arc<Session>>>,
    storage: Storage,

    feature_flags: Arc<FeatureFlags>,
    webhook_config: SharedWebhookConfig,

    geoip_db: Arc<Option<maxminddb::Reader<Vec<u8>>>>,
    gateway_policy_store: Arc<RwLock<PolicyStore>>,
}

impl ClientManager {
    pub fn new(
        db: Db,
        geoip_db: Option<String>,
        feature_flags: Arc<FeatureFlags>,
        webhook_config: SharedWebhookConfig,
    ) -> Self {
        let client_sessions = Arc::new(DashMap::new());
        let sessions: Arc<DashMap<url::Url, Arc<Session>>> = client_sessions.clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                sessions.retain(|_, session| session.is_running());
            }
        });
        ClientManager {
            tasks,

            listeners_cnt: Arc::new(AtomicU32::new(0)),

            client_sessions,
            storage: Storage::new(db),
            feature_flags,
            webhook_config,

            geoip_db: Arc::new(load_geoip_db(geoip_db)),
            gateway_policy_store: Arc::new(RwLock::new(PolicyStore::default())),
        }
    }

    pub async fn add_listener<L: TunnelListener + 'static>(
        &mut self,
        mut listener: L,
    ) -> Result<(), anyhow::Error> {
        listener.listen().await?;
        self.listeners_cnt.fetch_add(1, Ordering::Relaxed);
        let sessions = self.client_sessions.clone();
        let storage = self.storage.weak_ref();
        let listeners_cnt = self.listeners_cnt.clone();
        let geoip_db = self.geoip_db.clone();
        let feature_flags = self.feature_flags.clone();
        let webhook_config = self.webhook_config.clone();
        self.tasks.spawn(async move {
            while let Ok(tunnel) = listener.accept().await {
                let (tunnel, secure) = match security::accept_or_upgrade_server_tunnel(tunnel).await {
                    Ok(v) => v,
                    Err(error) => {
                        tracing::warn!(%error, "failed to accept secure tunnel, dropping connection");
                        continue;
                    }
                };
                let info = tunnel.info().unwrap();
                let client_url: url::Url = info.remote_addr.unwrap().into();
                let location = Self::lookup_location(&client_url, geoip_db.clone());
                tracing::info!(
                    "New session from {:?}, secure: {}, location: {:?}",
                    client_url,
                    secure,
                    location
                );
                let mut session = Session::new(
                    storage.clone(),
                    client_url.clone(),
                    location,
                    feature_flags.clone(),
                    webhook_config.clone(),
                );
                session.serve(tunnel).await;
                sessions.insert(client_url, Arc::new(session));
            }
            listeners_cnt.fetch_sub(1, Ordering::Relaxed);
        });

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.listeners_cnt.load(Ordering::Relaxed) > 0
    }

    pub async fn list_sessions(&self) -> Vec<StorageToken> {
        let sessions = self
            .client_sessions
            .iter()
            .map(|item| item.value().clone())
            .collect::<Vec<_>>();

        let mut ret: Vec<StorageToken> = vec![];
        for s in sessions {
            if let Some(t) = s.get_token().await {
                ret.push(t);
            }
        }

        ret
    }

    pub fn get_session_by_machine_id(
        &self,
        user_id: UserIdInDb,
        machine_id: &uuid::Uuid,
    ) -> Option<Arc<Session>> {
        let c_url = self
            .storage
            .get_client_url_by_machine_id(user_id, machine_id)?;
        self.client_sessions
            .get(&c_url)
            .map(|item| item.value().clone())
    }

    pub async fn disconnect_session_by_machine_id(
        &self,
        user_id: UserIdInDb,
        machine_id: &uuid::Uuid,
    ) -> bool {
        let Some(client_url) = self
            .storage
            .get_client_url_by_machine_id(user_id, machine_id)
        else {
            return false;
        };
        let Some((_, session)) = self.client_sessions.remove(&client_url) else {
            return false;
        };
        session.stop().await;
        true
    }

    pub async fn list_machine_by_user_id(&self, user_id: UserIdInDb) -> Vec<url::Url> {
        self.storage.list_user_clients(user_id)
    }

    pub fn has_machine(&self, user_id: UserIdInDb, machine_id: &uuid::Uuid) -> bool {
        self.storage.has_machine(user_id, machine_id)
    }

    pub fn agent_api_base_url(&self) -> Option<String> {
        self.webhook_config
            .web_instance_api_base_url
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .cloned()
    }

    pub async fn get_heartbeat_requests(&self, client_url: &url::Url) -> Option<HeartbeatRequest> {
        let s = self.client_sessions.get(client_url)?.clone();
        s.data().read().await.req()
    }

    pub async fn get_machine_location(&self, client_url: &url::Url) -> Option<Location> {
        let s = self.client_sessions.get(client_url)?.clone();
        s.data().read().await.location().cloned()
    }

    pub(crate) fn db(&self) -> &Db {
        self.storage.db()
    }

    #[cfg(test)]
    pub(crate) fn storage_for_tests(&self) -> Storage {
        self.storage.clone()
    }

    pub async fn upsert_gateway_policy(
        &self,
        user_id: UserIdInDb,
        policy: GatewayFullTunnelPolicy,
    ) -> Result<(), anyhow::Error> {
        self.storage
            .db()
            .upsert_gateway_policy(user_id, policy.clone())
            .await?;
        self.gateway_policy_store
            .write()
            .await
            .upsert_policy(user_id, policy.clone())?;
        if let Err(error) = self
            .sync_gateway_policy_to_native_networks(user_id, &policy)
            .await
        {
            tracing::warn!(%error, policy_id = %policy.policy_id, "failed to sync gateway policy to native EasyTier configs");
        }
        Ok(())
    }

    async fn sync_gateway_policy_to_native_networks(
        &self,
        user_id: UserIdInDb,
        policy: &GatewayFullTunnelPolicy,
    ) -> Result<(), anyhow::Error> {
        let store = self.gateway_policy_store(user_id).await?;
        let exit_peer_ipv4 = store
            .device_policies_for_machine(user_id, policy.source_machine_id)?
            .into_iter()
            .find(|device_policy| device_policy.policy_id == policy.policy_id)
            .and_then(|device_policy| device_policy.exit_peer_ipv4)
            .ok_or_else(|| anyhow::anyhow!("exit peer IPv4 is not ready"))?;

        let mut source_config = self
            .handle_get_network_config(
                (user_id, policy.source_machine_id),
                policy.network_instance_id,
            )
            .await?;
        let mut exit_config = self
            .handle_get_network_config(
                (user_id, policy.exit_machine_id),
                policy.network_instance_id,
            )
            .await?;

        apply_gateway_policy_to_native_network_configs(
            policy,
            &mut source_config,
            &mut exit_config,
            &exit_peer_ipv4,
        );

        self.handle_run_network_instance((user_id, policy.source_machine_id), source_config, true)
            .await?;
        self.handle_run_network_instance((user_id, policy.exit_machine_id), exit_config, true)
            .await?;
        Ok(())
    }

    async fn reconcile_gateway_policy_native_networks(
        &self,
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
    ) -> Result<(), anyhow::Error> {
        let store = self.gateway_policy_store(user_id).await?;
        let policies = store.native_sync_ready_policies_for_machine(user_id, machine_id);
        for policy in policies {
            if let Err(error) = self
                .sync_gateway_policy_to_native_networks(user_id, &policy)
                .await
            {
                tracing::warn!(
                    %error,
                    policy_id = %policy.policy_id,
                    machine_id = %machine_id,
                    "failed to reconcile gateway policy to native EasyTier configs"
                );
            }
        }
        Ok(())
    }

    async fn native_network_config_needs_sync(
        &self,
        user_id: UserIdInDb,
        policy: &GatewayFullTunnelPolicy,
    ) -> Result<bool, anyhow::Error> {
        let store = self.gateway_policy_store(user_id).await?;
        let exit_peer_ipv4 = store
            .device_policies_for_machine(user_id, policy.source_machine_id)?
            .into_iter()
            .find(|device_policy| device_policy.policy_id == policy.policy_id)
            .and_then(|device_policy| device_policy.exit_peer_ipv4)
            .ok_or_else(|| anyhow::anyhow!("exit peer IPv4 is not ready"))?;

        let mut desired_source_config = self
            .handle_get_network_config(
                (user_id, policy.source_machine_id),
                policy.network_instance_id,
            )
            .await?;
        let mut desired_exit_config = self
            .handle_get_network_config(
                (user_id, policy.exit_machine_id),
                policy.network_instance_id,
            )
            .await?;
        apply_gateway_policy_to_native_network_configs(
            policy,
            &mut desired_source_config,
            &mut desired_exit_config,
            &exit_peer_ipv4,
        );

        let current_source_config = self
            .handle_get_network_config(
                (user_id, policy.source_machine_id),
                policy.network_instance_id,
            )
            .await?;
        let current_exit_config = self
            .handle_get_network_config(
                (user_id, policy.exit_machine_id),
                policy.network_instance_id,
            )
            .await?;

        Ok(current_source_config != desired_source_config
            || current_exit_config != desired_exit_config)
    }

    pub async fn list_gateway_policies(
        &self,
        user_id: UserIdInDb,
    ) -> Result<Vec<GatewayFullTunnelPolicy>, anyhow::Error> {
        self.storage
            .db()
            .list_gateway_policies(user_id)
            .await
            .map_err(Into::into)
    }

    pub async fn get_gateway_policy_snapshot(
        &self,
        user_id: UserIdInDb,
        policy_id: uuid::Uuid,
    ) -> Result<Option<GatewayPolicySnapshot>, anyhow::Error> {
        let store = self.gateway_policy_store(user_id).await?;
        Ok(store.policy_snapshot(user_id, policy_id))
    }

    pub async fn list_gateway_policy_snapshots(
        &self,
        user_id: UserIdInDb,
    ) -> Result<Vec<GatewayPolicySnapshot>, anyhow::Error> {
        let store = self.gateway_policy_store(user_id).await?;
        Ok(store.list_policy_snapshots(user_id))
    }

    pub async fn list_gateway_node_views(
        &self,
        user_id: UserIdInDb,
    ) -> Result<Vec<GatewayNodeView>, anyhow::Error> {
        let client_urls = self.list_machine_by_user_id(user_id).await;
        let mut machines = Vec::new();
        for client_url in client_urls {
            let Some(heartbeat) = self.get_heartbeat_requests(&client_url).await else {
                continue;
            };
            let Some(machine_id) = heartbeat.machine_id else {
                continue;
            };
            machines.push(GatewayNodeMachineSnapshot {
                machine_id: machine_id.into(),
                hostname: (!heartbeat.hostname.trim().is_empty()).then_some(heartbeat.hostname),
                public_ip: Some(client_url.to_string()),
                running_network_instances: heartbeat
                    .running_network_instances
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            });
        }

        let reports = self
            .storage
            .db()
            .list_gateway_runtime_reports(user_id)
            .await?;
        Ok(build_gateway_node_views(
            machines,
            reports,
            chrono::Utc::now(),
            chrono::Duration::seconds(30),
        ))
    }

    pub async fn quick_apply_gateway_policy(
        &self,
        user_id: UserIdInDb,
        request: QuickApplyGatewayPolicyRequest,
    ) -> Result<QuickApplyGatewayPolicyResponse, anyhow::Error> {
        let nodes = self.list_gateway_node_views(user_id).await?;
        let selected_network_instance_id = self
            .select_or_prepare_gateway_network_instance(user_id, &request, &nodes)
            .await?;
        let existing_policy = self
            .storage
            .db()
            .list_gateway_policies(user_id)
            .await?
            .into_iter()
            .find(|policy| policy.enabled && policy.source_machine_id == request.source_machine_id);
        let (policy_id, desired_version) = existing_policy
            .map(|policy| (policy.policy_id, policy.desired_version.saturating_add(1)))
            .unwrap_or_else(|| (uuid::Uuid::new_v4(), 1));

        let policy = build_quick_apply_gateway_policy_for_network(
            &request,
            &nodes,
            policy_id,
            desired_version,
            selected_network_instance_id,
        )?;
        let managed_cidrs = policy.managed_cidrs.clone();
        self.upsert_gateway_policy(user_id, policy.clone()).await?;
        let snapshot = self
            .get_gateway_policy_snapshot(user_id, policy.policy_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("gateway policy snapshot not found after upsert"))?;
        Ok(QuickApplyGatewayPolicyResponse {
            policy: snapshot,
            selected_network_instance_id,
            managed_cidrs,
        })
    }

    async fn select_or_prepare_gateway_network_instance(
        &self,
        user_id: UserIdInDb,
        request: &QuickApplyGatewayPolicyRequest,
        nodes: &[GatewayNodeView],
    ) -> Result<uuid::Uuid, anyhow::Error> {
        if request.source_machine_id == request.exit_machine_id {
            return Err(PolicyError::SourceEqualsExit.into());
        }
        let source = nodes
            .iter()
            .find(|node| node.machine_id == request.source_machine_id)
            .ok_or(PolicyError::MachineOffline(request.source_machine_id))?;
        let exit = nodes
            .iter()
            .find(|node| node.machine_id == request.exit_machine_id)
            .ok_or(PolicyError::MachineOffline(request.exit_machine_id))?;

        if !source.machine_online {
            return Err(PolicyError::MachineOffline(source.machine_id).into());
        }
        if !exit.machine_online {
            return Err(PolicyError::MachineOffline(exit.machine_id).into());
        }
        if !source.agent.online {
            return Err(PolicyError::AgentReportStale(source.machine_id).into());
        }
        if !exit.agent.online {
            return Err(PolicyError::AgentReportStale(exit.machine_id).into());
        }

        if let Some(network_instance_id) = request.network_instance_id {
            return source
                .running_network_instances
                .contains(&network_instance_id)
                .then_some(())
                .and_then(|_| {
                    exit.running_network_instances
                        .contains(&network_instance_id)
                        .then_some(network_instance_id)
                })
                .ok_or_else(|| PolicyError::NetworkInstanceNotReady.into());
        }

        let mut source_networks = source.running_network_instances.clone();
        source_networks.sort();
        if let Some(network_id) = source_networks
            .into_iter()
            .find(|network_id| exit.running_network_instances.contains(network_id))
        {
            return Ok(network_id);
        }

        self.prepare_gateway_default_network(user_id, source, exit)
            .await
    }

    async fn prepare_gateway_default_network(
        &self,
        user_id: UserIdInDb,
        source: &GatewayNodeView,
        exit: &GatewayNodeView,
    ) -> Result<uuid::Uuid, anyhow::Error> {
        let template = self
            .load_gateway_default_network_template(user_id, source.machine_id, exit.machine_id)
            .await?;
        let source_config = gateway_default_network_config(
            template.instance_id,
            template.network_secret.clone(),
            source.hostname.clone(),
            template.peer_urls.clone(),
        );
        let exit_config = gateway_default_network_config(
            template.instance_id,
            template.network_secret,
            exit.hostname.clone(),
            template.peer_urls,
        );

        self.handle_run_network_instance((user_id, source.machine_id), source_config, true)
            .await?;
        self.handle_run_network_instance((user_id, exit.machine_id), exit_config, true)
            .await?;
        Ok(template.instance_id)
    }

    async fn load_gateway_default_network_template(
        &self,
        user_id: UserIdInDb,
        source_machine_id: uuid::Uuid,
        exit_machine_id: uuid::Uuid,
    ) -> Result<GatewayDefaultNetworkTemplate, anyhow::Error> {
        let existing = self
            .find_gateway_default_network_config(user_id, source_machine_id)
            .await?
            .or(self
                .find_gateway_default_network_config(user_id, exit_machine_id)
                .await?);

        if let Some((instance_id, config)) = existing {
            let network_secret = config
                .network_secret
                .filter(|secret| !secret.trim().is_empty())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let peer_urls = if config.peer_urls.is_empty() {
                gateway_default_peer_urls()
            } else {
                config.peer_urls
            };
            return Ok(GatewayDefaultNetworkTemplate {
                instance_id,
                network_secret,
                peer_urls,
            });
        }

        Ok(GatewayDefaultNetworkTemplate {
            instance_id: uuid::Uuid::new_v4(),
            network_secret: uuid::Uuid::new_v4().to_string(),
            peer_urls: gateway_default_peer_urls(),
        })
    }

    async fn find_gateway_default_network_config(
        &self,
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
    ) -> Result<Option<(uuid::Uuid, NetworkConfig)>, anyhow::Error> {
        for row in self
            .storage
            .db()
            .list_network_configs((user_id, machine_id), ListNetworkProps::All)
            .await?
        {
            let config = row.get_network_config()?;
            if config.network_name.as_deref() != Some(GATEWAY_DEFAULT_NETWORK_NAME) {
                continue;
            }
            let instance_id = uuid::Uuid::parse_str(row.get_network_inst_id())?;
            return Ok(Some((instance_id, config)));
        }
        Ok(None)
    }

    pub async fn disable_gateway_policy(
        &self,
        user_id: UserIdInDb,
        policy_id: uuid::Uuid,
    ) -> Result<GatewayPolicySnapshot, anyhow::Error> {
        let mut policy = self
            .storage
            .db()
            .list_gateway_policies(user_id)
            .await?
            .into_iter()
            .find(|policy| policy.policy_id == policy_id)
            .ok_or(PolicyError::PolicyNotFound)?;
        policy.enabled = false;
        policy.desired_version = policy.desired_version.saturating_add(1);
        self.upsert_gateway_policy(user_id, policy.clone()).await?;
        self.get_gateway_policy_snapshot(user_id, policy_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("gateway policy snapshot not found after disable"))
    }

    pub async fn gateway_device_policies(
        &self,
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
    ) -> Result<Vec<DevicePolicy>, anyhow::Error> {
        let store = self.gateway_policy_store(user_id).await?;
        Ok(store.device_policies_for_machine(user_id, machine_id)?)
    }

    async fn gateway_policy_store(
        &self,
        user_id: UserIdInDb,
    ) -> Result<PolicyStore, anyhow::Error> {
        let policies = self.storage.db().list_gateway_policies(user_id).await?;
        let reports = self
            .storage
            .db()
            .list_gateway_runtime_reports(user_id)
            .await?;
        let mut store = PolicyStore::default();
        for policy in policies {
            store.upsert_policy(user_id, policy)?;
        }
        for report in reports {
            store.update_report(user_id, report);
        }
        Ok(store)
    }

    pub async fn update_gateway_runtime_report(
        &self,
        user_id: UserIdInDb,
        report: RuntimeReport,
    ) -> Result<(), anyhow::Error> {
        let machine_id = report.machine_id;
        self.storage
            .db()
            .upsert_gateway_runtime_report(user_id, report.clone())
            .await?;
        self.gateway_policy_store
            .write()
            .await
            .update_report(user_id, report);
        let store = self.gateway_policy_store(user_id).await?;
        for policy in store.native_sync_ready_policies_for_machine(user_id, machine_id) {
            match self
                .native_network_config_needs_sync(user_id, &policy)
                .await
            {
                Ok(true) => {
                    if let Err(error) = self
                        .sync_gateway_policy_to_native_networks(user_id, &policy)
                        .await
                    {
                        tracing::warn!(
                            %error,
                            policy_id = %policy.policy_id,
                            machine_id = %machine_id,
                            "failed to sync gateway policy after runtime report"
                        );
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(
                        %error,
                        policy_id = %policy.policy_id,
                        machine_id = %machine_id,
                        "failed to check native gateway policy sync after runtime report"
                    );
                }
            }
        }
        Ok(())
    }

    fn lookup_location(
        client_url: &url::Url,
        geoip_db: Arc<Option<maxminddb::Reader<Vec<u8>>>>,
    ) -> Option<Location> {
        let host = client_url.host_str()?;
        let ip: std::net::IpAddr = if let Ok(ip) = host.parse() {
            ip
        } else {
            tracing::debug!("Failed to parse host as IP address: {}", host);
            return None;
        };

        // Skip lookup for private/special IPs
        let is_private = match ip {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_loopback() || ipv4.is_unspecified()
            }
            std::net::IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
        };

        if is_private {
            tracing::debug!("Skipping GeoIP lookup for special IP: {}", ip);
            let location = Location {
                country: "本地网络".to_string(),
                city: None,
                region: None,
            };
            return Some(location);
        }

        let location = if let Some(db) = &*geoip_db {
            match db.lookup::<geoip2::City>(ip) {
                Ok(city) => {
                    let country = city
                        .country
                        .and_then(|c| c.names)
                        .and_then(|n| {
                            n.get("zh-CN")
                                .or_else(|| n.get("en"))
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_else(|| "海外".to_string());

                    let city_name = city.city.and_then(|c| c.names).and_then(|n| {
                        n.get("zh-CN")
                            .or_else(|| n.get("en"))
                            .map(|s| s.to_string())
                    });

                    let region = city.subdivisions.map(|r| {
                        r.iter()
                            .filter_map(|x| x.names.as_ref())
                            .filter_map(|x| x.get("zh-CN").or_else(|| x.get("en")))
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    });

                    Location {
                        country,
                        city: city_name,
                        region,
                    }
                }
                Err(err) => {
                    tracing::debug!("GeoIP lookup failed for {}: {}", ip, err);
                    Location {
                        country: "海外".to_string(),
                        city: None,
                        region: None,
                    }
                }
            }
        } else {
            tracing::debug!(
                "GeoIP database not available, using default location for {}",
                ip
            );
            Location {
                country: "海外".to_string(),
                city: None,
                region: None,
            }
        };

        Some(location)
    }
}

impl
    RemoteClientManager<
        (UserIdInDb, uuid::Uuid),
        user_running_network_configs::Model,
        sea_orm::DbErr,
    > for ClientManager
{
    fn get_rpc_client(
        &self,
        (user_id, machine_id): (UserIdInDb, uuid::Uuid),
    ) -> Option<Box<dyn WebClientService<Controller = BaseController> + Send>> {
        let s = self.get_session_by_machine_id(user_id, &machine_id)?;
        Some(s.scoped_rpc_client())
    }

    fn get_storage(
        &self,
    ) -> &impl remote_client::Storage<
        (UserIdInDb, uuid::Uuid),
        user_running_network_configs::Model,
        sea_orm::DbErr,
    > {
        self.storage.db()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use easytier::{
        instance_manager::NetworkInstanceManager,
        tunnel::{
            common::tests::wait_for_condition,
            udp::{UdpTunnelConnector, UdpTunnelListener},
        },
        web_client::WebClient,
    };
    use sqlx::Executor;

    use crate::{
        FeatureFlags,
        client_manager::ClientManager,
        db::Db,
        gateway_policy::{
            ExitEgress, GatewayFullTunnelPolicy, HealthcheckConfig, PolicyStore, RollbackConfig,
            RuntimeReport,
        },
    };

    #[tokio::test]
    async fn gateway_native_sync_is_reconciled_after_reports_arrive() {
        let source = uuid::Uuid::new_v4();
        let exit = uuid::Uuid::new_v4();
        let policy = GatewayFullTunnelPolicy {
            policy_id: uuid::Uuid::new_v4(),
            enabled: true,
            network_instance_id: uuid::Uuid::new_v4(),
            source_machine_id: source,
            managed_cidrs: vec!["192.168.100.0/24".to_string()],
            ingress_ifaces: vec!["br-lan".to_string()],
            include_device_traffic: false,
            exit_machine_id: exit,
            exit_egress: ExitEgress::default(),
            desired_version: 1,
            protect_control_plane: true,
            healthcheck: HealthcheckConfig::default(),
            rollback: RollbackConfig::default(),
        };

        let mut store = PolicyStore::default();
        store.upsert_policy(1, policy).unwrap();
        store.update_report(
            1,
            RuntimeReport {
                machine_id: source,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.2".to_string()),
                last_report_at: None,
                policy_id: None,
                device_policy_id: None,
                version: None,
                role: None,
                status: None,
                observed_policy_id: None,
                observed_policy_version: None,
                observed_policy_status: None,
                last_error: None,
                ..Default::default()
            },
        );
        assert!(
            store
                .native_sync_ready_policies_for_machine(1, source)
                .is_empty()
        );
        store.update_report(
            1,
            RuntimeReport {
                machine_id: exit,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.3".to_string()),
                last_report_at: None,
                policy_id: None,
                device_policy_id: None,
                version: None,
                role: None,
                status: None,
                observed_policy_id: None,
                observed_policy_version: None,
                observed_policy_status: None,
                last_error: None,
                ..Default::default()
            },
        );
        assert_eq!(
            store
                .native_sync_ready_policies_for_machine(1, source)
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn test_client() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:54333".parse().unwrap());
        let mut mgr = ClientManager::new(
            Db::memory_db().await,
            None,
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        );
        mgr.add_listener(Box::new(listener)).await.unwrap();

        mgr.db()
            .inner()
            .execute("INSERT INTO users (username, password) VALUES ('test', 'test')")
            .await
            .unwrap();

        let connector = UdpTunnelConnector::new("udp://127.0.0.1:54333".parse().unwrap());
        let _c = WebClient::new(
            connector,
            "test",
            uuid::Uuid::new_v4(),
            "test",
            false,
            Arc::new(NetworkInstanceManager::new()),
            None,
        );

        wait_for_condition(
            || async { !mgr.client_sessions.is_empty() },
            Duration::from_secs(12),
        )
        .await;

        let req = tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let sessions = mgr
                    .client_sessions
                    .iter()
                    .map(|item| item.value().clone())
                    .collect::<Vec<_>>();
                if sessions.is_empty() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                let mut found_req = None;
                for session in sessions {
                    if let Some(req) = session.data().read().await.req() {
                        found_req = Some(req);
                        break;
                    }
                }
                if let Some(req) = found_req {
                    break req;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        println!("{:?}", req);
        println!("{:?}", mgr);
    }
}
