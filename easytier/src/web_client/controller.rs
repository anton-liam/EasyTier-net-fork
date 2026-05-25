use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{rpc_impl::service_registry::ServiceRegistry, web::DeviceOsInfo},
    rpc_service::api::register_api_rpc_service,
    web_client::WebClientHooks,
};

#[cfg(feature = "gateway-policy")]
use crate::{gateway_policy::GatewayPolicyManager, rpc_service::api::register_gateway_policy_rpc};

pub struct Controller {
    token: String,
    machine_id: uuid::Uuid,
    hostname: String,
    device_os: DeviceOsInfo,
    manager: Arc<NetworkInstanceManager>,
    hooks: Arc<dyn WebClientHooks>,
    #[cfg(feature = "gateway-policy")]
    gateway_policy_manager: Option<Arc<GatewayPolicyManager>>,
}

impl Controller {
    pub fn new(
        token: String,
        machine_id: uuid::Uuid,
        hostname: String,
        device_os: DeviceOsInfo,
        manager: Arc<NetworkInstanceManager>,
        hooks: Arc<dyn WebClientHooks>,
    ) -> Self {
        Controller {
            token,
            machine_id,
            hostname,
            device_os,
            manager,
            hooks,
            #[cfg(feature = "gateway-policy")]
            gateway_policy_manager: None,
        }
    }

    /// 设置网关策略管理器
    #[cfg(feature = "gateway-policy")]
    pub fn set_gateway_policy_manager(&mut self, manager: Arc<GatewayPolicyManager>) {
        self.gateway_policy_manager = Some(manager);
    }

    pub fn list_network_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.manager.list_network_instance_ids()
    }

    pub fn token(&self) -> String {
        self.token.clone()
    }

    pub fn hostname(&self) -> String {
        self.hostname.clone()
    }

    pub fn machine_id(&self) -> uuid::Uuid {
        self.machine_id
    }

    pub fn device_os(&self) -> DeviceOsInfo {
        self.device_os.clone()
    }

    pub fn register_api_rpc_service(&self, registry: &ServiceRegistry) {
        register_api_rpc_service(&self.manager, registry, Some(self.hooks.clone()));

        #[cfg(feature = "gateway-policy")]
        if let Some(gw_manager) = &self.gateway_policy_manager {
            register_gateway_policy_rpc(registry, gw_manager.clone());
        }
    }

    pub(super) fn notify_manager_stopping(&self) {
        self.manager.notify_stop_check();
    }
}
