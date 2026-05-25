//! 网关策略 RPC 服务实现
//!
//! 处理来自控制面的策略下发请求，调用 GatewayPolicyManager 执行。

use std::sync::Arc;

use crate::gateway_policy::GatewayPolicyManager;
use crate::proto::common::Void;
use crate::proto::gateway_policy::{
    GatewayPolicy, GatewayPolicyRpc, GatewayPolicyStatus, GatewayState,
};
use crate::proto::rpc_types::controller::BaseController;

/// 网关策略 RPC 服务，桥接 RPC 调用和 GatewayPolicyManager
#[derive(Clone)]
pub struct GatewayPolicyRpcService {
    manager: Arc<GatewayPolicyManager>,
}

impl GatewayPolicyRpcService {
    /// 使用指定的策略管理器创建 RPC 服务
    pub fn new(manager: Arc<GatewayPolicyManager>) -> Self {
        Self { manager }
    }
}

#[async_trait::async_trait]
impl GatewayPolicyRpc for GatewayPolicyRpcService {
    type Controller = BaseController;

    /// 应用网关策略
    async fn apply_policy(
        &self,
        _ctrl: Self::Controller,
        input: GatewayPolicy,
    ) -> crate::proto::rpc_types::error::Result<GatewayPolicyStatus> {
        if !input.enabled {
            // enabled=false 表示移除策略
            self.manager
                .remove_policy()
                .await
                .map_err(|e| crate::proto::rpc_types::error::Error::ExecutionError(e))?;
            return Ok(GatewayPolicyStatus {
                policy_id: input.policy_id,
                state: GatewayState::Idle.into(),
                message: "策略已移除".to_string(),
            });
        }

        self.manager
            .apply_policy(input)
            .await
            .map_err(|e| crate::proto::rpc_types::error::Error::ExecutionError(e))
    }

    /// 移除当前策略
    async fn remove_policy(
        &self,
        _ctrl: Self::Controller,
        _input: Void,
    ) -> crate::proto::rpc_types::error::Result<Void> {
        self.manager
            .remove_policy()
            .await
            .map_err(|e| crate::proto::rpc_types::error::Error::ExecutionError(e))?;
        Ok(Void::default())
    }

    /// 查询当前策略状态
    async fn get_status(
        &self,
        _ctrl: Self::Controller,
        _input: Void,
    ) -> crate::proto::rpc_types::error::Result<GatewayPolicyStatus> {
        Ok(self.manager.get_status())
    }
}
