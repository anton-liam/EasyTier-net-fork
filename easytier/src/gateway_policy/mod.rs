//! 出口网关策略模块
//!
//! 管理 D → A → B → Internet 出口网关策略的生命周期：
//! - 接收控制面下发的策略
//! - 执行 nft/ip rule/route 规则
//! - 监控隧道健康状态，异常时自动回滚
//! - 进程退出时清理所有规则

mod executor;
mod monitor;
mod state;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::proto::gateway_policy::{GatewayPolicy, GatewayPolicyStatus, GatewayRole, GatewayState};
use executor::Executor;
use monitor::Monitor;
use state::StateMachine;

/// 网关策略管理器，负责策略的应用、监控和清理
pub struct GatewayPolicyManager {
    state_machine: Arc<RwLock<StateMachine>>,
    executor: Arc<Executor>,
    monitor: Arc<Monitor>,
}

impl GatewayPolicyManager {
    /// 创建新的策略管理器实例
    pub fn new() -> Self {
        let executor = Arc::new(Executor::new());
        let monitor = Arc::new(Monitor::new());
        let state_machine = Arc::new(RwLock::new(StateMachine::new()));

        Self {
            state_machine,
            executor,
            monitor,
        }
    }

    /// 应用网关策略，根据角色执行对应的 nft/route 规则
    pub async fn apply_policy(&self, policy: GatewayPolicy) -> anyhow::Result<GatewayPolicyStatus> {
        info!(policy_id = %policy.policy_id, role = ?policy.role, "应用网关策略");

        if let Err(e) = self.executor.apply(&policy).await {
            warn!(policy_id = %policy.policy_id, error = %e, "策略应用失败，状态回到 Idle");
            let mut sm = self.state_machine.write().await;
            sm.transition_to_idle();
            return Err(e);
        }

        let mut sm = self.state_machine.write().await;
        sm.transition_to_applied(policy.clone());

        Ok(GatewayPolicyStatus {
            policy_id: policy.policy_id,
            state: GatewayState::Applied.into(),
            message: "策略已应用".to_string(),
        })
    }

    /// 移除当前策略，清理所有 nft/ip rule/route 规则
    pub async fn remove_policy(&self) -> anyhow::Result<()> {
        info!("移除网关策略");
        self.executor.cleanup().await?;

        let mut sm = self.state_machine.write().await;
        sm.transition_to_idle();

        Ok(())
    }

    /// 获取当前策略状态
    pub fn get_status(&self) -> GatewayPolicyStatus {
        // 使用 try_read 避免异步，状态查询允许短暂不一致
        let sm = self.state_machine.try_read();
        match sm {
            Ok(sm) => sm.status(),
            Err(_) => GatewayPolicyStatus {
                policy_id: String::new(),
                state: GatewayState::Idle.into(),
                message: "状态查询中".to_string(),
            },
        }
    }

    /// 启动监控 run loop，每 5 秒检查隧道健康状态
    pub async fn run_loop(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        info!("网关策略监控 run loop 启动");

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    info!("收到关闭信号，退出 run loop");
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    self.check_and_reconcile().await;
                }
            }
        }
    }

    /// 检查隧道状态并协调策略执行
    async fn check_and_reconcile(&self) {
        let sm = self.state_machine.read().await;
        let current_state = sm.state();
        let policy = sm.current_policy().cloned();
        drop(sm);

        // 只在已应用或已保护降级状态下检查健康
        if current_state != GatewayState::Applied && current_state != GatewayState::DegradedGuarded
        {
            return;
        }

        let Some(policy) = policy else {
            return;
        };

        // 检查隧道健康状态
        let tunnel_ok = self.monitor.check_tunnel_health(&policy).await;

        if tunnel_ok && current_state == GatewayState::DegradedGuarded {
            info!(policy_id = %policy.policy_id, "隧道恢复，重新应用网关策略");
            if let Err(e) = self.executor.apply(&policy).await {
                warn!(error = %e, "隧道恢复后策略重新应用失败");
                return;
            }
            let mut sm = self.state_machine.write().await;
            sm.transition_to_applied(policy);
            return;
        }

        if !tunnel_ok && current_state == GatewayState::Applied {
            warn!(policy_id = %policy.policy_id, "隧道异常，自动回滚策略");
            let role = GatewayRole::try_from(policy.role).unwrap_or(GatewayRole::Source);
            if role == GatewayRole::Source {
                if let Err(e) = self.executor.apply_source_guard(&policy).await {
                    warn!(error = %e, "Source fail-closed guard 安装失败");
                    let mut sm = self.state_machine.write().await;
                    sm.transition_to_degraded();
                    return;
                }
                if let Err(e) = self.executor.cleanup_policy_rules().await {
                    warn!(error = %e, "Source 回滚清理失败");
                }
                let mut sm = self.state_machine.write().await;
                sm.transition_to_degraded_guarded();
            } else {
                if let Err(e) = self.executor.cleanup().await {
                    warn!(error = %e, "回滚清理失败");
                }
                let mut sm = self.state_machine.write().await;
                sm.transition_to_degraded();
                sm.transition_to_idle();
            }
        }
    }

    /// 进程退出时清理所有规则，确保网络回到干净状态
    pub async fn cleanup(&self) {
        info!("进程退出，清理网关策略规则");
        if let Err(e) = self.executor.cleanup().await {
            warn!(error = %e, "退出清理失败");
        }
        let mut sm = self.state_machine.write().await;
        sm.transition_to_idle();
    }
}

impl Default for GatewayPolicyManager {
    fn default() -> Self {
        Self::new()
    }
}
