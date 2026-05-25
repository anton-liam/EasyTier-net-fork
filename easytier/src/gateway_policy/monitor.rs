//! 隧道健康监控
//!
//! 检查 tun0 网口是否存在和 exit peer 是否可达，
//! 用于 run loop 中判断是否需要回滚策略。

use tracing::{debug, warn};

use crate::proto::gateway_policy::{GatewayPolicy, GatewayRole};

const DEFAULT_EASYTIER_IFACE: &str = "tun0";

/// 隧道健康监控器
pub struct Monitor;

impl Monitor {
    /// 创建监控器实例
    pub fn new() -> Self {
        Self
    }

    /// 综合检查隧道健康状态
    pub async fn check_tunnel_health(&self, policy: &GatewayPolicy) -> bool {
        let iface = easytier_iface(policy);
        let tun_exists = self.check_tun_exists(&iface).await;
        if !tun_exists {
            warn!(iface = %iface, "EasyTier tun 网口不存在");
            return false;
        }

        let role = GatewayRole::try_from(policy.role).unwrap_or(GatewayRole::Source);
        if role == GatewayRole::Exit {
            return true;
        }

        let peer_ip = &policy.exit_peer_tun_ip;
        if peer_ip.is_empty() {
            warn!("Source 策略缺少 exit peer tunnel IP");
            return false;
        }

        let peer_reachable = self.check_peer_reachable(peer_ip).await;
        if !peer_reachable {
            warn!(peer_ip = %peer_ip, "exit peer 不可达");
            return false;
        }

        true
    }

    /// 检查 tun0 网口是否存在
    async fn check_tun_exists(&self, iface: &str) -> bool {
        let path = format!("/sys/class/net/{}", iface);
        let exists = tokio::fs::metadata(&path).await.is_ok();
        debug!(iface = %iface, exists = %exists, "检查 EasyTier tun 网口存在");
        exists
    }

    /// 通过 ping 检查 exit peer 是否可达
    async fn check_peer_reachable(&self, peer_ip: &str) -> bool {
        let output = tokio::process::Command::new("ping")
            .args(["-c", "1", "-W", "2", peer_ip])
            .output()
            .await;

        match output {
            Ok(o) => {
                let reachable = o.status.success();
                debug!(peer_ip = %peer_ip, reachable = %reachable, "ping 检查");
                reachable
            }
            Err(e) => {
                warn!(peer_ip = %peer_ip, error = %e, "ping 执行失败");
                false
            }
        }
    }
}

/// 获取策略中的 EasyTier tun 网口，未配置时回退到 tun0
fn easytier_iface(policy: &GatewayPolicy) -> String {
    if policy.easytier_iface.trim().is_empty() {
        DEFAULT_EASYTIER_IFACE.to_string()
    } else {
        policy.easytier_iface.trim().to_string()
    }
}
