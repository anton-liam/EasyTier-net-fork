//! 网关策略状态机
//!
//! 三状态模型：Idle → Applied → Degraded → Idle
//! - Idle：无策略或策略已清除
//! - Applied：策略已应用且隧道健康
//! - Degraded：隧道异常，策略已回滚（过渡状态，立即转为 Idle）

use tracing::info;

use crate::proto::gateway_policy::{GatewayPolicy, GatewayPolicyStatus, GatewayState};

/// 策略状态机，维护当前状态和活跃策略
pub struct StateMachine {
    state: GatewayState,
    current_policy: Option<GatewayPolicy>,
}

impl StateMachine {
    /// 创建初始状态为 Idle 的状态机
    pub fn new() -> Self {
        Self {
            state: GatewayState::Idle,
            current_policy: None,
        }
    }

    /// 获取当前状态
    pub fn state(&self) -> GatewayState {
        self.state
    }

    /// 获取当前策略的引用
    pub fn current_policy(&self) -> Option<&GatewayPolicy> {
        self.current_policy.as_ref()
    }

    /// 转换到 Applied 状态，记录当前策略
    pub fn transition_to_applied(&mut self, policy: GatewayPolicy) {
        info!(
            from = ?self.state,
            policy_id = %policy.policy_id,
            "状态转换 → Applied"
        );
        self.state = GatewayState::Applied;
        self.current_policy = Some(policy);
    }

    /// 转换到 Idle 状态，清除当前策略
    pub fn transition_to_idle(&mut self) {
        info!(from = ?self.state, "状态转换 → Idle");
        self.state = GatewayState::Idle;
        self.current_policy = None;
    }

    /// 转换到 Degraded 状态（隧道异常过渡态）
    pub fn transition_to_degraded(&mut self) {
        info!(from = ?self.state, "状态转换 → Degraded");
        self.state = GatewayState::Degraded;
    }

    /// 生成当前状态报告
    pub fn status(&self) -> GatewayPolicyStatus {
        let policy_id = self
            .current_policy
            .as_ref()
            .map(|p| p.policy_id.clone())
            .unwrap_or_default();

        let message = match self.state {
            GatewayState::Idle => "空闲".to_string(),
            GatewayState::Applied => "策略已应用".to_string(),
            GatewayState::Degraded => "隧道异常，策略已回滚".to_string(),
        };

        GatewayPolicyStatus {
            policy_id,
            state: self.state.into(),
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_initial_state_is_idle() {
        let sm = StateMachine::new();
        assert_eq!(sm.state(), GatewayState::Idle);
        assert!(sm.current_policy().is_none());
    }

    #[test]
    fn state_machine_transitions() {
        let mut sm = StateMachine::new();

        let policy = GatewayPolicy {
            policy_id: "test-001".to_string(),
            enabled: true,
            ..Default::default()
        };

        // Idle → Applied
        sm.transition_to_applied(policy.clone());
        assert_eq!(sm.state(), GatewayState::Applied);
        assert_eq!(sm.current_policy().unwrap().policy_id, "test-001");

        // Applied → Degraded
        sm.transition_to_degraded();
        assert_eq!(sm.state(), GatewayState::Degraded);

        // Degraded → Idle
        sm.transition_to_idle();
        assert_eq!(sm.state(), GatewayState::Idle);
        assert!(sm.current_policy().is_none());
    }

    #[test]
    fn status_reflects_current_state() {
        let mut sm = StateMachine::new();

        let status = sm.status();
        assert_eq!(status.state(), GatewayState::Idle);

        sm.transition_to_applied(GatewayPolicy {
            policy_id: "gw-001".to_string(),
            ..Default::default()
        });
        let status = sm.status();
        assert_eq!(status.state(), GatewayState::Applied);
        assert_eq!(status.policy_id, "gw-001");
    }
}
