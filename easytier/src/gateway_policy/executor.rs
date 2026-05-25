//! 网关策略规则执行器
//!
//! 负责校验策略参数、生成 nft/ip rule/ip route 命令并执行：
//! - Source 角色：mark 受管流量 + policy route 到 exit peer
//! - Exit 角色：masquerade 出网

use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use cidr::IpCidr;
use tracing::{debug, info, warn};

use crate::proto::gateway_policy::{GatewayPolicy, GatewayRole};

/// nft 表名常量
const NFT_TABLE: &str = "easytier_gw";
/// fwmark 值
const FWMARK: u32 = 0x7e;
/// 策略路由表号
const ROUTE_TABLE: u32 = 126;
/// EasyTier 默认 tun 网口名
const DEFAULT_EASYTIER_IFACE: &str = "tun0";

/// 一条待执行的系统命令
#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandSpec {
    cmd: &'static str,
    args: Vec<String>,
    ignore_error: bool,
}

impl CommandSpec {
    /// 创建系统命令描述，便于执行前测试命令规划结果
    fn new<I, S>(cmd: &'static str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            cmd,
            args: args.into_iter().map(Into::into).collect(),
            ignore_error: false,
        }
    }

    /// 创建允许失败的命令，适合兼容 OpenWrt fw4 不存在的普通 Linux 环境
    fn optional<I, S>(cmd: &'static str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            cmd,
            args: args.into_iter().map(Into::into).collect(),
            ignore_error: true,
        }
    }
}

/// 规则执行器，通过系统命令管理 nft 和路由规则
pub struct Executor;

impl Executor {
    /// 创建执行器实例
    pub fn new() -> Self {
        Self
    }

    /// 根据策略角色应用对应的网络规则
    pub async fn apply(&self, policy: &GatewayPolicy) -> Result<()> {
        let commands = self.plan_apply(policy)?;

        // 先清理旧规则，再应用新规则，确保重复下发不会因规则已存在失败。
        self.cleanup().await?;

        for command in commands {
            if let Err(e) = run_command(&command).await {
                warn!(error = %e, "策略应用失败，执行回滚清理");
                let _ = self.cleanup().await;
                return Err(e);
            }
        }

        Ok(())
    }

    /// 清理所有网关策略相关的网络规则
    pub async fn cleanup(&self) -> Result<()> {
        info!("清理网关策略规则");

        for command in plan_cleanup() {
            let _ = run_command(&command).await;
        }

        info!("规则清理完成");
        Ok(())
    }

    /// 生成策略应用命令，执行前完成参数校验
    fn plan_apply(&self, policy: &GatewayPolicy) -> Result<Vec<CommandSpec>> {
        let role = GatewayRole::try_from(policy.role)
            .with_context(|| format!("未知网关角色: {}", policy.role))?;

        match role {
            GatewayRole::Source => plan_source(policy),
            GatewayRole::Exit => plan_exit(policy),
        }
    }
}

/// 生成 Source 角色命令：mark 受管流量并策略路由到 exit peer
fn plan_source(policy: &GatewayPolicy) -> Result<Vec<CommandSpec>> {
    validate_common(policy)?;
    validate_iface("ingress_iface", &policy.ingress_iface)?;
    let easytier_iface = normalize_easytier_iface(policy)?;
    let exit_ip = validate_ip("exit_peer_tun_ip", &policy.exit_peer_tun_ip)?;

    info!(
        iface = %policy.ingress_iface,
        easytier_iface = %easytier_iface,
        exit_ip = %exit_ip,
        "生成 Source 规则"
    );

    let mut commands = vec![
        CommandSpec::new("nft", ["add", "table", "inet", NFT_TABLE]),
        CommandSpec::new(
            "nft",
            [
                "add",
                "chain",
                "inet",
                NFT_TABLE,
                "prerouting",
                "{",
                "type",
                "filter",
                "hook",
                "prerouting",
                "priority",
                "-150",
                ";",
                "}",
            ],
        ),
        CommandSpec::optional(
            "nft",
            [
                "insert",
                "rule",
                "inet",
                "fw4",
                "input",
                "iifname",
                easytier_iface.as_str(),
                "accept",
                "comment",
                "easytier_gw",
            ],
        ),
    ];

    for cidr in &policy.managed_cidrs {
        let fwmark_str = format!("0x{:x}", FWMARK);
        commands.push(CommandSpec::new(
            "nft",
            [
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                "prerouting",
                "iifname",
                policy.ingress_iface.as_str(),
                "ip",
                "saddr",
                cidr.as_str(),
                "ip",
                "daddr",
                "!=",
                cidr.as_str(),
                "meta",
                "mark",
                "set",
                fwmark_str.as_str(),
            ],
        ));

        commands.push(CommandSpec::optional(
            "nft",
            [
                "insert",
                "rule",
                "inet",
                "fw4",
                "forward",
                "iifname",
                policy.ingress_iface.as_str(),
                "oifname",
                easytier_iface.as_str(),
                "ip",
                "saddr",
                cidr.as_str(),
                "counter",
                "accept",
                "comment",
                "easytier_gw",
            ],
        ));

        commands.push(CommandSpec::optional(
            "nft",
            [
                "insert",
                "rule",
                "inet",
                "fw4",
                "forward",
                "iifname",
                easytier_iface.as_str(),
                "oifname",
                policy.ingress_iface.as_str(),
                "ct",
                "state",
                "established,related",
                "counter",
                "accept",
                "comment",
                "easytier_gw",
            ],
        ));
    }

    commands.push(CommandSpec::new(
        "ip",
        [
            "rule",
            "add",
            "fwmark",
            format!("0x{:x}", FWMARK).as_str(),
            "table",
            ROUTE_TABLE.to_string().as_str(),
        ],
    ));

    commands.push(CommandSpec::new(
        "ip",
        [
            "route",
            "replace",
            "default",
            "via",
            policy.exit_peer_tun_ip.as_str(),
            "dev",
            easytier_iface.as_str(),
            "table",
            ROUTE_TABLE.to_string().as_str(),
        ],
    ));

    Ok(commands)
}

/// 生成 Exit 角色命令：启用转发并 masquerade 出网
fn plan_exit(policy: &GatewayPolicy) -> Result<Vec<CommandSpec>> {
    validate_common(policy)?;
    validate_iface("exit_wan_iface", &policy.exit_wan_iface)?;
    let easytier_iface = normalize_easytier_iface(policy)?;

    info!(
        wan_iface = %policy.exit_wan_iface,
        easytier_iface = %easytier_iface,
        "生成 Exit 规则"
    );

    let mut commands = vec![
        CommandSpec::new("sysctl", ["-w", "net.ipv4.ip_forward=1"]),
        CommandSpec::new("nft", ["add", "table", "inet", NFT_TABLE]),
        CommandSpec::new(
            "nft",
            [
                "add", "chain", "inet", NFT_TABLE, "forward", "{", "type", "filter", "hook",
                "forward", "priority", "-150", ";", "}",
            ],
        ),
        CommandSpec::new(
            "nft",
            [
                "add",
                "chain",
                "inet",
                NFT_TABLE,
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "100",
                ";",
                "}",
            ],
        ),
        CommandSpec::optional(
            "nft",
            [
                "insert",
                "rule",
                "inet",
                "fw4",
                "input",
                "iifname",
                easytier_iface.as_str(),
                "accept",
                "comment",
                "easytier_gw",
            ],
        ),
    ];

    commands.push(CommandSpec::new(
        "nft",
        [
            "add",
            "rule",
            "inet",
            NFT_TABLE,
            "forward",
            "iifname",
            policy.exit_wan_iface.as_str(),
            "oifname",
            easytier_iface.as_str(),
            "ct",
            "state",
            "established,related",
            "counter",
            "accept",
        ],
    ));

    for cidr in &policy.managed_cidrs {
        commands.push(CommandSpec::new(
            "nft",
            [
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                "postrouting",
                "ip",
                "saddr",
                cidr.as_str(),
                "oif",
                policy.exit_wan_iface.as_str(),
                "masquerade",
            ],
        ));

        commands.push(CommandSpec::new(
            "nft",
            [
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                "forward",
                "iifname",
                easytier_iface.as_str(),
                "oifname",
                policy.exit_wan_iface.as_str(),
                "ip",
                "saddr",
                cidr.as_str(),
                "counter",
                "accept",
            ],
        ));

        commands.push(CommandSpec::optional(
            "nft",
            [
                "insert",
                "rule",
                "inet",
                "fw4",
                "forward",
                "iifname",
                easytier_iface.as_str(),
                "oifname",
                policy.exit_wan_iface.as_str(),
                "ip",
                "saddr",
                cidr.as_str(),
                "counter",
                "accept",
                "comment",
                "easytier_gw",
            ],
        ));
    }

    commands.push(CommandSpec::optional(
        "nft",
        [
            "insert",
            "rule",
            "inet",
            "fw4",
            "forward",
            "iifname",
            policy.exit_wan_iface.as_str(),
            "oifname",
            easytier_iface.as_str(),
            "ct",
            "state",
            "established,related",
            "counter",
            "accept",
            "comment",
            "easytier_gw",
        ],
    ));

    Ok(commands)
}

/// 生成清理命令，调用方会忽略不存在规则产生的错误
fn plan_cleanup() -> Vec<CommandSpec> {
    vec![
        CommandSpec::optional(
            "sh",
            [
                "-c",
                "for chain in input forward srcnat; do nft -a list chain inet fw4 \"$chain\" 2>/dev/null | awk '/easytier_gw/ {print $NF}' | while read handle; do nft delete rule inet fw4 \"$chain\" handle \"$handle\" 2>/dev/null || true; done; done",
            ],
        ),
        CommandSpec::optional(
            "sh",
            [
                "-c",
                "while ip rule show | grep -q 'fwmark 0x7e.*lookup 126\\|fwmark 0x7e.*table 126'; do ip rule del fwmark 0x7e table 126 2>/dev/null || break; done",
            ],
        ),
        CommandSpec::new(
            "ip",
            [
                "rule",
                "del",
                "fwmark",
                format!("0x{:x}", FWMARK).as_str(),
                "table",
                ROUTE_TABLE.to_string().as_str(),
            ],
        ),
        CommandSpec::new(
            "ip",
            ["route", "flush", "table", ROUTE_TABLE.to_string().as_str()],
        ),
        CommandSpec::new("nft", ["delete", "table", "inet", NFT_TABLE]),
    ]
}

/// 校验策略的通用字段
fn validate_common(policy: &GatewayPolicy) -> Result<()> {
    if policy.policy_id.trim().is_empty() {
        bail!("policy_id 不能为空");
    }

    if policy.managed_cidrs.is_empty() {
        bail!("managed_cidrs 不能为空");
    }

    for cidr in &policy.managed_cidrs {
        cidr.parse::<IpCidr>()
            .with_context(|| format!("managed_cidrs 包含非法 CIDR: {}", cidr))?;
    }

    Ok(())
}

/// 校验 Linux 网口名，避免空值或明显非法参数进入命令执行
fn validate_iface(field: &str, iface: &str) -> Result<()> {
    if iface.trim().is_empty() {
        bail!("{} 不能为空", field);
    }

    let valid = iface
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'));
    if !valid {
        bail!("{} 包含非法字符: {}", field, iface);
    }

    Ok(())
}

/// 校验 IP 字段并返回解析结果
fn validate_ip(field: &str, ip: &str) -> Result<IpAddr> {
    if ip.trim().is_empty() {
        bail!("{} 不能为空", field);
    }

    ip.parse::<IpAddr>()
        .with_context(|| format!("{} 不是合法 IP: {}", field, ip))
}

/// 获取 EasyTier tun 网口，策略未指定时使用 tun0
fn normalize_easytier_iface(policy: &GatewayPolicy) -> Result<String> {
    let iface = if policy.easytier_iface.trim().is_empty() {
        DEFAULT_EASYTIER_IFACE.to_string()
    } else {
        policy.easytier_iface.trim().to_string()
    };

    validate_iface("easytier_iface", &iface)?;
    Ok(iface)
}

/// 执行系统命令并记录日志
async fn run_command(command: &CommandSpec) -> Result<()> {
    debug!(cmd = %command.cmd, args = ?command.args, "执行命令");

    let output = tokio::process::Command::new(command.cmd)
        .args(&command.args)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if command.ignore_error {
            debug!(
                cmd = %command.cmd,
                args = ?command.args,
                stderr = %stderr,
                "可选命令执行失败，已忽略"
            );
            return Ok(());
        }
        warn!(
            cmd = %command.cmd,
            args = ?command.args,
            stderr = %stderr,
            "命令执行失败"
        );
        anyhow::bail!("命令 {} {:?} 失败: {}", command.cmd, command.args, stderr);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::gateway_policy::{GatewayPolicy, GatewayRole};

    fn source_policy() -> GatewayPolicy {
        GatewayPolicy {
            policy_id: "gw-source".to_string(),
            enabled: true,
            role: GatewayRole::Source.into(),
            managed_cidrs: vec!["192.168.128.0/24".to_string()],
            ingress_iface: "br-lan".to_string(),
            exit_peer_tun_ip: "10.126.126.3".to_string(),
            easytier_iface: "et0".to_string(),
            ..Default::default()
        }
    }

    fn exit_policy() -> GatewayPolicy {
        GatewayPolicy {
            policy_id: "gw-exit".to_string(),
            enabled: true,
            role: GatewayRole::Exit.into(),
            managed_cidrs: vec!["192.168.128.0/24".to_string()],
            exit_wan_iface: "eth0".to_string(),
            easytier_iface: "tun0".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn source_plan_uses_configured_tunnel_iface_and_replace_route() {
        let executor = Executor::new();
        let commands = executor.plan_apply(&source_policy()).unwrap();

        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "ip"
                && cmd.args
                    == vec![
                        "route",
                        "replace",
                        "default",
                        "via",
                        "10.126.126.3",
                        "dev",
                        "et0",
                        "table",
                        "126",
                    ]
        }));
    }

    #[test]
    fn source_plan_allows_openwrt_forward_between_lan_and_tunnel() {
        let executor = Executor::new();
        let commands = executor.plan_apply(&source_policy()).unwrap();

        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "nft"
                && cmd.args
                    == vec![
                        "insert",
                        "rule",
                        "inet",
                        "fw4",
                        "input",
                        "iifname",
                        "et0",
                        "accept",
                        "comment",
                        "easytier_gw",
                    ]
        }));
        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "nft"
                && cmd.args
                    == vec![
                        "insert",
                        "rule",
                        "inet",
                        "fw4",
                        "forward",
                        "iifname",
                        "br-lan",
                        "oifname",
                        "et0",
                        "ip",
                        "saddr",
                        "192.168.128.0/24",
                        "counter",
                        "accept",
                        "comment",
                        "easytier_gw",
                    ]
        }));
        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "nft"
                && cmd.args
                    == vec![
                        "insert",
                        "rule",
                        "inet",
                        "fw4",
                        "forward",
                        "iifname",
                        "et0",
                        "oifname",
                        "br-lan",
                        "ct",
                        "state",
                        "established,related",
                        "counter",
                        "accept",
                        "comment",
                        "easytier_gw",
                    ]
        }));
    }

    #[test]
    fn source_plan_rejects_empty_exit_peer() {
        let executor = Executor::new();
        let mut policy = source_policy();
        policy.exit_peer_tun_ip.clear();

        let err = executor.plan_apply(&policy).unwrap_err().to_string();
        assert!(err.contains("exit_peer_tun_ip"));
    }

    #[test]
    fn plan_rejects_invalid_cidr_before_cleanup() {
        let executor = Executor::new();
        let mut policy = source_policy();
        policy.managed_cidrs = vec!["not-a-cidr".to_string()];

        let err = executor.plan_apply(&policy).unwrap_err().to_string();
        assert!(err.contains("非法 CIDR"));
    }

    #[test]
    fn exit_plan_adds_masquerade_for_managed_cidr() {
        let executor = Executor::new();
        let commands = executor.plan_apply(&exit_policy()).unwrap();

        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "nft"
                && cmd.args
                    == vec![
                        "add",
                        "rule",
                        "inet",
                        NFT_TABLE,
                        "postrouting",
                        "ip",
                        "saddr",
                        "192.168.128.0/24",
                        "oif",
                        "eth0",
                        "masquerade",
                    ]
        }));
    }

    #[test]
    fn exit_plan_allows_forwarding_between_tunnel_and_wan() {
        let executor = Executor::new();
        let commands = executor.plan_apply(&exit_policy()).unwrap();

        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "nft"
                && cmd.args
                    == vec![
                        "add",
                        "rule",
                        "inet",
                        NFT_TABLE,
                        "forward",
                        "iifname",
                        "tun0",
                        "oifname",
                        "eth0",
                        "ip",
                        "saddr",
                        "192.168.128.0/24",
                        "counter",
                        "accept",
                    ]
        }));
        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "nft"
                && cmd.args
                    == vec![
                        "add",
                        "rule",
                        "inet",
                        NFT_TABLE,
                        "forward",
                        "iifname",
                        "eth0",
                        "oifname",
                        "tun0",
                        "ct",
                        "state",
                        "established,related",
                        "counter",
                        "accept",
                    ]
        }));
    }

    #[test]
    fn exit_plan_allows_openwrt_input_from_tunnel() {
        let executor = Executor::new();
        let commands = executor.plan_apply(&exit_policy()).unwrap();

        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "nft"
                && cmd.args
                    == vec![
                        "insert",
                        "rule",
                        "inet",
                        "fw4",
                        "input",
                        "iifname",
                        "tun0",
                        "accept",
                        "comment",
                        "easytier_gw",
                    ]
        }));
    }

    #[test]
    fn plan_rejects_unknown_role() {
        let executor = Executor::new();
        let mut policy = source_policy();
        policy.role = 99;

        let err = executor.plan_apply(&policy).unwrap_err().to_string();
        assert!(err.contains("未知网关角色"));
    }

    #[test]
    fn cleanup_plan_removes_policy_route_and_nft_table() {
        let commands = plan_cleanup();

        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "ip" && cmd.args == vec!["rule", "del", "fwmark", "0x7e", "table", "126"]
        }));
        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "nft" && cmd.args == vec!["delete", "table", "inet", NFT_TABLE]
        }));
    }

    #[test]
    fn cleanup_plan_removes_all_duplicate_fwmark_rules() {
        let commands = plan_cleanup();

        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "sh"
                && cmd.args.iter().any(|arg| {
                    arg.contains("while ip rule show")
                        && arg.contains("fwmark 0x7e")
                        && arg.contains("ip rule del fwmark 0x7e table 126")
                })
        }));
    }

    #[test]
    fn cleanup_plan_removes_openwrt_fw4_gateway_rules_from_all_used_chains() {
        let commands = plan_cleanup();

        assert!(commands.iter().any(|cmd| {
            cmd.cmd == "sh"
                && cmd.args.iter().any(|arg| {
                    arg.contains("for chain in input forward srcnat")
                        && arg.contains("/easytier_gw/")
                        && arg.contains("nft delete rule inet fw4 \"$chain\" handle")
                })
        }));
    }
}
