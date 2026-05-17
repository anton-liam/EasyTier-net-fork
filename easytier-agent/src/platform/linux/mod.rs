use crate::{
    platform::{CommandPlan, PlatformBackend},
    policy::{DevicePolicy, DevicePolicyRole},
};

#[derive(Debug, Clone)]
pub struct LinuxBackend {
    table_id: u32,
    mark: String,
    nft_table: String,
}

impl Default for LinuxBackend {
    fn default() -> Self {
        Self {
            table_id: 126,
            mark: "0x7e".to_string(),
            nft_table: "easytier_agent".to_string(),
        }
    }
}

impl LinuxBackend {
    pub fn new(table_id: u32, mark: impl Into<String>, nft_table: impl Into<String>) -> Self {
        Self {
            table_id,
            mark: mark.into(),
            nft_table: nft_table.into(),
        }
    }

    pub fn table_id(&self) -> u32 {
        self.table_id
    }

    fn ensure_nft_table_command(&self) -> CommandPlan {
        let nft_table = &self.nft_table;
        CommandPlan::new(
            "sh",
            [
                "-c",
                &format!(
                    "nft list table inet {nft_table} >/dev/null 2>&1 || nft add table inet {nft_table}"
                ),
            ],
        )
    }

    fn delete_nft_rules_by_comment_command(&self, chain: &str, comment: &str) -> CommandPlan {
        let script = format!(
            "nft -a list chain inet {} {} 2>/dev/null | awk -v comment=\"$1\" '$0 ~ \"comment \\\\\"\" comment \"\\\\\"\" {{ print $NF }}' | while read handle; do nft delete rule inet {} {} handle \"$handle\"; done",
            self.nft_table, chain, self.nft_table, chain
        );
        CommandPlan::new("sh", ["-c", &script, "easytier-agent-cleanup", comment])
    }

    fn source_apply(&self, policy: &DevicePolicy) -> Vec<CommandPlan> {
        let exit_peer = policy.exit_peer_ipv4.as_deref().unwrap_or_default();
        let easytier_iface = policy.easytier_iface.as_str();
        let mut commands = vec![
            CommandPlan::new("ip", ["route", "show", "default"]),
            CommandPlan::new(
                "ip",
                [
                    "route",
                    "replace",
                    "default",
                    "via",
                    exit_peer,
                    "dev",
                    easytier_iface,
                    "table",
                    &self.table_id.to_string(),
                ],
            ),
        ];

        for cidr in &policy.managed_cidrs {
            commands.push(CommandPlan::new(
                "sh",
                [
                    "-c",
                    &format!(
                        "ip rule del from {cidr} lookup {table} 2>/dev/null || true; ip rule add from {cidr} lookup {table}",
                        table = self.table_id
                    ),
                ],
            ));
        }

        if policy.include_device_traffic {
            let nft_table = &self.nft_table;
            let output_chain = format!(
                "nft list chain inet {nft_table} output >/dev/null 2>&1 || nft add chain inet {nft_table} output '{{ type route hook output priority mangle; }}'"
            );
            commands.push(self.ensure_nft_table_command());
            commands.push(CommandPlan::new("sh", ["-c", &output_chain]));
            commands
                .push(self.delete_nft_rules_by_comment_command("output", &policy.device_policy_id));
            commands.push(CommandPlan::new(
                "nft",
                [
                    "add",
                    "rule",
                    "inet",
                    &self.nft_table,
                    "output",
                    "meta",
                    "mark",
                    "set",
                    &self.mark,
                    "comment",
                    &policy.device_policy_id,
                ],
            ));
            commands.push(CommandPlan::new(
                "sh",
                [
                    "-c",
                    &format!(
                        "ip rule del fwmark {mark} lookup {table} 2>/dev/null || true; ip rule add fwmark {mark} lookup {table}",
                        mark = self.mark,
                        table = self.table_id
                    ),
                ],
            ));
        }

        commands
    }

    fn source_cleanup(&self, policy: &DevicePolicy) -> Vec<CommandPlan> {
        let mut commands = Vec::new();
        for cidr in &policy.managed_cidrs {
            if cidr.trim() == "0.0.0.0/0" {
                continue;
            }
            commands.push(CommandPlan::new(
                "ip",
                [
                    "rule",
                    "del",
                    "from",
                    cidr,
                    "lookup",
                    &self.table_id.to_string(),
                ],
            ));
        }
        if policy.include_device_traffic {
            commands.push(CommandPlan::new(
                "ip",
                [
                    "rule",
                    "del",
                    "fwmark",
                    &self.mark,
                    "lookup",
                    &self.table_id.to_string(),
                ],
            ));
            commands
                .push(self.delete_nft_rules_by_comment_command("output", &policy.device_policy_id));
        }
        commands
    }

    fn exit_apply(&self, policy: &DevicePolicy) -> Vec<CommandPlan> {
        let easytier_iface = policy.easytier_iface.as_str();
        let source_peer = policy.source_peer_ipv4.as_deref().unwrap_or_default();
        let nft_table = &self.nft_table;
        let postrouting_chain = format!(
            "nft list chain inet {nft_table} postrouting >/dev/null 2>&1 || nft add chain inet {nft_table} postrouting '{{ type nat hook postrouting priority srcnat; }}'"
        );
        let forward_chain = format!(
            "nft list chain inet {nft_table} forward >/dev/null 2>&1 || nft add chain inet {nft_table} forward '{{ type filter hook forward priority filter; }}'"
        );
        let mut commands = vec![
            CommandPlan::new("sysctl", ["-w", "net.ipv4.ip_forward=1"]),
            self.ensure_nft_table_command(),
            CommandPlan::new("sh", ["-c", &postrouting_chain]),
            CommandPlan::new("sh", ["-c", &forward_chain]),
            self.delete_nft_rules_by_comment_command("forward", &policy.device_policy_id),
            CommandPlan::new(
                "nft",
                [
                    "add",
                    "rule",
                    "inet",
                    &self.nft_table,
                    "forward",
                    "iifname",
                    easytier_iface,
                    "accept",
                    "comment",
                    &policy.device_policy_id,
                ],
            ),
        ];

        commands.push(
            self.delete_nft_rules_by_comment_command("postrouting", &policy.device_policy_id),
        );
        if policy.include_device_traffic {
            commands.push(CommandPlan::new(
                "nft",
                [
                    "add",
                    "rule",
                    "inet",
                    &self.nft_table,
                    "postrouting",
                    "ip",
                    "saddr",
                    &format!("{source_peer}/32"),
                    "masquerade",
                    "comment",
                    &policy.device_policy_id,
                ],
            ));
        }
        for cidr in &policy.managed_cidrs {
            commands.push(CommandPlan::new(
                "nft",
                [
                    "add",
                    "rule",
                    "inet",
                    &self.nft_table,
                    "postrouting",
                    "ip",
                    "saddr",
                    cidr,
                    "masquerade",
                    "comment",
                    &policy.device_policy_id,
                ],
            ));
        }
        for cidr in &policy.managed_cidrs {
            commands.push(CommandPlan::new(
                "ip",
                [
                    "route",
                    "replace",
                    cidr,
                    "via",
                    source_peer,
                    "dev",
                    easytier_iface,
                ],
            ));
        }

        commands
    }

    fn exit_cleanup(&self, policy: &DevicePolicy) -> Vec<CommandPlan> {
        vec![
            self.delete_nft_rules_by_comment_command("postrouting", &policy.device_policy_id),
            self.delete_nft_rules_by_comment_command("forward", &policy.device_policy_id),
        ]
        .into_iter()
        .chain(
            policy
                .managed_cidrs
                .iter()
                .filter(|cidr| cidr.trim() != "0.0.0.0/0")
                .map(|cidr| CommandPlan::new("ip", ["route", "del", cidr])),
        )
        .collect()
    }
}

impl PlatformBackend for LinuxBackend {
    fn plan_apply(&self, policy: &DevicePolicy) -> anyhow::Result<Vec<CommandPlan>> {
        policy.validate()?;
        Ok(match policy.role {
            DevicePolicyRole::ClientGatewayViaPeer => self.source_apply(policy),
            DevicePolicyRole::ProvideExitForGateway => self.exit_apply(policy),
        })
    }

    fn plan_cleanup(&self, policy: &DevicePolicy) -> anyhow::Result<Vec<CommandPlan>> {
        policy.validate()?;
        Ok(match policy.role {
            DevicePolicyRole::ClientGatewayViaPeer => self.source_cleanup(policy),
            DevicePolicyRole::ProvideExitForGateway => self.exit_cleanup(policy),
        })
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::policy::{ExitEgress, ExitEgressMode};

    fn policy(role: DevicePolicyRole) -> DevicePolicy {
        DevicePolicy {
            policy_id: "p1".to_string(),
            device_policy_id: "p1/source".to_string(),
            version: 1,
            role,
            network_instance_id: Uuid::nil(),
            source_machine_id: "node-a".to_string(),
            managed_cidrs: vec!["192.168.10.0/24".to_string()],
            ingress_ifaces: vec!["br-lan".to_string()],
            include_device_traffic: true,
            exit_machine_id: "node-b".to_string(),
            exit_peer_ipv4: Some("10.126.126.3".to_string()),
            source_peer_ipv4: Some("10.126.126.2".to_string()),
            easytier_iface: "easytier0".to_string(),
            exit_egress: ExitEgress {
                mode: ExitEgressMode::Auto,
                iface: None,
            },
            protect_control_plane: true,
            rollback_enabled: true,
        }
    }

    #[test]
    fn source_apply_plan_is_idempotent_shape() {
        let backend = LinuxBackend::default();
        let commands = backend
            .plan_apply(&policy(DevicePolicyRole::ClientGatewayViaPeer))
            .unwrap();
        assert!(commands.iter().any(|cmd| {
            cmd.program == "ip"
                && cmd
                    .args
                    .starts_with(&["route".to_string(), "replace".to_string()])
        }));
        assert!(!commands.iter().any(|cmd| {
            cmd.program == "ip"
                && cmd
                    .args
                    .starts_with(&["rule".to_string(), "replace".to_string()])
        }));
        let shell_commands = commands
            .iter()
            .filter(|cmd| cmd.program == "sh")
            .map(|cmd| cmd.args.join(" "))
            .collect::<Vec<_>>();
        assert!(shell_commands.iter().any(|cmd| {
            cmd.contains("ip rule del from 192.168.10.0/24 lookup 126 2>/dev/null || true")
                && cmd.contains("ip rule add from 192.168.10.0/24 lookup 126")
        }));
        assert!(shell_commands.iter().any(|cmd| {
            cmd.contains("ip rule del fwmark 0x7e lookup 126 2>/dev/null || true")
                && cmd.contains("ip rule add fwmark 0x7e lookup 126")
        }));
    }

    #[test]
    fn source_cleanup_only_targets_this_policy_shape() {
        let backend = LinuxBackend::default();
        let commands = backend
            .plan_cleanup(&policy(DevicePolicyRole::ClientGatewayViaPeer))
            .unwrap();
        assert!(
            commands
                .iter()
                .any(|cmd| cmd.args.contains(&"del".to_string()))
        );
        assert!(commands.iter().any(|cmd| {
            cmd.program == "sh"
                && cmd
                    .args
                    .join(" ")
                    .contains("list chain inet easytier_agent output")
                && cmd.args.contains(&"p1/source".to_string())
        }));
    }

    #[test]
    fn exit_apply_adds_nat_for_managed_cidr() {
        let backend = LinuxBackend::default();
        let commands = backend
            .plan_apply(&policy(DevicePolicyRole::ProvideExitForGateway))
            .unwrap();
        assert!(commands.iter().any(|cmd| cmd.program == "sysctl"));
        assert!(commands.iter().any(|cmd| {
            cmd.program == "nft" && cmd.args.contains(&"192.168.10.0/24".to_string())
        }));
    }

    #[test]
    fn exit_apply_adds_nat_for_source_peer_when_device_traffic_enabled() {
        let backend = LinuxBackend::default();
        let mut policy = policy(DevicePolicyRole::ProvideExitForGateway);
        policy.managed_cidrs.clear();
        policy.include_device_traffic = true;

        let commands = backend.plan_apply(&policy).unwrap();

        assert!(commands.iter().any(|cmd| {
            cmd.program == "nft" && cmd.args.contains(&"10.126.126.2/32".to_string())
        }));
    }

    #[test]
    fn exit_apply_routes_managed_cidrs_back_to_source_peer() {
        let backend = LinuxBackend::default();
        let commands = backend
            .plan_apply(&policy(DevicePolicyRole::ProvideExitForGateway))
            .unwrap();

        assert!(commands.iter().any(|cmd| {
            cmd.program == "ip"
                && cmd.args
                    == [
                        "route".to_string(),
                        "replace".to_string(),
                        "192.168.10.0/24".to_string(),
                        "via".to_string(),
                        "10.126.126.2".to_string(),
                        "dev".to_string(),
                        "easytier0".to_string(),
                    ]
        }));
    }

    #[test]
    fn exit_apply_prepares_nft_table_and_chain_idempotently() {
        let backend = LinuxBackend::default();
        let commands = backend
            .plan_apply(&policy(DevicePolicyRole::ProvideExitForGateway))
            .unwrap();
        let shell_commands = commands
            .iter()
            .filter(|cmd| cmd.program == "sh")
            .map(|cmd| cmd.args.join(" "))
            .collect::<Vec<_>>();

        assert!(shell_commands.iter().any(|cmd| {
            cmd.contains("nft list table inet easytier_agent")
                && cmd.contains("|| nft add table inet easytier_agent")
        }));
        assert!(shell_commands.iter().any(|cmd| {
            cmd.contains("nft list chain inet easytier_agent postrouting")
                && cmd.contains("|| nft add chain inet easytier_agent postrouting")
        }));
    }

    #[test]
    fn source_apply_marks_device_traffic_when_enabled() {
        let backend = LinuxBackend::default();
        let commands = backend
            .plan_apply(&policy(DevicePolicyRole::ClientGatewayViaPeer))
            .unwrap();
        let shell_commands = commands
            .iter()
            .filter(|cmd| cmd.program == "sh")
            .map(|cmd| cmd.args.join(" "))
            .collect::<Vec<_>>();

        assert!(
            shell_commands
                .iter()
                .any(|cmd| cmd.contains("nft list chain inet easytier_agent output"))
        );
        assert!(commands.iter().any(|cmd| {
            cmd.program == "nft"
                && cmd.args.contains(&"output".to_string())
                && cmd.args.windows(4).any(|window| {
                    window
                        == [
                            "meta".to_string(),
                            "mark".to_string(),
                            "set".to_string(),
                            "0x7e".to_string(),
                        ]
                })
        }));
    }

    #[test]
    fn exit_apply_allows_forwarding_from_configured_easytier_interface() {
        let backend = LinuxBackend::default();
        let mut policy = policy(DevicePolicyRole::ProvideExitForGateway);
        policy.easytier_iface = "easytierw0".to_string();
        let commands = backend.plan_apply(&policy).unwrap();
        let shell_commands = commands
            .iter()
            .filter(|cmd| cmd.program == "sh")
            .map(|cmd| cmd.args.join(" "))
            .collect::<Vec<_>>();

        assert!(
            shell_commands
                .iter()
                .any(|cmd| cmd.contains("nft list chain inet easytier_agent forward"))
        );
        assert!(commands.iter().any(|cmd| {
            cmd.program == "nft"
                && cmd.args.contains(&"forward".to_string())
                && cmd.args.windows(3).any(|window| {
                    window
                        == [
                            "iifname".to_string(),
                            "easytierw0".to_string(),
                            "accept".to_string(),
                        ]
                })
        }));
    }

    #[test]
    fn exit_cleanup_targets_policy_comment() {
        let backend = LinuxBackend::default();
        let commands = backend
            .plan_cleanup(&policy(DevicePolicyRole::ProvideExitForGateway))
            .unwrap();
        assert!(commands.len() >= 2);
        assert!(
            commands
                .iter()
                .filter(|command| command.program == "sh")
                .all(|command| command.args.contains(&"p1/source".to_string()))
        );
        assert!(commands.iter().any(|command| command.program == "ip"
            && command.args
                == [
                    "route".to_string(),
                    "del".to_string(),
                    "192.168.10.0/24".to_string(),
                ]));
        assert!(
            commands
                .iter()
                .any(|command| command.args.join(" ").contains("postrouting"))
        );
        assert!(
            commands
                .iter()
                .any(|command| command.args.join(" ").contains("forward"))
        );
    }

    #[test]
    fn exit_cleanup_deletes_nft_rules_by_handle_for_policy_comment() {
        let backend = LinuxBackend::default();
        let commands = backend
            .plan_cleanup(&policy(DevicePolicyRole::ProvideExitForGateway))
            .unwrap();

        assert_eq!(commands[0].program, "sh");
        assert!(
            commands[0]
                .args
                .iter()
                .any(|arg| arg.contains("nft -a list chain"))
        );
        assert!(commands[0].args.iter().any(|arg| arg.contains("handle")));
        assert!(commands[0].args.contains(&"p1/source".to_string()));
    }
}
