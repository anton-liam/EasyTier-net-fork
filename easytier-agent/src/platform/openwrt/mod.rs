use crate::{
    platform::{CommandPlan, PlatformBackend},
    policy::{DevicePolicy, DevicePolicyRole},
};

#[derive(Debug, Clone)]
pub struct OpenWrtBackend {
    table_id: u32,
    mark: String,
}

impl Default for OpenWrtBackend {
    fn default() -> Self {
        Self {
            table_id: 126,
            mark: "0x7e".to_string(),
        }
    }
}

impl OpenWrtBackend {
    fn source_apply(&self, policy: &DevicePolicy) -> Vec<CommandPlan> {
        let exit_peer = policy.exit_peer_ipv4.as_deref().unwrap_or_default();
        let easytier_iface = policy.easytier_iface.as_str();
        let mut commands = vec![CommandPlan::new(
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
        )];

        for cidr in policy
            .managed_cidrs
            .iter()
            .filter(|cidr| !is_ipv4_default_route(cidr))
        {
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

        if policy
            .managed_cidrs
            .iter()
            .any(|cidr| is_ipv4_default_route(cidr))
        {
            commands.push(CommandPlan::new(
                "sh",
                [
                    "-c",
                    &format!(
                        "ip rule del from 0.0.0.0/0 lookup {table} 2>/dev/null || true",
                        table = self.table_id
                    ),
                ],
            ));
            for iface in &policy.ingress_ifaces {
                commands.push(CommandPlan::new(
                    "sh",
                    [
                        "-c",
                        &format!(
                            "ip rule del iif {iface} lookup {table} 2>/dev/null || true; ip rule add iif {iface} lookup {table}",
                            table = self.table_id
                        ),
                    ],
                ));
            }
        }

        if policy.include_device_traffic {
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
        for cidr in policy
            .managed_cidrs
            .iter()
            .filter(|cidr| !is_ipv4_default_route(cidr))
        {
            commands.push(CommandPlan::new(
                "sh",
                [
                    "-c",
                    &format!(
                        "ip rule del from {cidr} lookup {table} 2>/dev/null || true",
                        table = self.table_id
                    ),
                ],
            ));
        }
        if policy
            .managed_cidrs
            .iter()
            .any(|cidr| is_ipv4_default_route(cidr))
        {
            for iface in &policy.ingress_ifaces {
                commands.push(CommandPlan::new(
                    "sh",
                    [
                        "-c",
                        &format!(
                            "ip rule del iif {iface} lookup {table} 2>/dev/null || true",
                            table = self.table_id
                        ),
                    ],
                ));
            }
        }
        if policy.include_device_traffic {
            commands.push(CommandPlan::new(
                "sh",
                [
                    "-c",
                    &format!(
                        "ip rule del fwmark {mark} lookup {table} 2>/dev/null || true",
                        mark = self.mark,
                        table = self.table_id
                    ),
                ],
            ));
        }
        commands.push(CommandPlan::new(
            "sh",
            [
                "-c",
                &format!(
                    "ip route flush table {table} 2>/dev/null || true",
                    table = self.table_id
                ),
            ],
        ));
        commands
    }

    fn exit_apply(&self, policy: &DevicePolicy) -> Vec<CommandPlan> {
        let easytier_iface = policy.easytier_iface.as_str();
        let source_peer = policy.source_peer_ipv4.as_deref().unwrap_or_default();
        let mut batch = String::new();
        batch.push_str("uci -q batch <<'UCI'\n");
        batch.push_str(&format!(
            "delete firewall.{}\n",
            uci_section_name("forward", &policy.device_policy_id)
        ));

        let nat_sources = nat_sources(policy);
        for (idx, cidr) in nat_sources.iter().enumerate() {
            let section = uci_section_name(&format!("nat_{idx}"), &policy.device_policy_id);
            batch.push_str(&format!("delete firewall.{section}\n"));
            batch.push_str(&format!("set firewall.{section}=nat\n"));
            batch.push_str(&format!(
                "set firewall.{section}.name='{}'\n",
                uci_quote(&format!(
                    "easytier-agent-nat-{}-{idx}",
                    policy.device_policy_id
                ))
            ));
            batch.push_str(&format!("set firewall.{section}.src='*'\n"));
            batch.push_str(&format!(
                "set firewall.{section}.src_ip='{}'\n",
                uci_quote(cidr)
            ));
            batch.push_str(&format!("set firewall.{section}.target='MASQUERADE'\n"));
        }
        batch.push_str("commit firewall\nUCI");
        let delete_forward_rule = nft_delete_forward_rule_command(&policy.device_policy_id);
        let add_forward_rule = format!(
            "nft insert rule inet fw4 forward iifname {} accept comment {}",
            nft_string(easytier_iface),
            nft_string(&policy.device_policy_id)
        );

        vec![
            CommandPlan::new("sysctl", ["-w", "net.ipv4.ip_forward=1"]),
            CommandPlan::new("sh", ["-c", &batch]),
            CommandPlan::new("fw4", ["reload"]),
            CommandPlan::new("sh", ["-c", &delete_forward_rule]),
            CommandPlan::new("sh", ["-c", &add_forward_rule]),
        ]
        .into_iter()
        .chain(
            policy
                .managed_cidrs
                .iter()
                .filter(|cidr| !is_ipv4_default_route(cidr))
                .map(|cidr| {
                    CommandPlan::new(
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
                    )
                }),
        )
        .chain(std::iter::once(CommandPlan::new(
            "sh",
            [
                "-c",
                &format!(
                    "ip route flush table {table} 2>/dev/null || true",
                    table = self.table_id
                ),
            ],
        )))
        .collect()
    }

    fn exit_cleanup(&self, policy: &DevicePolicy) -> Vec<CommandPlan> {
        let mut batch = String::new();
        batch.push_str("uci -q batch <<'UCI'\n");
        batch.push_str(&format!(
            "delete firewall.{}\n",
            uci_section_name("forward", &policy.device_policy_id)
        ));
        for idx in 0..nat_sources(policy).len() {
            batch.push_str(&format!(
                "delete firewall.{}\n",
                uci_section_name(&format!("nat_{idx}"), &policy.device_policy_id)
            ));
        }
        batch.push_str("commit firewall\nUCI");
        let delete_forward_rule = nft_delete_forward_rule_command(&policy.device_policy_id);
        vec![
            CommandPlan::new("sh", ["-c", &batch]),
            CommandPlan::new("fw4", ["reload"]),
            CommandPlan::new("sh", ["-c", &delete_forward_rule]),
        ]
        .into_iter()
        .chain(
            policy
                .managed_cidrs
                .iter()
                .filter(|cidr| !is_ipv4_default_route(cidr))
                .map(|cidr| {
                    CommandPlan::new(
                        "sh",
                        [
                            "-c",
                            &format!("ip route del {cidr} 2>/dev/null || true"),
                        ],
                    )
                }),
        )
        .chain(std::iter::once(CommandPlan::new(
            "sh",
            [
                "-c",
                &format!(
                    "ip route flush table {table} 2>/dev/null || true",
                    table = self.table_id
                ),
            ],
        )))
        .collect()
    }
}

impl PlatformBackend for OpenWrtBackend {
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

fn uci_section_name(prefix: &str, device_policy_id: &str) -> String {
    let suffix = device_policy_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("easytier_agent_{prefix}_{suffix}")
}

fn is_ipv4_default_route(cidr: &str) -> bool {
    cidr.trim() == "0.0.0.0/0"
}

fn uci_quote(value: &str) -> String {
    value.replace('\'', "'\"'\"'")
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn nft_delete_forward_rule_command(device_policy_id: &str) -> String {
    let quoted_comment = shell_single_quote(device_policy_id);
    format!(
        "nft -a list chain inet fw4 forward 2>/dev/null | awk -v c={} 'index($0, c) {{ print $NF }}' | xargs -r -n1 nft delete rule inet fw4 forward handle",
        quoted_comment
    )
}

fn nft_string(value: &str) -> String {
    format!(
        "\\\"{}\\\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    )
}

fn nat_sources(policy: &DevicePolicy) -> Vec<String> {
    let mut sources = Vec::new();
    if policy.include_device_traffic {
        if let Some(source_peer) = policy.source_peer_ipv4.as_deref() {
            sources.push(format!("{source_peer}/32"));
        }
    }
    sources.extend(policy.managed_cidrs.iter().cloned());
    sources
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::{
        platform::{PlatformBackend, openwrt::OpenWrtBackend},
        policy::{DevicePolicy, DevicePolicyRole, ExitEgress, ExitEgressMode},
    };

    fn policy(role: DevicePolicyRole) -> DevicePolicy {
        DevicePolicy {
            policy_id: "p1".to_string(),
            device_policy_id: "p1/source".to_string(),
            enabled: true,
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
    fn exit_apply_uses_uci_firewall_and_fw4_reload() {
        let backend = OpenWrtBackend::default();
        let commands = backend
            .plan_apply(&policy(DevicePolicyRole::ProvideExitForGateway))
            .unwrap();
        let shell_commands = commands
            .iter()
            .filter(|cmd| cmd.program == "sh")
            .map(|cmd| cmd.args.join(" "))
            .collect::<Vec<_>>();

        assert!(
            shell_commands
                .iter()
                .any(|cmd| cmd.contains("uci -q batch") && cmd.contains("=nat"))
        );
        assert!(
            shell_commands
                .iter()
                .any(|cmd| cmd.contains("=nat") && cmd.contains("MASQUERADE"))
        );
        assert!(
            commands
                .iter()
                .any(|cmd| cmd.program == "fw4" && cmd.args == ["reload"])
        );
        assert!(
            shell_commands
                .iter()
                .any(|cmd| cmd.contains("nft insert rule inet fw4 forward"))
        );
        assert!(!shell_commands.iter().any(|cmd| cmd.contains(".extra=")));
    }

    #[test]
    fn exit_apply_adds_nat_for_source_peer_when_device_traffic_enabled() {
        let backend = OpenWrtBackend::default();
        let mut policy = policy(DevicePolicyRole::ProvideExitForGateway);
        policy.device_policy_id = "p1/exit".to_string();
        policy.managed_cidrs.clear();
        policy.include_device_traffic = true;

        let commands = backend.plan_apply(&policy).unwrap();
        let command_text = commands
            .iter()
            .map(|cmd| format!("{} {}", cmd.program, cmd.args.join(" ")))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            command_text
                .contains("set firewall.easytier_agent_nat_0_p1_exit.src_ip='10.126.126.2/32'")
        );
    }

    #[test]
    fn exit_apply_inserts_forward_rule_before_fw4_reject_tail() {
        let backend = OpenWrtBackend::default();
        let commands = backend
            .plan_apply(&policy(DevicePolicyRole::ProvideExitForGateway))
            .unwrap();
        let add_forward_rule = commands
            .iter()
            .filter(|cmd| cmd.program == "sh")
            .map(|cmd| cmd.args.join(" "))
            .find(|cmd| cmd.contains("nft") && cmd.contains("iifname"))
            .expect("missing nft forward accept rule");

        assert!(
            add_forward_rule.contains("nft insert rule inet fw4 forward"),
            "forward accept rule must be inserted before fw4 handle_reject tail: {add_forward_rule}"
        );
    }

    #[test]
    fn exit_apply_routes_managed_cidrs_back_to_source_peer() {
        let backend = OpenWrtBackend::default();
        let commands = backend
            .plan_apply(&policy(DevicePolicyRole::ProvideExitForGateway))
            .unwrap();
        let command_text = commands
            .iter()
            .map(|cmd| format!("{} {}", cmd.program, cmd.args.join(" ")))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            command_text
                .contains("ip route replace 192.168.10.0/24 via 10.126.126.2 dev easytier0"),
            "exit node must route managed client CIDRs back to the source EasyTier peer: {command_text}"
        );
    }

    #[test]
    fn source_apply_keeps_policy_routing_outside_firewall_zones() {
        let backend = OpenWrtBackend::default();
        let commands = backend
            .plan_apply(&policy(DevicePolicyRole::ClientGatewayViaPeer))
            .unwrap();
        let command_text = commands
            .iter()
            .map(|cmd| format!("{} {}", cmd.program, cmd.args.join(" ")))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(command_text.contains("ip route replace default via 10.126.126.3"));
        assert!(command_text.contains("ip rule add from 192.168.10.0/24 lookup 126"));
        assert!(!command_text.contains("set firewall.@zone"));
        assert!(!command_text.contains("network.wan"));
        assert!(!command_text.contains("network.lan"));
    }

    #[test]
    fn source_apply_routes_full_tunnel_by_ingress_interface_not_all_sources() {
        let backend = OpenWrtBackend::default();
        let mut policy = policy(DevicePolicyRole::ClientGatewayViaPeer);
        policy.managed_cidrs = vec!["0.0.0.0/0".to_string()];
        policy.ingress_ifaces = vec!["br-lan".to_string()];

        let commands = backend.plan_apply(&policy).unwrap();
        let command_text = commands
            .iter()
            .map(|cmd| format!("{} {}", cmd.program, cmd.args.join(" ")))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(command_text.contains("ip rule add iif br-lan lookup 126"));
        assert!(command_text.contains("ip rule del from 0.0.0.0/0 lookup 126"));
        assert!(!command_text.contains("ip rule add from 0.0.0.0/0 lookup 126"));
    }

    #[test]
    fn source_cleanup_flushes_policy_route_table() {
        let backend = OpenWrtBackend::default();
        let commands = backend
            .plan_cleanup(&policy(DevicePolicyRole::ClientGatewayViaPeer))
            .unwrap();

        assert!(commands.iter().any(|cmd| {
            cmd.program == "sh"
                && cmd
                    .args
                    .join(" ")
                    .contains("ip route flush table 126 2>/dev/null || true")
        }));
    }

    #[test]
    fn exit_cleanup_flushes_policy_route_table() {
        let backend = OpenWrtBackend::default();
        let commands = backend
            .plan_cleanup(&policy(DevicePolicyRole::ProvideExitForGateway))
            .unwrap();

        assert!(commands.iter().any(|cmd| {
            cmd.program == "sh"
                && cmd
                    .args
                    .join(" ")
                    .contains("ip route flush table 126 2>/dev/null || true")
        }));
    }

    #[test]
    fn apply_uses_configured_easytier_interface() {
        let backend = OpenWrtBackend::default();
        let mut source_policy = policy(DevicePolicyRole::ClientGatewayViaPeer);
        source_policy.easytier_iface = "easytierw0".to_string();
        let source_text = backend
            .plan_apply(&source_policy)
            .unwrap()
            .iter()
            .map(|cmd| format!("{} {}", cmd.program, cmd.args.join(" ")))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(source_text.contains("dev easytierw0 table 126"));

        let mut exit_policy = policy(DevicePolicyRole::ProvideExitForGateway);
        exit_policy.easytier_iface = "easytierw0".to_string();
        let exit_text = backend
            .plan_apply(&exit_policy)
            .unwrap()
            .iter()
            .map(|cmd| format!("{} {}", cmd.program, cmd.args.join(" ")))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(exit_text.contains("iifname \\\"easytierw0\\\""));
    }
}
