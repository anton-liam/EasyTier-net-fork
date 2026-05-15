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
        let mut commands = vec![CommandPlan::new(
            "ip",
            [
                "route",
                "replace",
                "default",
                "via",
                exit_peer,
                "dev",
                "easytier0",
                "table",
                &self.table_id.to_string(),
            ],
        )];

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
        }
        commands
    }

    fn exit_apply(&self, policy: &DevicePolicy) -> Vec<CommandPlan> {
        let mut batch = String::new();
        batch.push_str("uci -q batch <<'UCI'\n");
        batch.push_str(&format!(
            "delete firewall.{}\n",
            uci_section_name("forward", &policy.device_policy_id)
        ));
        batch.push_str(&format!(
            "set firewall.{}=rule\n",
            uci_section_name("forward", &policy.device_policy_id)
        ));
        batch.push_str(&format!(
            "set firewall.{}.name='{}'\n",
            uci_section_name("forward", &policy.device_policy_id),
            uci_quote(&format!(
                "easytier-agent-forward-{}",
                policy.device_policy_id
            ))
        ));
        batch.push_str(&format!(
            "set firewall.{}.proto='all'\n",
            uci_section_name("forward", &policy.device_policy_id)
        ));
        batch.push_str(&format!(
            "set firewall.{}.target='ACCEPT'\n",
            uci_section_name("forward", &policy.device_policy_id)
        ));
        batch.push_str(&format!(
            "set firewall.{}.extra='-i easytier0 -m comment --comment {}'\n",
            uci_section_name("forward", &policy.device_policy_id),
            uci_quote(&policy.device_policy_id)
        ));

        for (idx, cidr) in policy.managed_cidrs.iter().enumerate() {
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
            batch.push_str(&format!(
                "set firewall.{section}.extra='-m comment --comment {}'\n",
                uci_quote(&policy.device_policy_id)
            ));
        }
        batch.push_str("commit firewall\nUCI");

        vec![
            CommandPlan::new("sysctl", ["-w", "net.ipv4.ip_forward=1"]),
            CommandPlan::new("sh", ["-c", &batch]),
            CommandPlan::new("fw4", ["reload"]),
        ]
    }

    fn exit_cleanup(&self, policy: &DevicePolicy) -> Vec<CommandPlan> {
        let mut batch = String::new();
        batch.push_str("uci -q batch <<'UCI'\n");
        batch.push_str(&format!(
            "delete firewall.{}\n",
            uci_section_name("forward", &policy.device_policy_id)
        ));
        for (idx, _) in policy.managed_cidrs.iter().enumerate() {
            batch.push_str(&format!(
                "delete firewall.{}\n",
                uci_section_name(&format!("nat_{idx}"), &policy.device_policy_id)
            ));
        }
        batch.push_str("commit firewall\nUCI");
        vec![
            CommandPlan::new("sh", ["-c", &batch]),
            CommandPlan::new("fw4", ["reload"]),
        ]
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

fn uci_quote(value: &str) -> String {
    value.replace('\'', "'\"'\"'")
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
                .any(|cmd| cmd.contains("uci -q batch") && cmd.contains("=rule"))
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
}
