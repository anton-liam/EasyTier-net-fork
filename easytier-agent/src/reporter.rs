use serde::Serialize;

use crate::DevicePolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportTarget {
    pub web_base_url: String,
    pub user_id: i32,
    pub machine_id: String,
    pub auth: AgentApiAuth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentApiAuth {
    MachineToken {
        token: String,
        credential_version: i64,
    },
    LegacyInternalToken(String),
}

impl ReportTarget {
    pub fn endpoint(&self) -> String {
        format!(
            "{}/api/internal/users/{}/machines/{}/gateway-report",
            self.web_base_url.trim_end_matches('/'),
            self.user_id,
            self.machine_id
        )
    }

    pub fn device_policies_endpoint(&self) -> String {
        format!(
            "{}/api/internal/users/{}/machines/{}/gateway-policies",
            self.web_base_url.trim_end_matches('/'),
            self.user_id,
            self.machine_id
        )
    }
}

pub fn fetch_device_policies(target: &ReportTarget) -> anyhow::Result<Vec<DevicePolicy>> {
    let request = apply_auth_headers(attohttpc::get(target.device_policies_endpoint()), target);
    let response = request.send()?;

    if !response.is_success() {
        anyhow::bail!(
            "gateway policy fetch failed with status {}",
            response.status()
        );
    }

    Ok(response.json()?)
}

pub fn post_runtime_report<T: Serialize>(target: &ReportTarget, report: &T) -> anyhow::Result<()> {
    let request = apply_auth_headers(attohttpc::post(target.endpoint()), target);
    let response = request.json(report)?.send()?;

    if !response.is_success() {
        anyhow::bail!(
            "gateway report post failed with status {}",
            response.status()
        );
    }

    Ok(())
}

pub fn apply_auth_headers(
    request: attohttpc::RequestBuilder,
    target: &ReportTarget,
) -> attohttpc::RequestBuilder {
    match &target.auth {
        AgentApiAuth::MachineToken {
            token,
            credential_version,
        } => request
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Credential-Version", credential_version.to_string()),
        AgentApiAuth::LegacyInternalToken(token) => request.header("X-Internal-Auth", token),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_target_builds_internal_gateway_report_endpoint() {
        let target = ReportTarget {
            web_base_url: "http://127.0.0.1:11211/".to_string(),
            user_id: 7,
            machine_id: "00000000-0000-0000-0000-000000000001".to_string(),
            auth: AgentApiAuth::LegacyInternalToken("secret".to_string()),
        };

        assert_eq!(
            target.endpoint(),
            "http://127.0.0.1:11211/api/internal/users/7/machines/00000000-0000-0000-0000-000000000001/gateway-report"
        );
    }

    #[test]
    fn report_target_builds_internal_device_policy_endpoint() {
        let target = ReportTarget {
            web_base_url: "http://127.0.0.1:11211/".to_string(),
            user_id: 7,
            machine_id: "00000000-0000-0000-0000-000000000001".to_string(),
            auth: AgentApiAuth::LegacyInternalToken("secret".to_string()),
        };

        assert_eq!(
            target.device_policies_endpoint(),
            "http://127.0.0.1:11211/api/internal/users/7/machines/00000000-0000-0000-0000-000000000001/gateway-policies"
        );
    }
}
