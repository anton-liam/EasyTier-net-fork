use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct EnrollAgentRequest {
    pub user_id: i32,
    pub machine_id: String,
    pub machine_token_hash: String,
    pub hostname: Option<String>,
    pub agent_version: Option<String>,
    pub easytier_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct EnrollAgentResponse {
    pub credential_version: i64,
    pub api_base_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CredentialStatusResponse {
    pub status: String,
    pub credential_version: i64,
    pub rotate_required: bool,
    pub grace_until: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RotateCredentialRequest {
    pub user_id: i32,
    pub machine_id: String,
    pub next_token_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RotateCredentialResponse {
    pub credential_version: i64,
    pub grace_until: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ConfirmCredentialRequest {
    pub user_id: i32,
    pub machine_id: String,
    pub credential_version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ConfirmCredentialResponse {
    pub status: String,
    pub credential_version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MachineCredentialFile {
    pub machine_id: String,
    pub credential_version: i64,
    pub current_token: String,
    pub next_token: Option<String>,
    pub next_token_status: Option<String>,
    pub api_base_url: Option<String>,
    pub updated_at: String,
}

pub fn read_credential(path: impl AsRef<Path>) -> anyhow::Result<MachineCredentialFile> {
    let raw = fs::read_to_string(path.as_ref())?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn write_credential_atomic(
    path: impl AsRef<Path>,
    credential: &MachineCredentialFile,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("credential path must have parent directory"))?;
    fs::create_dir_all(parent)?;

    let tmp_path = tmp_path_for(path);
    let raw = serde_json::to_vec_pretty(credential)?;
    {
        let mut tmp = fs::File::create(&tmp_path)?;
        tmp.write_all(&raw)?;
        tmp.write_all(b"\n")?;
        tmp.sync_all()?;
    }
    set_private_file_permissions(&tmp_path)?;
    fs::rename(&tmp_path, path)?;
    set_private_file_permissions(path)?;
    Ok(())
}

pub fn enroll_agent(
    web_base_url: &str,
    bootstrap_token: &str,
    request: &EnrollAgentRequest,
) -> anyhow::Result<EnrollAgentResponse> {
    let endpoint = format!(
        "{}/api/internal/agent/enroll",
        web_base_url.trim_end_matches('/')
    );
    let response = attohttpc::post(endpoint)
        .header("Authorization", format!("Bearer {bootstrap_token}"))
        .json(request)?
        .send()?;

    if !response.is_success() {
        anyhow::bail!("agent enrollment failed with status {}", response.status());
    }

    Ok(response.json()?)
}

pub fn enroll_and_store_agent(
    web_base_url: &str,
    bootstrap_token: &str,
    user_id: i32,
    machine_id: &str,
    credential_file: impl AsRef<Path>,
) -> anyhow::Result<MachineCredentialFile> {
    let machine_token = new_machine_token();
    let response = enroll_agent(
        web_base_url,
        bootstrap_token,
        &EnrollAgentRequest {
            user_id,
            machine_id: machine_id.to_string(),
            machine_token_hash: hash_agent_token(&machine_token),
            hostname: None,
            agent_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            easytier_version: None,
        },
    )?;
    let credential = MachineCredentialFile {
        machine_id: machine_id.to_string(),
        credential_version: response.credential_version,
        current_token: machine_token,
        next_token: None,
        next_token_status: None,
        api_base_url: response.api_base_url,
        updated_at: current_unix_timestamp_string(),
    };
    write_credential_atomic(credential_file, &credential)?;
    Ok(credential)
}

pub fn credential_status(
    web_base_url: &str,
    user_id: i32,
    credential: &MachineCredentialFile,
) -> anyhow::Result<CredentialStatusResponse> {
    let endpoint = format!(
        "{}/api/internal/agent/credential",
        web_base_url.trim_end_matches('/')
    );
    let response = machine_auth(attohttpc::get(endpoint), user_id, credential).send()?;

    if !response.is_success() {
        anyhow::bail!("credential status failed with status {}", response.status());
    }

    Ok(response.json()?)
}

pub fn rotate_credential(
    web_base_url: &str,
    user_id: i32,
    credential: &MachineCredentialFile,
) -> anyhow::Result<(RotateCredentialResponse, String)> {
    let endpoint = format!(
        "{}/api/internal/agent/credential/rotate",
        web_base_url.trim_end_matches('/')
    );
    let next_token = new_machine_token();
    let response = machine_auth(attohttpc::post(endpoint), user_id, credential)
        .json(&RotateCredentialRequest {
            user_id,
            machine_id: credential.machine_id.clone(),
            next_token_hash: hash_agent_token(&next_token),
        })?
        .send()?;

    if !response.is_success() {
        anyhow::bail!("credential rotate failed with status {}", response.status());
    }

    Ok((response.json()?, next_token))
}

pub fn confirm_credential(
    web_base_url: &str,
    user_id: i32,
    credential: &MachineCredentialFile,
) -> anyhow::Result<ConfirmCredentialResponse> {
    let Some(next_token) = credential.next_token.as_ref() else {
        anyhow::bail!("credential confirm requires next_token");
    };
    let endpoint = format!(
        "{}/api/internal/agent/credential/confirm",
        web_base_url.trim_end_matches('/')
    );
    let response = attohttpc::post(endpoint)
        .header("Authorization", format!("Bearer {next_token}"))
        .header("X-User-Id", user_id.to_string())
        .header("X-Machine-Id", credential.machine_id.as_str())
        .header(
            "X-Credential-Version",
            credential.credential_version.to_string(),
        )
        .json(&ConfirmCredentialRequest {
            user_id,
            machine_id: credential.machine_id.clone(),
            credential_version: credential.credential_version,
        })?
        .send()?;

    if !response.is_success() {
        anyhow::bail!(
            "credential confirm failed with status {}",
            response.status()
        );
    }

    Ok(response.json()?)
}

pub fn rotate_and_confirm_credential(
    web_base_url: &str,
    user_id: i32,
    credential_file: impl AsRef<Path>,
) -> anyhow::Result<MachineCredentialFile> {
    let credential_file = credential_file.as_ref();
    let mut credential = read_credential(credential_file)?;
    let status = credential_status(web_base_url, user_id, &credential)?;
    if !status.rotate_required {
        return Ok(credential);
    }

    let (rotate, next_token) = rotate_credential(web_base_url, user_id, &credential)?;
    credential.credential_version = rotate.credential_version;
    credential.next_token = Some(next_token);
    credential.next_token_status = Some("pending_confirm".to_string());
    credential.updated_at = current_unix_timestamp_string();
    write_credential_atomic(credential_file, &credential)?;

    confirm_credential(web_base_url, user_id, &credential)?;
    let next_token = credential
        .next_token
        .take()
        .ok_or_else(|| anyhow::anyhow!("next token disappeared during confirm"))?;
    credential.current_token = next_token;
    credential.next_token_status = None;
    credential.updated_at = current_unix_timestamp_string();
    write_credential_atomic(credential_file, &credential)?;
    Ok(credential)
}

fn machine_auth(
    request: attohttpc::RequestBuilder,
    user_id: i32,
    credential: &MachineCredentialFile,
) -> attohttpc::RequestBuilder {
    request
        .header(
            "Authorization",
            format!("Bearer {}", credential.current_token),
        )
        .header("X-User-Id", user_id.to_string())
        .header("X-Machine-Id", credential.machine_id.as_str())
        .header(
            "X-Credential-Version",
            credential.credential_version.to_string(),
        )
}

pub fn new_machine_token() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn hash_agent_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    format!("plain-sha256:{digest:x}")
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "credential.json".into());
    file_name.push(".tmp");
    path.with_file_name(file_name)
}

fn current_unix_timestamp_string() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_store_round_trip_uses_atomic_tmp_file() {
        let dir = std::env::temp_dir().join(format!(
            "easytier-agent-credential-{}",
            uuid::Uuid::new_v4()
        ));
        let path = dir.join("credential.json");
        let credential = MachineCredentialFile {
            machine_id: "00000000-0000-0000-0000-000000000001".to_string(),
            credential_version: 3,
            current_token: "current-token".to_string(),
            next_token: Some("next-token".to_string()),
            next_token_status: Some("pending_confirm".to_string()),
            api_base_url: Some("http://10.126.126.1:11211".to_string()),
            updated_at: "2026-05-20T10:00:00Z".to_string(),
        };

        write_credential_atomic(&path, &credential).unwrap();

        assert_eq!(read_credential(&path).unwrap(), credential);
        assert!(!tmp_path_for(&path).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
