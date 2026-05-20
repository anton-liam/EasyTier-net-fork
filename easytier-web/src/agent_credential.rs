use chrono::{DateTime, Utc};

use crate::db::UserIdInDb;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapToken {
    pub id: i64,
    pub user_id: UserIdInDb,
    pub token_hash: String,
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenMatch {
    Current,
    Next,
    Previous,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStatus {
    Active,
    Rotating,
    Confirmed,
    Revoked,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Confirmed => "confirmed",
            Self::Revoked => "revoked",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "rotating" => Some(Self::Rotating),
            "confirmed" => Some(Self::Confirmed),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineCredential {
    pub user_id: UserIdInDb,
    pub machine_id: uuid::Uuid,
    pub credential_version: i64,
    pub current_token_hash: String,
    pub next_token_hash: Option<String>,
    pub previous_token_hash: Option<String>,
    pub rotation_status: RotationStatus,
    pub grace_until: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub fn hash_token(token: &str) -> String {
    password_auth::generate_hash(token)
}

pub fn verify_token(token: &str, token_hash: &str) -> bool {
    if let Some(expected) = token_hash.strip_prefix("plain-sha256:") {
        return sha256_hex(token) == expected;
    }
    password_auth::verify_password(token, token_hash).is_ok()
}

fn sha256_hex(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    format!("{digest:x}")
}

impl MachineCredential {
    pub fn active(
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
        credential_version: i64,
        current_token_hash: String,
    ) -> Self {
        Self {
            user_id,
            machine_id,
            credential_version,
            current_token_hash,
            next_token_hash: None,
            previous_token_hash: None,
            rotation_status: RotationStatus::Active,
            grace_until: None,
            revoked_at: None,
        }
    }

    pub fn rotating(
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
        credential_version: i64,
        current_token_hash: String,
        next_token_hash: String,
        grace_until: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id,
            machine_id,
            credential_version,
            current_token_hash,
            next_token_hash: Some(next_token_hash),
            previous_token_hash: None,
            rotation_status: RotationStatus::Rotating,
            grace_until: Some(grace_until),
            revoked_at: None,
        }
    }

    pub fn confirmed(
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
        credential_version: i64,
        current_token_hash: String,
        previous_token_hash: String,
        grace_until: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id,
            machine_id,
            credential_version,
            current_token_hash,
            next_token_hash: None,
            previous_token_hash: Some(previous_token_hash),
            rotation_status: RotationStatus::Confirmed,
            grace_until: Some(grace_until),
            revoked_at: None,
        }
    }

    pub fn verify_machine_token(&self, token: &str, now: DateTime<Utc>) -> TokenMatch {
        if self.revoked_at.is_some() || matches!(self.rotation_status, RotationStatus::Revoked) {
            return TokenMatch::None;
        }

        if verify_token(token, &self.current_token_hash) {
            return TokenMatch::Current;
        }

        if self
            .next_token_hash
            .as_deref()
            .is_some_and(|hash| verify_token(token, hash))
        {
            return TokenMatch::Next;
        }

        if self
            .grace_until
            .is_some_and(|grace_until| now <= grace_until)
            && self
                .previous_token_hash
                .as_deref()
                .is_some_and(|hash| verify_token(token, hash))
        {
            return TokenMatch::Previous;
        }

        TokenMatch::None
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;

    #[test]
    fn token_hash_verifies_only_matching_token() {
        let hash = hash_token("machine-token");

        assert!(verify_token("machine-token", &hash));
        assert!(!verify_token("other-token", &hash));
    }

    #[test]
    fn active_credential_accepts_current_token_only() {
        let credential =
            MachineCredential::active(2, uuid::Uuid::new_v4(), 1, hash_token("current-token"));

        assert_eq!(
            credential.verify_machine_token("current-token", Utc::now()),
            TokenMatch::Current
        );
        assert_eq!(
            credential.verify_machine_token("next-token", Utc::now()),
            TokenMatch::None
        );
    }

    #[test]
    fn rotating_credential_accepts_current_and_next_token() {
        let credential = MachineCredential::rotating(
            2,
            uuid::Uuid::new_v4(),
            2,
            hash_token("current-token"),
            hash_token("next-token"),
            Utc::now() + Duration::hours(1),
        );

        assert_eq!(
            credential.verify_machine_token("current-token", Utc::now()),
            TokenMatch::Current
        );
        assert_eq!(
            credential.verify_machine_token("next-token", Utc::now()),
            TokenMatch::Next
        );
    }

    #[test]
    fn confirmed_credential_accepts_previous_token_only_during_grace_period() {
        let now = Utc::now();
        let credential = MachineCredential::confirmed(
            2,
            uuid::Uuid::new_v4(),
            3,
            hash_token("new-current-token"),
            hash_token("previous-token"),
            now + Duration::hours(1),
        );

        assert_eq!(
            credential.verify_machine_token("new-current-token", now),
            TokenMatch::Current
        );
        assert_eq!(
            credential.verify_machine_token("previous-token", now),
            TokenMatch::Previous
        );
        assert_eq!(
            credential.verify_machine_token("previous-token", now + Duration::hours(2)),
            TokenMatch::None
        );
    }
}
