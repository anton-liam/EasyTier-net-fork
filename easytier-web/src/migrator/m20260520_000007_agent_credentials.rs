use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260520_000007_agent_credentials"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE TABLE agent_bootstrap_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                    user_id INTEGER NOT NULL,
                    token_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    expires_at TEXT,
                    revoked_at TEXT,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    CONSTRAINT fk_agent_bootstrap_tokens_user_id_to_users_id
                        FOREIGN KEY (user_id) REFERENCES users(id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                );
                CREATE INDEX idx_agent_bootstrap_tokens_user_id
                    ON agent_bootstrap_tokens(user_id);

                CREATE TABLE agent_machine_credentials (
                    user_id INTEGER NOT NULL,
                    machine_id TEXT NOT NULL,
                    credential_version INTEGER NOT NULL,
                    current_token_hash TEXT NOT NULL,
                    next_token_hash TEXT,
                    previous_token_hash TEXT,
                    rotation_status TEXT NOT NULL,
                    grace_until TEXT,
                    revoked_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_seen_at TEXT,
                    last_error TEXT,
                    PRIMARY KEY (user_id, machine_id),
                    CONSTRAINT fk_agent_machine_credentials_user_id_to_users_id
                        FOREIGN KEY (user_id) REFERENCES users(id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                );

                CREATE TABLE agent_credential_audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                    user_id INTEGER NOT NULL,
                    machine_id TEXT,
                    action TEXT NOT NULL,
                    credential_version INTEGER,
                    result TEXT NOT NULL,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    CONSTRAINT fk_agent_credential_audit_logs_user_id_to_users_id
                        FOREIGN KEY (user_id) REFERENCES users(id)
                        ON DELETE CASCADE
                        ON UPDATE CASCADE
                );
                CREATE INDEX idx_agent_credential_audit_logs_user_machine
                    ON agent_credential_audit_logs(user_id, machine_id);
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP TABLE agent_credential_audit_logs;
                DROP TABLE agent_machine_credentials;
                DROP TABLE agent_bootstrap_tokens;
                "#,
            )
            .await?;

        Ok(())
    }
}
