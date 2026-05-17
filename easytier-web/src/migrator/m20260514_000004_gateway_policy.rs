use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260514_000004_gateway_policy"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(
            r#"
            CREATE TABLE gateway_full_tunnel_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                user_id INTEGER NOT NULL,
                policy_id TEXT NOT NULL,
                policy_json TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT FALSE,
                source_machine_id TEXT NOT NULL,
                exit_machine_id TEXT NOT NULL,
                desired_version INTEGER NOT NULL,
                create_time TEXT NOT NULL,
                update_time TEXT NOT NULL,
                CONSTRAINT fk_gateway_full_tunnel_policies_user_id_to_users_id
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );
            CREATE UNIQUE INDEX idx_gateway_full_tunnel_policies_user_policy
                ON gateway_full_tunnel_policies(user_id, policy_id);
            CREATE INDEX idx_gateway_full_tunnel_policies_user_source
                ON gateway_full_tunnel_policies(user_id, source_machine_id);

            CREATE TABLE gateway_runtime_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                user_id INTEGER NOT NULL,
                machine_id TEXT NOT NULL,
                report_json TEXT NOT NULL,
                easytier_ipv4 TEXT,
                update_time TEXT NOT NULL,
                CONSTRAINT fk_gateway_runtime_reports_user_id_to_users_id
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );
            CREATE UNIQUE INDEX idx_gateway_runtime_reports_user_machine
                ON gateway_runtime_reports(user_id, machine_id);
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
            DROP TABLE gateway_runtime_reports;
            DROP TABLE gateway_full_tunnel_policies;
            "#,
        )
        .await?;
        Ok(())
    }
}
