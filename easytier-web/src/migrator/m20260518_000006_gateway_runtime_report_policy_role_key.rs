use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260518_000006_gateway_runtime_report_policy_role_key"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
            CREATE TABLE gateway_runtime_reports_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                user_id INTEGER NOT NULL,
                machine_id TEXT NOT NULL,
                policy_id TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT '',
                device_policy_id TEXT,
                report_json TEXT NOT NULL,
                easytier_ipv4 TEXT,
                last_report_at TEXT,
                update_time TEXT NOT NULL,
                CONSTRAINT fk_gateway_runtime_reports_user_id_to_users_id
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );

            INSERT INTO gateway_runtime_reports_v2 (
                user_id,
                machine_id,
                policy_id,
                role,
                device_policy_id,
                report_json,
                easytier_ipv4,
                last_report_at,
                update_time
            )
            SELECT
                user_id,
                machine_id,
                '',
                '',
                NULL,
                report_json,
                easytier_ipv4,
                last_report_at,
                update_time
            FROM gateway_runtime_reports;

            DROP TABLE gateway_runtime_reports;
            ALTER TABLE gateway_runtime_reports_v2 RENAME TO gateway_runtime_reports;

            CREATE UNIQUE INDEX idx_gateway_runtime_reports_policy_role
                ON gateway_runtime_reports(user_id, machine_id, policy_id, role);
            CREATE INDEX idx_gateway_runtime_reports_user_machine
                ON gateway_runtime_reports(user_id, machine_id);
            "#,
        )
        .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
