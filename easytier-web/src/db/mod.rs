// sea-orm-cli generate entity -u sqlite:./et.db -o easytier-web/src/db/entity/ --with-serde both --with-copy-enums
#[allow(unused_imports)]
pub mod entity;

use easytier::{
    common::config::ConfigSource,
    launcher::NetworkConfig,
    rpc_service::remote_client::{ListNetworkProps, Storage},
};
use entity::user_running_network_configs;
use sea_orm::{
    ColumnTrait as _, DatabaseConnection, DbErr, EntityTrait, QueryFilter as _, Set,
    SqlxSqliteConnector, TransactionTrait as _, prelude::Expr, sea_query::OnConflict,
};
use sea_orm_migration::MigratorTrait as _;
use sqlx::{Row, Sqlite, SqlitePool, migrate::MigrateDatabase as _, types::chrono};
use uuid::Uuid;

use crate::gateway_policy::{GatewayFullTunnelPolicy, RuntimeReport, validate_policy_conflicts};
use crate::migrator;
use async_trait::async_trait;

pub type UserIdInDb = i32;

#[derive(Debug, Clone)]
pub struct Db {
    db_path: String,
    db: SqlitePool,
    orm_db: DatabaseConnection,
}

impl Db {
    pub async fn new<T: ToString>(db_path: T) -> anyhow::Result<Self> {
        let db = Self::prepare_db(db_path.to_string().as_str()).await?;
        let orm_db = SqlxSqliteConnector::from_sqlx_sqlite_pool(db.clone());
        migrator::Migrator::up(&orm_db, None).await?;

        Ok(Self {
            db_path: db_path.to_string(),
            db,
            orm_db,
        })
    }

    pub async fn memory_db() -> Self {
        Self::new(":memory:").await.unwrap()
    }

    #[tracing::instrument(ret)]
    async fn prepare_db(db_path: &str) -> anyhow::Result<SqlitePool> {
        if !Sqlite::database_exists(db_path).await.unwrap_or(false) {
            tracing::info!("Database not found, creating a new one");
            Sqlite::create_database(db_path).await?;
        }

        let db = sqlx::pool::PoolOptions::new()
            .max_lifetime(None)
            .idle_timeout(None)
            .connect(db_path)
            .await?;

        Ok(db)
    }

    pub fn inner(&self) -> SqlitePool {
        self.db.clone()
    }

    pub fn orm_db(&self) -> &DatabaseConnection {
        &self.orm_db
    }

    pub async fn get_user_id<T: ToString>(
        &self,
        user_name: T,
    ) -> Result<Option<UserIdInDb>, DbErr> {
        use entity::users as u;

        let user = u::Entity::find()
            .filter(u::Column::Username.eq(user_name.to_string()))
            .one(self.orm_db())
            .await?;

        Ok(user.map(|u| u.id))
    }

    /// `password_hash` must be pre-hashed by the caller.
    /// Creates user + joins "users" group in one transaction. Returns the created user model.
    pub async fn create_user_and_join_users_group(
        &self,
        username: &str,
        password_hash: String,
    ) -> Result<entity::users::Model, DbErr> {
        use entity::{groups, users, users_groups};

        let txn = self.orm_db().begin().await?;

        let user_active = users::ActiveModel {
            username: Set(username.to_string()),
            password: Set(password_hash),
            ..Default::default()
        };
        let insert_result = users::Entity::insert(user_active).exec(&txn).await?;

        let new_user = users::Entity::find_by_id(insert_result.last_insert_id)
            .one(&txn)
            .await?
            .ok_or_else(|| DbErr::Custom("Failed to find newly created user".to_string()))?;

        let users_group = groups::Entity::find()
            .filter(groups::Column::Name.eq("users"))
            .one(&txn)
            .await?
            .ok_or_else(|| DbErr::Custom("Users group not found".to_string()))?;

        let ug_active = users_groups::ActiveModel {
            user_id: Set(new_user.id),
            group_id: Set(users_group.id),
            ..Default::default()
        };
        users_groups::Entity::insert(ug_active).exec(&txn).await?;

        txn.commit().await?;

        Ok(new_user)
    }

    pub async fn auto_create_user(&self, username: &str) -> Result<entity::users::Model, DbErr> {
        let random_password = uuid::Uuid::new_v4().to_string();
        let hashed_password =
            tokio::task::spawn_blocking(move || password_auth::generate_hash(&random_password))
                .await
                .map_err(|e| DbErr::Custom(format!("Failed to hash password: {}", e)))?;
        self.create_user_and_join_users_group(username, hashed_password)
            .await
    }

    // TODO: currently we don't have a token system, so we just use the user name as token
    pub async fn get_user_id_by_token<T: ToString>(
        &self,
        token: T,
    ) -> Result<Option<UserIdInDb>, DbErr> {
        self.get_user_id(token).await
    }

    pub async fn upsert_gateway_policy(
        &self,
        user_id: UserIdInDb,
        policy: GatewayFullTunnelPolicy,
    ) -> Result<(), DbErr> {
        let existing = self.list_gateway_policies(user_id).await?;
        validate_policy_conflicts(&existing, &policy).map_err(|e| DbErr::Custom(e.to_string()))?;
        let policy_json = serde_json::to_string(&policy).map_err(|e| DbErr::Json(e.to_string()))?;
        let now = chrono::Local::now().fixed_offset().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO gateway_full_tunnel_policies (
                user_id,
                policy_id,
                policy_json,
                enabled,
                source_machine_id,
                exit_machine_id,
                desired_version,
                create_time,
                update_time
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, policy_id) DO UPDATE SET
                policy_json = excluded.policy_json,
                enabled = excluded.enabled,
                source_machine_id = excluded.source_machine_id,
                exit_machine_id = excluded.exit_machine_id,
                desired_version = excluded.desired_version,
                update_time = excluded.update_time
            "#,
        )
        .bind(user_id)
        .bind(policy.policy_id.to_string())
        .bind(policy_json)
        .bind(policy.enabled)
        .bind(policy.source_machine_id.to_string())
        .bind(policy.exit_machine_id.to_string())
        .bind(policy.desired_version as i64)
        .bind(now.clone())
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| DbErr::Custom(e.to_string()))?;

        Ok(())
    }

    pub async fn list_gateway_policies(
        &self,
        user_id: UserIdInDb,
    ) -> Result<Vec<GatewayFullTunnelPolicy>, DbErr> {
        let rows = sqlx::query(
            r#"
            SELECT policy_json
            FROM gateway_full_tunnel_policies
            WHERE user_id = ?
            ORDER BY policy_id
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| DbErr::Custom(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let policy_json: String = row.get("policy_json");
                serde_json::from_str(&policy_json).map_err(|e| DbErr::Json(e.to_string()))
            })
            .collect()
    }

    pub async fn upsert_gateway_runtime_report(
        &self,
        user_id: UserIdInDb,
        report: RuntimeReport,
    ) -> Result<(), DbErr> {
        let report_json = serde_json::to_string(&report).map_err(|e| DbErr::Json(e.to_string()))?;
        let now = chrono::Local::now().fixed_offset().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO gateway_runtime_reports (
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, machine_id, policy_id, role) DO UPDATE SET
                device_policy_id = excluded.device_policy_id,
                report_json = excluded.report_json,
                easytier_ipv4 = excluded.easytier_ipv4,
                last_report_at = excluded.last_report_at,
                update_time = excluded.update_time
            "#,
        )
        .bind(user_id)
        .bind(report.machine_id.to_string())
        .bind(
            report
                .observed_policy_id
                .or(report.policy_id)
                .map(|id| id.to_string())
                .unwrap_or_default(),
        )
        .bind(
            report
                .role
                .map(|role| role.as_str().to_string())
                .unwrap_or_default(),
        )
        .bind(report.device_policy_id.clone())
        .bind(report_json)
        .bind(report.easytier_ipv4.clone())
        .bind(now.clone())
        .bind(now)
        .execute(&self.db)
        .await
        .map_err(|e| DbErr::Custom(e.to_string()))?;

        Ok(())
    }

    pub async fn list_gateway_runtime_reports(
        &self,
        user_id: UserIdInDb,
    ) -> Result<Vec<RuntimeReport>, DbErr> {
        let rows = sqlx::query(
            r#"
            SELECT report_json, last_report_at
            FROM gateway_runtime_reports
            WHERE user_id = ?
            ORDER BY last_report_at
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| DbErr::Custom(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let report_json: String = row.get("report_json");
                let mut report: RuntimeReport =
                    serde_json::from_str(&report_json).map_err(|e| DbErr::Json(e.to_string()))?;
                report.last_report_at = row
                    .try_get::<Option<String>, _>("last_report_at")
                    .ok()
                    .flatten();
                Ok(report)
            })
            .collect()
    }
}

#[async_trait]
impl Storage<(UserIdInDb, Uuid), user_running_network_configs::Model, DbErr> for Db {
    async fn insert_or_update_user_network_config(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        network_inst_id: Uuid,
        network_config: NetworkConfig,
        source: ConfigSource,
    ) -> Result<(), DbErr> {
        let txn = self.orm_db().begin().await?;

        use entity::user_running_network_configs as urnc;

        let on_conflict = OnConflict::columns([
            urnc::Column::UserId,
            urnc::Column::DeviceId,
            urnc::Column::NetworkInstanceId,
        ])
        .update_columns([
            urnc::Column::NetworkConfig,
            urnc::Column::Source,
            urnc::Column::Disabled,
            urnc::Column::UpdateTime,
        ])
        .to_owned();
        let insert_m = urnc::ActiveModel {
            user_id: sea_orm::Set(user_id),
            device_id: sea_orm::Set(device_id.to_string()),
            network_instance_id: sea_orm::Set(network_inst_id.to_string()),
            network_config: sea_orm::Set(
                serde_json::to_string(&network_config).map_err(|e| DbErr::Json(e.to_string()))?,
            ),
            source: sea_orm::Set(source.as_str().to_string()),
            disabled: sea_orm::Set(false),
            create_time: sea_orm::Set(chrono::Local::now().fixed_offset()),
            update_time: sea_orm::Set(chrono::Local::now().fixed_offset()),
            ..Default::default()
        };
        urnc::Entity::insert(insert_m)
            .on_conflict(on_conflict)
            .do_nothing()
            .exec(&txn)
            .await?;

        txn.commit().await
    }

    async fn delete_network_configs(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        network_inst_ids: &[Uuid],
    ) -> Result<(), DbErr> {
        use entity::user_running_network_configs as urnc;

        urnc::Entity::delete_many()
            .filter(urnc::Column::UserId.eq(user_id))
            .filter(urnc::Column::DeviceId.eq(device_id.to_string()))
            .filter(
                urnc::Column::NetworkInstanceId
                    .is_in(network_inst_ids.iter().map(|id| id.to_string())),
            )
            .exec(self.orm_db())
            .await?;

        Ok(())
    }

    async fn update_network_config_state(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        network_inst_id: Uuid,
        disabled: bool,
    ) -> Result<(), DbErr> {
        use entity::user_running_network_configs as urnc;

        urnc::Entity::update_many()
            .filter(urnc::Column::UserId.eq(user_id))
            .filter(urnc::Column::DeviceId.eq(device_id.to_string()))
            .filter(urnc::Column::NetworkInstanceId.eq(network_inst_id.to_string()))
            .col_expr(urnc::Column::Disabled, Expr::value(disabled))
            .col_expr(
                urnc::Column::UpdateTime,
                Expr::value(chrono::Local::now().fixed_offset()),
            )
            .exec(self.orm_db())
            .await?;

        Ok(())
    }

    async fn list_network_configs(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        props: ListNetworkProps,
    ) -> Result<Vec<user_running_network_configs::Model>, DbErr> {
        use entity::user_running_network_configs as urnc;

        let configs = urnc::Entity::find().filter(urnc::Column::UserId.eq(user_id));
        let configs = if matches!(
            props,
            ListNetworkProps::EnabledOnly | ListNetworkProps::DisabledOnly
        ) {
            configs
                .filter(urnc::Column::Disabled.eq(matches!(props, ListNetworkProps::DisabledOnly)))
        } else {
            configs
        };
        let configs = if !device_id.is_nil() {
            configs.filter(urnc::Column::DeviceId.eq(device_id.to_string()))
        } else {
            configs
        };

        let configs = configs.all(self.orm_db()).await?;

        Ok(configs)
    }

    async fn get_network_config(
        &self,
        (user_id, device_id): (UserIdInDb, Uuid),
        network_inst_id: &str,
    ) -> Result<Option<user_running_network_configs::Model>, DbErr> {
        use entity::user_running_network_configs as urnc;

        let config = urnc::Entity::find()
            .filter(urnc::Column::UserId.eq(user_id))
            .filter(urnc::Column::DeviceId.eq(device_id.to_string()))
            .filter(urnc::Column::NetworkInstanceId.eq(network_inst_id))
            .one(self.orm_db())
            .await?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use easytier::{
        common::config::ConfigSource,
        proto::api::manage::NetworkConfig,
        rpc_service::remote_client::{PersistentConfig, Storage},
    };
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter as _, Set};

    use crate::db::{Db, ListNetworkProps, entity::user_running_network_configs};
    use crate::gateway_policy::{
        ExitEgress, GatewayFullTunnelPolicy, HealthcheckConfig, RollbackConfig, RuntimeReport,
    };

    #[tokio::test]
    async fn test_user_network_config_management() {
        let db = Db::memory_db().await;
        let user_id = 1;
        let network_config = NetworkConfig {
            network_name: Some("test_config".to_string()),
            ..Default::default()
        };
        let network_config_json = serde_json::to_string(&network_config).unwrap();
        let inst_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();

        db.insert_or_update_user_network_config(
            (user_id, device_id),
            inst_id,
            network_config,
            ConfigSource::User,
        )
        .await
        .unwrap();

        let result = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap()
            .unwrap();
        println!("{:?}", result);
        assert_eq!(result.network_config, network_config_json);
        assert_eq!(result.get_network_config_source(), ConfigSource::User);

        // overwrite the config
        let network_config = NetworkConfig {
            network_name: Some("test_config2".to_string()),
            ..Default::default()
        };
        let network_config_json = serde_json::to_string(&network_config).unwrap();
        db.insert_or_update_user_network_config(
            (user_id, device_id),
            inst_id,
            network_config,
            ConfigSource::Webhook,
        )
        .await
        .unwrap();

        let result2 = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap()
            .unwrap();
        println!("device: {}, {:?}", device_id, result2);
        assert_eq!(result2.network_config, network_config_json);
        assert_eq!(result2.get_network_config_source(), ConfigSource::Webhook);
        assert_eq!(
            result2.get_runtime_network_config_source(),
            ConfigSource::Webhook
        );

        assert_eq!(result.create_time, result2.create_time);
        assert_ne!(result.update_time, result2.update_time);

        assert_eq!(
            db.list_network_configs((user_id, device_id), ListNetworkProps::All)
                .await
                .unwrap()
                .len(),
            1
        );

        db.delete_network_configs((user_id, device_id), &[inst_id])
            .await
            .unwrap();
        let result3 = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap();
        assert!(result3.is_none());
    }

    #[tokio::test]
    async fn test_legacy_network_config_defaults_to_user_runtime_source() {
        let db = Db::memory_db().await;
        let user_id = 1;
        let inst_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();

        user_running_network_configs::ActiveModel {
            user_id: Set(user_id),
            device_id: Set(device_id.to_string()),
            network_instance_id: Set(inst_id.to_string()),
            network_config: Set(serde_json::to_string(&NetworkConfig {
                network_name: Some("legacy".to_string()),
                ..Default::default()
            })
            .unwrap()),
            source: Set("legacy".to_string()),
            disabled: Set(false),
            create_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            update_time: Set(sqlx::types::chrono::Local::now().fixed_offset()),
            ..Default::default()
        }
        .insert(db.orm_db())
        .await
        .unwrap();

        let result = user_running_network_configs::Entity::find()
            .filter(user_running_network_configs::Column::UserId.eq(user_id))
            .one(db.orm_db())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.get_network_config_source(), ConfigSource::User);
        assert_eq!(
            result.get_runtime_network_config_source(),
            ConfigSource::User
        );
    }

    #[tokio::test]
    async fn test_user_network_config_same_instance_id_is_scoped_by_device() {
        let db = Db::memory_db().await;
        let user_id = db.auto_create_user("user-1").await.unwrap().id;
        let device1 = uuid::Uuid::new_v4();
        let device2 = uuid::Uuid::new_v4();
        let inst_id = uuid::Uuid::new_v4();

        db.insert_or_update_user_network_config(
            (user_id, device1),
            inst_id,
            NetworkConfig {
                network_name: Some("cfg-1".to_string()),
                ..Default::default()
            },
            ConfigSource::User,
        )
        .await
        .unwrap();
        db.insert_or_update_user_network_config(
            (user_id, device2),
            inst_id,
            NetworkConfig {
                network_name: Some("cfg-2".to_string()),
                ..Default::default()
            },
            ConfigSource::User,
        )
        .await
        .unwrap();

        let first = db
            .get_network_config((user_id, device1), &inst_id.to_string())
            .await
            .unwrap()
            .unwrap();
        let second = db
            .get_network_config((user_id, device2), &inst_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.user_id, user_id);
        assert_eq!(first.device_id, device1.to_string());
        assert_eq!(second.user_id, user_id);
        assert_eq!(second.device_id, device2.to_string());

        let device1_configs = db
            .list_network_configs((user_id, device1), ListNetworkProps::All)
            .await
            .unwrap();
        let device2_configs = db
            .list_network_configs((user_id, device2), ListNetworkProps::All)
            .await
            .unwrap();
        assert_eq!(device1_configs.len(), 1);
        assert_eq!(device2_configs.len(), 1);
    }

    fn base_gateway_policy(source: uuid::Uuid, exit: uuid::Uuid) -> GatewayFullTunnelPolicy {
        GatewayFullTunnelPolicy {
            policy_id: uuid::Uuid::new_v4(),
            enabled: true,
            network_instance_id: uuid::Uuid::new_v4(),
            source_machine_id: source,
            managed_cidrs: vec!["192.168.10.0/24".to_string()],
            ingress_ifaces: vec!["br-lan".to_string()],
            include_device_traffic: true,
            exit_machine_id: exit,
            exit_egress: ExitEgress::default(),
            desired_version: 1,
            protect_control_plane: true,
            healthcheck: HealthcheckConfig::default(),
            rollback: RollbackConfig::default(),
        }
    }

    #[tokio::test]
    async fn test_gateway_policy_and_report_persistence() {
        let db = Db::memory_db().await;
        let user_id = db.auto_create_user("gateway-user").await.unwrap().id;
        let source = uuid::Uuid::new_v4();
        let exit = uuid::Uuid::new_v4();
        let policy = base_gateway_policy(source, exit);

        db.upsert_gateway_policy(user_id, policy.clone())
            .await
            .unwrap();
        let policies = db.list_gateway_policies(user_id).await.unwrap();
        assert_eq!(policies, vec![policy.clone()]);

        let duplicate_source = base_gateway_policy(source, uuid::Uuid::new_v4());
        assert!(
            db.upsert_gateway_policy(user_id, duplicate_source)
                .await
                .is_err()
        );

        db.upsert_gateway_runtime_report(
            user_id,
            RuntimeReport {
                machine_id: source,
                agent_version: "0.1.0".to_string(),
                easytier_ipv4: Some("10.126.126.2".to_string()),
                last_report_at: Some("2026-05-16T10:00:00+00:00".to_string()),
                policy_id: Some(policy.policy_id),
                device_policy_id: Some(format!("{}/source", policy.policy_id)),
                version: Some(policy.desired_version),
                role: Some(crate::gateway_policy::DevicePolicyRole::ClientGatewayViaPeer),
                status: Some("active".to_string()),
                observed_policy_id: Some(policy.policy_id),
                observed_policy_version: Some(policy.desired_version),
                observed_policy_status: Some("active".to_string()),
                last_error: None,
            },
        )
        .await
        .unwrap();

        let reports = db.list_gateway_runtime_reports(user_id).await.unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].machine_id, source);
        assert_eq!(reports[0].easytier_ipv4.as_deref(), Some("10.126.126.2"));
    }

    #[tokio::test]
    async fn test_gateway_reports_keep_machine_latest_and_policy_role_rows() {
        let db = Db::memory_db().await;
        let user_id = db.auto_create_user("gateway-report-user").await.unwrap().id;
        let node = uuid::Uuid::new_v4();
        let policy_a = uuid::Uuid::new_v4();
        let policy_b = uuid::Uuid::new_v4();

        for (policy_id, role, status) in [
            (
                policy_a,
                crate::gateway_policy::DevicePolicyRole::ClientGatewayViaPeer,
                "active",
            ),
            (
                policy_b,
                crate::gateway_policy::DevicePolicyRole::ProvideExitForGateway,
                "prepared",
            ),
        ] {
            db.upsert_gateway_runtime_report(
                user_id,
                RuntimeReport {
                    machine_id: node,
                    agent_version: "0.1.0".to_string(),
                    easytier_ipv4: Some("10.126.126.2".to_string()),
                    last_report_at: Some("2026-05-16T10:00:00+00:00".to_string()),
                    policy_id: Some(policy_id),
                    device_policy_id: Some(format!("{policy_id}/{status}")),
                    version: Some(1),
                    role: Some(role),
                    status: Some(status.to_string()),
                    observed_policy_id: Some(policy_id),
                    observed_policy_version: Some(1),
                    observed_policy_status: Some(status.to_string()),
                    last_error: None,
                },
            )
            .await
            .unwrap();
        }

        let reports = db.list_gateway_runtime_reports(user_id).await.unwrap();

        assert_eq!(reports.len(), 2);
        assert!(reports.iter().any(|report| {
            report.observed_policy_id == Some(policy_a)
                && report.role
                    == Some(crate::gateway_policy::DevicePolicyRole::ClientGatewayViaPeer)
        }));
        assert!(reports.iter().any(|report| {
            report.observed_policy_id == Some(policy_b)
                && report.role
                    == Some(crate::gateway_policy::DevicePolicyRole::ProvideExitForGateway)
        }));
    }
}
