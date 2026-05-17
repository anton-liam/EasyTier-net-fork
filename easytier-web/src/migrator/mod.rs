use sea_orm_migration::prelude::*;

mod m20241029_000001_init;
mod m20260403_000002_scope_network_config_unique;
mod m20260421_000003_add_network_config_source;
mod m20260514_000004_gateway_policy;
mod m20260516_000005_gateway_runtime_report_last_report_at;
mod m20260518_000006_gateway_runtime_report_policy_role_key;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20241029_000001_init::Migration),
            Box::new(m20260403_000002_scope_network_config_unique::Migration),
            Box::new(m20260421_000003_add_network_config_source::Migration),
            Box::new(m20260514_000004_gateway_policy::Migration),
            Box::new(m20260516_000005_gateway_runtime_report_last_report_at::Migration),
            Box::new(m20260518_000006_gateway_runtime_report_policy_role_key::Migration),
        ]
    }
}
