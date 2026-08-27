use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthUser, DatabaseIdGeneration,
    DatabaseIdGenerationRequest, DatabaseIdGenerationResult, DatabaseIdGenerationSize,
    DatabaseIdGenerator, MemoryOrganizationStore, MemoryStore, NewOrganization,
    NewOrganizationInvitation, OrganizationDataStore, OrganizationDynamicAccessControlConfig,
    OrganizationInvitationStore, OrganizationLifecycleHooks, OrganizationPlugin,
    OrganizationPluginConfig, OrganizationRoleStore, OrganizationTeamStore,
    OrganizationTeamsConfig, SessionWithUser,
};
use std::sync::{Arc, Mutex};

#[path = "organization_database_id_contract/support.rs"]
mod support;
use support::{persisted_session, session};

#[path = "organization_database_id_contract/callback_ids.rs"]
mod callback_ids;
#[path = "organization_database_id_contract/hooks.rs"]
mod hooks;
#[path = "organization_database_id_contract/strategies.rs"]
mod strategies;

#[tokio::test]
async fn callback_ids_cover_every_organization_create_with_typed_references() {
    callback_ids::run().await;
}

#[tokio::test]
async fn memory_organization_ids_support_default_uuid_and_serial_strategies() {
    strategies::run_memory_strategies().await;
}

#[tokio::test]
async fn empty_callback_and_database_ids_defer_to_the_adapter() {
    strategies::run_deferred_strategies().await;
}

#[tokio::test]
async fn organization_and_team_hooks_use_force_allow_id_semantics() {
    hooks::run().await;
}

#[derive(Debug, Default)]
struct IdLedger {
    calls: Mutex<Vec<(String, DatabaseIdGenerationSize)>>,
}

impl IdLedger {
    fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }

    fn calls(&self) -> Vec<(String, DatabaseIdGenerationSize)> {
        self.calls.lock().unwrap().clone()
    }
}

impl DatabaseIdGenerator for IdLedger {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        let mut calls = self.calls.lock().unwrap();
        calls.push((request.model.into(), request.size));
        DatabaseIdGenerationResult::Id(format!("opaque::{}::{}::?/+", request.model, calls.len()))
    }
}

#[derive(Debug)]
struct EmptyIds;

impl DatabaseIdGenerator for EmptyIds {
    fn generate(&self, _: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        DatabaseIdGenerationResult::Id(String::new())
    }
}

#[derive(Debug)]
struct ForcedOrganizationIds;

#[async_trait]
impl OrganizationLifecycleHooks for ForcedOrganizationIds {
    async fn before_create(
        &self,
        mut value: lucid_auth::Organization,
        _: &AuthUser,
    ) -> Result<lucid_auth::Organization, AuthError> {
        value.id = "forced::organization::?/+".into();
        Ok(value)
    }

    async fn before_create_team(
        &self,
        mut value: lucid_auth::OrganizationTeam,
        _: &AuthUser,
        _: &lucid_auth::Organization,
    ) -> Result<lucid_auth::OrganizationTeam, AuthError> {
        value.id = "forced::team::?/+".into();
        Ok(value)
    }
}

fn service(
    strategy: DatabaseIdGeneration,
    organizations: Arc<MemoryOrganizationStore>,
    hooks: Option<Arc<dyn OrganizationLifecycleHooks>>,
) -> AuthService {
    let mut config = AuthConfig::new([b'O'; 32]).unwrap();
    config.database_id_generation = strategy;
    config
        .add_plugin(OrganizationPlugin::with_config(
            organizations,
            OrganizationPluginConfig {
                teams: OrganizationTeamsConfig {
                    enabled: true,
                    ..OrganizationTeamsConfig::default()
                },
                dynamic_access_control: OrganizationDynamicAccessControlConfig {
                    enabled: true,
                    ..OrganizationDynamicAccessControlConfig::default()
                },
                hooks,
                ..OrganizationPluginConfig::default()
            },
        ))
        .unwrap();
    AuthService::new(Arc::new(MemoryStore::default()), config)
}

async fn create_organization(
    service: &AuthService,
    owner: &SessionWithUser,
    slug: &str,
) -> lucid_auth::OrganizationCreation {
    service
        .create_organization(owner, organization_input(slug))
        .await
        .unwrap()
}

fn organization_input(slug: &str) -> NewOrganization {
    NewOrganization {
        name: "ID Organization".into(),
        slug: slug.into(),
        logo: None,
        metadata: None,
        keep_current_active_organization: true,
    }
}

fn is_base62(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}
