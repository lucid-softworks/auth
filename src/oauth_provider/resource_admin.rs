use super::{
    OAuthCallbackContext, OAuthClientResourceLinkOutcome, OAuthProviderClientResource,
    OAuthProviderConfig, OAuthProviderResource, OAuthProviderStore, OAuthResourceAction,
    OAuthResourceInput,
    runtime_store::seed::{identifier_allowed, resource_from_input},
};
use crate::{AuthError, AuthService};
use chrono::Utc;
use std::sync::Arc;

mod facade;
mod input;
mod validation;

pub use input::OAuthProviderResourceAdminUpdateInput;
use validation::{validate_create_input, validate_update_input};

#[derive(Clone)]
pub struct OAuthProviderResourceAdmin {
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth_provider::{
        MemoryOAuthProviderStore, OAuthClientRegistrationMode, OAuthClientRegistrationWrite,
        OAuthIdentifierValidator, OAuthProviderClient, OAuthProviderClientStore,
        OAuthResourcePrivileges,
    };
    use async_trait::async_trait;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    struct Privileges(Mutex<Vec<OAuthResourceAction>>);

    #[async_trait]
    impl OAuthResourcePrivileges for Privileges {
        async fn authorize(
            &self,
            action: OAuthResourceAction,
            _resource_id: Option<&str>,
            _context: &OAuthCallbackContext,
        ) -> Result<Option<bool>, AuthError> {
            self.0.lock().unwrap().push(action);
            Ok(Some(true))
        }
    }

    struct DeniedPrivileges;

    #[async_trait]
    impl OAuthResourcePrivileges for DeniedPrivileges {
        async fn authorize(
            &self,
            _action: OAuthResourceAction,
            _resource_id: Option<&str>,
            _context: &OAuthCallbackContext,
        ) -> Result<Option<bool>, AuthError> {
            Ok(None)
        }
    }

    struct IdentifierValidator(AtomicUsize);

    #[async_trait]
    impl OAuthIdentifierValidator for IdentifierValidator {
        async fn validate(&self, identifier: &str) -> Result<bool, AuthError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(identifier.starts_with("tenant:"))
        }
    }

    fn context() -> OAuthCallbackContext {
        OAuthCallbackContext {
            session: Some(serde_json::json!({"id": "session"})),
            user: Some(serde_json::json!({"id": "user"})),
            ..OAuthCallbackContext::default()
        }
    }

    fn input(identifier: &str) -> OAuthResourceInput {
        OAuthResourceInput {
            identifier: identifier.into(),
            name: Some("API".into()),
            access_token_ttl: None,
            refresh_token_ttl: None,
            signing_algorithm: None,
            signing_key_id: None,
            allowed_scopes: None,
            custom_claims: None,
            dpop_bound_access_tokens_required: None,
            disabled: None,
            metadata: None,
        }
    }

    fn client() -> OAuthProviderClient {
        OAuthProviderClient {
            id: String::new(),
            client_id: "client".into(),
            client_secret: None,
            client_discovery_id: None,
            disabled: false,
            skip_consent: None,
            enable_end_session: None,
            subject_type: None,
            scopes: None,
            client_credentials_scopes: Vec::new(),
            user_id: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            expires_at: None,
            name: None,
            uri: None,
            icon: None,
            contacts: None,
            tos: None,
            policy: None,
            software_id: None,
            software_version: None,
            software_statement: None,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: None,
            token_endpoint_auth_method: Some("none".into()),
            application_type: Some("web".into()),
            jwks: None,
            jwks_uri: None,
            grant_types: None,
            response_types: None,
            require_pkce: None,
            dpop_bound_access_tokens: false,
            reference_id: None,
            metadata: None,
        }
    }

    fn admin(
        config: OAuthProviderConfig,
        inner: Arc<MemoryOAuthProviderStore>,
    ) -> OAuthProviderResourceAdmin {
        let config = Arc::new(config);
        let store: Arc<dyn OAuthProviderStore> = Arc::new(
            crate::oauth_provider::runtime_store::OAuthProviderRuntimeStore::new(
                config.clone(),
                inner,
            ),
        );
        OAuthProviderResourceAdmin::new(config, store)
    }

    fn service() -> AuthService {
        AuthService::try_new(
            Arc::new(crate::MemoryStore::default()),
            crate::AuthConfig::new([12_u8; 32]).unwrap(),
        )
        .unwrap()
    }

    async fn insert_client(service: &AuthService, store: &MemoryOAuthProviderStore) {
        store
            .persist_oauth_client_registration(
                &|| {
                    service.prepare_database_id(&service.database_id_plan(
                        "oauthClient",
                        crate::DatabaseIdInput::Absent,
                        false,
                    ))
                },
                &|| {
                    service.prepare_database_id(&service.database_id_plan(
                        "oauthClientResource",
                        crate::DatabaseIdInput::Absent,
                        false,
                    ))
                },
                OAuthClientRegistrationWrite {
                    client: client(),
                    resource_ids: Vec::new(),
                    mode: OAuthClientRegistrationMode::Create,
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn every_resource_operation_requires_an_authenticated_context() {
        let admin = admin(
            OAuthProviderConfig::new("/login", "/consent"),
            Arc::new(MemoryOAuthProviderStore::new()),
        );
        assert!(matches!(
            admin.list(&OAuthCallbackContext::default()).await,
            Err(AuthError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn configured_resource_privileges_require_an_explicit_true_result() {
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.callbacks.resource_privileges = Some(Arc::new(DeniedPrivileges));
        let admin = admin(config, Arc::new(MemoryOAuthProviderStore::new()));

        assert!(matches!(
            admin.list(&context()).await,
            Err(AuthError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn facade_applies_identifier_validation_and_every_privilege_action() {
        let inner = Arc::new(MemoryOAuthProviderStore::new());
        let service = service();
        insert_client(&service, &inner).await;
        let privileges = Arc::new(Privileges(Mutex::new(Vec::new())));
        let validator = Arc::new(IdentifierValidator(AtomicUsize::new(0)));
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.callbacks.resource_privileges = Some(privileges.clone());
        config.callbacks.identifier_validator = Some(validator.clone());
        let admin = admin(config, inner);
        let context = context();

        assert!(
            admin
                .create(&service, input("https://rejected.example"), &context)
                .await
                .is_err()
        );
        let resource = admin
            .create(&service, input("tenant:api"), &context)
            .await
            .unwrap();
        admin.list(&context).await.unwrap();
        admin.get("tenant:api", &context).await.unwrap();
        admin
            .update(
                &resource.identifier,
                OAuthProviderResourceAdminUpdateInput {
                    name: Some("Updated".into()),
                    ..Default::default()
                },
                &context,
            )
            .await
            .unwrap();
        assert!(matches!(
            admin
                .link(&service, "client", "tenant:api", &context)
                .await
                .unwrap(),
            OAuthClientResourceLinkOutcome::Linked(_)
        ));
        admin
            .unlink("client", "tenant:api", &context)
            .await
            .unwrap();
        admin.delete("tenant:api", &context).await.unwrap();

        assert_eq!(validator.0.load(Ordering::SeqCst), 2);
        assert_eq!(
            *privileges.0.lock().unwrap(),
            vec![
                OAuthResourceAction::Create,
                OAuthResourceAction::Create,
                OAuthResourceAction::List,
                OAuthResourceAction::Read,
                OAuthResourceAction::Update,
                OAuthResourceAction::Link,
                OAuthResourceAction::Unlink,
                OAuthResourceAction::Delete,
            ]
        );
    }

    #[tokio::test]
    async fn admin_writes_reject_values_rejected_by_the_upstream_body_schema() {
        let admin = admin(
            OAuthProviderConfig::new("/login", "/consent"),
            Arc::new(MemoryOAuthProviderStore::new()),
        );
        let context = context();
        let service = service();
        let mut invalid = input("https://api.example.com");
        invalid.access_token_ttl = Some(0);
        assert!(matches!(
            admin.create(&service, invalid, &context).await,
            Err(AuthError::InvalidRequest(_))
        ));

        let mut invalid = input("https://api.example.com");
        invalid.signing_algorithm = Some("HS256".into());
        assert!(matches!(
            admin.create(&service, invalid, &context).await,
            Err(AuthError::InvalidRequest(_))
        ));

        let created = admin
            .create(&service, input("https://api.example.com"), &context)
            .await
            .unwrap();
        assert!(matches!(
            admin
                .update(
                    &created.identifier,
                    OAuthProviderResourceAdminUpdateInput {
                        signing_algorithm: Some(Some("HS256".into())),
                        ..Default::default()
                    },
                    &context,
                )
                .await,
            Err(AuthError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn update_is_a_partial_nullable_patch_and_preserves_server_owned_fields() {
        let admin = admin(
            OAuthProviderConfig::new("/login", "/consent"),
            Arc::new(MemoryOAuthProviderStore::new()),
        );
        let context = context();
        let service = service();
        let mut create = input("https://api.example.com");
        create.access_token_ttl = Some(300);
        create.signing_algorithm = Some("RS256".into());
        let created = admin.create(&service, create, &context).await.unwrap();

        let updated = admin
            .update(
                &created.identifier,
                OAuthProviderResourceAdminUpdateInput {
                    access_token_ttl: Some(None),
                    signing_algorithm: Some(None),
                    disabled: Some(true),
                    ..Default::default()
                },
                &context,
            )
            .await
            .unwrap();

        assert_eq!(updated.id, created.id);
        assert_eq!(updated.identifier, created.identifier);
        assert_eq!(updated.created_at, created.created_at);
        assert_eq!(updated.policy_version, created.policy_version);
        assert_eq!(updated.name, created.name);
        assert_eq!(updated.access_token_ttl, None);
        assert_eq!(updated.signing_algorithm, None);
        assert!(updated.disabled);
    }

    #[tokio::test]
    async fn duplicate_and_missing_rows_are_errors_like_the_server_only_endpoints() {
        let admin = admin(
            OAuthProviderConfig::new("/login", "/consent"),
            Arc::new(MemoryOAuthProviderStore::new()),
        );
        let context = context();
        let service = service();
        admin
            .create(&service, input("https://api.example.com"), &context)
            .await
            .unwrap();
        assert!(matches!(
            admin
                .create(&service, input("https://api.example.com"), &context)
                .await,
            Err(AuthError::InvalidRequest(_))
        ));
        assert!(matches!(
            admin.get("https://missing.example.com", &context).await,
            Err(AuthError::NotFound)
        ));
        assert!(matches!(
            admin
                .update(
                    "https://missing.example.com",
                    OAuthProviderResourceAdminUpdateInput::default(),
                    &context,
                )
                .await,
            Err(AuthError::NotFound)
        ));
        assert!(matches!(
            admin.delete("https://missing.example.com", &context).await,
            Err(AuthError::NotFound)
        ));
    }
}
