mod credentials;
mod input;
mod metadata;
mod record;
mod shape;
mod support;

pub use input::*;

use super::{
    OAuthCallbackContext, OAuthClientAction, OAuthClientRegistrationMode,
    OAuthClientRegistrationOutcome, OAuthClientRegistrationWrite, OAuthProviderClient,
    OAuthProviderConfig, OAuthProviderError, OAuthProviderStore,
};
use crate::AuthService;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use support::{context_user_id, server_error};

#[derive(Clone)]
pub struct OAuthProviderClientAdmin {
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
}

impl OAuthProviderClientAdmin {
    pub(crate) fn new(
        config: Arc<OAuthProviderConfig>,
        store: Arc<dyn OAuthProviderStore>,
    ) -> Self {
        Self { config, store }
    }

    pub async fn create(
        &self,
        service: &AuthService,
        mut input: OAuthProviderClientAdminCreateInput,
        context: &OAuthCallbackContext,
    ) -> Result<OAuthProviderClientAdminRegistration, OAuthProviderError> {
        self.authorize(OAuthClientAction::Create, context).await?;
        let (user_id, reference_id) = self.owner(context).await?;
        shape::normalize_strings(
            &mut input.token_endpoint_auth_method,
            &mut input.grant_types,
        );
        shape::validate_create(&input)?;
        input
            .grant_types
            .get_or_insert_with(|| vec!["authorization_code".into()]);
        credentials::normalize(&mut input.client_credentials_scopes)?;
        credentials::validate(
            &self.config,
            &input.client_credentials_scopes,
            input.grant_types.as_deref().unwrap_or_default(),
            input.token_endpoint_auth_method.as_deref(),
        )?;
        if !input.client_credentials_scopes.is_empty() {
            self.authorize(OAuthClientAction::ConfigureClientCredentialsScopes, context)
                .await?;
        }
        self.persist_create(service, input, user_id, reference_id, context)
            .await
    }

    async fn persist_create(
        &self,
        service: &AuthService,
        input: OAuthProviderClientAdminCreateInput,
        user_id: Option<Uuid>,
        reference_id: Option<String>,
        context: &OAuthCallbackContext,
    ) -> Result<OAuthProviderClientAdminRegistration, OAuthProviderError> {
        let client_id = self.generate_client_id().await?;
        let plaintext = self.generate_client_secret(&input).await?;
        let stored_secret = match plaintext.as_deref() {
            Some(secret) => Some(
                super::crypto::store_client_secret(service, &self.config, secret)
                    .await
                    .map_err(server_error)?,
            ),
            None => None,
        };
        let mut client = record::from_create(
            input,
            client_id,
            stored_secret,
            user_id,
            reference_id,
            Utc::now(),
        );
        metadata::sanitize(&mut client.metadata);
        super::axum::management::validation_support::validate_client(
            service,
            &self.config,
            &client,
            context,
        )
        .await?;
        let outcome = self
            .store
            .persist_oauth_client_registration(OAuthClientRegistrationWrite {
                client,
                resource_ids: Vec::new(),
                mode: OAuthClientRegistrationMode::Create,
            })
            .await
            .map_err(server_error)?;
        let client = match outcome {
            OAuthClientRegistrationOutcome::Created(client) => client,
            OAuthClientRegistrationOutcome::ClientIdTaken => {
                return Err(OAuthProviderError::InvalidClient(
                    "client_id is already registered".into(),
                ));
            }
            _ => {
                return Err(OAuthProviderError::ServerError(
                    "unable to register client".into(),
                ));
            }
        };
        let client_secret = plaintext.map(|secret| {
            format!(
                "{}{}",
                self.config.prefix.client_secret.as_deref().unwrap_or(""),
                secret
            )
        });
        Ok(OAuthProviderClientAdminRegistration {
            client,
            client_secret,
        })
    }

    pub async fn update(
        &self,
        service: &AuthService,
        client_id: &str,
        mut input: OAuthProviderClientAdminUpdateInput,
        context: &OAuthCallbackContext,
    ) -> Result<Option<OAuthProviderClient>, OAuthProviderError> {
        self.authorize(OAuthClientAction::Update, context).await?;
        if self.config.cached_trusted_clients.contains(client_id) {
            return Err(OAuthProviderError::InvalidClient(
                "trusted clients must be updated manually".into(),
            ));
        }
        let Some(mut client) = self
            .store
            .find_oauth_client(client_id)
            .await
            .map_err(server_error)?
        else {
            return Ok(None);
        };
        let owns_client = self.owns(&client, context).await?;
        let cross_owner_scope_only = !owns_client && input.only_client_credentials_scopes();
        if !owns_client && !cross_owner_scope_only {
            return Err(OAuthProviderError::UnauthorizedClient(
                "client action is not permitted".into(),
            ));
        }
        self.prepare_update(&client, &mut input, cross_owner_scope_only, context)
            .await?;
        record::apply_update(&mut client, input);
        record::clear_inapplicable_client_credentials_scopes(&mut client);
        metadata::sanitize(&mut client.metadata);
        super::axum::management::validation_support::validate_client(
            service,
            &self.config,
            &client,
            context,
        )
        .await?;
        client.updated_at = Some(Utc::now());
        self.store
            .update_oauth_client(client)
            .await
            .map_err(server_error)
    }

    async fn prepare_update(
        &self,
        client: &OAuthProviderClient,
        input: &mut OAuthProviderClientAdminUpdateInput,
        cross_owner_scope_only: bool,
        context: &OAuthCallbackContext,
    ) -> Result<(), OAuthProviderError> {
        shape::normalize_grants(&mut input.grant_types);
        shape::validate_update(input)?;
        if let Some(scopes) = input.client_credentials_scopes.as_mut() {
            credentials::normalize(scopes)?;
            credentials::validate(
                &self.config,
                scopes,
                input
                    .grant_types
                    .as_deref()
                    .or(client.grant_types.as_deref())
                    .unwrap_or_default(),
                client.token_endpoint_auth_method.as_deref(),
            )?;
            if cross_owner_scope_only || !scopes.is_empty() {
                self.authorize(OAuthClientAction::ConfigureClientCredentialsScopes, context)
                    .await?;
            }
        }
        Ok(())
    }

    async fn owner(
        &self,
        context: &OAuthCallbackContext,
    ) -> Result<(Option<Uuid>, Option<String>), OAuthProviderError> {
        let reference_id = match &self.config.callbacks.client_reference {
            Some(callback) => callback.resolve(context).await.map_err(server_error)?,
            None => None,
        };
        Ok(if reference_id.is_none() {
            (Some(context_user_id(context)?), None)
        } else {
            (None, reference_id)
        })
    }

    async fn owns(
        &self,
        client: &OAuthProviderClient,
        context: &OAuthCallbackContext,
    ) -> Result<bool, OAuthProviderError> {
        if let Some(owner) = client.user_id {
            return Ok(context_user_id(context).is_ok_and(|actual| actual == owner));
        }
        let (Some(expected), Some(callback)) = (
            client.reference_id.as_deref(),
            &self.config.callbacks.client_reference,
        ) else {
            return Ok(false);
        };
        Ok(callback
            .resolve(context)
            .await
            .map_err(server_error)?
            .as_deref()
            == Some(expected))
    }

    async fn authorize(
        &self,
        action: OAuthClientAction,
        context: &OAuthCallbackContext,
    ) -> Result<(), OAuthProviderError> {
        if context.session.is_none() {
            return Err(OAuthProviderError::UnauthorizedClient(
                "authentication required".into(),
            ));
        }
        let Some(callback) = &self.config.callbacks.client_privileges else {
            return Ok(());
        };
        if callback
            .authorize(action, context)
            .await
            .map_err(server_error)?
            == Some(true)
        {
            Ok(())
        } else {
            Err(OAuthProviderError::UnauthorizedClient(
                "client action is not permitted".into(),
            ))
        }
    }

    async fn generate_client_id(&self) -> Result<String, OAuthProviderError> {
        match &self.config.callbacks.generate_client_id {
            Some(generator) => generator.generate().await.map_err(server_error),
            None => Ok(super::crypto::random_letters(32)),
        }
    }

    async fn generate_client_secret(
        &self,
        input: &OAuthProviderClientAdminCreateInput,
    ) -> Result<Option<String>, OAuthProviderError> {
        let method = input
            .token_endpoint_auth_method
            .as_deref()
            .unwrap_or("client_secret_basic");
        let extension_method = self.config.extensions.iter().any(|extension| {
            extension
                .client_authentication_methods()
                .iter()
                .any(|candidate| candidate.method == method)
        });
        if matches!(method, "none" | "private_key_jwt") || extension_method {
            return Ok(None);
        }
        match &self.config.callbacks.generate_client_secret {
            Some(generator) => generator.generate().await.map(Some).map_err(server_error),
            None => Ok(Some(super::crypto::random_letters(32))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, JwtPlugin, MemoryStore,
        oauth_provider::{MemoryOAuthProviderStore, OAuthProviderClientStore, OAuthProviderPlugin},
    };
    use serde_json::{Map, json};

    fn context() -> OAuthCallbackContext {
        OAuthCallbackContext {
            session: Some(json!({"id":"session"})),
            user: Some(json!({"id":"9d742988-e92a-41b7-9a74-20a8c1d3a443"})),
            ..OAuthCallbackContext::default()
        }
    }

    async fn fixture() -> (
        OAuthProviderClientAdmin,
        Arc<AuthService>,
        Arc<MemoryOAuthProviderStore>,
    ) {
        let store = Arc::new(MemoryOAuthProviderStore::new());
        let mut provider = OAuthProviderConfig::new("/login", "/consent");
        provider.scopes.push("api.read".into());
        let plugin = OAuthProviderPlugin::from_arc(provider, store.clone());
        let admin = plugin.client_admin();
        let mut config = AuthConfig::new([191; 32]).unwrap();
        config.add_plugin(JwtPlugin::default()).unwrap();
        config.add_plugin(plugin).unwrap();
        let service =
            Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
        (admin, service, store)
    }

    #[tokio::test]
    async fn native_admin_create_and_update_reach_admin_only_fields() {
        let (admin, service, store) = fixture().await;
        let created = admin
            .create(
                &service,
                OAuthProviderClientAdminCreateInput {
                    grant_types: Some(vec!["client_credentials".into()]),
                    client_credentials_scopes: vec!["api.read".into()],
                    scopes: Some(vec!["api.read".into()]),
                    skip_consent: Some(true),
                    enable_end_session: Some(true),
                    require_pkce: Some(false),
                    dpop_bound_access_tokens: Some(true),
                    client_secret_expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
                    metadata: Some(Map::from_iter([
                        ("tenant".into(), json!("one")),
                        ("client_name".into(), json!("must be stripped")),
                    ])),
                    ..OAuthProviderClientAdminCreateInput::default()
                },
                &context(),
            )
            .await
            .unwrap();
        assert!(created.client_secret.is_some());
        assert_eq!(created.client.skip_consent, Some(true));
        assert_eq!(created.client.enable_end_session, Some(true));
        assert_eq!(created.client.require_pkce, Some(false));
        assert!(created.client.dpop_bound_access_tokens);
        assert!(created.client.expires_at.is_some());
        assert_eq!(
            created.client.user_id,
            Some(context_user_id(&context()).unwrap())
        );
        assert_eq!(created.client.client_credentials_scopes, ["api.read"]);
        assert_eq!(created.client.metadata, Some(json!({"tenant":"one"})));

        let updated = admin
            .update(
                &service,
                &created.client.client_id,
                OAuthProviderClientAdminUpdateInput {
                    client_name: Some("Native admin".into()),
                    redirect_uris: Some(vec!["https://native.example/callback".into()]),
                    grant_types: Some(vec!["authorization_code".into()]),
                    response_types: Some(vec!["code".into()]),
                    skip_consent: Some(false),
                    enable_end_session: Some(false),
                    dpop_bound_access_tokens: Some(false),
                    client_secret_expires_at: Some(None),
                    metadata: Some(Map::from_iter([("tenant".into(), json!("two"))])),
                    ..OAuthProviderClientAdminUpdateInput::default()
                },
                &context(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.name.as_deref(), Some("Native admin"));
        assert!(updated.client_credentials_scopes.is_empty());
        assert_eq!(updated.skip_consent, Some(false));
        assert_eq!(updated.enable_end_session, Some(false));
        assert!(!updated.dpop_bound_access_tokens);
        assert!(updated.expires_at.is_none());
        assert_eq!(updated.metadata, Some(json!({"tenant":"two"})));
        assert_eq!(
            store
                .find_oauth_client(&updated.client_id)
                .await
                .unwrap()
                .unwrap(),
            updated
        );
    }
}
