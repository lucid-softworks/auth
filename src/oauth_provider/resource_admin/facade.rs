use super::*;

impl OAuthProviderResourceAdmin {
    pub(crate) fn new(
        config: Arc<OAuthProviderConfig>,
        store: Arc<dyn OAuthProviderStore>,
    ) -> Self {
        Self { config, store }
    }

    pub async fn create(
        &self,
        input: OAuthResourceInput,
        context: &OAuthCallbackContext,
    ) -> Result<OAuthProviderResource, AuthError> {
        self.authorize(OAuthResourceAction::Create, None, context)
            .await?;
        validate_create_input(&input)?;
        self.validate_identifier(&input.identifier).await?;
        let identifier = input.identifier.clone();
        self.store
            .create_oauth_resource(resource_from_input(input, Utc::now())?)
            .await?
            .ok_or_else(|| {
                AuthError::InvalidRequest(format!("resource {identifier} already exists"))
            })
    }

    pub async fn list(
        &self,
        context: &OAuthCallbackContext,
    ) -> Result<Vec<OAuthProviderResource>, AuthError> {
        self.authorize(OAuthResourceAction::List, None, context)
            .await?;
        self.store.list_oauth_resources().await
    }

    pub async fn get(
        &self,
        identifier: &str,
        context: &OAuthCallbackContext,
    ) -> Result<OAuthProviderResource, AuthError> {
        self.authorize(OAuthResourceAction::Read, Some(identifier), context)
            .await?;
        self.store
            .find_oauth_resource(identifier)
            .await?
            .ok_or(AuthError::NotFound)
    }

    pub async fn update(
        &self,
        identifier: &str,
        input: OAuthProviderResourceAdminUpdateInput,
        context: &OAuthCallbackContext,
    ) -> Result<OAuthProviderResource, AuthError> {
        self.authorize(OAuthResourceAction::Update, Some(identifier), context)
            .await?;
        validate_update_input(&input)?;
        let Some(mut resource) = self.store.find_oauth_resource(identifier).await? else {
            return Err(AuthError::NotFound);
        };
        input.apply_to(&mut resource);
        resource.updated_at = Some(Utc::now());
        self.store
            .update_oauth_resource(resource)
            .await?
            .ok_or(AuthError::NotFound)
    }

    pub async fn delete(
        &self,
        identifier: &str,
        context: &OAuthCallbackContext,
    ) -> Result<OAuthProviderResource, AuthError> {
        self.authorize(OAuthResourceAction::Delete, Some(identifier), context)
            .await?;
        self.store
            .delete_oauth_resource(identifier)
            .await?
            .ok_or(AuthError::NotFound)
    }

    pub async fn link(
        &self,
        client_id: impl Into<String>,
        resource_id: impl Into<String>,
        context: &OAuthCallbackContext,
    ) -> Result<OAuthClientResourceLinkOutcome, AuthError> {
        let resource_id = resource_id.into();
        self.authorize(OAuthResourceAction::Link, Some(&resource_id), context)
            .await?;
        self.store
            .link_oauth_client_resource(OAuthProviderClientResource {
                id: Uuid::new_v4(),
                client_id: client_id.into(),
                resource_id,
                metadata: None,
                created_at: Some(Utc::now()),
            })
            .await
    }

    pub async fn unlink(
        &self,
        client_id: &str,
        resource_id: &str,
        context: &OAuthCallbackContext,
    ) -> Result<Option<OAuthProviderClientResource>, AuthError> {
        self.authorize(OAuthResourceAction::Unlink, Some(resource_id), context)
            .await?;
        self.store
            .unlink_oauth_client_resource(client_id, resource_id)
            .await
    }

    async fn authorize(
        &self,
        action: OAuthResourceAction,
        resource_id: Option<&str>,
        context: &OAuthCallbackContext,
    ) -> Result<(), AuthError> {
        if context.session.is_none() {
            return Err(AuthError::Unauthorized);
        }
        let Some(callback) = &self.config.callbacks.resource_privileges else {
            return Ok(());
        };
        if callback.authorize(action, resource_id, context).await? == Some(true) {
            Ok(())
        } else {
            Err(AuthError::Unauthorized)
        }
    }

    async fn validate_identifier(&self, identifier: &str) -> Result<(), AuthError> {
        if identifier_allowed(&self.config, identifier).await? {
            Ok(())
        } else {
            Err(AuthError::InvalidRequest(format!(
                "resource identifier {identifier} failed validation"
            )))
        }
    }
}
