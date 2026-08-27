use super::*;

impl OAuthProviderClientAdmin {
    pub(super) async fn persist_create(
        &self,
        service: &AuthService,
        input: OAuthProviderClientAdminCreateInput,
        user_id: Option<String>,
        reference_id: Option<String>,
        context: &OAuthCallbackContext,
    ) -> Result<OAuthProviderClientAdminRegistration, OAuthProviderError> {
        let (client, plaintext) = self
            .prepare_create(service, input, user_id, reference_id, context)
            .await?;
        let outcome = self
            .store
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
                    client,
                    resource_ids: Vec::new(),
                    mode: OAuthClientRegistrationMode::Create,
                },
            )
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

    async fn prepare_create(
        &self,
        service: &AuthService,
        input: OAuthProviderClientAdminCreateInput,
        user_id: Option<String>,
        reference_id: Option<String>,
        context: &OAuthCallbackContext,
    ) -> Result<(OAuthProviderClient, Option<String>), OAuthProviderError> {
        let client_id = self.generate_client_id().await?;
        let plaintext = self.generate_client_secret(&input).await?;
        let stored_secret = match plaintext.as_deref() {
            Some(secret) => Some(
                super::super::crypto::store_client_secret(service, &self.config, secret)
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
        super::super::axum::management::validation_support::validate_client(
            service,
            &self.config,
            &client,
            context,
        )
        .await?;
        Ok((client, plaintext))
    }
}
