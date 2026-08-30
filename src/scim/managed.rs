use super::{
    ScimError, ScimErrorType, ScimManagedConnection, ScimManagedConnectionEvent,
    ScimManagedConnectionOptions, ScimManagedCredential, ScimPlugin, ScimScope,
    plugin::{store_error, token_digest},
};
use chrono::{DateTime, Utc};
use std::collections::HashSet;

impl ScimPlugin {
    pub async fn create_managed_connection(
        &self,
        creation_request_id: &str,
        provisioning_domain_id: &str,
        actor_id: &str,
        scopes: Vec<ScimScope>,
        expires_at: DateTime<Utc>,
    ) -> Result<(ScimManagedConnection, ScimManagedCredential, String), ScimError> {
        let options = self.managed_options()?;
        validate_text(creation_request_id, 16, "creationRequestId")?;
        validate_policy(provisioning_domain_id, actor_id, &scopes, expires_at)?;
        let now = super::timestamp::now();
        let expires_at = super::timestamp::milliseconds(expires_at);
        let record_id = super::random_urlsafe(32);
        let connection_id = format!("ba_scim_connection_{}", super::random_urlsafe(32));
        let credential_id = format!("ba_scim_credential_{}", super::random_urlsafe(32));
        let token = format!("{credential_id}.{}", super::random_urlsafe(48));
        let connection = ScimManagedConnection {
            id: record_id.clone(),
            creation_request_id: creation_request_id.into(),
            connection_id,
            provisioning_domain_id: provisioning_domain_id.into(),
            status: "active".into(),
            revision: 2,
            created_at: now,
            created_by: actor_id.into(),
            decommission_started_at: None,
            decommission_started_by: None,
            decommissioned_at: None,
            decommissioned_by: None,
        };
        let credential = credential(NewCredential {
            record_id: &record_id,
            credential_id: &credential_id,
            token_digest: token_digest(&options.credential_hash_secret, &token)?,
            active_slot_key: format!("{record_id}:active:0"),
            scopes,
            expires_at,
            actor_id,
            now,
        });
        let events = vec![
            event(&record_id, 1, "connection.created", actor_id, None, now),
            event(
                &record_id,
                2,
                "credential.issued",
                actor_id,
                Some(&credential_id),
                now,
            ),
        ];
        self.store
            .create_managed_connection(creation_request_id, connection, credential, events)
            .await
            .map(|(connection, credential)| (connection, credential, token))
            .map_err(store_error)
    }

    pub async fn list_managed_connections(
        &self,
        provisioning_domain_id: &str,
    ) -> Result<Vec<ScimManagedConnection>, ScimError> {
        self.managed_options()?;
        validate_text(provisioning_domain_id, 1, "provisioningDomainId")?;
        self.store
            .list_managed_connections(provisioning_domain_id)
            .await
            .map_err(store_error)
    }

    pub async fn get_managed_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
    ) -> Result<(ScimManagedConnection, Vec<ScimManagedCredential>), ScimError> {
        self.managed_options()?;
        let connection = self
            .qualified_connection(connection_id, provisioning_domain_id)
            .await?;
        let credentials = self
            .store
            .list_managed_credentials(&connection.id)
            .await
            .map_err(store_error)?;
        Ok((
            connection,
            observed_credentials(credentials, super::timestamp::now()),
        ))
    }

    pub async fn rotate_managed_credential(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        actor_id: &str,
        scopes: Vec<ScimScope>,
        expires_at: DateTime<Utc>,
    ) -> Result<(ScimManagedConnection, ScimManagedCredential, String), ScimError> {
        let options = self.managed_options()?;
        validate_policy(provisioning_domain_id, actor_id, &scopes, expires_at)?;
        let connection = self
            .qualified_connection(connection_id, provisioning_domain_id)
            .await?;
        let now = super::timestamp::now();
        let expires_at = super::timestamp::milliseconds(expires_at);
        let credentials = self
            .store
            .list_managed_credentials(&connection.id)
            .await
            .map_err(store_error)?;
        let used_slots = credentials
            .iter()
            .filter(|credential| credential.status == "active" && credential.expires_at > now)
            .map(|credential| credential.active_slot_key.as_str())
            .collect::<HashSet<_>>();
        let slot = (0..options.max_active_credentials)
            .find(|slot| !used_slots.contains(format!("{}:active:{slot}", connection.id).as_str()))
            .unwrap_or(options.max_active_credentials);
        let credential_id = format!("ba_scim_credential_{}", super::random_urlsafe(32));
        let token = format!("{credential_id}.{}", super::random_urlsafe(48));
        let credential = credential(NewCredential {
            record_id: &connection.id,
            credential_id: &credential_id,
            token_digest: token_digest(&options.credential_hash_secret, &token)?,
            active_slot_key: format!("{}:active:{slot}", connection.id),
            scopes,
            expires_at,
            actor_id,
            now,
        });
        let event = event(
            &connection.id,
            connection.revision + 1,
            "credential.rotated",
            actor_id,
            Some(&credential_id),
            now,
        );
        self.store
            .rotate_managed_credential(
                connection_id,
                provisioning_domain_id,
                credential,
                event,
                options.max_active_credentials,
                now,
            )
            .await
            .map(|(connection, credential)| (connection, credential, token))
            .map_err(store_error)
    }

    pub async fn revoke_managed_credential(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        credential_id: &str,
        actor_id: &str,
    ) -> Result<(ScimManagedConnection, Vec<ScimManagedCredential>), ScimError> {
        self.managed_options()?;
        validate_text(actor_id, 1, "actorId")?;
        let connection = self
            .qualified_connection(connection_id, provisioning_domain_id)
            .await?;
        self.store
            .revoke_managed_credential(
                &connection.id,
                credential_id,
                actor_id,
                super::timestamp::now(),
            )
            .await
            .map_err(store_error)?;
        self.get_managed_connection(connection_id, provisioning_domain_id)
            .await
    }

    pub async fn list_managed_connection_events(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
    ) -> Result<Vec<ScimManagedConnectionEvent>, ScimError> {
        self.managed_options()?;
        let connection = self
            .qualified_connection(connection_id, provisioning_domain_id)
            .await?;
        self.store
            .list_managed_events(&connection.id)
            .await
            .map_err(store_error)
    }

    pub async fn decommission_managed_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        actor_id: &str,
    ) -> Result<(ScimManagedConnection, Vec<ScimManagedCredential>), ScimError> {
        self.managed_options()?;
        validate_text(actor_id, 1, "actorId")?;
        self.store
            .decommission_managed_connection(
                connection_id,
                provisioning_domain_id,
                actor_id,
                super::timestamp::now(),
            )
            .await
            .map_err(store_error)?;
        self.get_managed_connection(connection_id, provisioning_domain_id)
            .await
    }

    pub async fn decommission_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
    ) -> Result<usize, ScimError> {
        self.store
            .decommission_connection(
                connection_id,
                provisioning_domain_id,
                "application",
                super::timestamp::now(),
            )
            .await
            .map_err(store_error)
    }

    fn managed_options(&self) -> Result<&ScimManagedConnectionOptions, ScimError> {
        self.options.managed_connections.as_ref().ok_or_else(|| {
            ScimError::new(400, "SCIM managed connections are not configured")
        })
    }

    async fn qualified_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
    ) -> Result<ScimManagedConnection, ScimError> {
        self.store
            .find_managed_connection(connection_id, provisioning_domain_id)
            .await
            .map_err(store_error)?
            .ok_or_else(|| ScimError::new(404, "Managed SCIM connection not found"))
    }
}

struct NewCredential<'a> {
    record_id: &'a str,
    credential_id: &'a str,
    token_digest: String,
    active_slot_key: String,
    scopes: Vec<ScimScope>,
    expires_at: DateTime<Utc>,
    actor_id: &'a str,
    now: DateTime<Utc>,
}

fn credential(input: NewCredential<'_>) -> ScimManagedCredential {
    let serialized_scopes =
        serde_json::to_string(&input.scopes).expect("SCIM scopes always serialize to JSON");
    ScimManagedCredential {
        id: super::random_urlsafe(32),
        connection_record_id: input.record_id.into(),
        credential_id: input.credential_id.into(),
        token_digest: input.token_digest,
        hash_version: "v1".into(),
        active_slot_key: input.active_slot_key,
        status: "active".into(),
        scopes: input.scopes,
        serialized_scopes,
        expires_at: input.expires_at,
        created_at: input.now,
        created_by: input.actor_id.into(),
        last_used_at: None,
        revoked_at: None,
        revoked_by: None,
        decommissioned_at: None,
    }
}

fn event(
    record_id: &str,
    sequence: u64,
    kind: &str,
    actor_id: &str,
    credential_id: Option<&str>,
    now: DateTime<Utc>,
) -> ScimManagedConnectionEvent {
    ScimManagedConnectionEvent {
        id: super::random_urlsafe(32),
        connection_record_id: record_id.into(),
        sequence,
        kind: kind.into(),
        actor_id: actor_id.into(),
        credential_id: credential_id.map(str::to_owned),
        created_at: now,
    }
}

fn observed_credentials(
    mut credentials: Vec<ScimManagedCredential>,
    now: DateTime<Utc>,
) -> Vec<ScimManagedCredential> {
    for credential in &mut credentials {
        if credential.status == "active" && credential.expires_at <= now {
            credential.status = "expired".into();
        }
    }
    credentials
}

fn validate_policy(
    provisioning_domain_id: &str,
    actor_id: &str,
    scopes: &[ScimScope],
    expires_at: DateTime<Utc>,
) -> Result<(), ScimError> {
    validate_text(provisioning_domain_id, 1, "provisioningDomainId")?;
    validate_text(actor_id, 1, "actorId")?;
    if scopes.is_empty() || scopes.iter().collect::<HashSet<_>>().len() != scopes.len() {
        return Err(invalid("Managed SCIM credential scopes must be non-empty and unique"));
    }
    if expires_at <= super::timestamp::now() {
        return Err(invalid("Managed SCIM credential expiry must be in the future"));
    }
    Ok(())
}

fn validate_text(value: &str, minimum: usize, field: &str) -> Result<(), ScimError> {
    if value.trim() != value || !(minimum..=255).contains(&value.chars().count()) {
        Err(invalid(format!(
            "{field} must contain {minimum} through 255 trimmed characters"
        )))
    } else {
        Ok(())
    }
}

fn invalid(detail: impl Into<String>) -> ScimError {
    ScimError::typed(400, detail, ScimErrorType::InvalidValue)
}
