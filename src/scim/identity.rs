use super::{ScimError, ScimOptions, ScimUser};
use crate::{AuthError, DashAdapterWhere, DatabaseModel, DatabaseRecord, DatabaseTransaction};
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use std::sync::Arc;

mod acquire;

pub use acquire::{
    ScimActiveUserLink, ScimUserExternalIdReference, acquire_active_scim_user_link,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimIdentityProfile {
    Manage,
    Preserve,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimIdentityResolution {
    Create,
    Link {
        user_id: String,
        profile: ScimIdentityProfile,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScimIdentityResolutionInput {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub resource: ScimUser,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimIdentitySource {
    pub id: String,
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimIdentityState {
    pub user_id: String,
    pub active: bool,
    pub profile_source_id: Option<String>,
    pub sources: Vec<ScimIdentitySource>,
}

#[derive(Clone)]
pub struct ScimTransactionContext {
    pub database: Arc<dyn DatabaseTransaction>,
}

impl std::fmt::Debug for ScimTransactionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScimTransactionContext")
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait ScimIdentity: Send + Sync {
    async fn resolve_user(
        &self,
        _input: ScimIdentityResolutionInput,
        _context: ScimTransactionContext,
    ) -> Result<ScimIdentityResolution, ScimError> {
        Ok(ScimIdentityResolution::Create)
    }

    async fn reconcile_user(
        &self,
        _input: ScimIdentityState,
        _context: ScimTransactionContext,
    ) -> Result<(), ScimError> {
        Ok(())
    }
}

pub(super) struct ResolvedIdentity {
    pub resolution: ScimIdentityResolution,
    pub tombstone_id: Option<String>,
}

pub(super) async fn resolve(
    options: &ScimOptions,
    transaction: Arc<dyn DatabaseTransaction>,
    connection_id: &str,
    provisioning_domain_id: &str,
    resource: &ScimUser,
) -> Result<ResolvedIdentity, ScimError> {
    if let Some(resolved) = resolve_tombstone(
        &transaction,
        connection_id,
        provisioning_domain_id,
        resource.external_id.as_deref(),
    )
    .await?
    {
        return Ok(resolved);
    }
    let Some(identity) = options.identity.as_ref() else {
        return Ok(ResolvedIdentity {
            resolution: ScimIdentityResolution::Create,
            tombstone_id: None,
        });
    };
    let mut resource = resource.clone();
    resource.id = None;
    resource.meta = None;
    let resolution = identity
        .resolve_user(
            ScimIdentityResolutionInput {
                connection_id: connection_id.into(),
                provisioning_domain_id: provisioning_domain_id.into(),
                resource,
            },
            ScimTransactionContext {
                database: transaction,
            },
        )
        .await?;
    Ok(ResolvedIdentity {
        resolution,
        tombstone_id: None,
    })
}

pub(super) async fn linked_user(
    transaction: &Arc<dyn DatabaseTransaction>,
    user_id: &str,
) -> Result<crate::AuthUser, ScimError> {
    match transaction
        .find_by_id(DatabaseModel::User, user_id)
        .await
        .map_err(database_error)?
    {
        Some(DatabaseRecord::User(user)) => Ok(user),
        _ => Err(ScimError::new(
            409,
            "The resolved Better Auth User does not exist",
        )),
    }
}

pub(super) async fn consume_tombstone(
    transaction: &Arc<dyn DatabaseTransaction>,
    tombstone_id: Option<&str>,
) -> Result<(), ScimError> {
    if let Some(tombstone_id) = tombstone_id {
        transaction
            .delete_records(
                "scimIdentityTombstone",
                &[equal("id", json!(tombstone_id))],
            )
            .await
            .map_err(database_error)?;
    }
    Ok(())
}

pub(super) async fn state(
    options: &ScimOptions,
    transaction: Arc<dyn DatabaseTransaction>,
    user_id: &str,
) -> Result<ScimIdentityState, ScimError> {
    let subject = find_one(
        &transaction,
        "scimSubject",
        &[equal("userId", json!(user_id))],
    )
    .await?;
    let records = transaction
        .find_records(
            "scimUser",
            &[equal("userId", json!(user_id))],
            None,
            0,
            None,
            &[],
        )
        .await
        .map_err(database_error)?;
    let mut sources = Vec::new();
    for record in records {
        let connection_id = string(&record, "connectionId")?;
        if !active_connection(&transaction, &connection_id).await? {
            continue;
        }
        sources.push(ScimIdentitySource {
            id: string(&record, "id")?,
            connection_id,
            provisioning_domain_id: string(&record, "provisioningDomainId")?,
            active: boolean(&record, "active")?,
        });
    }
    sources.sort_by(|left, right| left.id.cmp(&right.id));
    let state = ScimIdentityState {
        user_id: user_id.into(),
        active: sources.iter().any(|source| source.active),
        profile_source_id: subject
            .as_ref()
            .and_then(|subject| subject.get("profileSourceId"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        sources,
    };
    if let Some(identity) = options.identity.as_ref() {
        identity
            .reconcile_user(
                state.clone(),
                ScimTransactionContext {
                    database: transaction,
                },
            )
            .await?;
    }
    Ok(state)
}

async fn resolve_tombstone(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
    provisioning_domain_id: &str,
    external_id: Option<&str>,
) -> Result<Option<ResolvedIdentity>, ScimError> {
    let Some(external_id) = external_id else {
        return Ok(None);
    };
    let Some(tombstone) = find_tombstone(transaction, connection_id, external_id).await? else {
        return Ok(None);
    };
    if string(&tombstone, "provisioningDomainId")? != provisioning_domain_id {
        return Err(ScimError::new(
            409,
            "The connection provisioningDomainId changed after this User was deleted",
        ));
    }
    let profile = match string(&tombstone, "profile")?.as_str() {
        "manage" => ScimIdentityProfile::Manage,
        _ => ScimIdentityProfile::Preserve,
    };
    Ok(Some(ResolvedIdentity {
        resolution: ScimIdentityResolution::Link {
            user_id: string(&tombstone, "userId")?,
            profile,
        },
        tombstone_id: Some(string(&tombstone, "id")?),
    }))
}

async fn find_tombstone(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
    external_id: &str,
) -> Result<Option<Map<String, Value>>, ScimError> {
    find_one(
        transaction,
        "scimIdentityTombstone",
        &[
            equal("connectionId", json!(connection_id)),
            equal(
                "externalIdKey",
                json!(super::database::keys::user_external_id(
                    connection_id,
                    external_id
                )),
            ),
            equal("externalId", json!(external_id)),
        ],
    )
    .await
}

async fn active_connection(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
) -> Result<bool, ScimError> {
    Ok(find_one(
        transaction,
        "scimConnectionBinding",
        &[
            equal("connectionId", json!(connection_id)),
            equal("decommissionStatus", json!("active")),
        ],
    )
    .await?
    .is_some())
}

async fn find_one(
    transaction: &Arc<dyn DatabaseTransaction>,
    model: &str,
    filter: &[DashAdapterWhere],
) -> Result<Option<Map<String, Value>>, ScimError> {
    transaction
        .find_records(model, filter, Some(1), 0, None, &[])
        .await
        .map(|mut records| records.pop())
        .map_err(database_error)
}

fn equal(field: &str, value: Value) -> DashAdapterWhere {
    DashAdapterWhere {
        field: field.into(),
        value,
        operator: Default::default(),
        connector: None,
    }
}

fn string(record: &Map<String, Value>, field: &str) -> Result<String, ScimError> {
    record
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ScimError::new(500, format!("stored SCIM field '{field}' is invalid")))
}

fn boolean(record: &Map<String, Value>, field: &str) -> Result<bool, ScimError> {
    record
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| ScimError::new(500, format!("stored SCIM field '{field}' is invalid")))
}

fn database_error(error: AuthError) -> ScimError {
    ScimError::new(500, format!("SCIM identity storage failed: {error}"))
}
