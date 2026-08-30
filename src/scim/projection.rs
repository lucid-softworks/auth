use super::{ScimError, ScimIdentitySource, ScimOptions, ScimTransactionContext};
use crate::DatabaseTransaction;
use async_trait::async_trait;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

mod grants;
mod query;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimAuthorizationSource {
    Group {
        id: String,
        external_id: Option<String>,
        display_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimProjectedRoleGrant {
    pub source: ScimAuthorizationSource,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimProjectedUserState {
    pub provisioning_domain_id: String,
    pub user_id: String,
    pub active: bool,
    pub sources: Vec<ScimIdentitySource>,
    pub grants: Vec<ScimProjectedRoleGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimRoleMappingInput {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub scim_user_id: String,
    pub user_id: String,
    pub source: ScimAuthorizationSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimRoleExistenceInput {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub role: String,
}

#[async_trait]
pub trait ScimRoleProjection: Send + Sync {
    async fn map(
        &self,
        input: ScimRoleMappingInput,
        context: ScimTransactionContext,
    ) -> Result<Option<Vec<String>>, ScimError>;

    async fn exists(
        &self,
        input: ScimRoleExistenceInput,
        context: ScimTransactionContext,
    ) -> Result<bool, ScimError>;
}

#[async_trait]
pub trait ScimProjection: Send + Sync {
    fn roles(&self) -> Option<&dyn ScimRoleProjection> {
        None
    }

    async fn reconcile_user(
        &self,
        input: ScimProjectedUserState,
        context: ScimTransactionContext,
    ) -> Result<(), ScimError>;
}

pub(super) async fn reconcile_user(
    options: &ScimOptions,
    transaction: Arc<dyn DatabaseTransaction>,
    provisioning_domain_id: &str,
    user_id: &str,
    lock_subject: bool,
) -> Result<(), ScimError> {
    if lock_subject {
        query::lock(&transaction, user_id).await?;
    }
    let sources = query::sources(&transaction, provisioning_domain_id, user_id).await?;
    let desired = grants::desired(
        options,
        transaction.clone(),
        provisioning_domain_id,
        user_id,
        &sources,
    )
    .await?;
    grants::sync(
        &transaction,
        provisioning_domain_id,
        user_id,
        &desired,
    )
    .await?;
    if let Some(projection) = options.projection.as_ref() {
        let mut projected = desired
            .iter()
            .map(grants::projected)
            .collect::<Vec<_>>();
        projected.sort_by(|left, right| grants::sort_key(left).cmp(&grants::sort_key(right)));
        projection
            .reconcile_user(
                ScimProjectedUserState {
                    provisioning_domain_id: provisioning_domain_id.into(),
                    user_id: user_id.into(),
                    active: sources.iter().any(|source| source.active),
                    sources,
                    grants: projected,
                },
                ScimTransactionContext {
                    database: transaction,
                },
            )
            .await?;
    }
    Ok(())
}

pub(super) async fn reconcile_scim_users(
    options: &ScimOptions,
    transaction: Arc<dyn DatabaseTransaction>,
    provisioning_domain_id: &str,
    scim_user_ids: &[String],
) -> Result<(), ScimError> {
    let mut user_ids = BTreeSet::new();
    for scim_user_id in scim_user_ids {
        if let Some(record) = query::find_one(
            &transaction,
            "scimUser",
            &[query::equal("id", json!(scim_user_id))],
        )
        .await?
        {
            user_ids.insert(query::string(&record, "userId")?);
        }
    }
    for user_id in user_ids {
        reconcile_user(
            options,
            transaction.clone(),
            provisioning_domain_id,
            &user_id,
            true,
        )
        .await?;
    }
    Ok(())
}
