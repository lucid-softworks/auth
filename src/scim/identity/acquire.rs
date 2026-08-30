use super::ScimTransactionContext;
use crate::{DatabaseModel, DatabaseRecord};
use serde_json::{Map, Value, json};

/// Exact external-directory reference for one connection-owned SCIM User.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimUserExternalIdReference {
    pub connection_id: String,
    pub external_id: String,
}

/// Better Auth User link acquired from an active SCIM source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimActiveUserLink {
    pub scim_user_id: String,
    pub user_id: String,
}

/// Acquires an active SCIM User link inside the caller's transaction.
///
/// Lookup is limited to the exact connection and external ID. It never falls
/// back to user name, email, or a deleted identity tombstone. A concurrent
/// lifecycle mutation returns a conflict so the caller can retry its complete
/// transaction from fresh state.
pub async fn acquire_active_scim_user_link(
    reference: ScimUserExternalIdReference,
    context: ScimTransactionContext,
) -> Result<Option<ScimActiveUserLink>, super::ScimError> {
    let database = context.database;
    let external_id_key = super::super::database::keys::user_external_id(
        &reference.connection_id,
        &reference.external_id,
    );
    let Some(source) = find_active_source(&database, &reference, &external_id_key).await? else {
        return Ok(None);
    };
    let Some(binding) = find_active_binding(&database, &reference.connection_id).await? else {
        return Ok(None);
    };
    if string(&binding, "provisioningDomainId")? != string(&source, "provisioningDomainId")? {
        return Ok(None);
    }
    if tombstone_exists(&database, &reference, &external_id_key).await? {
        return Ok(None);
    }
    let user_id = string(&source, "userId")?;
    let Some(subject) = find_live_subject(&database, &user_id).await? else {
        return Ok(None);
    };

    let acquired_subject = fence_subject(&database, &subject, &user_id).await?;
    let acquired_source = super::find_one(
        &database,
        "scimUser",
        &[
            super::equal("id", field(&source, "id")?.clone()),
            super::equal("connectionId", json!(reference.connection_id)),
            super::equal(
                "provisioningDomainId",
                field(&binding, "provisioningDomainId")?.clone(),
            ),
            super::equal("userId", json!(user_id)),
            super::equal(
                "connectionUserKey",
                field(&source, "connectionUserKey")?.clone(),
            ),
            super::equal("externalIdKey", json!(external_id_key)),
            super::equal("externalId", json!(reference.external_id)),
            super::equal("active", json!(true)),
        ],
    )
    .await?
    .ok_or_else(concurrent_mutation)?;
    if string(&acquired_source, "userId")? != string(&acquired_subject, "userId")?
        || !user_exists(&database, &user_id).await?
        || tombstone_exists(&database, &reference, &external_id_key).await?
    {
        return Err(concurrent_mutation());
    }
    let acquired_binding = database
        .increment_record(
            "scimConnectionBinding",
            &active_binding_filter(&reference.connection_id),
            object(json!({"decommissionRevision": 1})),
            Map::new(),
        )
        .await
        .map_err(super::database_error)?
        .ok_or_else(concurrent_mutation)?;
    if field(&acquired_binding, "id")? != field(&binding, "id")?
        || field(&acquired_binding, "provisioningDomainId")?
            != field(&acquired_source, "provisioningDomainId")?
    {
        return Err(concurrent_mutation());
    }
    Ok(Some(ScimActiveUserLink {
        scim_user_id: string(&source, "id")?,
        user_id,
    }))
}

async fn find_live_subject(
    database: &std::sync::Arc<dyn crate::DatabaseTransaction>,
    user_id: &str,
) -> Result<Option<Map<String, Value>>, super::ScimError> {
    let subject = super::find_one(
        database,
        "scimSubject",
        &[super::equal("userId", json!(user_id))],
    )
    .await?;
    if subject.is_some() && user_exists(database, user_id).await? {
        Ok(subject)
    } else {
        Ok(None)
    }
}

async fn find_active_source(
    database: &std::sync::Arc<dyn crate::DatabaseTransaction>,
    reference: &ScimUserExternalIdReference,
    external_id_key: &str,
) -> Result<Option<Map<String, Value>>, super::ScimError> {
    super::find_one(
        database,
        "scimUser",
        &[
            super::equal("connectionId", json!(reference.connection_id)),
            super::equal("externalIdKey", json!(external_id_key)),
            super::equal("externalId", json!(reference.external_id)),
            super::equal("active", json!(true)),
        ],
    )
    .await
}

async fn find_active_binding(
    database: &std::sync::Arc<dyn crate::DatabaseTransaction>,
    connection_id: &str,
) -> Result<Option<Map<String, Value>>, super::ScimError> {
    super::find_one(
        database,
        "scimConnectionBinding",
        &active_binding_filter(connection_id),
    )
    .await
}

fn active_binding_filter(connection_id: &str) -> [crate::DashAdapterWhere; 3] {
    [
        super::equal(
            "connectionKey",
            json!(super::super::database::keys::connection(connection_id)),
        ),
        super::equal("connectionId", json!(connection_id)),
        super::equal("decommissionStatus", json!("active")),
    ]
}

async fn fence_subject(
    database: &std::sync::Arc<dyn crate::DatabaseTransaction>,
    subject: &Map<String, Value>,
    user_id: &str,
) -> Result<Map<String, Value>, super::ScimError> {
    database
        .increment_record(
            "scimSubject",
            &[
                super::equal("id", field(subject, "id")?.clone()),
                super::equal("userId", json!(user_id)),
                super::equal("revision", field(subject, "revision")?.clone()),
            ],
            object(json!({"revision": 1})),
            object(json!({"updatedAt": super::super::timestamp::now().to_rfc3339()})),
        )
        .await
        .map_err(super::database_error)?
        .ok_or_else(concurrent_mutation)
}

async fn tombstone_exists(
    database: &std::sync::Arc<dyn crate::DatabaseTransaction>,
    reference: &ScimUserExternalIdReference,
    external_id_key: &str,
) -> Result<bool, super::ScimError> {
    super::find_one(
        database,
        "scimIdentityTombstone",
        &[
            super::equal("connectionId", json!(reference.connection_id)),
            super::equal("externalIdKey", json!(external_id_key)),
            super::equal("externalId", json!(reference.external_id)),
        ],
    )
    .await
    .map(|record| record.is_some())
}

async fn user_exists(
    database: &std::sync::Arc<dyn crate::DatabaseTransaction>,
    user_id: &str,
) -> Result<bool, super::ScimError> {
    database
        .find_by_id(DatabaseModel::User, user_id)
        .await
        .map(|record| matches!(record, Some(DatabaseRecord::User(_))))
        .map_err(super::database_error)
}

fn field<'a>(record: &'a Map<String, Value>, name: &str) -> Result<&'a Value, super::ScimError> {
    record
        .get(name)
        .ok_or_else(|| super::ScimError::new(500, format!("SCIM {name} is missing")))
}

fn string(record: &Map<String, Value>, name: &str) -> Result<String, super::ScimError> {
    field(record, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| super::ScimError::new(500, format!("SCIM {name} is invalid")))
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("record literal is an object")
}

fn concurrent_mutation() -> super::ScimError {
    super::ScimError::new(
        409,
        "The SCIM identity changed concurrently; retry the request",
    )
}
