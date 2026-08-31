use crate::{
    AuthService, DashAdapterOperator, DashAdapterWhere, DatabaseTransaction, ScimError,
    run_database_transaction,
};
use chrono::Utc;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

pub(crate) async fn reconcile(
    service: &AuthService,
    provisioning_domain_id: &str,
    user_id: &str,
    active: bool,
) -> Result<(), ScimError> {
    let Some(policy) = service
        .dash_plugin()
        .map(|dash| &dash.options().managed_directory_sync)
        .filter(|managed| managed.enabled && managed.membership_projection.enabled)
    else {
        return Ok(());
    };
    if policy.membership_projection.role.trim().is_empty() {
        return Err(ScimError::new(
            500,
            "Directory sync membership role must not be empty",
        ));
    }
    let store = service.database_store();
    let domain = provisioning_domain_id.to_owned();
    let user = user_id.to_owned();
    let role = policy.membership_projection.role.clone();
    run_database_transaction(store.as_ref(), move |database| {
        Box::pin(async move { reconcile_transaction(database, &domain, &user, &role, active).await })
    })
    .await
    .map_err(database_error)
}

async fn reconcile_transaction(
    database: Arc<dyn DatabaseTransaction>,
    provisioning_domain_id: &str,
    user_id: &str,
    role: &str,
    active: bool,
) -> Result<(), crate::AuthError> {
    let Some(directory) = find_one(
        &database,
        "directorySyncConnection",
        &[equal("provisioningDomainId", json!(provisioning_domain_id))],
    )
    .await?
    else {
        return Ok(());
    };
    if !matches!(
        string(&directory, "status")?.as_str(),
        "active" | "decommissioning" | "decommissioned"
    )
        || optional_string(&directory, "connectionId")?.is_none()
    {
        return Ok(());
    }
    let organization_id = string(&directory, "organizationId")?;
    let membership_key = membership_key(provisioning_domain_id, user_id);
    let memberships = database
        .find_records(
            "member",
            &[
                equal("organizationId", json!(organization_id)),
                equal("userId", json!(user_id)),
            ],
            None,
            0,
            None,
            &[],
        )
        .await?;
    if memberships.len() > 1 {
        return Err(crate::AuthError::Storage(
            "Directory sync membership projection requires a unique organization and user membership".into(),
        ));
    }
    let membership = memberships.into_iter().next();
    let provenance = find_one(
        &database,
        "directorySyncMembershipProvenance",
        &[equal("membershipKey", json!(membership_key))],
    )
    .await?;
    validate_provenance(
        provenance.as_ref(),
        provisioning_domain_id,
        &organization_id,
        user_id,
    )?;
    if active {
        activate(
            &database,
            membership,
            provenance,
            &membership_key,
            &organization_id,
            provisioning_domain_id,
            user_id,
            role,
        )
        .await
    } else {
        deactivate(&database, membership.as_ref(), provenance.as_ref(), &membership_key).await
    }
}

#[allow(clippy::too_many_arguments)]
async fn activate(
    database: &Arc<dyn DatabaseTransaction>,
    membership: Option<Map<String, Value>>,
    provenance: Option<Map<String, Value>>,
    membership_key: &str,
    organization_id: &str,
    provisioning_domain_id: &str,
    user_id: &str,
    role: &str,
) -> Result<(), crate::AuthError> {
    if let Some(membership) = membership {
        if provenance
            .as_ref()
            .is_some_and(|row| row.get("memberId") == membership.get("id"))
        {
            return Ok(());
        }
        delete_provenance(database, provenance.as_ref(), membership_key).await?;
        let member_id = string(&membership, "id")?;
        return create_provenance(
            database,
            membership_key,
            organization_id,
            user_id,
            &member_id,
            "observed",
            provisioning_domain_id,
        )
        .await;
    }
    delete_provenance(database, provenance.as_ref(), membership_key).await?;
    let now = Utc::now();
    let member = database
        .create_record(
            "member",
            object(json!({
                "id": crate::scim::random_urlsafe(32),
                "organizationId": organization_id,
                "userId": user_id,
                "role": role,
                "createdAt": now,
            })),
        )
        .await?;
    let member_id = string(&member, "id")?;
    create_provenance(
        database,
        membership_key,
        organization_id,
        user_id,
        &member_id,
        "created",
        provisioning_domain_id,
    )
    .await
}

async fn deactivate(
    database: &Arc<dyn DatabaseTransaction>,
    membership: Option<&Map<String, Value>>,
    provenance: Option<&Map<String, Value>>,
    membership_key: &str,
) -> Result<(), crate::AuthError> {
    let Some(provenance) = provenance else {
        return Ok(());
    };
    if string(provenance, "ownership")? == "created"
        && membership.is_some_and(|membership| membership.get("id") == provenance.get("memberId"))
    {
        database
            .delete_records(
                "member",
                &[
                    equal("id", field(provenance, "memberId")?.clone()),
                    equal("organizationId", field(provenance, "organizationId")?.clone()),
                    equal("userId", field(provenance, "userId")?.clone()),
                ],
            )
            .await?;
    }
    delete_provenance(database, Some(provenance), membership_key).await
}

async fn create_provenance(
    database: &Arc<dyn DatabaseTransaction>,
    membership_key: &str,
    organization_id: &str,
    user_id: &str,
    member_id: &str,
    ownership: &str,
    provisioning_domain_id: &str,
) -> Result<(), crate::AuthError> {
    let now = Utc::now();
    database
        .create_record(
            "directorySyncMembershipProvenance",
            object(json!({
                "id": crate::scim::random_urlsafe(32),
                "membershipKey": membership_key,
                "organizationId": organization_id,
                "userId": user_id,
                "memberId": member_id,
                "ownership": ownership,
                "provisioningDomainId": provisioning_domain_id,
                "createdAt": now,
                "updatedAt": now,
            })),
        )
        .await?;
    Ok(())
}

async fn delete_provenance(
    database: &Arc<dyn DatabaseTransaction>,
    provenance: Option<&Map<String, Value>>,
    membership_key: &str,
) -> Result<(), crate::AuthError> {
    if let Some(provenance) = provenance {
        database
            .delete_records(
                "directorySyncMembershipProvenance",
                &[
                    equal("id", field(provenance, "id")?.clone()),
                    equal("membershipKey", json!(membership_key)),
                ],
            )
            .await?;
    }
    Ok(())
}

fn validate_provenance(
    provenance: Option<&Map<String, Value>>,
    provisioning_domain_id: &str,
    organization_id: &str,
    user_id: &str,
) -> Result<(), crate::AuthError> {
    let Some(row) = provenance else {
        return Ok(());
    };
    let valid = matches!(string(row, "ownership")?.as_str(), "created" | "observed")
        && string(row, "provisioningDomainId")? == provisioning_domain_id
        && string(row, "organizationId")? == organization_id
        && string(row, "userId")? == user_id;
    if valid {
        Ok(())
    } else {
        Err(crate::AuthError::Storage(
            "Directory sync membership provenance does not match its provisioning domain".into(),
        ))
    }
}

async fn find_one(
    database: &Arc<dyn DatabaseTransaction>,
    model: &str,
    filters: &[DashAdapterWhere],
) -> Result<Option<Map<String, Value>>, crate::AuthError> {
    Ok(database
        .find_records(model, filters, Some(1), 0, None, &[])
        .await?
        .into_iter()
        .next())
}

fn membership_key(provisioning_domain_id: &str, user_id: &str) -> String {
    let input = serde_json::to_string(&(provisioning_domain_id, user_id))
        .expect("membership key input serializes");
    format!("directory-sync-membership:{}", hex::encode(Sha256::digest(input.as_bytes())))
}

fn equal(field: &str, value: Value) -> DashAdapterWhere {
    DashAdapterWhere {
        field: field.into(),
        value,
        operator: DashAdapterOperator::Eq,
        connector: None,
    }
}

fn field<'a>(row: &'a Map<String, Value>, name: &str) -> Result<&'a Value, crate::AuthError> {
    row.get(name)
        .ok_or_else(|| crate::AuthError::Storage(format!("directory projection row has no {name}")))
}

fn string(row: &Map<String, Value>, name: &str) -> Result<String, crate::AuthError> {
    field(row, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| crate::AuthError::Storage(format!("directory projection {name} is invalid")))
}

fn optional_string(row: &Map<String, Value>, name: &str) -> Result<Option<String>, crate::AuthError> {
    match field(row, name)? {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        _ => Err(crate::AuthError::Storage(format!("directory projection {name} is invalid"))),
    }
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("projection values are objects")
}

fn database_error(error: crate::AuthError) -> ScimError {
    ScimError::new(500, format!("Directory sync membership projection failed: {error}"))
}
