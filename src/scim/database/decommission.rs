use crate::scim::{ScimError, ScimOptions};
use crate::AuthStore;
use chrono::{DateTime, Utc};
use std::sync::Arc;

mod lease;
mod reconcile;

pub(super) struct AcquiredLease {
    binding_id: String,
    lease_id: Option<String>,
    reconciled_users: usize,
}

pub(in crate::scim) async fn run(
    store: Arc<dyn AuthStore>,
    options: Arc<ScimOptions>,
    connection_id: &str,
    provisioning_domain_id: &str,
    now: DateTime<Utc>,
) -> Result<usize, ScimError> {
    let acquired = lease::acquire(
        store.clone(),
        connection_id,
        provisioning_domain_id,
        now,
    )
    .await?;
    let Some(lease_id) = acquired.lease_id.as_deref() else {
        return Ok(acquired.reconciled_users);
    };
    match reconcile::run(
        store.clone(),
        &options,
        &acquired.binding_id,
        lease_id,
    )
    .await
    {
        Ok(reconciled) => Ok(reconciled),
        Err(error) => {
            lease::release(store, &acquired.binding_id, lease_id).await;
            Err(error)
        }
    }
}

pub(super) fn error(error: crate::AuthError) -> ScimError {
    ScimError::new(500, format!("SCIM decommission failed: {error}"))
}

pub(super) fn transaction_error(error: ScimError) -> crate::AuthError {
    crate::AuthError::Storage(format!("SCIM decommission failed: {error}"))
}
