use super::{
    PostgresAgentAuthStore,
    host_lifecycle::{lock_host, lock_other_public_key, write_host},
    storage_error,
};
use crate::{
    AuthError,
    agent_auth::{AgentHost, AgentHostEnrollment, AgentHostEnrollmentOutcome, AgentHostStatus},
};
use sqlx::{Postgres, Transaction};

pub(super) async fn enroll(
    store: &PostgresAgentAuthStore,
    token_hash: &str,
    enrollment: AgentHostEnrollment,
) -> Result<AgentHostEnrollmentOutcome, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let Some(mut provisioned) =
        lock_host(&mut transaction, store, "enrollmentTokenHash", token_hash).await?
    else {
        return Ok(AgentHostEnrollmentOutcome::TokenNotFound);
    };
    if provisioned.status != AgentHostStatus::PendingEnrollment {
        return Ok(AgentHostEnrollmentOutcome::HostNotPendingEnrollment);
    }
    if provisioned
        .enrollment_token_expires_at
        .is_none_or(|expires_at| expires_at <= enrollment.now)
    {
        return Ok(AgentHostEnrollmentOutcome::TokenExpired);
    }
    let existing = lock_other_public_key(
        &mut transaction,
        store,
        &enrollment.public_key,
        &provisioned.id,
    )
    .await?;
    let enrolled = if let Some(existing) = existing {
        if existing.status == AgentHostStatus::Revoked {
            return Ok(AgentHostEnrollmentOutcome::PublicKeyHostRevoked);
        }
        if existing.user_id.is_some()
            && provisioned.user_id.is_some()
            && existing.user_id != provisioned.user_id
        {
            return Ok(AgentHostEnrollmentOutcome::HostAlreadyLinked);
        }
        merge(&mut transaction, store, provisioned, existing, enrollment).await?
    } else {
        provisioned.public_key = Some(enrollment.public_key);
        provisioned.kid = enrollment.kid;
        if enrollment.name.is_some() {
            provisioned.name = enrollment.name;
        }
        provisioned.status = AgentHostStatus::Active;
        provisioned.activated_at = Some(enrollment.now);
        provisioned.expires_at = enrollment.expires_at;
        provisioned.enrollment_token_hash = None;
        provisioned.enrollment_token_expires_at = None;
        provisioned.updated_at = enrollment.now;
        write_host(&mut transaction, store, &provisioned).await?
    };
    transaction.commit().await.map_err(storage_error)?;
    Ok(AgentHostEnrollmentOutcome::Enrolled(Box::new(enrolled)))
}

async fn merge(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    mut provisioned: AgentHost,
    mut existing: AgentHost,
    enrollment: AgentHostEnrollment,
) -> Result<AgentHost, AuthError> {
    existing.name = enrollment
        .name
        .or_else(|| provisioned.name.clone())
        .or(existing.name);
    existing.user_id = existing.user_id.or(provisioned.user_id);
    existing.kid = enrollment.kid;
    existing.status = AgentHostStatus::Active;
    existing.activated_at = Some(enrollment.now);
    existing.expires_at = enrollment.expires_at;
    existing.updated_at = enrollment.now;
    provisioned.status = AgentHostStatus::Rejected;
    provisioned.enrollment_token_hash = None;
    provisioned.enrollment_token_expires_at = None;
    provisioned.updated_at = enrollment.now;
    write_host(transaction, store, &provisioned).await?;
    write_host(transaction, store, &existing).await
}
