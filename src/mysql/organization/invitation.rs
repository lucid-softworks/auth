use super::{codec, eq, invitation_acceptance};
use crate::{
    AuthError, DatabaseIdSupplier, OrganizationInvitation, OrganizationInvitationStatus,
    OrganizationInvitationStore, OrganizationInvitationWriteOutcome,
    mysql::{
        MySqlComparisonMode, MySqlFilter, MySqlFindOptions, MySqlSort, MySqlSortDirection,
        MySqlStore, query::execute,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

#[async_trait]
impl OrganizationInvitationStore for MySqlStore {
    async fn create_invitation(
        &self,
        invitation: &mut OrganizationInvitation,
        id: &dyn DatabaseIdSupplier,
        invitation_limit: usize,
        membership_limit: usize,
        cancel_pending: bool,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(super::storage)?;
        let organization = [eq("organizationId", &invitation.organization_id)];
        if execute::count(&mut transaction, schema, "member", &organization).await?
            >= membership_limit as u64
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationInvitationWriteOutcome::LimitReached);
        }
        let pending = pending_filters(&invitation.organization_id, Some(&invitation.email));
        if execute::count(&mut transaction, schema, "invitation", &pending).await? > 0
            && !cancel_pending
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationInvitationWriteOutcome::AlreadyInvited);
        }
        if cancel_pending {
            execute::update_many(
                &mut transaction,
                schema,
                "invitation",
                &pending,
                Map::from_iter([("status".into(), json!("canceled"))]),
            )
            .await?;
        }
        if execute::count(
            &mut transaction,
            schema,
            "invitation",
            &pending_filters(&invitation.organization_id, None),
        )
        .await?
            >= invitation_limit as u64
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationInvitationWriteOutcome::LimitReached);
        }
        invitation.email = invitation.email.to_lowercase();
        invitation.status = OrganizationInvitationStatus::Pending;
        let mut record = codec::invitation_record(self, invitation)?;
        insert_id(&mut record, id.prepare()?)?;
        *invitation = codec::decode(
            "invitation",
            execute::insert_required(&mut transaction, schema, "invitation", record).await?,
        )?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(OrganizationInvitationWriteOutcome::Written)
    }

    async fn find_invitation(&self, id: &str) -> Result<Option<OrganizationInvitation>, AuthError> {
        find(self, &[eq("id", id)]).await
    }

    async fn list_invitations(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationInvitation>, AuthError> {
        list(self, &[eq("organizationId", organization_id)]).await
    }

    async fn list_user_invitations(
        &self,
        email: &str,
    ) -> Result<Vec<OrganizationInvitation>, AuthError> {
        let mut filter = eq("email", email);
        filter.mode = MySqlComparisonMode::Insensitive;
        list(self, &[filter]).await
    }

    async fn set_invitation_status(
        &self,
        id: &str,
        status: OrganizationInvitationStatus,
    ) -> Result<Option<OrganizationInvitation>, AuthError> {
        self.update_record(
            "invitation",
            &[eq("id", id)],
            Map::from_iter([("status".into(), json!(status))]),
        )
        .await?
        .map(|record| codec::decode("invitation", record))
        .transpose()
    }

    async fn resend_invitation(
        &self,
        organization_id: &str,
        email: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Option<OrganizationInvitation>, AuthError> {
        let mut email_filter = eq("email", email);
        email_filter.mode = MySqlComparisonMode::Insensitive;
        let filters = [
            eq("organizationId", organization_id),
            email_filter,
            eq("status", "pending"),
        ];
        let latest = self
            .find_records(
                "invitation",
                &filters,
                &MySqlFindOptions {
                    sort: Some(MySqlSort {
                        field: "createdAt".into(),
                        direction: MySqlSortDirection::Descending,
                    }),
                    limit: Some(1),
                    ..MySqlFindOptions::default()
                },
            )
            .await?
            .into_iter()
            .next();
        let Some(latest) = latest else {
            return Ok(None);
        };
        let id = latest
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Storage("invalid MySQL invitation row: id".into()))?;
        self.update_record(
            "invitation",
            &[eq("id", id)],
            Map::from_iter([("expiresAt".into(), json!(expires_at))]),
        )
        .await?
        .map(|record| codec::decode("invitation", record))
        .transpose()
    }

    async fn accept_invitation(
        &self,
        invitation_id: &str,
        user_id: &str,
        now: DateTime<Utc>,
        membership_limit: usize,
        member_id: &dyn DatabaseIdSupplier,
        team_member_id: &dyn DatabaseIdSupplier,
    ) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
        invitation_acceptance::accept(
            self,
            invitation_id,
            user_id,
            now,
            membership_limit,
            member_id,
            team_member_id,
        )
        .await
    }
}

async fn find(
    store: &MySqlStore,
    filters: &[MySqlFilter],
) -> Result<Option<OrganizationInvitation>, AuthError> {
    store
        .find_record("invitation", filters, &[])
        .await?
        .map(|record| codec::decode("invitation", record))
        .transpose()
}
async fn list(
    store: &MySqlStore,
    filters: &[MySqlFilter],
) -> Result<Vec<OrganizationInvitation>, AuthError> {
    store
        .find_records(
            "invitation",
            filters,
            &MySqlFindOptions {
                sort: Some(MySqlSort {
                    field: "createdAt".into(),
                    direction: MySqlSortDirection::Ascending,
                }),
                ..MySqlFindOptions::default()
            },
        )
        .await?
        .into_iter()
        .map(|record| codec::decode("invitation", record))
        .collect()
}
fn pending_filters(organization_id: &str, email: Option<&str>) -> Vec<MySqlFilter> {
    let mut filters = vec![
        eq("organizationId", organization_id),
        eq("status", "pending"),
    ];
    if let Some(email) = email {
        let mut filter = eq("email", email);
        filter.mode = MySqlComparisonMode::Insensitive;
        filters.push(filter);
    }
    filters
}
pub(super) fn insert_id(
    record: &mut Map<String, Value>,
    id: crate::PreparedDatabaseId,
) -> Result<(), AuthError> {
    if let crate::PreparedDatabaseId::Value(value) = id {
        record.insert("id".into(), value.to_json()?);
    }
    Ok(())
}
