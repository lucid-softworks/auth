use super::{eq, insert};
use crate::{
    AuthError, DatabaseIdSupplier, OrganizationMember, OrganizationMemberStore,
    OrganizationMemberWriteOutcome,
    mongodb::{MongoFindOptions, MongoStore, query::execute},
};
use async_trait::async_trait;
use serde_json::{Map, json};

#[async_trait]
impl OrganizationMemberStore for MongoStore {
    async fn raw_insert_member(
        &self,
        member: OrganizationMember,
        id: &dyn DatabaseIdSupplier,
    ) -> Result<OrganizationMember, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        let record = insert(
            self,
            &mut transaction,
            schema,
            "member",
            &member,
            id.prepare()?,
        )
        .await?;
        transaction.commit().await.map_err(super::storage)?;
        super::codec::decode("member", record)
    }

    async fn find_member_by_id(&self, id: &str) -> Result<Option<OrganizationMember>, AuthError> {
        find(self, &[eq("id", id)]).await
    }

    async fn find_member(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> Result<Option<OrganizationMember>, AuthError> {
        find(
            self,
            &[eq("organizationId", organization_id), eq("userId", user_id)],
        )
        .await
    }

    async fn list_members(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationMember>, AuthError> {
        list(self, &[eq("organizationId", organization_id)]).await
    }

    async fn add_member(
        &self,
        member: &mut OrganizationMember,
        id: &dyn DatabaseIdSupplier,
        membership_limit: usize,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        let filters = [eq("organizationId", &member.organization_id)];
        if execute::find_one(
            &mut transaction,
            schema,
            "member",
            &[
                eq("organizationId", &member.organization_id),
                eq("userId", &member.user_id),
            ],
            &[],
        )
        .await?
        .is_some()
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationMemberWriteOutcome::AlreadyMember);
        }
        if execute::count(&mut transaction, schema, "member", &filters).await?
            >= membership_limit as u64
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationMemberWriteOutcome::LimitReached);
        }
        let record = insert(
            self,
            &mut transaction,
            schema,
            "member",
            member,
            id.prepare()?,
        )
        .await?;
        *member = super::codec::decode("member", record)?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn update_member_role(
        &self,
        member_id: &str,
        role: String,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        let Some(current) = find_tx(&mut transaction, schema, &[eq("id", member_id)]).await? else {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationMemberWriteOutcome::NotFound);
        };
        if has_role(&current.role, creator_role)
            && !has_role(&role, creator_role)
            && owner_count(
                &mut transaction,
                schema,
                &current.organization_id,
                creator_role,
            )
            .await?
                <= 1
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationMemberWriteOutcome::LastOwner);
        }
        execute::update_one(
            &mut transaction,
            schema,
            "member",
            &[eq("id", member_id)],
            Map::from_iter([("role".into(), json!(role))]),
        )
        .await?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn remove_member(
        &self,
        member_id: &str,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        let Some(current) = find_tx(&mut transaction, schema, &[eq("id", member_id)]).await? else {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationMemberWriteOutcome::NotFound);
        };
        if has_role(&current.role, creator_role)
            && owner_count(
                &mut transaction,
                schema,
                &current.organization_id,
                creator_role,
            )
            .await?
                <= 1
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationMemberWriteOutcome::LastOwner);
        }
        execute::delete_many(&mut transaction, schema, "member", &[eq("id", member_id)]).await?;
        delete_team_members(
            &mut transaction,
            schema,
            &current.organization_id,
            &current.user_id,
        )
        .await?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(OrganizationMemberWriteOutcome::Written)
    }
}

async fn find(
    store: &MongoStore,
    filters: &[super::super::MongoFilter],
) -> Result<Option<OrganizationMember>, AuthError> {
    store
        .find_record("member", filters, &[])
        .await?
        .map(|record| super::codec::decode("member", record))
        .transpose()
}

async fn list(
    store: &MongoStore,
    filters: &[super::super::MongoFilter],
) -> Result<Vec<OrganizationMember>, AuthError> {
    store
        .find_records("member", filters, &MongoFindOptions::default())
        .await?
        .into_iter()
        .map(|record| super::codec::decode("member", record))
        .collect()
}

async fn find_tx(
    transaction: &mut crate::mongodb::query::MongoTransaction,
    schema: &super::super::schema::MongoSchema,
    filters: &[super::super::MongoFilter],
) -> Result<Option<OrganizationMember>, AuthError> {
    execute::find_one(transaction, schema, "member", filters, &[])
        .await?
        .map(|record| super::codec::decode("member", record))
        .transpose()
}

async fn owner_count(
    transaction: &mut crate::mongodb::query::MongoTransaction,
    schema: &super::super::schema::MongoSchema,
    organization_id: &str,
    role: &str,
) -> Result<usize, AuthError> {
    Ok(execute::find_many(
        transaction,
        schema,
        "member",
        &[eq("organizationId", organization_id)],
        &MongoFindOptions::default(),
    )
    .await?
    .into_iter()
    .map(|record| super::codec::decode::<OrganizationMember>("member", record))
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .filter(|member| has_role(&member.role, role))
    .count())
}

async fn delete_team_members(
    transaction: &mut crate::mongodb::query::MongoTransaction,
    schema: &super::super::schema::MongoSchema,
    organization_id: &str,
    user_id: &str,
) -> Result<(), AuthError> {
    if !schema.has_model("team") && !schema.has_model("teamMember") {
        return Ok(());
    }
    if !schema.has_model("team") || !schema.has_model("teamMember") {
        return Err(AuthError::InvalidConfiguration(
            "organization team schema is incomplete".into(),
        ));
    }
    let teams = execute::find_many(
        transaction,
        schema,
        "team",
        &[eq("organizationId", organization_id)],
        &MongoFindOptions::default(),
    )
    .await?;
    for team in teams {
        let id = team
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AuthError::Storage("invalid MongoDB team row: id".into()))?;
        execute::delete_many(
            transaction,
            schema,
            "teamMember",
            &[eq("teamId", id), eq("userId", user_id)],
        )
        .await?;
    }
    Ok(())
}

fn has_role(roles: &str, role: &str) -> bool {
    roles
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == role)
}
