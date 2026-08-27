use super::super::{rows, storage_error};
use crate::{AuthError, postgres::PostgresModel};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};

pub(super) async fn remove_team_from_invitations(
    transaction: &mut Transaction<'_, Postgres>,
    invitation_model: &PostgresModel<'_>,
    organization_id: &str,
    team_id: &str,
) -> Result<(), AuthError> {
    let mut query = crate::postgres::rows::select_query(invitation_model);
    query
        .push(" WHERE ")
        .push(invitation_model.quoted_column("organizationId")?)
        .push(" = ");
    invitation_model
        .encode("organizationId", json!(organization_id))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(invitation_model.quoted_column("status")?)
        .push(" = ");
    invitation_model
        .encode("status", json!("pending"))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(invitation_model.quoted_column("teamId")?)
        .push(" IS NOT NULL FOR UPDATE");
    let invitations = query
        .build()
        .fetch_all(&mut **transaction)
        .await
        .map_err(storage_error)?
        .iter()
        .map(|row| rows::decode_invitation(invitation_model, row))
        .collect::<Result<Vec<_>, _>>()?;
    for invitation in invitations {
        let remaining = invitation
            .team_id
            .unwrap_or_default()
            .split(',')
            .filter(|candidate| *candidate != team_id)
            .collect::<Vec<_>>()
            .join(",");
        let writes = invitation_model.encode_fields([(
            "teamId",
            (!remaining.is_empty())
                .then_some(remaining)
                .map_or(Value::Null, Value::String),
        )])?;
        let mut update = crate::postgres::rows::update_query(invitation_model, writes);
        update.push(" WHERE \"id\" = ");
        invitation_model
            .encode("id", json!(invitation.id))?
            .push_bind(&mut update);
        update
            .build()
            .execute(&mut **transaction)
            .await
            .map_err(storage_error)?;
    }
    Ok(())
}
