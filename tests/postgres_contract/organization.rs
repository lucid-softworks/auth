use lucid_auth::{
    AuthService, NewOrganization, NewOrganizationInvitation, OrganizationInvitationStore,
    OrganizationInvitationWriteOutcome, OrganizationMemberStore, OrganizationPermissions,
    OrganizationTeamStore, SessionWithUser, postgres::PostgresStore,
};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};

pub(crate) async fn assert_table_absent(
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT to_regclass('lucid_auth_organizations')::TEXT"
        )
        .fetch_one(pool)
        .await?,
        None
    );
    Ok(())
}

pub(crate) async fn assert_persistence(
    service: &Arc<AuthService>,
    store: &Arc<PostgresStore>,
    actor: &SessionWithUser,
) -> Result<(), Box<dyn std::error::Error>> {
    let created = service
        .create_organization(
            actor,
            NewOrganization {
                name: "PostgreSQL Organization".into(),
                slug: "postgresql-organization".into(),
                logo: None,
                metadata: Some(json!({ "adapter": "postgres" })),
                keep_current_active_organization: false,
            },
        )
        .await?;
    assert_eq!(store.list_members(created.organization.id).await?.len(), 1);
    assert_eq!(store.list_teams(created.organization.id).await?.len(), 1);

    let team = service
        .create_organization_team(actor, Some(created.organization.id), "Operations".into())
        .await?;
    let role = service
        .create_organization_role(
            actor,
            Some(created.organization.id),
            "auditor".into(),
            permissions(&[("ac", &["read"])]),
        )
        .await?;
    assert_eq!(role.role, "auditor");

    assert_invitation_is_atomic(service, store, actor, created.organization.id, team.id).await?;
    Ok(())
}

async fn assert_invitation_is_atomic(
    service: &Arc<AuthService>,
    store: &Arc<PostgresStore>,
    actor: &SessionWithUser,
    organization_id: uuid::Uuid,
    team_id: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let invitee = service
        .provision_password_user(lucid_auth::NewPasswordUser {
            username: "postgres_org_invitee".into(),
            name: "PostgreSQL Organization Invitee".into(),
            email: Some("postgres-org-invitee@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "member".into(),
        })
        .await?;
    let invitation = service
        .invite_organization_member(
            actor,
            NewOrganizationInvitation {
                email: invitee.email.clone(),
                role: "member".into(),
                organization_id: Some(organization_id),
                team_ids: vec![team_id],
                resend: false,
            },
        )
        .await?;
    let (left, right) = tokio::join!(
        store.accept_invitation(invitation.id, invitee.id, chrono::Utc::now(), 100),
        store.accept_invitation(invitation.id, invitee.id, chrono::Utc::now(), 100),
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == OrganizationInvitationWriteOutcome::Written)
            .count(),
        1
    );
    assert!(
        store
            .find_member(organization_id, invitee.id)
            .await?
            .is_some()
    );
    assert!(
        store
            .list_team_members(team_id)
            .await?
            .iter()
            .any(|member| member.user_id == invitee.id)
    );
    Ok(())
}

fn permissions(entries: &[(&str, &[&str])]) -> OrganizationPermissions {
    entries
        .iter()
        .map(|(resource, actions)| {
            (
                (*resource).to_owned(),
                actions.iter().map(|action| (*action).to_owned()).collect(),
            )
        })
        .collect::<BTreeMap<_, _>>()
}
