use super::{callback::CallbackLedger, database::StrategyDatabase};
use lucid_auth::{
    DatabaseIdGenerationSize, NewOrganization, NewOrganizationInvitation, NewPasswordUser,
    OrganizationInvitationStore, OrganizationMemberStore, OrganizationRoleStore,
    OrganizationTeamStore, SessionWithUser,
};
use std::future::Future;

pub(super) struct OrganizationIds {
    pub(super) organization: String,
    pub(super) owner_member: String,
    pub(super) team: String,
    pub(super) owner_team_member: String,
    pub(super) role: String,
    pub(super) invitation: String,
    pub(super) invited_member: String,
    pub(super) invited_team_member: String,
}

pub(super) async fn exercise(
    database: &StrategyDatabase,
    label: &str,
    owner: &SessionWithUser,
    ledger: Option<&CallbackLedger>,
    physical_type: &str,
) -> Result<OrganizationIds, Box<dyn std::error::Error>> {
    let seed = create_organization_role(database, label, owner, ledger).await?;
    let invitation = invite_and_accept(database, label, owner, &seed, ledger).await?;
    let ids = OrganizationIds {
        organization: seed.created.organization.id,
        owner_member: seed.created.member.id,
        team: seed.team.id,
        owner_team_member: seed.owner_team_member.id,
        role: seed.role.id,
        invitation: invitation.invitation.id,
        invited_member: invitation.accepted_member.id,
        invited_team_member: invitation.team_member.id,
    };
    assert_string_references(database, owner, &invitation.invitee, &ids).await?;
    assert_physical_types(database, physical_type).await?;
    if let Some(ledger) = ledger {
        assert_callback_contract(ledger, &ids);
    }
    Ok(ids)
}

struct OrganizationSeed {
    created: lucid_auth::OrganizationCreation,
    team: lucid_auth::OrganizationTeam,
    owner_team_member: lucid_auth::OrganizationTeamMember,
    role: lucid_auth::OrganizationRole,
}

async fn create_organization_role(
    database: &StrategyDatabase,
    label: &str,
    owner: &SessionWithUser,
    ledger: Option<&CallbackLedger>,
) -> Result<OrganizationSeed, Box<dyn std::error::Error>> {
    let created = database
        .service
        .create_organization(owner, organization_input(&format!("strategy-{label}")))
        .await?;
    assert_conflict_is_lazy(ledger, || async {
        database
            .service
            .create_organization(owner, organization_input(&format!("strategy-{label}")))
            .await
            .map(|_| ())
    })
    .await;
    let team = database
        .store
        .list_teams(&created.organization.id)
        .await?
        .remove(0);
    let owner_team_member = database.store.list_team_members(&team.id).await?.remove(0);
    let role = database
        .service
        .create_organization_role(
            owner,
            Some(created.organization.id.clone()),
            "auditor".into(),
            Default::default(),
        )
        .await?;
    assert_conflict_is_lazy(ledger, || async {
        database
            .service
            .create_organization_role(
                owner,
                Some(created.organization.id.clone()),
                "auditor".into(),
                Default::default(),
            )
            .await
            .map(|_| ())
    })
    .await;
    Ok(OrganizationSeed {
        created,
        team,
        owner_team_member,
        role,
    })
}

struct InvitationSeed {
    invitee: SessionWithUser,
    invitation: lucid_auth::OrganizationInvitation,
    accepted_member: lucid_auth::OrganizationMember,
    team_member: lucid_auth::OrganizationTeamMember,
}

async fn invite_and_accept(
    database: &StrategyDatabase,
    label: &str,
    owner: &SessionWithUser,
    seed: &OrganizationSeed,
    ledger: Option<&CallbackLedger>,
) -> Result<InvitationSeed, Box<dyn std::error::Error>> {
    let invitee = persisted_actor(database, &format!("strategy_{label}_invitee")).await?;
    let invitation_input = || NewOrganizationInvitation {
        email: invitee.user.email.clone(),
        role: "member".into(),
        organization_id: Some(seed.created.organization.id.clone()),
        team_ids: vec![seed.team.id.clone()],
        resend: false,
    };
    let invitation = database
        .service
        .invite_organization_member(owner, invitation_input())
        .await?;
    assert_conflict_is_lazy(ledger, || async {
        database
            .service
            .invite_organization_member(owner, invitation_input())
            .await
            .map(|_| ())
    })
    .await;
    let accepted = database
        .service
        .accept_organization_invitation(&invitee, invitation.id.clone())
        .await?;
    assert_conflict_is_lazy(ledger, || async {
        database
            .service
            .accept_organization_invitation(&invitee, invitation.id.clone())
            .await
            .map(|_| ())
    })
    .await;
    let invited_team_member = database
        .store
        .list_team_members(&seed.team.id)
        .await?
        .into_iter()
        .find(|member| member.user_id == invitee.user.id)
        .expect("accepted invitation team member");
    Ok(InvitationSeed {
        invitee,
        invitation,
        accepted_member: accepted.member,
        team_member: invited_team_member,
    })
}

async fn assert_conflict_is_lazy<F, Fut>(ledger: Option<&CallbackLedger>, operation: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), lucid_auth::AuthError>>,
{
    let before = ledger.map(CallbackLedger::snapshot);
    assert!(operation().await.is_err());
    if let (Some(ledger), Some(before)) = (ledger, before) {
        assert_eq!(ledger.snapshot(), before);
    }
}

fn assert_callback_contract(ledger: &CallbackLedger, ids: &OrganizationIds) {
    let models = [
        "organization",
        "member",
        "team",
        "teamMember",
        "organizationRole",
        "invitation",
        "member",
        "teamMember",
    ];
    let calls = ledger
        .snapshot()
        .into_iter()
        .enumerate()
        .filter(|(_, call)| models.contains(&call.model.as_str()))
        .map(|(index, call)| {
            assert_eq!(call.size, DatabaseIdGenerationSize::Omitted);
            (
                call.model.clone(),
                format!("callback/{}/{}", call.model, index + 1),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        calls.iter().map(|call| call.0.as_str()).collect::<Vec<_>>(),
        models
    );
    assert_eq!(
        calls.iter().map(|call| call.1.as_str()).collect::<Vec<_>>(),
        ids.all()
            .into_iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
}

async fn assert_string_references(
    database: &StrategyDatabase,
    owner: &SessionWithUser,
    invitee: &SessionWithUser,
    ids: &OrganizationIds,
) -> Result<(), Box<dyn std::error::Error>> {
    let members = database.store.list_members(&ids.organization).await?;
    assert!(members.iter().any(|member| {
        member.id == ids.owner_member
            && member.organization_id == ids.organization
            && member.user_id == owner.user.id
    }));
    assert!(members.iter().any(|member| {
        member.id == ids.invited_member
            && member.organization_id == ids.organization
            && member.user_id == invitee.user.id
    }));
    let team_members = database.store.list_team_members(&ids.team).await?;
    assert!(team_members.iter().all(|member| member.team_id == ids.team));
    assert!(
        team_members.iter().any(|member| {
            member.id == ids.owner_team_member && member.user_id == owner.user.id
        })
    );
    assert!(team_members.iter().any(|member| {
        member.id == ids.invited_team_member && member.user_id == invitee.user.id
    }));
    assert_eq!(
        database
            .store
            .find_role(&ids.role)
            .await?
            .unwrap()
            .organization_id,
        ids.organization
    );
    let invitation = database
        .store
        .find_invitation(&ids.invitation)
        .await?
        .unwrap();
    assert_eq!(invitation.organization_id, ids.organization);
    assert_eq!(invitation.inviter_id, owner.user.id);
    Ok(())
}

async fn assert_physical_types(
    database: &StrategyDatabase,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for (table, columns) in [
        ("organization", &["id"][..]),
        ("member", &["id", "organizationId", "userId"][..]),
        ("team", &["id", "organizationId"][..]),
        ("teamMember", &["id", "teamId", "userId"][..]),
        ("organizationRole", &["id", "organizationId"][..]),
        ("invitation", &["id", "organizationId", "inviterId"][..]),
    ] {
        for column in columns {
            let data_type = sqlx::query_scalar::<_, String>(
                "SELECT data_type FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
            )
            .bind(table)
            .bind(column)
            .fetch_one(&database.pool)
            .await?;
            assert_eq!(data_type, expected, "unexpected type for {table}.{column}");
        }
    }
    Ok(())
}

pub(super) async fn persisted_actor(
    database: &StrategyDatabase,
    username: &str,
) -> Result<SessionWithUser, Box<dyn std::error::Error>> {
    let username = username.replace('-', "_");
    database
        .service
        .provision_password_user(NewPasswordUser {
            username: username.clone(),
            name: username.clone(),
            email: Some(format!("{username}@example.com")),
            password: "correct horse battery staple".into(),
            role: "user".into(),
        })
        .await?;
    Ok(database
        .service
        .sign_in_username(&username, "correct horse battery staple".into(), None, None)
        .await?
        .session)
}

pub(super) fn organization_input(slug: &str) -> NewOrganization {
    NewOrganization {
        name: "Strategy Organization".into(),
        slug: slug.into(),
        logo: None,
        metadata: None,
        keep_current_active_organization: true,
    }
}

impl OrganizationIds {
    pub(super) fn all(&self) -> [&String; 8] {
        [
            &self.organization,
            &self.owner_member,
            &self.team,
            &self.owner_team_member,
            &self.role,
            &self.invitation,
            &self.invited_member,
            &self.invited_team_member,
        ]
    }
}
