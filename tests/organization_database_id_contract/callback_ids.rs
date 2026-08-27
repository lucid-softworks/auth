use super::*;

pub(super) async fn run() {
    let ledger = Arc::new(IdLedger::default());
    let organizations = Arc::new(MemoryOrganizationStore::default());
    let service = service(
        DatabaseIdGeneration::Callback(ledger.clone()),
        organizations.clone(),
        None,
    );
    let owner = persisted_session(&service, "callback_owner", "owner@example.com").await;
    let invitee = persisted_session(&service, "callback_invitee", "invitee@example.com").await;
    ledger.clear();

    let (created, team, role) =
        create_org_role_with_conflicts(&service, &organizations, &owner, &ledger).await;
    let (invitation, accepted) = invite_accept_with_conflicts(
        &service,
        &owner,
        &invitee,
        &created.organization.id,
        &team.id,
        &ledger,
    )
    .await;

    assert_eq!(created.organization.id, "opaque::organization::1::?/+");
    assert_eq!(created.member.id, "opaque::member::2::?/+");
    assert_eq!(created.member.organization_id, created.organization.id);
    assert_eq!(team.id, "opaque::team::3::?/+");
    assert_eq!(team.organization_id, created.organization.id);
    assert_eq!(role.id, "opaque::organizationRole::5::?/+");
    assert_eq!(role.organization_id, created.organization.id);
    assert_eq!(invitation.id, "opaque::invitation::6::?/+");
    assert_eq!(invitation.organization_id, created.organization.id);
    assert_eq!(accepted.member.id, "opaque::member::7::?/+");
    assert_eq!(accepted.member.organization_id, created.organization.id);
    let team_members = organizations.list_team_members(&team.id).await.unwrap();
    assert_eq!(team_members[0].id, "opaque::teamMember::4::?/+");
    assert_eq!(team_members[0].team_id, team.id);
    assert_eq!(team_members[1].id, "opaque::teamMember::8::?/+");
    assert_eq!(team_members[1].team_id, team.id);
    assert_eq!(
        ledger.calls(),
        [
            ("organization".into(), DatabaseIdGenerationSize::Omitted),
            ("member".into(), DatabaseIdGenerationSize::Omitted),
            ("team".into(), DatabaseIdGenerationSize::Omitted),
            ("teamMember".into(), DatabaseIdGenerationSize::Omitted),
            ("organizationRole".into(), DatabaseIdGenerationSize::Omitted,),
            ("invitation".into(), DatabaseIdGenerationSize::Omitted),
            ("member".into(), DatabaseIdGenerationSize::Omitted),
            ("teamMember".into(), DatabaseIdGenerationSize::Omitted),
        ]
    );
}

async fn create_org_role_with_conflicts(
    service: &AuthService,
    organizations: &MemoryOrganizationStore,
    owner: &SessionWithUser,
    ledger: &IdLedger,
) -> (
    lucid_auth::OrganizationCreation,
    lucid_auth::OrganizationTeam,
    lucid_auth::OrganizationRole,
) {
    let created = create_organization(service, owner, "callback-organization").await;
    let team = organizations
        .list_teams(&created.organization.id)
        .await
        .unwrap()
        .remove(0);
    let before_conflict = ledger.calls();
    assert!(
        service
            .create_organization(owner, organization_input("callback-organization"))
            .await
            .is_err()
    );
    assert!(
        service
            .create_organization_team(
                owner,
                Some(created.organization.id.clone()),
                "ID Organization".into(),
            )
            .await
            .is_err()
    );
    assert_eq!(ledger.calls(), before_conflict);
    let role = service
        .create_organization_role(
            owner,
            Some(created.organization.id.clone()),
            "auditor".into(),
            Default::default(),
        )
        .await
        .unwrap();
    let before_conflict = ledger.calls();
    assert!(
        service
            .create_organization_role(
                owner,
                Some(created.organization.id.clone()),
                "auditor".into(),
                Default::default(),
            )
            .await
            .is_err()
    );
    assert_eq!(ledger.calls(), before_conflict);
    (created, team, role)
}

async fn invite_accept_with_conflicts(
    service: &AuthService,
    owner: &SessionWithUser,
    invitee: &SessionWithUser,
    organization_id: &str,
    team_id: &str,
    ledger: &IdLedger,
) -> (
    lucid_auth::OrganizationInvitation,
    lucid_auth::OrganizationInvitationAcceptance,
) {
    let input = || NewOrganizationInvitation {
        email: invitee.user.email.clone(),
        role: "member".into(),
        organization_id: Some(organization_id.into()),
        team_ids: vec![team_id.into()],
        resend: false,
    };
    let invitation = service
        .invite_organization_member(owner, input())
        .await
        .unwrap();
    let before_conflict = ledger.calls();
    assert!(
        service
            .invite_organization_member(owner, input())
            .await
            .is_err()
    );
    assert_eq!(ledger.calls(), before_conflict);
    let accepted = service
        .accept_organization_invitation(invitee, invitation.id.clone())
        .await
        .unwrap();
    let before_conflict = ledger.calls();
    assert!(
        service
            .accept_organization_invitation(invitee, invitation.id.clone())
            .await
            .is_err()
    );
    assert_eq!(ledger.calls(), before_conflict);
    (invitation, accepted)
}
