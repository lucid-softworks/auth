use super::*;

pub(super) async fn run_memory_strategies() {
    for strategy in [
        DatabaseIdGeneration::Default,
        DatabaseIdGeneration::Uuid,
        DatabaseIdGeneration::Serial,
    ] {
        assert_memory_strategy(strategy).await;
    }
}

async fn assert_memory_strategy(strategy: DatabaseIdGeneration) {
    let organizations = Arc::new(MemoryOrganizationStore::default());
    let service = service(strategy.clone(), organizations.clone(), None);
    let owner = persisted_session(&service, "strategy_owner", "owner@example.com").await;
    let created = create_organization(&service, &owner, "ids").await;
    let team = organizations
        .list_teams(&created.organization.id)
        .await
        .unwrap()
        .remove(0);
    let team_member = organizations
        .list_team_members(&team.id)
        .await
        .unwrap()
        .remove(0);
    let role = service
        .create_organization_role(
            &owner,
            Some(created.organization.id.clone()),
            "auditor".into(),
            Default::default(),
        )
        .await
        .unwrap();
    let invitation = service
        .invite_organization_member(
            &owner,
            NewOrganizationInvitation {
                email: "invited@example.com".into(),
                role: "member".into(),
                organization_id: Some(created.organization.id.clone()),
                team_ids: vec![team.id.clone()],
                resend: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        organizations.find_role(&role.id).await.unwrap(),
        Some(role.clone())
    );
    assert_eq!(
        organizations.find_invitation(&invitation.id).await.unwrap(),
        Some(invitation.clone())
    );
    for id in [
        &created.organization.id,
        &created.member.id,
        &team.id,
        &team_member.id,
        &role.id,
        &invitation.id,
    ] {
        match strategy {
            DatabaseIdGeneration::Default => assert!(is_base62(id, 32)),
            DatabaseIdGeneration::Uuid => assert!(uuid::Uuid::parse_str(id).is_ok()),
            DatabaseIdGeneration::Serial => assert_eq!(id, "1"),
            _ => unreachable!(),
        }
    }
    if matches!(strategy, DatabaseIdGeneration::Serial) {
        organizations
            .delete_organization(&created.organization.id)
            .await
            .unwrap();
        let next =
            create_organization(&service, &session("owner", "owner@example.com"), "ids-2").await;
        assert_eq!(next.organization.id, "2");
        assert_eq!(next.member.id, "2");
    }
}

pub(super) async fn run_deferred_strategies() {
    assert_deferred_strategy(DatabaseIdGeneration::Callback(Arc::new(EmptyIds)), "empty").await;
    assert_deferred_strategy(DatabaseIdGeneration::Database, "deferred").await;
}

async fn assert_deferred_strategy(strategy: DatabaseIdGeneration, label: &str) {
    let organizations = Arc::new(MemoryOrganizationStore::default());
    let service = service(strategy, organizations.clone(), None);
    let error = service
        .create_organization(
            &session(label, &format!("{label}@example.com")),
            organization_input(label),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("did not return an id"));
    assert!(
        organizations
            .list_organizations(label)
            .await
            .unwrap()
            .is_empty()
    );
}
