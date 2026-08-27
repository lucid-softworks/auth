use super::*;

pub(super) async fn run() {
    let ledger = Arc::new(IdLedger::default());
    let organizations = Arc::new(MemoryOrganizationStore::default());
    let service = service(
        DatabaseIdGeneration::Callback(ledger.clone()),
        organizations.clone(),
        Some(Arc::new(ForcedOrganizationIds)),
    );
    let created =
        create_organization(&service, &session("owner", "owner@example.com"), "forced").await;
    let team = organizations
        .list_teams(&created.organization.id)
        .await
        .unwrap()
        .remove(0);

    assert_eq!(created.organization.id, "forced::organization::?/+");
    assert_eq!(team.id, "forced::team::?/+");
    assert_eq!(
        ledger.calls(),
        [
            ("member".into(), DatabaseIdGenerationSize::Omitted),
            ("teamMember".into(), DatabaseIdGenerationSize::Omitted),
        ]
    );
}
