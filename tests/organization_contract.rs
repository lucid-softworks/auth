use chrono::{Duration, Utc};
use lucid_auth::{
    AuthPlugin, MemoryOrganizationStore, Organization, OrganizationCreateOutcome,
    OrganizationDataStore, OrganizationDynamicAccessControlConfig, OrganizationInvitation,
    OrganizationInvitationStatus, OrganizationInvitationStore, OrganizationInvitationWriteOutcome,
    OrganizationMember, OrganizationMemberStore, OrganizationMemberWriteOutcome,
    OrganizationPlugin, OrganizationPluginConfig, OrganizationTeamsConfig,
};
use std::sync::Arc;
use uuid::Uuid;

#[test]
fn descriptor_exposes_only_enabled_organization_client_methods() {
    let core = OrganizationPlugin::new(Arc::new(MemoryOrganizationStore::default()));
    let core_methods = methods(&core);
    assert!(core_methods.contains(&"organization.create"));
    assert!(!core_methods.contains(&"organization.createTeam"));
    assert!(!core_methods.contains(&"organization.createRole"));

    let complete = OrganizationPlugin::with_config(
        Arc::new(MemoryOrganizationStore::default()),
        OrganizationPluginConfig {
            teams: OrganizationTeamsConfig {
                enabled: true,
                ..OrganizationTeamsConfig::default()
            },
            dynamic_access_control: OrganizationDynamicAccessControlConfig {
                enabled: true,
                ..OrganizationDynamicAccessControlConfig::default()
            },
            ..OrganizationPluginConfig::default()
        },
    );
    let complete_methods = methods(&complete);
    assert_eq!(complete_methods.len(), 36);
    assert!(complete_methods.contains(&"organization.createTeam"));
    assert!(complete_methods.contains(&"organization.createRole"));
}

#[tokio::test]
async fn memory_organization_limits_and_invitation_redemption_are_atomic() {
    let store = Arc::new(MemoryOrganizationStore::default());
    let owner_id = Uuid::new_v4();
    let (left, right) = tokio::join!(
        create_fixture(store.clone(), owner_id, "atomic-organization"),
        create_fixture(store.clone(), owner_id, "atomic-organization"),
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == OrganizationCreateOutcome::Created)
            .count(),
        1
    );
    let organization = store
        .find_organization_by_slug("atomic-organization")
        .await
        .unwrap()
        .unwrap();
    let owner = store
        .find_member(organization.id, owner_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store.remove_member(owner.id, "owner").await.unwrap(),
        OrganizationMemberWriteOutcome::LastOwner
    );

    let invitee_id = Uuid::new_v4();
    let invitation = invitation(organization.id, owner_id);
    assert_eq!(
        store
            .create_invitation(invitation.clone(), 100, 100, false)
            .await
            .unwrap(),
        OrganizationInvitationWriteOutcome::Written
    );
    let (left, right) = tokio::join!(
        store.accept_invitation(invitation.id, invitee_id, Utc::now(), 100),
        store.accept_invitation(invitation.id, invitee_id, Utc::now(), 100),
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == OrganizationInvitationWriteOutcome::Written)
            .count(),
        1
    );
    assert!(
        store
            .find_member(organization.id, invitee_id)
            .await
            .unwrap()
            .is_some()
    );
}

fn methods(plugin: &OrganizationPlugin) -> Vec<&'static str> {
    plugin
        .descriptor()
        .endpoints
        .iter()
        .map(|endpoint| endpoint.client_method)
        .collect()
}

async fn create_fixture(
    store: Arc<MemoryOrganizationStore>,
    owner_id: Uuid,
    slug: &str,
) -> Result<OrganizationCreateOutcome, lucid_auth::AuthError> {
    let now = Utc::now();
    let organization_id = Uuid::new_v4();
    store
        .create_organization(
            Organization {
                id: organization_id,
                name: "Atomic Organization".into(),
                slug: slug.into(),
                logo: None,
                metadata: None,
                created_at: now,
            },
            OrganizationMember {
                id: Uuid::new_v4(),
                organization_id,
                user_id: owner_id,
                role: "owner".into(),
                created_at: now,
            },
            None,
            Some(1),
        )
        .await
}

fn invitation(organization_id: Uuid, inviter_id: Uuid) -> OrganizationInvitation {
    let now = Utc::now();
    OrganizationInvitation {
        id: Uuid::new_v4(),
        organization_id,
        email: "atomic-invitee@example.com".into(),
        role: "member".into(),
        status: OrganizationInvitationStatus::Pending,
        team_id: None,
        inviter_id,
        expires_at: now + Duration::hours(1),
        created_at: now,
    }
}
