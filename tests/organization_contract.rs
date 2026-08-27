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
    let owner_id = Uuid::new_v4().to_string();
    let (left, right) = tokio::join!(
        create_fixture(store.clone(), owner_id.clone(), "atomic-organization"),
        create_fixture(store.clone(), owner_id.clone(), "atomic-organization"),
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
        .find_member(&organization.id, &owner_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store.remove_member(&owner.id, "owner").await.unwrap(),
        OrganizationMemberWriteOutcome::LastOwner
    );

    let invitee_id = Uuid::new_v4().to_string();
    let mut invitation = invitation(organization.id.clone(), owner_id);
    let invitation_value = invitation.id.clone();
    let invitation_id = || Ok(explicit_id(&invitation_value));
    assert_eq!(
        store
            .create_invitation(&mut invitation, &invitation_id, 100, 100, false)
            .await
            .unwrap(),
        OrganizationInvitationWriteOutcome::Written
    );
    let member_id = || Ok(explicit_id("accepted-member"));
    let team_member_id = || Ok(explicit_id("accepted-team-member"));
    let (left, right) = tokio::join!(
        store.accept_invitation(
            &invitation.id,
            &invitee_id,
            Utc::now(),
            100,
            &member_id,
            &team_member_id,
        ),
        store.accept_invitation(
            &invitation.id,
            &invitee_id,
            Utc::now(),
            100,
            &member_id,
            &team_member_id,
        ),
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
            .find_member(&organization.id, &invitee_id)
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
    owner_id: String,
    slug: &str,
) -> Result<OrganizationCreateOutcome, lucid_auth::AuthError> {
    let now = Utc::now();
    let organization_id = Uuid::new_v4().to_string();
    let mut organization = Organization {
        id: organization_id.clone(),
        name: "Atomic Organization".into(),
        slug: slug.into(),
        logo: None,
        metadata: None,
        created_at: now,
    };
    let mut owner = OrganizationMember {
        id: Uuid::new_v4().to_string(),
        organization_id,
        user_id: owner_id,
        role: "owner".into(),
        created_at: now,
    };
    let organization_value = organization.id.clone();
    let owner_value = owner.id.clone();
    let organization_id = || Ok(explicit_id(&organization_value));
    let owner_id = || Ok(explicit_id(&owner_value));
    store
        .create_organization(
            &mut organization,
            &organization_id,
            &mut owner,
            &owner_id,
            None,
            Some(1),
        )
        .await
}

fn explicit_id(value: &str) -> lucid_auth::PreparedDatabaseId {
    lucid_auth::PreparedDatabaseId::Value(lucid_auth::DatabaseIdValue::String(value.into()))
}

fn invitation(organization_id: String, inviter_id: String) -> OrganizationInvitation {
    let now = Utc::now();
    OrganizationInvitation {
        id: Uuid::new_v4().to_string(),
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
