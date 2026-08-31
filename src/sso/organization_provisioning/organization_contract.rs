use super::*;
use crate::{
    AuthConfig, MemoryOrganizationStore, MemorySsoStore, MemoryStore, NewSsoProvider,
    OrganizationCreateOutcome, OrganizationDataStore, OrganizationInvitation,
    OrganizationInvitationStatus, OrganizationInvitationStore, OrganizationMember,
    OrganizationMemberStore, OrganizationPlugin, PreparedDatabaseId, SsoOptions, SsoPlugin,
    SsoProviderUpdate, SsoStore,
};
use chrono::{Duration, Utc};
use std::sync::Arc;

#[tokio::test]
async fn verified_domain_assignment_skips_ambiguity_and_pending_invitations() {
    let (service, providers, organizations) = fixture().await;
    let user = user("employee", "employee@staff.example.com");

    service
        .assign_sso_organization_by_domain(&user)
        .await
        .unwrap();
    assert!(organizations.find_member("org-a", &user.id).await.unwrap().is_none());
    assert!(organizations.find_member("org-b", &user.id).await.unwrap().is_none());

    providers
        .update(
            "row-b",
            SsoProviderUpdate {
                domain: Some("other.example".into()),
                ..SsoProviderUpdate::default()
            },
        )
        .await
        .unwrap();
    create_invitation(&organizations, &user.email).await;
    service
        .assign_sso_organization_by_domain(&user)
        .await
        .unwrap();
    assert!(organizations.find_member("org-a", &user.id).await.unwrap().is_none());

    let invitation = organizations
        .list_user_invitations(&user.email)
        .await
        .unwrap()
        .pop()
        .unwrap();
    organizations
        .set_invitation_status(&invitation.id, OrganizationInvitationStatus::Canceled)
        .await
        .unwrap();
    service
        .assign_sso_organization_by_domain(&user)
        .await
        .unwrap();
    let member = organizations
        .find_member("org-a", &user.id)
        .await
        .unwrap()
        .expect("unambiguous verified domain membership");
    assert_eq!(member.role, "member");
}

async fn fixture() -> (
    crate::AuthService,
    Arc<MemorySsoStore>,
    Arc<MemoryOrganizationStore>,
) {
    let providers = Arc::new(MemorySsoStore::new());
    let organizations = Arc::new(MemoryOrganizationStore::default());
    create_organization(&organizations, "org-a", "owner-a").await;
    create_organization(&organizations, "org-b", "owner-b").await;
    for (row, provider_id, organization_id) in [
        ("row-a", "a-provider", "org-a"),
        ("row-b", "b-provider", "org-b"),
    ] {
        providers
            .create(NewSsoProvider {
                id: row.into(),
                issuer: format!("https://{provider_id}.example"),
                oidc_config: None,
                saml_config: None,
                user_id: "owner".into(),
                provider_id: provider_id.into(),
                organization_id: Some(organization_id.into()),
                domain: "example.com".into(),
                domain_verified: Some(true),
                additional_fields: Map::new(),
            })
            .await
            .unwrap();
    }
    let mut config = AuthConfig::new([71; 32]).unwrap();
    config
        .add_plugin(SsoPlugin::with_store(
            SsoOptions {
                domain_verification: true,
                ..SsoOptions::default()
            },
            providers.clone(),
        ))
        .unwrap();
    config
        .add_plugin(OrganizationPlugin::new(organizations.clone()))
        .unwrap();
    let service = crate::AuthService::new(Arc::new(MemoryStore::default()), config);
    (service, providers, organizations)
}

async fn create_organization(
    store: &MemoryOrganizationStore,
    organization_id: &str,
    owner_id: &str,
) {
    let mut organization = crate::Organization {
        id: String::new(),
        name: organization_id.into(),
        slug: organization_id.into(),
        logo: None,
        metadata: None,
        created_at: Utc::now(),
    };
    let mut owner = OrganizationMember {
        id: String::new(),
        organization_id: String::new(),
        user_id: owner_id.into(),
        role: "owner".into(),
        created_at: Utc::now(),
    };
    let organization_id = organization_id.to_owned();
    let owner_member_id = format!("member-{owner_id}");
    assert_eq!(
        store
            .create_organization(
                &mut organization,
                &move || Ok(id(&organization_id)),
                &mut owner,
                &move || Ok(id(&owner_member_id)),
                None,
                None,
            )
            .await
            .unwrap(),
        OrganizationCreateOutcome::Created
    );
}

async fn create_invitation(store: &MemoryOrganizationStore, email: &str) {
    let mut invitation = OrganizationInvitation {
        id: String::new(),
        organization_id: "org-a".into(),
        email: email.into(),
        role: "member".into(),
        status: OrganizationInvitationStatus::Pending,
        team_id: None,
        inviter_id: "owner-a".into(),
        expires_at: Utc::now() + Duration::hours(1),
        created_at: Utc::now(),
    };
    store
        .create_invitation(
            &mut invitation,
            &|| Ok(id("pending-invitation")),
            100,
            100,
            false,
        )
        .await
        .unwrap();
}

fn id(value: &str) -> PreparedDatabaseId {
    PreparedDatabaseId::Value(crate::DatabaseIdValue::String(value.into()))
}

fn user(id: &str, email: &str) -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: id.into(),
        username: None,
        display_username: None,
        name: id.into(),
        email: email.into(),
        email_verified: true,
        image: None,
        additional_fields: Map::new(),
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}
