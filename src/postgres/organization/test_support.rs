use crate::{
    AdapterSchemaOptions, AuthConfig, AuthPlugin, AuthSchemaCatalog, DatabaseModelSchema,
    MemoryOrganizationStore, OrganizationPlugin, OrganizationPluginConfig, ResolvedAdapterSchema,
};
use std::sync::Arc;

pub(super) fn physical_schema() -> super::super::physical_schema::PostgresPhysicalSchema {
    let mut auth = AuthConfig::new([41; 32]).unwrap();
    auth.user.model_name = Some("core\"users".into());
    auth.user.fields.email = Some("mail address".into());
    auth.session.model_name = Some("core\"sessions".into());

    let organization = organization_config();
    let plugin =
        OrganizationPlugin::with_config(Arc::new(MemoryOrganizationStore::default()), organization);
    let catalog = Arc::new(AuthSchemaCatalog::build(&auth, plugin.schema()).unwrap());
    let resolved = ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
    super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap()
}

fn organization_config() -> OrganizationPluginConfig {
    let mut config = OrganizationPluginConfig::default();
    config.teams.enabled = true;
    config.dynamic_access_control.enabled = true;
    remap_primary_models(&mut config);
    remap_team_and_role_models(&mut config);
    config
}

fn remap_primary_models(config: &mut OrganizationPluginConfig) {
    remap(
        &mut config.schema.organization,
        "org\"records",
        &[
            ("name", "display name"),
            ("slug", "public\"slug"),
            ("logo", "brand image"),
            ("createdAt", "created time"),
            ("metadata", "private metadata"),
        ],
    );
    remap(
        &mut config.schema.member,
        "org\"members",
        &[
            ("organizationId", "tenant id"),
            ("userId", "person id"),
            ("role", "access roles"),
            ("createdAt", "joined time"),
        ],
    );
    remap(
        &mut config.schema.invitation,
        "org\"invitations",
        &[
            ("organizationId", "tenant id"),
            ("email", "invitee email"),
            ("role", "offered roles"),
            ("teamId", "team ids"),
            ("status", "invite status"),
            ("expiresAt", "expiry time"),
            ("createdAt", "issued time"),
            ("inviterId", "sender id"),
        ],
    );
}

fn remap_team_and_role_models(config: &mut OrganizationPluginConfig) {
    remap(
        &mut config.schema.team,
        "org\"teams",
        &[
            ("name", "team name"),
            ("memberCount", "member count"),
            ("organizationId", "tenant id"),
            ("createdAt", "created time"),
            ("updatedAt", "updated time"),
        ],
    );
    remap(
        &mut config.schema.team_member,
        "org\"team members",
        &[
            ("teamId", "team id"),
            ("userId", "person id"),
            ("membershipKey", "membership key"),
            ("createdAt", "joined time"),
        ],
    );
    remap(
        &mut config.schema.organization_role,
        "org\"roles",
        &[
            ("organizationId", "tenant id"),
            ("role", "role name"),
            ("permission", "permission json"),
            ("createdAt", "created time"),
            ("updatedAt", "updated time"),
        ],
    );
    remap(
        &mut config.schema.session,
        "core\"sessions",
        &[
            ("activeOrganizationId", "active tenant"),
            ("activeTeamId", "active team"),
        ],
    );
}

fn remap(schema: &mut DatabaseModelSchema, model: &str, fields: &[(&str, &str)]) {
    schema.model_name = Some(model.into());
    schema.fields.extend(
        fields
            .iter()
            .map(|(logical, physical)| ((*logical).into(), (*physical).into())),
    );
}
