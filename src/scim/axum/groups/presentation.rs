use crate::{
    AuthService,
    scim::{ScimPlugin, ScimStoreError, model::ScimMeta, store::StoredScimGroup},
};
use serde_json::Value;

pub(super) async fn present(
    service: &AuthService,
    plugin: &ScimPlugin,
    stored: &StoredScimGroup,
) -> Result<Value, ScimStoreError> {
    let users = plugin.store.list_users(&stored.connection_id).await?;
    Ok(present_with_users(service, stored, &users))
}

pub(super) fn present_with_users(
    service: &AuthService,
    stored: &StoredScimGroup,
    users: &[crate::scim::store::StoredScimUser],
) -> Value {
    let mut resource = stored.resource.clone();
    let id = resource.id.clone().unwrap_or_default();
    let base = service.scim_base_url();
    for member in &mut resource.members {
        member.reference = Some(format!("{base}/scim/v2/Users/{}", member.value));
        member.display = users
            .iter()
            .find(|user| user.resource.id.as_deref() == Some(&member.value))
            .and_then(|user| user.resource.display_name.clone());
        member.kind = Some("User".into());
    }
    resource.meta = Some(ScimMeta {
        resource_type: "Group".into(),
        created: Some(stored.created_at),
        last_modified: Some(stored.updated_at),
        location: format!("{base}/scim/v2/Groups/{id}"),
    });
    serde_json::to_value(resource).unwrap_or(Value::Null)
}
