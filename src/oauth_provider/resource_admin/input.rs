use serde_json::{Map, Value};

/// Partial update accepted by Better Auth's resource-administration endpoint.
///
/// Nested options distinguish an omitted field from an explicit `null`, which
/// restores inheritance for nullable resource policy columns.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OAuthProviderResourceAdminUpdateInput {
    pub name: Option<String>,
    pub access_token_ttl: Option<Option<u64>>,
    pub refresh_token_ttl: Option<Option<u64>>,
    pub signing_algorithm: Option<Option<String>>,
    pub signing_key_id: Option<Option<String>>,
    pub allowed_scopes: Option<Option<Vec<String>>>,
    pub custom_claims: Option<Option<Map<String, Value>>>,
    pub dpop_bound_access_tokens_required: Option<bool>,
    pub disabled: Option<bool>,
    pub metadata: Option<Option<Map<String, Value>>>,
}

impl OAuthProviderResourceAdminUpdateInput {
    pub(super) fn apply_to(self, resource: &mut super::OAuthProviderResource) {
        if let Some(value) = self.name {
            resource.name = value;
        }
        apply_nullable(
            &mut resource.access_token_ttl,
            self.access_token_ttl,
            |value| value as i64,
        );
        apply_nullable(
            &mut resource.refresh_token_ttl,
            self.refresh_token_ttl,
            |value| value as i64,
        );
        apply_nullable_identity(&mut resource.signing_algorithm, self.signing_algorithm);
        apply_nullable_identity(&mut resource.signing_key_id, self.signing_key_id);
        apply_nullable_identity(&mut resource.allowed_scopes, self.allowed_scopes);
        apply_nullable(
            &mut resource.custom_claims,
            self.custom_claims,
            Value::Object,
        );
        if let Some(value) = self.dpop_bound_access_tokens_required {
            resource.dpop_bound_access_tokens_required = value;
        }
        if let Some(value) = self.disabled {
            resource.disabled = value;
        }
        apply_nullable(&mut resource.metadata, self.metadata, Value::Object);
    }
}

fn apply_nullable<T, U>(target: &mut Option<U>, update: Option<Option<T>>, map: impl Fn(T) -> U) {
    if let Some(value) = update {
        *target = value.map(map);
    }
}

fn apply_nullable_identity<T>(target: &mut Option<T>, update: Option<Option<T>>) {
    if let Some(value) = update {
        *target = value;
    }
}
