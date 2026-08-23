use super::Fixture;
use axum::{Extension, Json};
use lucid_auth::{PluginDescriptor, protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION};
use serde_json::json;

pub(super) async fn compatible_version() -> Json<serde_json::Value> {
    Json(json!({ "betterAuth": COMPATIBLE_BETTER_AUTH_VERSION }))
}

pub(super) async fn plugin_metadata(
    Extension(fixture): Extension<Fixture>,
) -> Json<Vec<PluginDescriptor>> {
    Json(fixture.service.plugin_metadata().to_vec())
}
