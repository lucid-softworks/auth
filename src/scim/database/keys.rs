use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub(super) fn scoped(parts: &[&str]) -> String {
    let encoded = serde_json::to_vec(parts).expect("SCIM scoped-key parts always serialize");
    URL_SAFE_NO_PAD.encode(Sha256::digest(encoded))
}

pub(super) fn connection(connection_id: &str) -> String {
    scoped(&["scim-connection", connection_id])
}

pub(super) fn connection_user(connection_id: &str, user_id: &str) -> String {
    scoped(&["scim-user", connection_id, user_id])
}

pub(super) fn user_name(connection_id: &str, user_name: &str) -> String {
    scoped(&["scim-user-name", connection_id, &user_name.to_lowercase()])
}

pub(in crate::scim) fn user_external_id(connection_id: &str, external_id: &str) -> String {
    scoped(&["scim-user-external-id", connection_id, external_id])
}

pub(super) fn email_value(email: &str) -> String {
    scoped(&["scim-email-value", &email.trim().to_lowercase()])
}

pub(super) fn group_display_name(connection_id: &str, display_name: &str) -> String {
    scoped(&[
        "scim-group-display-name",
        connection_id,
        &display_name.to_lowercase(),
    ])
}

pub(super) fn group_external_id(connection_id: &str, external_id: &str) -> String {
    scoped(&["scim-group-external-id", connection_id, external_id])
}

pub(super) fn membership(connection_id: &str, group_id: &str, user_id: &str) -> String {
    scoped(&["scim-group-member", connection_id, group_id, user_id])
}

pub(in crate::scim) fn projection_grant(
    connection_id: &str,
    scim_user_id: &str,
    source_kind: &str,
    source_id: &str,
    role: &str,
) -> String {
    scoped(&[
        "scim-projection-grant",
        connection_id,
        scim_user_id,
        source_kind,
        source_id,
        role,
    ])
}
