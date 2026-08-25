use super::{TestOrganizationOverrides, TestUserOverrides};
use crate::{AuthUser, Organization};
use chrono::Utc;
use rand::RngExt;
use regex::Regex;
use std::sync::LazyLock;
use uuid::Uuid;

static WHITESPACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+").expect("static whitespace expression is valid"));

pub(crate) fn user(id: Uuid, default_role: String, overrides: TestUserOverrides) -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: overrides.id.unwrap_or(id),
        username: overrides.username,
        display_username: overrides.display_username,
        name: overrides.name.unwrap_or_else(|| "Test User".into()),
        email: overrides
            .email
            .unwrap_or_else(|| format!("test-{}@example.com", random_string(8))),
        email_verified: overrides.email_verified.unwrap_or(true),
        image: overrides.image.unwrap_or(None),
        additional_fields: overrides.additional_fields,
        role: overrides.role.unwrap_or(default_role),
        is_anonymous: overrides.is_anonymous.unwrap_or(false),
        banned: overrides.banned.unwrap_or(false),
        ban_reason: overrides.ban_reason.unwrap_or(None),
        ban_expires: overrides.ban_expires.unwrap_or(None),
        created_at: overrides.created_at.unwrap_or(now),
        updated_at: overrides.updated_at.unwrap_or(now),
    }
}

pub(crate) fn organization(id: Uuid, overrides: TestOrganizationOverrides) -> Organization {
    let generated_name = overrides
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or("Test Organization")
        .to_owned();
    let generated_slug = format!(
        "{}-{}",
        WHITESPACE.replace_all(&generated_name.to_lowercase(), "-"),
        random_string(4)
    );
    Organization {
        id: overrides.id.unwrap_or(id),
        name: overrides.name.unwrap_or(generated_name),
        slug: overrides.slug.unwrap_or(generated_slug),
        logo: overrides.logo.unwrap_or(None),
        metadata: overrides.metadata.unwrap_or(None),
        created_at: overrides.created_at.unwrap_or_else(Utc::now),
    }
}

fn random_string(length: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
        .collect()
}
