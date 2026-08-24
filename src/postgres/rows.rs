use crate::{AuthSession, AuthUser, AuthenticationMethod, StoredPasskey};
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
pub(super) struct PasskeyRow {
    id: Uuid,
    user_id: Uuid,
    name: Option<String>,
    credential_id: String,
    public_key: String,
    counter: i64,
    device_type: String,
    backed_up: bool,
    transports: Option<String>,
    aaguid: Option<String>,
    credential: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<PasskeyRow> for StoredPasskey {
    fn from(row: PasskeyRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            credential_id: row.credential_id,
            public_key: row.public_key,
            counter: u32::try_from(row.counter).unwrap_or(u32::MAX),
            device_type: row.device_type,
            backed_up: row.backed_up,
            transports: row.transports,
            aaguid: row.aaguid,
            credential: row.credential,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(FromRow)]
pub(super) struct UserRow {
    pub(super) id: Uuid,
    username: Option<String>,
    display_username: Option<String>,
    name: String,
    email: String,
    email_verified: bool,
    image: Option<String>,
    additional_fields: serde_json::Value,
    role: String,
    is_anonymous: bool,
    banned: bool,
    ban_reason: Option<String>,
    ban_expires: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<UserRow> for AuthUser {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
            username: row.username,
            display_username: row.display_username,
            name: row.name,
            email: row.email,
            email_verified: row.email_verified,
            image: row.image,
            additional_fields: row
                .additional_fields
                .as_object()
                .cloned()
                .unwrap_or_default(),
            role: row.role,
            is_anonymous: row.is_anonymous,
            banned: row.banned,
            ban_reason: row.ban_reason,
            ban_expires: row.ban_expires,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(FromRow)]
pub(super) struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    token: String,
    actor_user_id: Option<Uuid>,
    authentication_method: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    additional_fields: serde_json::Value,
}

impl From<SessionRow> for AuthSession {
    fn from(row: SessionRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            token: row.token,
            actor_user_id: row.actor_user_id,
            authentication_method: AuthenticationMethod::parse(&row.authentication_method),
            expires_at: row.expires_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            additional_fields: row
                .additional_fields
                .as_object()
                .cloned()
                .unwrap_or_default(),
        }
    }
}
