use super::Fixture;
use axum::{
    Extension, Json,
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use lucid_auth::{Assurance, AuthSession, AuthStore, StoredPasskey};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) async fn create(
    Extension(fixture): Extension<Fixture>,
    Path(assurance): Path<String>,
) -> Response {
    let assurance = match assurance.as_str() {
        "strong" => Assurance::PasswordAndPasskey,
        "pending" => Assurance::PasswordPendingPasskey,
        "password" => Assurance::Password,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let token = Uuid::new_v4().to_string();
    let now = Utc::now();
    ensure_passkey(&fixture, assurance, now).await;
    fixture
        .store
        .create_session(AuthSession {
            id: Uuid::new_v4(),
            user_id: fixture.owner_id,
            token_hash: hex::encode(Sha256::digest(token.as_bytes())),
            actor_user_id: None,
            assurance,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: Some("official Better Auth client conformance".into()),
        })
        .await
        .expect("persist fixture session");
    session_response(&fixture, &token)
}

async fn ensure_passkey(fixture: &Fixture, assurance: Assurance, now: chrono::DateTime<Utc>) {
    if assurance != Assurance::PasswordAndPasskey
        || !fixture
            .store
            .list_passkeys(fixture.owner_id)
            .await
            .expect("list fixture passkeys")
            .is_empty()
    {
        return;
    }
    fixture
        .store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: fixture.owner_id,
            name: Some("Conformance key".into()),
            credential_id: "conformance-credential".into(),
            public_key: "cHVibGljLWtleQ==".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            aaguid: None,
            credential: json!({}),
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("persist fixture passkey");
}

fn session_response(fixture: &Fixture, token: &str) -> Response {
    let cookie = format!(
        "better-auth.session_token={}; Path=/; HttpOnly; SameSite=Lax",
        fixture.service.signed_cookie_value(token)
    );
    let mut response = Json(json!({ "status": true })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("fixture cookie header"),
    );
    response
}
