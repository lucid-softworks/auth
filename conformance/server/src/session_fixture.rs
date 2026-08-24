use super::Fixture;
use axum::{
    Extension, Json,
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use lucid_auth::{AuthSession, AuthStore, AuthenticationMethod, StoredPasskey};
use serde_json::json;
use uuid::Uuid;

pub(crate) async fn create(
    Extension(fixture): Extension<Fixture>,
    Path(authentication_method): Path<String>,
) -> Response {
    let authentication_method = match authentication_method.as_str() {
        "strong" => AuthenticationMethod::Passkey,
        "password" => AuthenticationMethod::Password,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let token = Uuid::new_v4().to_string();
    let now = Utc::now();
    ensure_passkey(&fixture, authentication_method, now).await;
    fixture
        .store
        .create_session(AuthSession {
            id: Uuid::new_v4(),
            user_id: fixture.owner_id,
            token: token.clone(),
            actor_user_id: None,
            authentication_method,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: Some("official Better Auth client conformance".into()),
            additional_fields: serde_json::Map::new(),
        })
        .await
        .expect("persist fixture session");
    session_response(&fixture, &token)
}

async fn ensure_passkey(
    fixture: &Fixture,
    authentication_method: AuthenticationMethod,
    now: chrono::DateTime<Utc>,
) {
    if authentication_method != AuthenticationMethod::Passkey
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
