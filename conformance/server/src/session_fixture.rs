use super::Fixture;
use axum::{
    Extension, Json,
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use lucid_auth::{
    AuthSession, AuthStore, AuthenticationMethod, DatabaseCreate, DatabaseIdGeneration,
    DatabaseIdInput, DatabaseIdPlan, SecondaryStorage, StoredPasskey,
};
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
    let session = fixture
        .store
        .create_session(DatabaseCreate::new(
            AuthSession {
                id: String::new(),
                user_id: fixture.owner_id.clone(),
                token: token.clone(),
                actor_user_id: None,
                authentication_method: Some(authentication_method),
                expires_at: now + Duration::hours(1),
                created_at: now,
                updated_at: now,
                ip_address: None,
                user_agent: Some("official Better Auth client conformance".into()),
                additional_fields: serde_json::Map::new(),
            },
            DatabaseIdPlan::new(
                DatabaseIdGeneration::Default,
                "session",
                DatabaseIdInput::Absent,
                false,
            ),
        ))
        .await
        .expect("persist fixture session");
    persist_secondary_session(&fixture, &session).await;
    session_response(&fixture, &token)
}

async fn persist_secondary_session(fixture: &Fixture, session: &AuthSession) {
    let user = fixture
        .store
        .find_user_by_id(&fixture.owner_id)
        .await
        .expect("load fixture owner")
        .expect("fixture owner exists");
    let ttl = u64::try_from((session.expires_at - Utc::now()).num_seconds())
        .expect("fixture session has a positive TTL");
    fixture
        .secondary
        .set(
            &session.token,
            json!({ "session": session, "user": user }).to_string(),
            Some(ttl),
        )
        .await
        .expect("cache fixture session");
    fixture
        .secondary
        .set(
            &format!("session-id:{}", session.id),
            session.token.clone(),
            Some(ttl),
        )
        .await
        .expect("index fixture session id");
    persist_active_reference(fixture, session, ttl).await;
}

async fn persist_active_reference(fixture: &Fixture, session: &AuthSession, ttl: u64) {
    let key = format!("active-sessions-{}", session.user_id);
    let mut references = match fixture
        .secondary
        .get(&key)
        .await
        .expect("load fixture session references")
    {
        Some(value) => serde_json::from_str::<Vec<serde_json::Value>>(&value)
            .expect("deserialize fixture session references"),
        None => Vec::new(),
    };
    references.retain(|reference| reference["token"] != session.token);
    references.push(json!({
        "token": session.token,
        "expiresAt": session.expires_at.timestamp_millis(),
    }));
    references.sort_by_key(|reference| reference["expiresAt"].as_i64().unwrap_or_default());
    fixture
        .secondary
        .set(
            &key,
            serde_json::to_string(&references).expect("serialize fixture session references"),
            Some(ttl),
        )
        .await
        .expect("cache fixture session references");
}

async fn ensure_passkey(
    fixture: &Fixture,
    authentication_method: AuthenticationMethod,
    now: chrono::DateTime<Utc>,
) {
    if authentication_method != AuthenticationMethod::Passkey
        || !fixture
            .store
            .list_passkeys(&fixture.owner_id)
            .await
            .expect("list fixture passkeys")
            .is_empty()
    {
        return;
    }
    fixture
        .store
        .save_passkey(DatabaseCreate::new(
            StoredPasskey {
                id: String::new(),
                user_id: fixture.owner_id.clone(),
                name: Some("Conformance key".into()),
                credential_id: "conformance-credential".into(),
                public_key: "cHVibGljLWtleQ==".into(),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: None,
                aaguid: None,
                created_at: now,
            },
            DatabaseIdPlan::new(
                DatabaseIdGeneration::Default,
                "passkey",
                DatabaseIdInput::Absent,
                false,
            ),
        ))
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
