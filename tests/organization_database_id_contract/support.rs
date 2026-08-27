use chrono::{Duration, Utc};
use lucid_auth::{AuthService, AuthSession, AuthUser, NewPasswordUser, SessionWithUser};

pub(super) async fn persisted_session(
    service: &AuthService,
    username: &str,
    email: &str,
) -> SessionWithUser {
    service
        .provision_password_user(NewPasswordUser {
            username: username.into(),
            name: username.into(),
            email: Some(email.into()),
            password: "correct horse battery staple".into(),
            role: "user".into(),
        })
        .await
        .unwrap();
    service
        .sign_in_username(username, "correct horse battery staple".into(), None, None)
        .await
        .unwrap()
        .session
}

pub(super) fn session(id: &str, email: &str) -> SessionWithUser {
    let now = Utc::now();
    SessionWithUser {
        session: AuthSession {
            id: format!("session::{id}"),
            user_id: id.into(),
            token: format!("token::{id}"),
            actor_user_id: None,
            authentication_method: None,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: None,
            additional_fields: Default::default(),
        },
        user: AuthUser {
            id: id.into(),
            username: None,
            display_username: None,
            name: id.into(),
            email: email.into(),
            email_verified: true,
            image: None,
            additional_fields: Default::default(),
            role: "user".into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        },
    }
}
