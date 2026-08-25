use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    HaveIBeenPwnedOptions, HaveIBeenPwnedPlugin, PasswordBreachCheckError, PasswordBreachChecker,
};
use serde_json::Value;
use tower::ServiceExt;

struct RejectCompromised;

#[async_trait]
impl PasswordBreachChecker for RejectCompromised {
    async fn is_compromised(&self, password: &str) -> Result<bool, PasswordBreachCheckError> {
        Ok(password == "compromised password")
    }
}

#[tokio::test]
async fn failure_happens_after_phone_reset_otp_consumption() {
    let (service, reset) = service_with_hibp();
    let phone_number = "hibp-reset-phone";
    service
        .sign_up_email(
            EmailSignUpInput {
                name: "Phone reset user".into(),
                email: "phone-reset@example.com".into(),
                password: "correct horse battery staple".into(),
                image: None,
                callback_url: None,
                remember_me: None,
                username: None,
                display_username: None,
                additional_fields: Map::from_iter([("phoneNumber".into(), json!(phone_number))]),
            },
            None,
            None,
        )
        .await
        .unwrap();
    service
        .request_phone_number_password_reset(phone_number, PhoneNumberRequestContext::default())
        .await
        .unwrap();
    let otp = reset.messages.lock().await[0].code.clone();
    assert_hibp_rejection(&service, phone_number, &otp).await;
    assert_consumed_and_unchanged(&service, phone_number, &otp).await;
}

fn service_with_hibp() -> (Arc<AuthService>, Arc<Sender>) {
    let store = Arc::new(MemoryStore::default());
    let reset = Arc::new(Sender::default());
    let mut config = AuthConfig::new([132_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.trust_origin("http://localhost").unwrap();
    config
        .add_plugin(PhoneNumberPlugin::new(
            store.clone(),
            PhoneNumberConfig {
                send_password_reset_otp: Some(reset.clone()),
                ..PhoneNumberConfig::default()
            },
        ))
        .unwrap();
    config
        .add_plugin(HaveIBeenPwnedPlugin::with_checker(
            HaveIBeenPwnedOptions::default(),
            Arc::new(RejectCompromised),
        ))
        .unwrap();
    (
        Arc::new(AuthService::try_new(store, config).unwrap()),
        reset,
    )
}

async fn assert_hibp_rejection(service: &Arc<AuthService>, phone_number: &str, otp: &str) {
    let response = lucid_auth::axum::router(service.clone())
        .oneshot(
            Request::post("/api/auth/phone-number/reset-password")
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "phoneNumber": phone_number,
                        "otp": otp,
                        "newPassword": "compromised password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["code"], "PASSWORD_COMPROMISED");
}

async fn assert_consumed_and_unchanged(service: &AuthService, phone_number: &str, otp: &str) {
    assert!(matches!(
        service
            .reset_phone_number_password(phone_number, otp, "safe replacement password".into())
            .await,
        Err(AuthError::PhoneNumber(PhoneNumberError::OtpNotFound))
    ));
    assert!(
        service
            .sign_in_email(
                "phone-reset@example.com",
                "correct horse battery staple".into(),
                None,
                None,
                None,
                None,
            )
            .await
            .is_ok()
    );
}
