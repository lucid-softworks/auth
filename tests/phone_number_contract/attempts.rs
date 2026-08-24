use super::*;

#[tokio::test]
async fn wrong_codes_exhaust_the_exact_default_attempt_budget() {
    let (service, otp, _) = fixture();
    service
        .send_phone_number_otp("attempt-budget", PhoneNumberRequestContext::default())
        .await
        .unwrap();
    assert_eq!(otp.messages.lock().await.len(), 1);
    for _ in 0..3 {
        assert!(matches!(
            service
                .consume_phone_number_otp("attempt-budget", "wrong")
                .await,
            Err(AuthError::PhoneNumber(PhoneNumberError::InvalidOtp))
        ));
    }
    assert!(matches!(
        service
            .consume_phone_number_otp("attempt-budget", "wrong")
            .await,
        Err(AuthError::PhoneNumber(PhoneNumberError::TooManyAttempts))
    ));
}

#[tokio::test]
async fn unknown_password_reset_is_enumeration_safe_but_stores_the_otp() {
    let (service, _, reset) = fixture();
    service
        .request_phone_number_password_reset("unknown-phone", PhoneNumberRequestContext::default())
        .await
        .unwrap();
    assert!(reset.messages.lock().await.is_empty());
    let result = service
        .reset_phone_number_password(
            "unknown-phone",
            "incorrect",
            "correct horse battery staple".into(),
        )
        .await;
    assert!(matches!(
        result,
        Err(AuthError::PhoneNumber(PhoneNumberError::InvalidOtp))
    ));
}
