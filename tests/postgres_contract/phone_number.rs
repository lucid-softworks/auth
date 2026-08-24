use async_trait::async_trait;
use chrono::Utc;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthStore, AuthUser, PhoneNumberConfig, PhoneNumberMessage,
    PhoneNumberOtpSender, PhoneNumberPlugin, PhoneNumberRequestContext, PhoneNumberSignInInput,
    PhoneNumberSignUpConfig, PhoneNumberStore, PhoneNumberTemporaryEmail, PhoneNumberVerifyInput,
    PhoneNumberWriteOutcome, postgres::PostgresStore,
};
use serde_json::{Map, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Default)]
struct Sender {
    messages: Mutex<Vec<PhoneNumberMessage>>,
}

#[async_trait]
impl PhoneNumberOtpSender for Sender {
    async fn send(
        &self,
        message: PhoneNumberMessage,
        _context: PhoneNumberRequestContext,
    ) -> Result<(), AuthError> {
        self.messages.lock().await.push(message);
        Ok(())
    }
}

struct TemporaryEmail;

#[async_trait]
impl PhoneNumberTemporaryEmail for TemporaryEmail {
    async fn generate(&self, phone_number: &str) -> Result<String, AuthError> {
        Ok(format!("{phone_number}@postgres-phone.test"))
    }
}

pub(super) struct Fixture {
    otp: Arc<Sender>,
    reset: Arc<Sender>,
}

pub(super) fn register(
    config: &mut AuthConfig,
    store: &Arc<PostgresStore>,
) -> Result<Fixture, AuthError> {
    let otp = Arc::new(Sender::default());
    let reset = Arc::new(Sender::default());
    config.add_plugin(PhoneNumberPlugin::new(
        store.clone(),
        PhoneNumberConfig {
            send_otp: Some(otp.clone()),
            send_password_reset_otp: Some(reset.clone()),
            sign_up_on_verification: Some(PhoneNumberSignUpConfig {
                temporary_email: Arc::new(TemporaryEmail),
                temporary_name: None,
            }),
            ..PhoneNumberConfig::default()
        },
    ))?;
    Ok(Fixture { otp, reset })
}

pub(super) async fn assert_atomic_and_persistent(
    service: &Arc<AuthService>,
    store: &Arc<PostgresStore>,
    pool: &sqlx::PgPool,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_plugin_migration_applied(pool).await?;
    assert_otp_redemption_is_atomic(service, pool, fixture).await?;
    assert_phone_number_uniqueness_is_atomic(store, pool).await?;
    assert_password_reset_persists(service, store, fixture).await?;
    Ok(())
}

async fn assert_plugin_migration_applied(
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('lucid_auth_users_phone_number_unique_idx') IS NOT NULL",
        )
        .fetch_one(pool)
        .await?
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_plugin_migrations \
             WHERE plugin_id = 'phone-number' \
               AND migration_id = 'better-auth-phone-number-schema'",
        )
        .fetch_one(pool)
        .await?,
        1
    );
    Ok(())
}

async fn assert_otp_redemption_is_atomic(
    service: &Arc<AuthService>,
    pool: &sqlx::PgPool,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let phone_number = "postgres-atomic-otp";
    service
        .send_phone_number_otp(phone_number, PhoneNumberRequestContext::default())
        .await?;
    let code = last_code(&fixture.otp, phone_number).await;
    let (left, right) = tokio::join!(
        service.verify_phone_number(None, verify_input(phone_number, &code)),
        service.verify_phone_number(None, verify_input(phone_number, &code)),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_users \
             WHERE additional_fields ->> 'phoneNumber' = $1",
        )
        .bind(phone_number)
        .fetch_one(pool)
        .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_verifications \
             WHERE purpose = 'phone-number' AND identifier = $1",
        )
        .bind(phone_number)
        .fetch_one(pool)
        .await?,
        0
    );
    Ok(())
}

async fn assert_phone_number_uniqueness_is_atomic(
    store: &Arc<PostgresStore>,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let phone_number = "postgres-unique-phone";
    let left = phone_user("postgres-phone-left@example.com", phone_number);
    let right = phone_user("postgres-phone-right@example.com", phone_number);
    let (left, right) = tokio::join!(
        store.create_phone_number_user(left),
        store.create_phone_number_user(right),
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PhoneNumberWriteOutcome::Written(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PhoneNumberWriteOutcome::AlreadyExists))
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_users \
             WHERE additional_fields ->> 'phoneNumber' = $1",
        )
        .bind(phone_number)
        .fetch_one(pool)
        .await?,
        1
    );
    Ok(())
}

async fn assert_password_reset_persists(
    service: &AuthService,
    store: &PostgresStore,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let phone_number = "postgres-atomic-otp";
    service
        .request_phone_number_password_reset(phone_number, PhoneNumberRequestContext::default())
        .await?;
    let code = last_code(&fixture.reset, phone_number).await;
    service
        .reset_phone_number_password(phone_number, &code, "postgres phone password".into())
        .await?;
    let signed_in = service
        .sign_in_phone_number(PhoneNumberSignInInput {
            phone_number: phone_number.into(),
            password: "postgres phone password".into(),
            remember_me: Some(false),
            origin: None,
            ip_address: None,
            user_agent: None,
        })
        .await?;
    assert!(
        store
            .find_password_hash(signed_in.session.user.id)
            .await?
            .is_some()
    );
    assert_eq!(
        signed_in.session.user.additional_fields.get("phoneNumber"),
        Some(&json!(phone_number))
    );
    Ok(())
}

async fn last_code(sender: &Sender, phone_number: &str) -> String {
    sender
        .messages
        .lock()
        .await
        .iter()
        .rev()
        .find(|message| message.phone_number == phone_number)
        .expect("phone-number sender should capture a message")
        .code
        .clone()
}

fn verify_input(phone_number: &str, code: &str) -> PhoneNumberVerifyInput {
    PhoneNumberVerifyInput {
        phone_number: phone_number.into(),
        code: code.into(),
        disable_session: false,
        update_phone_number: false,
        additional_fields: Map::new(),
        origin: None,
        ip_address: None,
        user_agent: None,
    }
}

fn phone_user(email: &str, phone_number: &str) -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: Uuid::new_v4(),
        username: None,
        display_username: None,
        name: "PostgreSQL phone user".into(),
        email: email.into(),
        email_verified: false,
        image: None,
        additional_fields: Map::from_iter([
            ("phoneNumber".into(), json!(phone_number)),
            ("phoneNumberVerified".into(), json!(true)),
        ]),
        role: "member".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}
