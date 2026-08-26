use super::{
    DeviceAuthorizationConfig, DeviceAuthorizationConfigError, DeviceAuthorizationStore,
    DeviceCode, DeviceCodeCreateOutcome, DeviceCodeStatus,
};
use crate::AuthError;
use chrono::{DateTime, Utc};
use rand::RngExt as _;
use url::Url;
use uuid::Uuid;

const DEVICE_CODE_ALPHABET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const MAX_GENERATION_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
    pub user_id: Option<String>,
    pub scope: Option<String>,
    pub resources: Option<Vec<String>>,
    pub oauth_client_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedDeviceAuthorization {
    pub record: DeviceCode,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceAuthorizationGenerationError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Configuration(#[from] DeviceAuthorizationConfigError),
    #[error("Invalid client ID")]
    InvalidClient,
    #[error("Generated {label} code must be at most 191 characters")]
    GeneratedCodeTooLong { label: &'static str },
    #[error("Failed to generate a unique device code")]
    UniqueCodesExhausted,
    #[error("unable to resolve the device verification URI")]
    InvalidVerificationUri,
    #[error("device-code expiry is outside the supported date range")]
    InvalidExpiration,
}

pub async fn generate_device_authorization(
    store: &dyn DeviceAuthorizationStore,
    config: &DeviceAuthorizationConfig,
    base_url: &str,
    request: DeviceAuthorizationRequest,
) -> Result<GeneratedDeviceAuthorization, DeviceAuthorizationGenerationError> {
    generate_device_authorization_at(store, config, base_url, request, Utc::now()).await
}

pub(crate) async fn generate_device_authorization_at(
    store: &dyn DeviceAuthorizationStore,
    config: &DeviceAuthorizationConfig,
    base_url: &str,
    request: DeviceAuthorizationRequest,
    now: DateTime<Utc>,
) -> Result<GeneratedDeviceAuthorization, DeviceAuthorizationGenerationError> {
    config.validate()?;
    if !config.includes_oauth_fields()
        && config
            .validate_client
            .as_ref()
            .is_some_and(|_| !request.client_id.is_empty())
    {
        let valid = config
            .validate_client
            .as_ref()
            .expect("validator presence was checked")
            .validate(&request.client_id)
            .await?;
        if !valid {
            return Err(DeviceAuthorizationGenerationError::InvalidClient);
        }
    }
    if let Some(observer) = &config.on_device_auth_request {
        observer
            .on_device_auth_request(&request.client_id, request.scope.as_deref())
            .await?;
    }

    let expires_ms = config.expires_in_milliseconds()?;
    let interval_ms = config.interval_milliseconds()?;
    let expires_at_ms = (now.timestamp_millis() as f64 + expires_ms).trunc();
    if !(i64::MIN as f64..=i64::MAX as f64).contains(&expires_at_ms) {
        return Err(DeviceAuthorizationGenerationError::InvalidExpiration);
    }
    let expires_at = DateTime::from_timestamp_millis(expires_at_ms as i64)
        .ok_or(DeviceAuthorizationGenerationError::InvalidExpiration)?;

    for _ in 0..MAX_GENERATION_ATTEMPTS {
        let device_code = generated_code(config, CodeKind::Device).await?;
        let user_code = generated_code(config, CodeKind::User).await?;
        let record = DeviceCode {
            id: Uuid::new_v4(),
            device_code,
            user_code,
            user_id: request.user_id.clone(),
            expires_at,
            status: DeviceCodeStatus::Pending,
            last_polled_at: None,
            polling_interval: Some(interval_ms),
            client_id: Some(request.client_id.clone()),
            scope: request.scope.clone(),
            resources: request.resources.clone(),
            oauth_client_id: request.oauth_client_id.clone(),
        };
        match store.create_device_code(record).await? {
            DeviceCodeCreateOutcome::Created(record) => {
                let (verification_uri, verification_uri_complete) = build_verification_uris(
                    config.verification_uri.as_deref(),
                    base_url,
                    &record.user_code,
                )?;
                return Ok(GeneratedDeviceAuthorization {
                    record,
                    verification_uri,
                    verification_uri_complete,
                    expires_in: floor_seconds(expires_ms),
                    interval: floor_seconds(interval_ms),
                });
            }
            DeviceCodeCreateOutcome::UniqueConflict => {}
        }
    }
    Err(DeviceAuthorizationGenerationError::UniqueCodesExhausted)
}

pub async fn find_device_code_by_user_code(
    store: &dyn DeviceAuthorizationStore,
    user_code: &str,
) -> Result<Option<DeviceCode>, AuthError> {
    if let Some(record) = store.find_device_code_by_user_code(user_code).await? {
        return Ok(Some(record));
    }
    let normalized = normalize_user_code(user_code);
    if normalized == user_code || !is_default_user_code(&normalized) {
        return Ok(None);
    }
    store.find_device_code_by_user_code(&normalized).await
}

pub fn build_verification_uris(
    verification_uri: Option<&str>,
    base_url: &str,
    user_code: &str,
) -> Result<(String, String), DeviceAuthorizationGenerationError> {
    let uri = verification_uri.unwrap_or("/device");
    let verification = match Url::parse(uri) {
        Ok(url) => url,
        Err(_) => Url::parse(base_url)
            .and_then(|base| base.join(uri))
            .map_err(|_| DeviceAuthorizationGenerationError::InvalidVerificationUri)?,
    };
    let mut complete = verification.clone();
    let retained = complete
        .query_pairs()
        .filter(|(name, _)| name != "user_code")
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    complete
        .query_pairs_mut()
        .clear()
        .extend_pairs(retained)
        .append_pair("user_code", user_code);
    Ok((verification.into(), complete.into()))
}

fn normalize_user_code(user_code: &str) -> String {
    user_code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_uppercase)
        .collect()
}

fn is_default_user_code(code: &str) -> bool {
    !code.is_empty()
        && code
            .bytes()
            .all(|character| USER_CODE_ALPHABET.contains(&character.to_ascii_uppercase()))
}

#[derive(Clone, Copy)]
enum CodeKind {
    Device,
    User,
}

async fn generated_code(
    config: &DeviceAuthorizationConfig,
    kind: CodeKind,
) -> Result<String, DeviceAuthorizationGenerationError> {
    let (custom, length, label) = match kind {
        CodeKind::Device => (
            config.generate_device_code.as_ref(),
            config.device_code_length,
            "device",
        ),
        CodeKind::User => (
            config.generate_user_code.as_ref(),
            config.user_code_length,
            "user",
        ),
    };
    let code = if let Some(generator) = custom {
        generator.generate().await?
    } else {
        default_code(kind, length)
    };
    if code.chars().count() > super::MAX_GENERATED_CODE_CHARACTERS {
        return Err(DeviceAuthorizationGenerationError::GeneratedCodeTooLong { label });
    }
    Ok(code)
}

fn default_code(kind: CodeKind, length: usize) -> String {
    let mut rng = rand::rng();
    match kind {
        CodeKind::Device => (0..length)
            .map(|_| {
                let index = rng.random_range(0..DEVICE_CODE_ALPHABET.len());
                char::from(DEVICE_CODE_ALPHABET[index])
            })
            .collect(),
        CodeKind::User => (0..length)
            .map(|_| char::from(USER_CODE_ALPHABET[usize::from(rng.random::<u8>() % 32)]))
            .collect(),
    }
}

fn floor_seconds(milliseconds: f64) -> i64 {
    (milliseconds / 1_000.0).floor() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_authorization::MemoryDeviceAuthorizationStore;
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn verification_uri_resolution_matches_javascript_urls() {
        assert_eq!(
            build_verification_uris(
                Some("verify?theme=dark"),
                "https://auth.example.test/api/auth/",
                "AB CD"
            )
            .unwrap(),
            (
                "https://auth.example.test/api/auth/verify?theme=dark".into(),
                "https://auth.example.test/api/auth/verify?theme=dark&user_code=AB+CD".into()
            )
        );
        assert_eq!(
            build_verification_uris(None, "https://auth.example.test/api/auth", "ABCD")
                .unwrap()
                .0,
            "https://auth.example.test/device"
        );
    }

    #[tokio::test]
    async fn custom_codes_accept_empty_and_count_unicode_characters() {
        let store = MemoryDeviceAuthorizationStore::new();
        let config = DeviceAuthorizationConfig {
            generate_device_code: Some(Arc::new(StaticGenerator(String::new()))),
            generate_user_code: Some(Arc::new(StaticGenerator("🦀".repeat(191)))),
            ..DeviceAuthorizationConfig::default()
        };
        let generated = generate_device_authorization_at(
            &store,
            &config,
            "https://auth.example.test",
            request(),
            DateTime::from_timestamp_millis(1_700_000_000_000).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(generated.record.device_code, "");
        assert_eq!(generated.record.user_code.chars().count(), 191);
    }

    #[tokio::test]
    async fn expiry_is_computed_once_with_javascript_time_clip_semantics() {
        let store = MemoryDeviceAuthorizationStore::new();
        let config = DeviceAuthorizationConfig {
            expires_in: "0.0005s".into(),
            interval: "-0.0005s".into(),
            ..DeviceAuthorizationConfig::default()
        };
        let now = DateTime::from_timestamp_millis(1_700_000_000_000).unwrap();
        let generated =
            generate_device_authorization_at(&store, &config, "https://a.test", request(), now)
                .await
                .unwrap();
        assert_eq!(generated.record.expires_at, now);
        assert_eq!(generated.record.polling_interval, Some(-0.5));
        assert_eq!(generated.expires_in, 0);
        assert_eq!(generated.interval, -1);
    }

    #[tokio::test]
    async fn default_generation_uses_exact_alphabets_and_lengths() {
        let store = MemoryDeviceAuthorizationStore::new();
        let generated = generate_device_authorization(
            &store,
            &DeviceAuthorizationConfig::default(),
            "https://auth.example.test",
            request(),
        )
        .await
        .unwrap();
        assert_eq!(generated.record.device_code.len(), 40);
        assert!(
            generated
                .record
                .device_code
                .bytes()
                .all(|byte| DEVICE_CODE_ALPHABET.contains(&byte))
        );
        assert_eq!(generated.record.user_code.len(), 8);
        assert!(
            generated
                .record
                .user_code
                .bytes()
                .all(|byte| USER_CODE_ALPHABET.contains(&byte))
        );
    }

    #[tokio::test]
    async fn uniqueness_conflicts_are_retried_exactly_three_times() {
        let store = MemoryDeviceAuthorizationStore::new();
        let initial = DeviceAuthorizationConfig {
            generate_device_code: Some(Arc::new(StaticGenerator("same".into()))),
            generate_user_code: Some(Arc::new(StaticGenerator("SAME".into()))),
            ..DeviceAuthorizationConfig::default()
        };
        generate_device_authorization(&store, &initial, "https://auth.example", request())
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let config = DeviceAuthorizationConfig {
            generate_device_code: Some(Arc::new(CountingGenerator {
                value: "same",
                calls: calls.clone(),
            })),
            generate_user_code: Some(Arc::new(CountingGenerator {
                value: "SAME",
                calls: calls.clone(),
            })),
            ..DeviceAuthorizationConfig::default()
        };
        assert!(matches!(
            generate_device_authorization(&store, &config, "https://auth.example", request()).await,
            Err(DeviceAuthorizationGenerationError::UniqueCodesExhausted)
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 6);
    }

    struct StaticGenerator(String);

    #[async_trait]
    impl super::super::DeviceCodeGenerator for StaticGenerator {
        async fn generate(&self) -> Result<String, AuthError> {
            Ok(self.0.clone())
        }
    }

    struct CountingGenerator {
        value: &'static str,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl super::super::DeviceCodeGenerator for CountingGenerator {
        async fn generate(&self) -> Result<String, AuthError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.value.into())
        }
    }

    fn request() -> DeviceAuthorizationRequest {
        DeviceAuthorizationRequest {
            client_id: "client".into(),
            ..DeviceAuthorizationRequest::default()
        }
    }
}
