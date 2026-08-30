use super::RegisterBody;
use crate::{
    AuthService, NewSsoProvider, SsoPlugin, SsoStoreError, VerificationValue,
};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use rand::distr::{Alphanumeric, SampleString as _};
use serde_json::{Value, json};

pub(super) async fn create(
    service: &AuthService,
    plugin: &SsoPlugin,
    user_id: String,
    body: RegisterBody,
    oidc_config: Option<Value>,
    saml_config: Option<Value>,
) -> Response {
    let id = match service.generate_plugin_database_id("ssoProvider") {
        Ok(id) => id,
        Err(error) => return storage(error.to_string()),
    };
    let provider = match plugin
        .store()
        .create(NewSsoProvider {
            id,
            issuer: body.issuer,
            oidc_config,
            saml_config,
            user_id,
            provider_id: body.provider_id,
            organization_id: body.organization_id,
            domain: body.domain,
            domain_verified: plugin.options().domain_verification.then_some(false),
        })
        .await
    {
        Ok(provider) => provider,
        Err(SsoStoreError::DuplicateProviderId) => return duplicate(),
        Err(error) => return super::super::support::storage(error),
    };
    let mut result = serde_json::to_value(&provider)
        .expect("SSO provider response is JSON")
        .as_object()
        .cloned()
        .expect("SSO provider is an object");
    result.remove("id");
    result.insert(
        "redirectURI".into(),
        json!(super::super::support::oidc_redirect_uri(
            service,
            plugin,
            &provider.provider_id
        )),
    );
    if plugin.options().domain_verification {
        let token = Alphanumeric.sample_string(&mut rand::rng(), 24);
        if let Err(error) = save_verification(service, &provider.provider_id, &token).await {
            return storage(error.to_string());
        }
        result.insert("domainVerificationToken".into(), json!(token));
    } else {
        result.remove("domainVerified");
    }
    Json(Value::Object(result)).into_response()
}

async fn save_verification(
    service: &AuthService,
    provider_id: &str,
    token: &str,
) -> Result<(), crate::AuthError> {
    service
        .create_verification_value(VerificationValue::new(
            format!("_better-auth-token-{provider_id}"),
            token,
            Utc::now() + Duration::days(7),
        ))
        .await
}

pub(super) fn duplicate() -> Response {
    super::super::support::error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "UNPROCESSABLE_ENTITY",
        "SSO provider with this providerId already exists",
    )
}

fn storage(message: String) -> Response {
    super::super::support::storage(SsoStoreError::Storage(message))
}
