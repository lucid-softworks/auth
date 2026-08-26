use axum::{
    Extension,
    http::{HeaderMap, HeaderValue, header},
    response::Response,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

use crate::oauth_provider::{
    OAuthProviderConfig, OAuthProviderConsent, OAuthProviderStore, OAuthStoredTokenType,
    authorization::{OAuthAuthorizationCodePayload, OAuthAuthorizationQuery},
    crypto::{random_alphanumeric, store_token},
};
use crate::{
    AuthError, AuthService, OAuthProviderError, VerificationValue,
    axum::http::current_session_cache_first,
};

use super::helpers::{
    callback_context, redirect, split_scopes, storage_error, verified_signed_query,
};
use super::{claims, prompt, redirect_error, validation::authorize_validated};
use crate::oauth_provider::axum::{
    body::JsonOnly, metadata::provider_issuer, response::oauth_error,
};

#[derive(Deserialize)]
pub(super) struct ConsentInput {
    accept: bool,
    scope: Option<String>,
    claims: Option<Value>,
    oauth_query: Option<String>,
}

pub(super) async fn consent(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    mut headers: HeaderMap,
    JsonOnly(input): JsonOnly<ConsentInput>,
) -> Response {
    let Some(session) = current_session_cache_first(&service, &headers).await else {
        return crate::axum::http::auth_error(AuthError::Unauthorized);
    };
    let Some(raw_query) = input.oauth_query.as_deref() else {
        return oauth_error(&OAuthProviderError::InvalidRequest(
            "oauth_query is required".into(),
        ));
    };
    let verified = match verified_signed_query(&service, raw_query) {
        Ok(query) => query,
        Err(error) => return oauth_error(&error),
    };
    let mut query = verified.query;
    if query.client_id.as_deref().is_none() {
        return oauth_error(&OAuthProviderError::InvalidRequest(
            "client_id is required".into(),
        ));
    }
    let selection = match validate_consent_selection(&config, &query, &input) {
        Ok(selection) => selection,
        Err(error) => return oauth_error(&error),
    };
    if !input.accept {
        force_json_redirects(&mut headers);
        return match redirect_error(
            &service,
            &config,
            store.as_ref(),
            &headers,
            &query,
            "access_denied",
            "User denied access",
        )
        .await
        {
            Ok(response) => response,
            Err(error) => oauth_error(&error),
        };
    }
    prompt::satisfy_fresh_authentication(
        &mut query,
        session.session.created_at.timestamp_millis(),
        verified.issued_at_ms,
    );
    force_json_redirects(&mut headers);
    complete_consent(
        &service,
        &config,
        store.as_ref(),
        &headers,
        session,
        query,
        selection,
    )
    .await
}

struct ConsentSelection {
    scopes: Vec<String>,
    userinfo_claims: Vec<String>,
    claims_were_selected: bool,
}

fn validate_consent_selection(
    config: &OAuthProviderConfig,
    query: &OAuthAuthorizationQuery,
    input: &ConsentInput,
) -> Result<ConsentSelection, OAuthProviderError> {
    let original_scopes = query.scope.as_deref().map(split_scopes).unwrap_or_default();
    let scopes = input.scope.as_deref().map_or_else(
        || original_scopes.clone(),
        |scope| scope.split(' ').map(str::to_owned).collect(),
    );
    if !scopes.iter().all(|scope| original_scopes.contains(scope)) {
        return Err(OAuthProviderError::InvalidRequest(
            "Scope not originally requested".into(),
        ));
    }
    let original_claims = claims::requested_userinfo_claims(config, query.claims.as_ref());
    let userinfo_claims = match input.claims.as_ref() {
        Some(accepted) => {
            if !claims::is_valid_request(accepted) {
                return Err(OAuthProviderError::InvalidRequest(
                    "claims must be a valid Claims request object".into(),
                ));
            }
            let accepted = claims::requested_userinfo_claims(config, Some(accepted));
            if !accepted.iter().all(|claim| original_claims.contains(claim)) {
                return Err(OAuthProviderError::InvalidRequest(
                    "Claim not originally requested".into(),
                ));
            }
            accepted
        }
        None => original_claims,
    };
    Ok(ConsentSelection {
        scopes,
        userinfo_claims,
        claims_were_selected: input.claims.is_some(),
    })
}

async fn complete_consent(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    session: crate::SessionWithUser,
    mut query: OAuthAuthorizationQuery,
    selection: ConsentSelection,
) -> Response {
    let reference_id = match consent_reference(config, headers, &session, &selection.scopes).await {
        Ok(value) => value,
        Err(error) => return crate::axum::http::auth_error(error),
    };
    let existing = match store
        .find_oauth_consent_for_grant(
            query.client_id.as_deref().expect("validated client id"),
            &session.user.id,
            reference_id.as_deref(),
        )
        .await
    {
        Ok(value) => value,
        Err(error) => return crate::axum::http::auth_error(error),
    };
    let now = Utc::now();
    let consent = OAuthProviderConsent {
        id: existing
            .as_ref()
            .map_or_else(uuid::Uuid::new_v4, |value| value.id),
        client_id: query.client_id.clone().expect("validated client id"),
        user_id: Some(session.user.id.clone()),
        reference_id: reference_id.clone(),
        resources: (!query.resource.is_empty()).then_some(query.resource.clone()),
        requested_user_info_claims: Some(selection.userinfo_claims.clone()),
        scopes: selection.scopes.clone(),
        created_at: existing.as_ref().map_or(now, |value| value.created_at),
        updated_at: now,
    };
    if let Err(error) = store.upsert_oauth_consent(consent).await {
        return crate::axum::http::auth_error(error);
    }
    if selection.scopes != query.scope.as_deref().map(split_scopes).unwrap_or_default() {
        query.scope = Some(selection.scopes.join(" "));
    }
    if selection.claims_were_selected {
        query.claims = query
            .claims
            .as_ref()
            .and_then(|claims| claims::filter_userinfo_claims(claims, &selection.userinfo_claims));
    }
    prompt::remove(&mut query, "consent");
    match issue_code(service, config, headers, query, &session, reference_id).await {
        Ok(response) => response,
        Err(error) => oauth_error(&error),
    }
}

async fn consent_reference(
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    session: &crate::SessionWithUser,
    scopes: &[String],
) -> Result<Option<String>, AuthError> {
    match &config.callbacks.consent_reference {
        Some(resolver) => {
            resolver
                .resolve(&callback_context(headers, session, scopes))
                .await
        }
        None => Ok(None),
    }
}

#[derive(Deserialize)]
pub(super) struct ContinueInput {
    oauth_query: Option<String>,
    selected: Option<bool>,
    created: Option<bool>,
    #[serde(rename = "postLogin")]
    post_login: Option<bool>,
}

pub(super) async fn continue_authorization(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    mut headers: HeaderMap,
    JsonOnly(input): JsonOnly<ContinueInput>,
) -> Response {
    let Some(raw_query) = input.oauth_query.as_deref() else {
        return oauth_error(&OAuthProviderError::InvalidRequest(
            "oauth_query is required".into(),
        ));
    };
    let verified = match verified_signed_query(&service, raw_query) {
        Ok(query) => query,
        Err(error) => return oauth_error(&error),
    };
    let mut query = verified.query;
    let stages = if input.selected == Some(true) {
        prompt::remove(&mut query, "select_account");
        super::stages::AuthorizationStageState {
            selected: true,
            ..Default::default()
        }
    } else if input.created == Some(true) {
        prompt::remove(&mut query, "create");
        super::stages::AuthorizationStageState {
            created: true,
            ..Default::default()
        }
    } else if input.post_login == Some(true) {
        super::stages::AuthorizationStageState {
            post_login: true,
            ..Default::default()
        }
    } else {
        return oauth_error(&OAuthProviderError::InvalidRequest(
            "Missing parameters".into(),
        ));
    };
    if let Some(session) = current_session_cache_first(&service, &headers).await {
        prompt::satisfy_fresh_authentication(
            &mut query,
            session.session.created_at.timestamp_millis(),
            verified.issued_at_ms,
        );
    }
    force_json_redirects(&mut headers);
    match authorize_validated(&service, &config, store.as_ref(), &headers, query, stages).await {
        Ok(response) => response,
        Err(error) => oauth_error(&error),
    }
}

pub(super) async fn issue_code(
    service: &AuthService,
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    query: OAuthAuthorizationQuery,
    session: &crate::SessionWithUser,
    reference_id: Option<String>,
) -> Result<Response, OAuthProviderError> {
    let code = random_alphanumeric(32);
    let stored_code = store_token(config, &code, OAuthStoredTokenType::AuthorizationCode)
        .await
        .map_err(storage_error)?;
    let now = Utc::now();
    let payload = OAuthAuthorizationCodePayload {
        kind: "authorization_code".into(),
        query: query.clone(),
        session_id: session.session.id.clone(),
        user_id: session.user.id.clone(),
        reference_id,
        auth_time: Some(session.session.created_at.timestamp_millis()),
        resource: query.resource.clone(),
    };
    service
        .create_verification_value(VerificationValue::new(
            stored_code,
            serde_json::to_string(&payload)
                .map_err(|error| OAuthProviderError::ServerError(error.to_string()))?,
            now + Duration::seconds(config.code_expires_in as i64),
        ))
        .await
        .map_err(storage_error)?;
    let redirect_uri = query
        .redirect_uri
        .as_deref()
        .ok_or_else(|| OAuthProviderError::InvalidRequest("redirect_uri is required".into()))?;
    let mut location = url::Url::parse(redirect_uri)
        .map_err(|_| OAuthProviderError::InvalidRequest("invalid redirect uri".into()))?;
    location.query_pairs_mut().append_pair("code", &code);
    if let Some(state) = &query.state {
        location.query_pairs_mut().append_pair("state", state);
    }
    location
        .query_pairs_mut()
        .append_pair("iss", &provider_issuer(service, headers, config));
    Ok(redirect(headers, location.as_str()))
}

fn force_json_redirects(headers: &mut HeaderMap) {
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
}
