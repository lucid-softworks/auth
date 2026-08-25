use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};

use crate::oauth_provider::{
    OAuthProviderClient, OAuthProviderConfig, OAuthProviderStore,
    authorization::OAuthAuthorizationQuery,
};
use crate::{
    AuthService, OAuthProviderError, SessionWithUser, axum::http::current_session_cache_first,
};

use super::client::resolve_client;
use super::helpers::{callback_context, redirect, signed_query, storage_error};
use super::{claims, constraints, flow::issue_code, redirect_error, syntax};

pub(super) enum Validation<T> {
    Ready(T),
    Respond(Response),
}

struct AuthorizationContext<'a> {
    service: &'a AuthService,
    config: &'a OAuthProviderConfig,
    store: &'a dyn OAuthProviderStore,
    headers: &'a HeaderMap,
}

struct ValidatedAuthorization {
    query: OAuthAuthorizationQuery,
    client: OAuthProviderClient,
    scopes: Vec<String>,
    prompt: Vec<String>,
    stages: super::stages::AuthorizationStageState,
}

struct SessionAuthorization {
    query: OAuthAuthorizationQuery,
    client: OAuthProviderClient,
    scopes: Vec<String>,
    prompt: Vec<String>,
    session: SessionWithUser,
}

pub(super) async fn authorize_validated(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: OAuthAuthorizationQuery,
    stages: super::stages::AuthorizationStageState,
) -> Result<Response, OAuthProviderError> {
    if !config
        .grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let (mut query, prompt) = match syntax::prepare(service, config, store, headers, query).await? {
        Validation::Ready(prepared) => prepared,
        Validation::Respond(response) => return Ok(response),
    };
    let client = match resolve_client(service, config, store, headers, &query).await? {
        Validation::Ready(client) => client,
        Validation::Respond(response) => return Ok(response),
    };
    let scopes =
        match constraints::validate(service, config, store, headers, &mut query, &client).await? {
            Validation::Ready(scopes) => scopes,
            Validation::Respond(response) => return Ok(response),
        };
    continue_with_session(
        AuthorizationContext {
            service,
            config,
            store,
            headers,
        },
        ValidatedAuthorization {
            query,
            client,
            scopes,
            prompt,
            stages,
        },
    )
    .await
}

pub(super) async fn respond<T>(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &OAuthAuthorizationQuery,
    code: &str,
    description: &str,
) -> Result<Validation<T>, OAuthProviderError> {
    super::redirect_error(service, config, store, headers, query, code, description)
        .await
        .map(Validation::Respond)
}

async fn continue_with_session(
    context: AuthorizationContext<'_>,
    mut request: ValidatedAuthorization,
) -> Result<Response, OAuthProviderError> {
    let session = current_session_cache_first(context.service, context.headers).await;
    if login_required(session.as_ref(), &request.query, &request.prompt) {
        return login_response(
            context.service,
            context.config,
            context.store,
            context.headers,
            &request.query,
            &request.prompt,
        )
        .await;
    }
    let session = session.expect("login-required branch handled missing session");
    if request.query.max_age.is_some() {
        request.query.max_age = None;
    }
    if let Some(response) = super::stages::ui_stage_response(
        context.service,
        context.config,
        context.store,
        context.headers,
        super::stages::UiStageRequest {
            query: &request.query,
            scopes: &request.scopes,
            prompt: &request.prompt,
            session: &session,
            stages: request.stages,
        },
    )
    .await?
    {
        return Ok(response);
    }
    finish_with_consent(
        context,
        SessionAuthorization {
            query: request.query,
            client: request.client,
            scopes: request.scopes,
            prompt: request.prompt,
            session,
        },
    )
    .await
}

fn login_required(
    session: Option<&SessionWithUser>,
    query: &OAuthAuthorizationQuery,
    prompt: &[String],
) -> bool {
    session.is_none_or(|session| {
        query.max_age.is_some_and(|max_age| {
            session.session.created_at + Duration::seconds(max_age as i64) < Utc::now()
        })
    }) || prompt
        .iter()
        .any(|value| value == "login" || value == "create")
}

async fn login_response(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &OAuthAuthorizationQuery,
    prompt: &[String],
) -> Result<Response, OAuthProviderError> {
    if prompt.iter().any(|value| value == "none") {
        return redirect_error(
            service,
            config,
            store,
            headers,
            query,
            "login_required",
            "authentication required",
        )
        .await;
    }
    let page = if prompt.iter().any(|value| value == "create") {
        config.signup_page.as_deref().unwrap_or(&config.login_page)
    } else {
        &config.login_page
    };
    Ok(redirect(
        headers,
        &format!("{page}?{}", signed_query(service, config, query)),
    ))
}

async fn finish_with_consent(
    context: AuthorizationContext<'_>,
    request: SessionAuthorization,
) -> Result<Response, OAuthProviderError> {
    let reference_id = match &context.config.callbacks.consent_reference {
        Some(resolver) => resolver
            .resolve(&callback_context(
                context.headers,
                &request.session,
                &request.scopes,
            ))
            .await
            .map_err(storage_error)?,
        None => None,
    };
    let client_id = request
        .query
        .client_id
        .as_deref()
        .expect("validated client id");
    let consent = context
        .store
        .find_oauth_consent_for_grant(client_id, request.session.user.id, reference_id.as_deref())
        .await
        .map_err(storage_error)?;
    if consent_required(
        context.config,
        &request.client,
        &request.query,
        &request.scopes,
        &request.prompt,
        consent.as_ref(),
    ) {
        if request.prompt.iter().any(|value| value == "none") {
            return redirect_error(
                context.service,
                context.config,
                context.store,
                context.headers,
                &request.query,
                "consent_required",
                "End-User consent is required",
            )
            .await;
        }
        return Ok(redirect(
            context.headers,
            &format!(
                "{}?{}",
                context.config.consent_page,
                signed_query(context.service, context.config, &request.query)
            ),
        ));
    }
    issue_code(
        context.service,
        context.config,
        context.headers,
        request.query,
        &request.session,
        reference_id,
    )
    .await
}

fn consent_required(
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    query: &OAuthAuthorizationQuery,
    scopes: &[String],
    prompt: &[String],
    consent: Option<&crate::OAuthProviderConsent>,
) -> bool {
    prompt.iter().any(|value| value == "consent")
        || (client.skip_consent != Some(true)
            && consent.is_none_or(|consent| {
                let requested_claims =
                    claims::requested_userinfo_claims(config, query.claims.as_ref());
                !scopes.iter().all(|scope| consent.scopes.contains(scope))
                    || !requested_claims.iter().all(|claim| {
                        consent
                            .requested_user_info_claims
                            .as_ref()
                            .is_some_and(|accepted| accepted.contains(claim))
                    })
                    || !query.resource.iter().all(|resource| {
                        consent
                            .resources
                            .as_ref()
                            .is_some_and(|set| set.contains(resource))
                    })
            }))
}
