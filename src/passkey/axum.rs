use super::PasskeyConfig;
use crate::{
    AuthError, AuthService, AxumPluginRoute,
    axum::http::{
        PeerAddress, auth_error, challenge_token, client_ip, current_session, user_agent,
        with_challenge_cookie, with_session_cookie,
    },
    protocol::better_auth::{
        BetterAuthPasskey, DeletePasskeyRequest, PasskeyRegistrationResponse, StatusResponse,
        UpdatePasskeyRequest, UpdatePasskeyResponse,
    },
};
use axum::{
    Extension, Json,
    extract::Query,
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

#[derive(Debug, Deserialize)]
struct VerifyRegistrationRequest {
    response: RegisterPublicKeyCredential,
    name: Option<String>,
    #[serde(rename = "createSession")]
    create_session: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct VerifyAuthenticationRequest {
    response: PublicKeyCredential,
}

#[derive(Debug, Deserialize)]
struct GenerateRegistrationQuery {
    #[serde(rename = "authenticatorAttachment")]
    authenticator_attachment: Option<String>,
    name: Option<String>,
    context: Option<String>,
}

pub(super) fn routes(
    _service: Arc<AuthService>,
    config: Arc<PasskeyConfig>,
) -> Vec<AxumPluginRoute> {
    vec![
        route(
            "/passkey/generate-register-options",
            get(generate_registration_options),
            config.clone(),
        ),
        route(
            "/passkey/verify-registration",
            post(verify_registration),
            config.clone(),
        ),
        route(
            "/passkey/generate-authenticate-options",
            get(generate_authentication_options),
            config.clone(),
        ),
        route(
            "/passkey/verify-authentication",
            post(verify_authentication),
            config.clone(),
        ),
        route(
            "/passkey/list-user-passkeys",
            get(list_user_passkeys),
            config.clone(),
        ),
        route(
            "/passkey/delete-passkey",
            post(delete_passkey),
            config.clone(),
        ),
        route("/passkey/update-passkey", post(update_passkey), config),
    ]
}

fn route(
    path: &'static str,
    route: axum::routing::MethodRouter,
    config: Arc<PasskeyConfig>,
) -> AxumPluginRoute {
    AxumPluginRoute::new(path, route.layer(Extension(config)))
}

async fn generate_registration_options(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<PasskeyConfig>>,
    headers: HeaderMap,
    Query(query): Query<GenerateRegistrationQuery>,
) -> Response {
    let session = current_session(&service, &headers).await;
    if config.registration.require_session && session.is_none() {
        return auth_error(AuthError::PasskeySessionRequired);
    }
    let authenticator_attachment = match query.authenticator_attachment.as_deref() {
        Some("platform") => Some(webauthn_rs::prelude::AuthenticatorAttachment::Platform),
        Some("cross-platform") => {
            Some(webauthn_rs::prelude::AuthenticatorAttachment::CrossPlatform)
        }
        Some(_) => {
            return auth_error(AuthError::InvalidRequest(
                "authenticatorAttachment must be platform or cross-platform".into(),
            ));
        }
        None => None,
    };
    match service
        .start_passkey_registration(
            &config,
            session.as_ref(),
            crate::PasskeyRegistrationRequest {
                name: query.name,
                context: query.context,
                authenticator_attachment,
            },
        )
        .await
    {
        Ok((token, options)) => with_challenge_cookie(
            &service,
            &config.webauthn_challenge_cookie,
            &token,
            Json(options.public_key),
        ),
        Err(error) => auth_error(error),
    }
}

async fn verify_registration(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<PasskeyConfig>>,
    headers: HeaderMap,
    Json(input): Json<VerifyRegistrationRequest>,
) -> Response {
    let session = current_session(&service, &headers).await;
    if config.registration.require_session && session.is_none() {
        return auth_error(AuthError::PasskeySessionRequired);
    }
    let request_origin = request_origin(&headers).map(str::to_owned);
    if config.origins.is_none() && request_origin.is_none() {
        return auth_error(AuthError::PasskeyRegistrationFailed);
    }
    let Some(challenge) = challenge_token(&service, &headers, &config.webauthn_challenge_cookie)
    else {
        return auth_error(AuthError::PasskeyChallengeExpired);
    };
    match service
        .finish_passkey_registration(
            &config,
            session.as_ref(),
            crate::PasskeyRegistrationVerification {
                request_origin,
                token: challenge,
                response: input.response,
                name: input.name,
                create_session: input.create_session.unwrap_or(false),
            },
        )
        .await
    {
        Ok(result) => {
            if let Some(replacement) = result.replacement_session {
                let user = match service.better_auth_user(&replacement.session.user).await {
                    Ok(user) => user,
                    Err(error) => return auth_error(error),
                };
                let body = Json(PasskeyRegistrationResponse {
                    passkey: BetterAuthPasskey::from(&result.passkey),
                    session: Some(
                        service
                            .better_auth_session(&replacement.session.session, &replacement.token),
                    ),
                    user: Some(user),
                });
                with_session_cookie(&service, &replacement.token, Some(true), body).await
            } else {
                Json(PasskeyRegistrationResponse {
                    passkey: BetterAuthPasskey::from(&result.passkey),
                    session: None,
                    user: None,
                })
                .into_response()
            }
        }
        Err(error) => auth_error(error),
    }
}

async fn generate_authentication_options(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<PasskeyConfig>>,
    headers: HeaderMap,
) -> Response {
    let session = current_session(&service, &headers).await;
    match service
        .start_passkey_authentication(&config, session.as_ref())
        .await
    {
        Ok((token, options)) => {
            let mut public_key =
                serde_json::to_value(options.public_key).unwrap_or(serde_json::Value::Null);
            if public_key
                .get("allowCredentials")
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty)
                && let Some(object) = public_key.as_object_mut()
            {
                object.remove("allowCredentials");
            }
            with_challenge_cookie(
                &service,
                &config.webauthn_challenge_cookie,
                &token,
                Json(public_key),
            )
        }
        Err(error) => auth_error(error),
    }
}

async fn verify_authentication(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<PasskeyConfig>>,
    peer: PeerAddress,
    headers: HeaderMap,
    Json(input): Json<VerifyAuthenticationRequest>,
) -> Response {
    let anonymous = current_session(&service, &headers)
        .await
        .filter(|session| session.user.is_anonymous);
    let request_origin = request_origin(&headers);
    if config.origins.is_none() && request_origin.is_none() {
        return auth_error(AuthError::PasskeyOriginMissing);
    }
    let Some(challenge) = challenge_token(&service, &headers, &config.webauthn_challenge_cookie)
    else {
        return auth_error(AuthError::PasskeyChallengeExpired);
    };
    match service
        .finish_passkey_authentication(
            &config,
            request_origin,
            &challenge,
            input.response,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(result) => {
            if let Some(source) = anonymous.as_ref()
                && let Err(error) = service.complete_anonymous_upgrade(source, &result).await
            {
                return auth_error(error);
            }
            match service
                .better_auth_session_response(&result.session, result.token.clone())
                .await
            {
                Ok(response) => {
                    with_session_cookie(&service, &result.token, Some(true), Json(response)).await
                }
                Err(error) => auth_error(error),
            }
        }
        Err(error) => auth_error(error),
    }
}

async fn list_user_passkeys(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service.list_passkeys(session.user.id).await {
        Ok(passkeys) => Json(
            passkeys
                .iter()
                .map(BetterAuthPasskey::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn delete_passkey(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<DeletePasskeyRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let Ok(passkey_id) = input.id.parse() else {
        return auth_error(AuthError::PasskeyNotFound);
    };
    match service.delete_passkey(&session, passkey_id).await {
        Ok(()) => Json(StatusResponse { status: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn update_passkey(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UpdatePasskeyRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let Ok(passkey_id) = input.id.parse() else {
        return auth_error(AuthError::PasskeyNotFound);
    };
    match service
        .rename_passkey(&session, passkey_id, &input.name)
        .await
    {
        Ok(passkey) => Json(UpdatePasskeyResponse {
            passkey: BetterAuthPasskey::from(&passkey),
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

fn request_origin(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
