use super::{SignInBody, support};
use crate::{AuthService, SsoProvider, VerificationValue, service::OAuthState};
use axum::{Json, response::{IntoResponse, Response}};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, SecondsFormat, Utc};
use flate2::{Compression, write::DeflateEncoder};
use serde_json::{Map, Value, json};
use std::io::Write as _;

#[derive(serde::Serialize)]
struct SignInResponse {
    url: String,
    redirect: bool,
}

pub(super) async fn start(
    service: &AuthService,
    provider: &SsoProvider,
    config: &Map<String, Value>,
    body: SignInBody,
) -> Response {
    if body.additional_params.is_some() {
        return support::error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "additionalParams is not supported for SAML providers; the SAML AuthnRequest is signed and cannot carry caller-supplied query parameters.",
        );
    }
    if config.get("authnRequestsSigned") == Some(&Value::Bool(true)) {
        let private_key = config
            .get("spMetadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("privateKey"))
            .or_else(|| config.get("privateKey"))
            .and_then(Value::as_str);
        if private_key.is_none_or(str::is_empty) {
            return support::error(
                axum::http::StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "authnRequestsSigned is enabled but no privateKey provided in spMetadata or samlConfig",
            );
        }
    }
    let Some(entry_point) = config.get("entryPoint").and_then(Value::as_str) else {
        return support::error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid SAML request",
        );
    };
    let request_id = format!("_{}", uuid::Uuid::new_v4().simple());
    let relay_state = uuid::Uuid::new_v4().simple().to_string();
    let reference = super::super::super::provider_reference::persisted(provider);
    let saved = match save_state(service, &relay_state, &reference, &body).await {
        Ok(saved) => saved,
        Err(response) => return *response,
    };
    if let Err(response) = save_request(service, provider, &request_id, &reference).await {
        return *response;
    }
    let request = authn_request(service, provider, config, entry_point, &request_id);
    let url = match redirect_url(entry_point, &request, &relay_state, config) {
        Ok(url) => url,
        Err(()) => {
            return support::error(
                axum::http::StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid SAML request",
            );
        }
    };
    let response = Json(SignInResponse { url, redirect: true }).into_response();
    crate::axum::http::with_cookie(
        response,
        crate::axum::http::serialize_cookie(
            &service.plugin_cookie(saved.0),
            &saved.1,
            Some(saved.2),
        ),
    )
}

async fn save_state(
    service: &AuthService,
    relay_state: &str,
    reference: &super::super::super::provider_reference::ProviderReference,
    body: &SignInBody,
) -> Result<(&'static str, String, i64), Box<Response>> {
    let state = OAuthState {
        oauth_state: Some(relay_state.into()),
        callback_url: body.callback_url.clone(),
        code_verifier: String::new(),
        error_url: body.error_callback_url.clone(),
        new_user_url: body.new_user_callback_url.clone(),
        expires_at: (Utc::now() + Duration::minutes(5)).timestamp_millis(),
        request_sign_up: body.request_sign_up.unwrap_or(false),
        id_token_nonce: None,
        additional_data: Map::from_iter([(
            "serverContext".into(),
            json!({"ssoProviderReference": reference}),
        )]),
        link: None,
        anonymous_user_id: None,
    };
    service.save_oauth_state(relay_state, &state).await.map_err(|_| {
        Box::new(support::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "State error: Unable to create verification for state",
        ))
    })
}

async fn save_request(
    service: &AuthService,
    provider: &SsoProvider,
    request_id: &str,
    reference: &super::super::super::provider_reference::ProviderReference,
) -> Result<(), Box<Response>> {
    let expires = Utc::now() + Duration::minutes(5);
    service
        .create_verification_value(VerificationValue::new(
            format!("saml-authn-request:{request_id}"),
            json!({
                "id": request_id,
                "providerId": provider.provider_id,
                "providerReference": reference,
                "createdAt": Utc::now().timestamp_millis(),
                "expiresAt": expires.timestamp_millis()
            })
            .to_string(),
            expires,
        ))
        .await
        .map_err(|_| {
            Box::new(support::error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERVER_ERROR",
                "Invalid SAML request",
            ))
        })
}

fn authn_request(
    service: &AuthService,
    provider: &SsoProvider,
    config: &Map<String, Value>,
    destination: &str,
    request_id: &str,
) -> String {
    let issuer = config
        .get("spMetadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("entityID"))
        .and_then(Value::as_str)
        .unwrap_or(&provider.issuer);
    let acs = format!(
        "{}/sso/saml2/sp/acs/{}",
        support::base_url(service),
        provider.provider_id
    );
    let name_id = config
        .get("identifierFormat")
        .and_then(Value::as_str)
        .map(|format| format!("<samlp:NameIDPolicy Format=\"{}\" AllowCreate=\"true\"/>", escape(format)))
        .unwrap_or_default();
    format!(
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{}\" Version=\"2.0\" IssueInstant=\"{}\" Destination=\"{}\" AssertionConsumerServiceURL=\"{}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"><saml:Issuer>{}</saml:Issuer>{}</samlp:AuthnRequest>",
        escape(request_id),
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        escape(destination),
        escape(&acs),
        escape(issuer),
        name_id
    )
}

fn redirect_url(
    entry_point: &str,
    request: &str,
    relay_state: &str,
    config: &Map<String, Value>,
) -> Result<String, ()> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(request.as_bytes()).map_err(|_| ())?;
    let encoded = STANDARD.encode(encoder.finish().map_err(|_| ())?);
    let mut url = url::Url::parse(entry_point).map_err(|_| ())?;
    if config.get("authnRequestsSigned") != Some(&Value::Bool(true)) {
        url.query_pairs_mut()
            .append_pair("SAMLRequest", &encoded)
            .append_pair("RelayState", relay_state);
        return Ok(url.into());
    }
    let algorithm = config
        .get("signatureAlgorithm")
        .and_then(Value::as_str)
        .unwrap_or("sha256");
    let (signature_uri, signer) = if algorithm.to_ascii_lowercase().contains("sha512") {
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            josekit::jws::RS512.signer_from_pem(private_key(config)).map_err(|_| ())?,
        )
    } else {
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            josekit::jws::RS256.signer_from_pem(private_key(config)).map_err(|_| ())?,
        )
    };
    let canonical = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("SAMLRequest", &encoded)
        .append_pair("RelayState", relay_state)
        .append_pair("SigAlg", signature_uri)
        .finish();
    let signature = STANDARD.encode(josekit::jws::JwsSigner::sign(&signer, canonical.as_bytes()).map_err(|_| ())?);
    url.set_query(Some(&canonical));
    url.query_pairs_mut().append_pair("Signature", &signature);
    Ok(url.into())
}

fn private_key(config: &Map<String, Value>) -> &str {
    config
        .get("spMetadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("privateKey"))
        .or_else(|| config.get("privateKey"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
