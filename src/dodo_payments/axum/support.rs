use crate::{
    AuthService, SessionWithUser, UserProfileUpdate,
    dodo_payments::{
        DodoCustomerCreateRequest, DodoCustomerListRequest, DodoPaymentsCallbackError,
        DodoPaymentsPlugin, DodoPaymentsProviderError,
    },
};
use axum::{
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
};
use serde_json::{Map, Value, json};
use url::Url;

pub(super) fn error(
    status: StatusCode,
    _code: &'static str,
    message: impl Into<String>,
) -> Response {
    crate::axum::api_error_with_body(status, json!({"message": message.into()}))
}

pub(super) fn validation_error(message: impl Into<String>) -> Response {
    crate::axum::api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", message.into())
}

pub(super) fn bad_request(message: impl Into<String>) -> Response {
    error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
}

pub(super) fn unauthorized(message: impl Into<String>) -> Response {
    error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", message)
}

pub(super) fn internal_empty() -> Response {
    crate::axum::api_error_empty(StatusCode::INTERNAL_SERVER_ERROR)
}

pub(super) async fn optional_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<SessionWithUser> {
    crate::axum::http::current_session(service, headers).await
}

pub(super) async fn required_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Result<SessionWithUser, Box<Response>> {
    optional_session(service, headers)
        .await
        .ok_or_else(|| Box::new(unauthorized("Unauthorized")))
}

pub(super) fn verified_user(session: &SessionWithUser) -> Result<(), Box<Response>> {
    if !session.user.email_verified {
        return Err(Box::new(unauthorized("User email not verified")));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(super) enum CustomerResolutionError {
    #[error(transparent)]
    Provider(#[from] DodoPaymentsProviderError),
    #[error(transparent)]
    Callback(#[from] DodoPaymentsCallbackError),
}

pub(super) async fn customer_id(
    plugin: &DodoPaymentsPlugin,
    session: &SessionWithUser,
) -> Result<String, CustomerResolutionError> {
    if let Some(customer_id) = session
        .user
        .additional_fields
        .get("dodoCustomerId")
        .and_then(Value::as_str)
        .filter(|customer_id| !customer_id.is_empty())
    {
        return Ok(customer_id.to_owned());
    }
    let options = plugin.options();
    let customers = options
        .client
        .list_customers(DodoCustomerListRequest {
            email: session.user.email.clone(),
        })
        .await?;
    let customer_id = match customers.items.into_iter().next() {
        Some(customer) => customer.customer_id,
        None => {
            let params = match &options.get_customer_params {
                Some(provider) => provider.params(&session.user).await?,
                None => Default::default(),
            };
            options
                .client
                .create_customer(
                    DodoCustomerCreateRequest {
                        email: session.user.email.clone(),
                        name: session.user.name.clone(),
                        metadata: params.metadata,
                        phone_number: params.phone_number,
                    },
                    Some(&session.user.id.to_string()),
                )
                .await?
                .customer_id
        }
    };
    let store = plugin.auth_store.clone();
    let user_id = session.user.id;
    let persisted_id = customer_id.clone();
    tokio::spawn(async move {
        let update = UserProfileUpdate {
            additional_fields: Map::from_iter([(
                "dodoCustomerId".into(),
                Value::String(persisted_id),
            )]),
            ..UserProfileUpdate::default()
        };
        let _ = store.update_user_profile(user_id, update).await;
    });
    Ok(customer_id)
}

pub(super) fn configured_success_url(
    service: &AuthService,
    headers: &HeaderMap,
    uri: &Uri,
    value: Option<&str>,
) -> Result<Option<String>, url::ParseError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Ok(url) = Url::parse(value) {
        return Ok(Some(url.to_string()));
    }
    request_url(service, headers, uri)
        .and_then(|base| base.join(value))
        .map(|url| Some(url.to_string()))
}

fn request_url(
    service: &AuthService,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<Url, url::ParseError> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Url::parse(&uri.to_string());
    }
    let scheme = header_text(headers, "x-forwarded-proto").unwrap_or("http");
    if let Some(host) = header_text(headers, "x-forwarded-host")
        .or_else(|| header_text(headers, header::HOST.as_str()))
    {
        return Url::parse(&format!("{scheme}://{host}{uri}"));
    }
    let mut base = service
        .configured_base_url()
        .cloned()
        .ok_or(url::ParseError::RelativeUrlWithoutBase)?;
    base.set_path(uri.path());
    base.set_query(uri.query());
    Ok(base)
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
