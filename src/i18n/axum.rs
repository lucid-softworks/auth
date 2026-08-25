use super::{I18nConfig, I18nLocaleContext, I18nLocaleDetection, detection};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderName, HeaderValue, header},
    response::Response,
};
use serde::Serialize;

pub(super) async fn translate_response(
    service: &crate::AuthService,
    config: &I18nConfig,
    request: &crate::PluginRequestContext,
    response: Response,
) -> Response {
    if response
        .extensions()
        .get::<crate::axum::ApiErrorResponse>()
        .is_none()
    {
        return response;
    }
    let headers = request_headers(request);
    let session = if config.detection.contains(&I18nLocaleDetection::Session) {
        crate::axum::http::current_session(service, &headers).await
    } else {
        None
    };
    let locale = detection::detect(
        config,
        I18nLocaleContext {
            request: Some(request.clone()),
            session,
        },
    )
    .await;

    let (mut parts, body) = response.into_parts();
    parts.extensions.remove::<crate::axum::ApiErrorResponse>();
    let bytes = match to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return Response::from_parts(parts, Body::empty()),
    };
    let Some((code, original_message)) = error_fields(&bytes) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    let Some(translation) = config
        .translations
        .get(&locale)
        .and_then(|dictionary| dictionary.get(&code))
        .filter(|translation| !translation.is_empty())
    else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    let replacement = serde_json::to_vec(&TranslatedError {
        code: &code,
        message: translation,
        original_message: &original_message,
    })
    .expect("i18n API errors are serializable");
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(replacement))
}

fn request_headers(request: &crate::PluginRequestContext) -> HeaderMap {
    request
        .headers
        .iter()
        .filter_map(|(name, value)| {
            Some((
                HeaderName::from_bytes(name.as_bytes()).ok()?,
                HeaderValue::from_str(value).ok()?,
            ))
        })
        .collect()
}

fn error_fields(bytes: &[u8]) -> Option<(String, String)> {
    let body: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let body = body.as_object()?;
    Some((
        body.get("code")?.as_str()?.to_owned(),
        body.get("message")?.as_str()?.to_owned(),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TranslatedError<'a> {
    code: &'a str,
    message: &'a str,
    original_message: &'a str,
}
