use super::{OpenApiConfig, generator::generate_open_api_schema_with_base_url};
use crate::{AuthService, AxumPluginRoute};
use axum::{
    Json,
    body::Body,
    extract::{OriginalUri, Request},
    http::{HeaderMap, Method, Response, StatusCode, header},
    response::IntoResponse,
    routing::{MethodFilter, MethodRouter},
};
use std::sync::Arc;

pub(super) fn routes(service: Arc<AuthService>, config: OpenApiConfig) -> Vec<AxumPluginRoute> {
    let schema_service = service.clone();
    let schema = MethodRouter::new()
        .on(
            MethodFilter::GET,
            move |method: Method, headers: HeaderMap, uri: OriginalUri| {
                let service = schema_service.clone();
                async move {
                    if method != Method::GET {
                        return empty_not_found_response();
                    }
                    Json(generate_open_api_schema_with_base_url(
                        &service,
                        request_base_url(&service, &headers, &uri.0),
                    ))
                    .into_response()
                }
            },
        )
        .fallback(empty_not_found);

    let reference_service = service;
    let reference_config = config.clone();
    let reference = MethodRouter::new()
        .on(
            MethodFilter::GET,
            move |method: Method, headers: HeaderMap, uri: OriginalUri| {
                let service = reference_service.clone();
                let config = reference_config.clone();
                async move {
                    if method != Method::GET {
                        return empty_not_found_response();
                    }
                    reference_response(&service, &config, &headers, &uri.0)
                }
            },
        )
        .fallback(empty_not_found);

    vec![
        AxumPluginRoute::new("/open-api/generate-schema", schema),
        AxumPluginRoute::new(config.path, reference),
    ]
}

fn reference_response(
    service: &AuthService,
    config: &OpenApiConfig,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> Response<Body> {
    if config.disable_default_reference {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::empty())
            .expect("static disabled-reference response");
    }
    let schema =
        generate_open_api_schema_with_base_url(service, request_base_url(service, headers, uri));
    let document = serde_json::to_string(&schema).expect("OpenAPI document serializes");
    let nonce = config
        .nonce
        .as_ref()
        .map_or_else(String::new, |nonce| format!("nonce=\"{nonce}\""));
    let html = format!(
        "<!doctype html>\n<html>\n  <head>\n    <title>Scalar API Reference</title>\n    <meta charset=\"utf-8\" />\n    <meta\n      name=\"viewport\"\n      content=\"width=device-width, initial-scale=1\" />\n  </head>\n  <body>\n    <script\n      id=\"api-reference\"\n      type=\"application/json\">\n    {document}\n    </script>\n\t <script {nonce}>\n      var configuration = {{\n\t  \tfavicon: \"{}\",\n\t   \ttheme: \"{}\",\n        metaData: {{\n\t\t\ttitle: \"Better Auth API\",\n\t\t\tdescription: \"API Reference for your Better Auth Instance\",\n\t\t}}\n      }}\n\n      document.getElementById('api-reference').dataset.configuration =\n        JSON.stringify(configuration)\n    </script>\n\t  <script src=\"https://cdn.jsdelivr.net/npm/@scalar/api-reference\" {nonce}></script>\n  </body>\n</html>",
        include_str!("favicon.txt"),
        config.theme.as_str(),
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html")
        .body(Body::from(html))
        .expect("static OpenAPI reference response")
}

async fn empty_not_found(_request: Request) -> impl IntoResponse {
    empty_not_found_response()
}

fn empty_not_found_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .expect("static empty not-found response")
}

fn request_base_url(service: &AuthService, headers: &HeaderMap, uri: &axum::http::Uri) -> String {
    if service.open_api_configured_base_url().is_some() {
        return super::generator::generate_open_api_schema(service).servers[0]
            .url
            .clone();
    }
    if let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) {
        return format!(
            "{scheme}://{}{path}",
            authority.as_str(),
            path = service.configured_base_path()
        );
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if host.is_empty() {
        return String::new();
    }
    let scheme = if service.trusted_proxy_headers() {
        headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| matches!(*value, "http" | "https"))
            .unwrap_or("http")
    } else {
        "http"
    };
    format!("{scheme}://{host}{}", service.configured_base_path())
}
