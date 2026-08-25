use super::{super::support, common, projection};
use crate::{AxumPluginRoute, commet::CommetPlugin};
use axum::{
    Extension,
    http::HeaderMap,
    response::Response,
    routing::{MethodRouter, get},
};
use serde_json::{Map, Value};
use std::sync::Arc;

pub(super) fn routes(layer: &impl Fn(MethodRouter) -> MethodRouter) -> Vec<AxumPluginRoute> {
    vec![AxumPluginRoute::new("/commet/portal", layer(get(portal)))]
}

async fn portal(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
) -> Response {
    let session = match common::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let result = plugin
        .options()
        .client
        .create_portal_session(&session.user.id.to_string())
        .await;
    match result {
        Ok(value) => portal_response(
            value,
            plugin
                .options()
                .portal()
                .and_then(|p| p.return_url.as_deref()),
        ),
        Err(error) => common::provider_error(error, "Failed to access customer portal"),
    }
}

fn portal_response(value: Value, return_url: Option<&str>) -> Response {
    let portal_url = value.get("portalUrl").cloned();
    let projected_url = if let Some(return_url) = return_url.filter(|value| !value.is_empty()) {
        let raw_url = projection::js_string(portal_url.as_ref());
        let Ok(mut parsed) = url::Url::parse(&raw_url) else {
            return support::message(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to access customer portal",
            );
        };
        set_query_value(&mut parsed, "return_url", return_url);
        Some(Value::String(parsed.into()))
    } else {
        portal_url
    };
    let mut response = Map::new();
    if let Some(projected_url) = projected_url {
        response.insert("url".into(), projected_url);
    }
    response.insert("redirect".into(), Value::Bool(true));
    support::json(Value::Object(response))
}

fn set_query_value(url: &mut url::Url, key: &str, value: &str) {
    let mut pairs = Vec::new();
    let mut replaced = false;
    for (current_key, current_value) in url.query_pairs() {
        if current_key == key {
            if !replaced {
                pairs.push((current_key.into_owned(), value.to_owned()));
                replaced = true;
            }
        } else {
            pairs.push((current_key.into_owned(), current_value.into_owned()));
        }
    }
    if !replaced {
        pairs.push((key.to_owned(), value.to_owned()));
    }
    url.set_query(None);
    url.query_pairs_mut().extend_pairs(pairs);
}

#[cfg(test)]
mod tests {
    use super::set_query_value;

    #[test]
    fn return_url_replaces_all_existing_values_in_place() {
        let mut url = url::Url::parse(
            "https://portal.commet.test/session?return_url=old&keep=1&return_url=older",
        )
        .unwrap();
        set_query_value(&mut url, "return_url", "https://app.test/billing?tab=plans");
        assert_eq!(
            url.as_str(),
            "https://portal.commet.test/session?return_url=https%3A%2F%2Fapp.test%2Fbilling%3Ftab%3Dplans&keep=1"
        );
    }
}
