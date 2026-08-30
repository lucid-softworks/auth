use super::{query::project_value, support};
use crate::{AuthService, scim::{SCIM_LIST_RESPONSE_SCHEMA, ScimError}};
use axum::{Extension, extract::{Path, Query}, http::StatusCode, response::Response};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};

pub(super) async fn service_provider_config(
    Extension(service): Extension<Arc<AuthService>>,
) -> Response {
    support::json(
        StatusCode::OK,
        super::super::discovery::service_provider_config(&service.scim_base_url()),
    )
}

pub(super) async fn schemas(
    Extension(service): Extension<Arc<AuthService>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let values = super::super::discovery::schemas(&service.scim_base_url());
    list(values, &query)
}

pub(super) async fn schema(
    Extension(service): Extension<Arc<AuthService>>,
    Path(schema_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    match super::super::discovery::schemas(&service.scim_base_url())
        .into_iter()
        .find(|value| value["id"] == schema_id)
    {
        Some(value) => support::json(StatusCode::OK, project_value(value, &query)),
        None => support::error_response(ScimError::new(404, "Schema not found")),
    }
}

pub(super) async fn resource_types(
    Extension(service): Extension<Arc<AuthService>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    list(super::super::discovery::resource_types(&service.scim_base_url()), &query)
}

pub(super) async fn resource_type(
    Extension(service): Extension<Arc<AuthService>>,
    Path(resource_type_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    match super::super::discovery::resource_types(&service.scim_base_url())
        .into_iter()
        .find(|value| value["id"] == resource_type_id)
    {
        Some(value) => support::json(StatusCode::OK, project_value(value, &query)),
        None => support::error_response(ScimError::new(404, "Resource type not found")),
    }
}

fn list(values: Vec<Value>, query: &HashMap<String, String>) -> Response {
    let values = values
        .into_iter()
        .map(|value| project_value(value, query))
        .collect::<Vec<_>>();
    support::json(
        StatusCode::OK,
        json!({
            "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
            "totalResults": values.len(),
            "startIndex": 1,
            "itemsPerPage": values.len(),
            "Resources": values,
        }),
    )
}
