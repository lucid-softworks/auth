use super::{query, support};
use crate::{
    AuthService,
    scim::{
        ScimError, ScimErrorType, ScimListResponse, ScimPatchRequest, ScimPlugin, ScimUser,
        plugin::store_error, store::StoredScimUser,
    },
};
use axum::{
    Extension,
    extract::{Path, Query, Request},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};

mod patch;
mod mutation;

pub(super) async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Query(query_parameters): Query<HashMap<String, String>>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let principal = match support::authenticate(
        &plugin,
        &headers,
        "POST",
        "/scim/v2/Users",
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let projection = match query::projection(&query_parameters, "User") {
        Ok(projection) => projection,
        Err(error) => return support::error_response(error),
    };
    let resource = match support::parse_body::<ScimUser>(request).await {
        Ok(resource) => match resource.normalize() {
            Ok(resource) => resource,
            Err(error) => return support::error_response(error),
        },
        Err(response) => return response,
    };
    let now = super::super::timestamp::now();
    let mut resource = resource;
    resource.id = Some(super::super::random_urlsafe(32));
    match mutation::create(service.clone(), plugin.clone(), principal, resource, now).await {
        Ok(stored) => {
            let complete = present(&service, &stored);
            let location = complete["meta"]["location"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let value = query::project_value(complete, &projection);
            let mut response = support::json(StatusCode::CREATED, value);
            support::set_location(&mut response, &location, true);
            response
        }
        Err(error) => support::error_response(error),
    }
}

pub(super) async fn get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Path(user_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let principal = match support::authenticate(
        &plugin,
        &headers,
        "GET",
        &format!("/scim/v2/Users/{user_id}"),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let projection = match query::projection(&query, "User") {
        Ok(projection) => projection,
        Err(error) => return support::error_response(error),
    };
    match plugin.store.find_user(&principal.connection_id, &user_id).await {
        Ok(Some(user)) => support::json(
            StatusCode::OK,
            query::project_value(present(&service, &user), &projection),
        ),
        Ok(None) => support::error_response(ScimError::new(404, "User not found")),
        Err(error) => support::error_response(store_error(error)),
    }
}

pub(super) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let principal = match support::authenticate(
        &plugin,
        &headers,
        "GET",
        "/scim/v2/Users",
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let pagination = match query::pagination(&query) {
        Ok(pagination) => pagination,
        Err(error) => return support::error_response(error),
    };
    let projection = match query::projection(&query, "User") {
        Ok(projection) => projection,
        Err(error) => return support::error_response(error),
    };
    let users = match plugin.store.list_users(&principal.connection_id).await {
        Ok(users) => users,
        Err(error) => return support::error_response(store_error(error)),
    };
    let values = users.iter().map(|user| present(&service, user)).collect();
    let values = match query::filter(values, &query, "User") {
        Ok(values) => values,
        Err(error) => return support::error_response(error),
    };
    let (total, values) = query::page(values, pagination);
    let values = values
        .into_iter()
        .map(|value| query::project_value(value, &projection))
        .collect();
    support::json(
        StatusCode::OK,
        ScimListResponse::new(total, pagination.start_index, values),
    )
}

pub(super) async fn replace(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Path(user_id): Path<String>,
    Query(query_parameters): Query<HashMap<String, String>>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let resource = match support::parse_body::<ScimUser>(request).await {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    replace_resource(
        service,
        plugin,
        headers,
        user_id,
        resource,
        "PUT",
        query_parameters,
    )
    .await
}

pub(super) async fn patch(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Path(user_id): Path<String>,
    Query(query_parameters): Query<HashMap<String, String>>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let patch = match support::parse_body::<ScimPatchRequest>(request).await {
        Ok(patch) => patch,
        Err(response) => return response,
    };
    if let Err(error) = patch.validate() {
        return support::error_response(error);
    }
    let principal = match support::authenticate(
        &plugin,
        &headers,
        "PATCH",
        &format!("/scim/v2/Users/{user_id}"),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let projection = match query::projection(&query_parameters, "User") {
        Ok(projection) => projection,
        Err(error) => return support::error_response(error),
    };
    let existing = match plugin.store.find_user(&principal.connection_id, &user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return support::error_response(ScimError::new(404, "User not found")),
        Err(error) => return support::error_response(store_error(error)),
    };
    let mut value = serde_json::to_value(&existing.resource).unwrap_or(Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.remove("id");
        object.remove("meta");
    }
    if let Err(error) = patch::apply(&mut value, &patch) {
        return support::error_response(error);
    }
    let resource = match serde_json::from_value::<ScimUser>(value) {
        Ok(resource) => resource,
        Err(error) => {
            return support::error_response(ScimError::typed(
                400,
                error.to_string(),
                ScimErrorType::InvalidValue,
            ));
        }
    };
    replace_authenticated(
        service,
        plugin,
        principal.connection_id,
        user_id,
        resource,
        projection,
    )
    .await
}

pub(super) async fn delete(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let principal = match support::authenticate(
        &plugin,
        &headers,
        "DELETE",
        &format!("/scim/v2/Users/{user_id}"),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match mutation::delete(service, plugin, principal.connection_id, user_id).await {
        Ok(()) => support::empty(StatusCode::NO_CONTENT),
        Err(error) => support::error_response(error),
    }
}

async fn replace_resource(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    headers: HeaderMap,
    user_id: String,
    resource: ScimUser,
    method: &str,
    query_parameters: HashMap<String, String>,
) -> Response {
    let principal = match support::authenticate(
        &plugin,
        &headers,
        method,
        &format!("/scim/v2/Users/{user_id}"),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let projection = match query::projection(&query_parameters, "User") {
        Ok(projection) => projection,
        Err(error) => return support::error_response(error),
    };
    replace_authenticated(
        service,
        plugin,
        principal.connection_id,
        user_id,
        resource,
        projection,
    )
    .await
}

async fn replace_authenticated(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    connection_id: String,
    user_id: String,
    resource: ScimUser,
    projection: query::AttributeProjection,
) -> Response {
    let mut resource = match resource.normalize() {
        Ok(resource) => resource,
        Err(error) => return support::error_response(error),
    };
    resource.id = Some(user_id.clone());
    match mutation::replace(
        service.clone(),
        plugin,
        connection_id,
        user_id,
        resource,
    )
    .await
    {
        Ok(stored) => {
            let complete = present(&service, &stored);
            let location = complete["meta"]["location"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let value = query::project_value(complete, &projection);
            let mut response = support::json(StatusCode::OK, value);
            support::set_location(&mut response, &location, false);
            response
        }
        Err(error) => support::error_response(error),
    }
}

pub(super) fn present(service: &AuthService, stored: &StoredScimUser) -> Value {
    let mut resource = stored.resource.clone();
    let id = resource.id.clone().unwrap_or_default();
    resource.meta = Some(crate::scim::model::ScimMeta {
        resource_type: "User".into(),
        created: Some(stored.created_at),
        last_modified: Some(stored.updated_at),
        location: format!("{}/scim/v2/Users/{id}", service.scim_base_url()),
    });
    serde_json::to_value(resource).unwrap_or(Value::Null)
}
