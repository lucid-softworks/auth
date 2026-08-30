use super::{query, support};
use crate::{
    AuthService,
    scim::{
        ScimError, ScimErrorType, ScimGroup, ScimListResponse, ScimPatchRequest, ScimPlugin,
        plugin::store_error, store::StoredScimGroup,
    },
};
use axum::{
    Extension,
    extract::{Path, Query, Request},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use chrono::Utc;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};

mod patch;

const ENTRA_LEGACY_GROUP_SCHEMA: &str =
    "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group";

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
        "/scim/v2/Groups",
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let projection = match query::projection(&query_parameters, "Group") {
        Ok(projection) => projection,
        Err(error) => return support::error_response(error),
    };
    let mut resource = match parse_group(request, plugin.options.microsoft_entra_legacy_group_schema).await {
        Ok(resource) => match resource.normalize() {
            Ok(resource) => resource,
            Err(error) => return support::error_response(error),
        },
        Err(response) => return response,
    };
    let now = Utc::now();
    resource.id = Some(super::super::random_urlsafe(32));
    let stored = StoredScimGroup {
        resource,
        connection_id: principal.connection_id,
        provisioning_domain_id: principal.provisioning_domain_id,
        created_at: now,
        updated_at: now,
    };
    match plugin.store.create_group(stored).await {
        Ok(stored) => {
            let complete = match present(&service, &plugin, &stored).await {
                Ok(value) => value,
                Err(error) => return support::error_response(store_error(error)),
            };
            let location = complete["meta"]["location"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let value = query::project_value(complete, &projection);
            let mut response = support::json(StatusCode::CREATED, value);
            support::set_location(&mut response, &location, true);
            response
        }
        Err(error) => support::error_response(store_error(error)),
    }
}

pub(super) async fn get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Path(group_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let principal = match support::authenticate(
        &plugin,
        &headers,
        "GET",
        &format!("/scim/v2/Groups/{group_id}"),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let projection = match query::projection(&query, "Group") {
        Ok(projection) => projection,
        Err(error) => return support::error_response(error),
    };
    match plugin.store.find_group(&principal.connection_id, &group_id).await {
        Ok(Some(group)) => match present(&service, &plugin, &group).await {
            Ok(value) => support::json(
                StatusCode::OK,
                query::project_value(value, &projection),
            ),
            Err(error) => support::error_response(store_error(error)),
        },
        Ok(None) => support::error_response(ScimError::new(404, "Group not found")),
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
        "/scim/v2/Groups",
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
    let projection = match query::projection(&query, "Group") {
        Ok(projection) => projection,
        Err(error) => return support::error_response(error),
    };
    let groups = match plugin.store.list_groups(&principal.connection_id).await {
        Ok(groups) => groups,
        Err(error) => return support::error_response(store_error(error)),
    };
    let users = match plugin.store.list_users(&principal.connection_id).await {
        Ok(users) => users,
        Err(error) => return support::error_response(store_error(error)),
    };
    let values = groups
        .iter()
        .map(|group| present_with_users(&service, group, &users))
        .collect();
    let values = match query::filter(values, &query, "Group") {
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
    Path(group_id): Path<String>,
    Query(query_parameters): Query<HashMap<String, String>>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let resource = match parse_group(request, false).await {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    replace_resource(
        service,
        plugin,
        headers,
        group_id,
        resource,
        "PUT",
        query_parameters,
    )
    .await
}

pub(super) async fn patch(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Path(group_id): Path<String>,
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
        &format!("/scim/v2/Groups/{group_id}"),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let projection = match query::projection(&query_parameters, "Group") {
        Ok(projection) => projection,
        Err(error) => return support::error_response(error),
    };
    let existing = match plugin.store.find_group(&principal.connection_id, &group_id).await {
        Ok(Some(group)) => group,
        Ok(None) => return support::error_response(ScimError::new(404, "Group not found")),
        Err(error) => return support::error_response(store_error(error)),
    };
    let mut resource = existing.resource.clone();
    if let Err(error) = patch::apply(&mut resource, patch) {
        return support::error_response(error);
    }
    replace_authenticated(
        service,
        plugin,
        principal.connection_id,
        group_id,
        resource,
        projection,
    )
    .await
}

pub(super) async fn delete(
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let principal = match support::authenticate(
        &plugin,
        &headers,
        "DELETE",
        &format!("/scim/v2/Groups/{group_id}"),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match plugin.store.delete_group(&principal.connection_id, &group_id).await {
        Ok(Some(_)) => support::empty(StatusCode::NO_CONTENT),
        Ok(None) => support::error_response(ScimError::new(404, "Group not found")),
        Err(error) => support::error_response(store_error(error)),
    }
}

async fn replace_resource(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    headers: HeaderMap,
    group_id: String,
    resource: ScimGroup,
    method: &str,
    query_parameters: HashMap<String, String>,
) -> Response {
    let principal = match support::authenticate(
        &plugin,
        &headers,
        method,
        &format!("/scim/v2/Groups/{group_id}"),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let projection = match query::projection(&query_parameters, "Group") {
        Ok(projection) => projection,
        Err(error) => return support::error_response(error),
    };
    replace_authenticated(
        service,
        plugin,
        principal.connection_id,
        group_id,
        resource,
        projection,
    )
    .await
}

async fn replace_authenticated(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    connection_id: String,
    group_id: String,
    resource: ScimGroup,
    projection: query::AttributeProjection,
) -> Response {
    let mut resource = match resource.normalize() {
        Ok(resource) => resource,
        Err(error) => return support::error_response(error),
    };
    resource.id = Some(group_id.clone());
    match plugin
        .store
        .replace_group(&connection_id, &group_id, resource, Utc::now())
        .await
    {
        Ok(stored) => {
            let complete = match present(&service, &plugin, &stored).await {
                Ok(value) => value,
                Err(error) => return support::error_response(store_error(error)),
            };
            let location = complete["meta"]["location"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let value = query::project_value(complete, &projection);
            let mut response = support::json(StatusCode::OK, value);
            support::set_location(&mut response, &location, false);
            response
        }
        Err(error) => support::error_response(store_error(error)),
    }
}

#[allow(clippy::result_large_err)]
async fn parse_group(request: Request, allow_entra_legacy: bool) -> Result<ScimGroup, Response> {
    let mut value = support::parse_body::<Value>(request).await?;
    let Some(object) = value.as_object_mut() else {
        return Err(support::error_response(ScimError::typed(
            400,
            "SCIM Group body must be an object",
            ScimErrorType::InvalidValue,
        )));
    };
    if object.contains_key(ENTRA_LEGACY_GROUP_SCHEMA) {
        return Err(support::error_response(ScimError::typed(
            400,
            "The Microsoft Entra Group compatibility schema cannot contain attributes",
            ScimErrorType::InvalidValue,
        )));
    }
    if let Some(schemas) = object.get_mut("schemas").and_then(Value::as_array_mut) {
        let count = schemas
            .iter()
            .filter(|schema| schema.as_str() == Some(ENTRA_LEGACY_GROUP_SCHEMA))
            .count();
        if count > 1 {
            return Err(support::error_response(ScimError::typed(
                400,
                "The Microsoft Entra Group compatibility schema must not be duplicated",
                ScimErrorType::InvalidValue,
            )));
        }
        if count == 1 && allow_entra_legacy {
            schemas.retain(|schema| schema.as_str() != Some(ENTRA_LEGACY_GROUP_SCHEMA));
        }
    }
    serde_json::from_value(value).map_err(|error| {
        support::error_response(ScimError::typed(
            400,
            error.to_string(),
            ScimErrorType::InvalidValue,
        ))
    })
}

async fn present(
    service: &AuthService,
    plugin: &ScimPlugin,
    stored: &StoredScimGroup,
) -> Result<Value, crate::scim::ScimStoreError> {
    let users = plugin.store.list_users(&stored.connection_id).await?;
    Ok(present_with_users(service, stored, &users))
}

fn present_with_users(
    service: &AuthService,
    stored: &StoredScimGroup,
    users: &[crate::scim::store::StoredScimUser],
) -> Value {
    let mut resource = stored.resource.clone();
    let id = resource.id.clone().unwrap_or_default();
    let base = service.scim_base_url();
    for member in &mut resource.members {
        member.reference = Some(format!("{base}/scim/v2/Users/{}", member.value));
        member.display = users
            .iter()
            .find(|user| user.resource.id.as_deref() == Some(&member.value))
            .and_then(|user| user.resource.display_name.clone());
        member.kind = Some("User".into());
    }
    resource.meta = Some(crate::scim::model::ScimMeta {
        resource_type: "Group".into(),
        created: Some(stored.created_at),
        last_modified: Some(stored.updated_at),
        location: format!("{base}/scim/v2/Groups/{id}"),
    });
    serde_json::to_value(resource).unwrap_or(Value::Null)
}
