use super::{query, support};
use crate::{
    AuthService,
    scim::{
        SCIM_GROUP_SCHEMA, ScimError, ScimErrorType, ScimGroup, ScimGroupMember,
        ScimListResponse, ScimPatchRequest, ScimPlugin, plugin::store_error,
        store::StoredScimGroup,
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

const ENTRA_LEGACY_GROUP_SCHEMA: &str =
    "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group";

pub(super) async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
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
            let value = present(&service, &stored);
            let location = value["meta"]["location"].as_str().unwrap_or_default().to_owned();
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
    match plugin.store.find_group(&principal.connection_id, &group_id).await {
        Ok(Some(group)) => support::json(
            StatusCode::OK,
            query::project_value(present(&service, &group), &query),
        ),
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
    let groups = match plugin.store.list_groups(&principal.connection_id).await {
        Ok(groups) => groups,
        Err(error) => return support::error_response(store_error(error)),
    };
    let values = groups.iter().map(|group| present(&service, group)).collect();
    let values = match query::filter(values, &query, "Group") {
        Ok(values) => values,
        Err(error) => return support::error_response(error),
    };
    let (total, values) = query::page(values, pagination);
    let values = values
        .into_iter()
        .map(|value| query::project_value(value, &query))
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
    headers: HeaderMap,
    request: Request,
) -> Response {
    let resource = match parse_group(request, false).await {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    replace_resource(service, plugin, headers, group_id, resource, "PUT").await
}

pub(super) async fn patch(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Path(group_id): Path<String>,
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
    let existing = match plugin.store.find_group(&principal.connection_id, &group_id).await {
        Ok(Some(group)) => group,
        Ok(None) => return support::error_response(ScimError::new(404, "Group not found")),
        Err(error) => return support::error_response(store_error(error)),
    };
    let mut resource = existing.resource.clone();
    if let Err(error) = apply_patch(&mut resource, patch) {
        return support::error_response(error);
    }
    replace_authenticated(service, plugin, principal.connection_id, group_id, resource).await
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
    replace_authenticated(service, plugin, principal.connection_id, group_id, resource).await
}

async fn replace_authenticated(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    connection_id: String,
    group_id: String,
    resource: ScimGroup,
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
            let value = present(&service, &stored);
            let location = value["meta"]["location"].as_str().unwrap_or_default().to_owned();
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

fn apply_patch(resource: &mut ScimGroup, patch: ScimPatchRequest) -> Result<(), ScimError> {
    for operation in patch.operations {
        let op = operation.op.to_ascii_lowercase();
        if !matches!(op.as_str(), "add" | "replace" | "remove") {
            return Err(ScimError::typed(400, "Invalid PATCH operation", ScimErrorType::InvalidSyntax));
        }
        let path = operation.path.as_deref().map(str::trim).filter(|path| !path.is_empty());
        if path.is_none() {
            if op == "remove" {
                return Err(ScimError::typed(400, "Pathless remove has no target", ScimErrorType::NoTarget));
            }
            let value = operation.value.and_then(|value| value.as_object().cloned()).ok_or_else(|| {
                ScimError::typed(400, "Pathless PATCH value must be an object", ScimErrorType::InvalidValue)
            })?;
            if let Some(display_name) = value.get("displayName").and_then(Value::as_str) {
                resource.display_name = display_name.into();
            }
            if let Some(external_id) = value.get("externalId").and_then(Value::as_str) {
                resource.external_id = Some(external_id.into());
            }
            if let Some(members) = value.get("members") {
                resource.members = serde_json::from_value(members.clone()).map_err(invalid_patch)?;
            }
            continue;
        }
        let path = path.unwrap();
        let lower = path.to_ascii_lowercase();
        if lower.starts_with("members[") {
            let value = path
                .split_once(" eq ")
                .or_else(|| path.split_once(" EQ "))
                .and_then(|(_, value)| value.split(']').next())
                .map(|value| value.trim().trim_matches('"'))
                .ok_or_else(|| ScimError::typed(400, "Invalid members filter", ScimErrorType::InvalidPath))?;
            if op == "remove" {
                resource.members.retain(|member| member.value != value);
            } else {
                return Err(ScimError::typed(400, "Filtered Group member targets support remove", ScimErrorType::InvalidPath));
            }
            continue;
        }
        match lower.as_str() {
            "displayname" if op == "remove" => {
                return Err(ScimError::typed(400, "displayName is required", ScimErrorType::Mutability));
            }
            "displayname" => resource.display_name = string_value(operation.value)?,
            "externalid" if op == "remove" => resource.external_id = None,
            "externalid" => resource.external_id = Some(string_value(operation.value)?),
            "members" if op == "remove" => resource.members.clear(),
            "members" if op == "add" => {
                let mut additions: Vec<ScimGroupMember> = serde_json::from_value(operation.value.unwrap_or(Value::Null)).map_err(invalid_patch)?;
                resource.members.append(&mut additions);
            }
            "members" => resource.members = serde_json::from_value(operation.value.unwrap_or(Value::Null)).map_err(invalid_patch)?,
            "id" | "meta" | "schemas" => return Err(ScimError::typed(400, "PATCH target is read-only", ScimErrorType::Mutability)),
            _ => return Err(ScimError::typed(400, "Unsupported SCIM Group PATCH path", ScimErrorType::InvalidPath)),
        }
    }
    resource.schemas = vec![SCIM_GROUP_SCHEMA.into()];
    Ok(())
}

fn string_value(value: Option<Value>) -> Result<String, ScimError> {
    value.and_then(|value| value.as_str().map(str::to_owned)).ok_or_else(|| {
        ScimError::typed(400, "PATCH value must be a string", ScimErrorType::InvalidValue)
    })
}

fn invalid_patch(error: serde_json::Error) -> ScimError {
    ScimError::typed(400, error.to_string(), ScimErrorType::InvalidValue)
}

fn present(service: &AuthService, stored: &StoredScimGroup) -> Value {
    let mut resource = stored.resource.clone();
    let id = resource.id.clone().unwrap_or_default();
    let base = service.scim_base_url();
    for member in &mut resource.members {
        member.reference = Some(format!("{base}/scim/v2/Users/{}", member.value));
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
