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
use chrono::Utc;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};

mod patch;

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
        "/scim/v2/Users",
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let resource = match support::parse_body::<ScimUser>(request).await {
        Ok(resource) => match resource.normalize() {
            Ok(resource) => resource,
            Err(error) => return support::error_response(error),
        },
        Err(response) => return response,
    };
    let auth_user = match service
        .scim_create_user(
            resource.primary_email().to_owned(),
            resource.display_name.clone().unwrap_or_default(),
        )
        .await
    {
        Ok(user) => user,
        Err(error) => {
            return support::error_response(ScimError::typed(
                409,
                error.to_string(),
                ScimErrorType::Uniqueness,
            ));
        }
    };
    let now = Utc::now();
    let mut resource = resource;
    resource.id = Some(super::super::random_urlsafe(32));
    let stored = StoredScimUser {
        resource,
        connection_id: principal.connection_id,
        provisioning_domain_id: principal.provisioning_domain_id,
        user_id: auth_user.id.clone(),
        profile_managed: true,
        created_at: now,
        updated_at: now,
    };
    match plugin.store.create_user(stored).await {
        Ok(stored) => {
            let value = present(&service, &stored);
            let location = value["meta"]["location"].as_str().unwrap_or_default().to_owned();
            let mut response = support::json(StatusCode::CREATED, value);
            support::set_location(&mut response, &location, true);
            response
        }
        Err(error) => {
            service.scim_rollback_created_user(&auth_user).await;
            support::error_response(store_error(error))
        }
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
    headers: HeaderMap,
    request: Request,
) -> Response {
    let resource = match support::parse_body::<ScimUser>(request).await {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    replace_resource(service, plugin, headers, user_id, resource, "PUT").await
}

pub(super) async fn patch(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<ScimPlugin>>,
    Path(user_id): Path<String>,
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
    replace_authenticated(service, plugin, principal.connection_id, user_id, resource).await
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
    match plugin
        .store
        .delete_user(&principal.connection_id, &user_id, Utc::now())
        .await
    {
        Ok(Some(user)) => {
            let _ = service.scim_revoke_user_sessions(&user.user_id).await;
            support::empty(StatusCode::NO_CONTENT)
        }
        Ok(None) => support::error_response(ScimError::new(404, "User not found")),
        Err(error) => support::error_response(store_error(error)),
    }
}

async fn replace_resource(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    headers: HeaderMap,
    user_id: String,
    resource: ScimUser,
    method: &str,
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
    replace_authenticated(service, plugin, principal.connection_id, user_id, resource).await
}

async fn replace_authenticated(
    service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
    connection_id: String,
    user_id: String,
    resource: ScimUser,
) -> Response {
    let mut resource = match resource.normalize() {
        Ok(resource) => resource,
        Err(error) => return support::error_response(error),
    };
    let existing = match plugin.store.find_user(&connection_id, &user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return support::error_response(ScimError::new(404, "User not found")),
        Err(error) => return support::error_response(store_error(error)),
    };
    resource.id = Some(user_id.clone());
    let old_email = existing.resource.primary_email().to_owned();
    let new_email = resource.primary_email().to_owned();
    let new_name = resource.display_name.clone().unwrap_or_default();
    let active_changed_to_false = existing.resource.active && !resource.active;
    match plugin
        .store
        .replace_user(&connection_id, &user_id, resource, Utc::now())
        .await
    {
        Ok(stored) => {
            if stored.profile_managed {
                let _ = service
                    .scim_update_user_profile(&stored.user_id, new_name, &old_email, new_email)
                    .await;
            }
            if active_changed_to_false {
                let _ = service.scim_revoke_user_sessions(&stored.user_id).await;
            }
            let value = present(&service, &stored);
            let location = value["meta"]["location"].as_str().unwrap_or_default().to_owned();
            let mut response = support::json(StatusCode::OK, value);
            support::set_location(&mut response, &location, false);
            response
        }
        Err(error) => support::error_response(store_error(error)),
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
