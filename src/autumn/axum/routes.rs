use super::route_table::{ROUTES, RouteOperation};
use super::{AutumnRouteState, support};
use crate::{
    AxumPluginRoute,
    autumn::{AutumnCustomerScope, AutumnIdentity, AutumnOperation, schema::normalize_public},
};
use axum::{
    Extension,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use serde_json::{Map, Value};
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<crate::AuthService>,
    state: AutumnRouteState,
) -> Vec<AxumPluginRoute> {
    ROUTES
        .iter()
        .map(|(path, operation)| {
            let handler: axum::routing::MethodRouter = if operation.optional_body {
                post(handle_optional)
            } else {
                post(handle_required)
            };
            AxumPluginRoute::new(
                *path,
                handler
                    .layer::<_, std::convert::Infallible>(Extension(*operation))
                    .layer::<_, std::convert::Infallible>(Extension(state.clone())),
            )
        })
        .collect()
}

async fn handle_required(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<AutumnRouteState>,
    Extension(operation): Extension<RouteOperation>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    handle(service, state, operation, headers, body).await
}

async fn handle_optional(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<AutumnRouteState>,
    Extension(operation): Extension<RouteOperation>,
    headers: HeaderMap,
    super::input::OptionalAutumnBody(body): super::input::OptionalAutumnBody,
) -> Response {
    handle(service, state, operation, headers, body).await
}

async fn handle(
    service: Arc<crate::AuthService>,
    state: AutumnRouteState,
    operation: RouteOperation,
    headers: HeaderMap,
    body: Value,
) -> Response {
    let body = match normalize_public(body, operation.schema) {
        Ok(body) => body,
        Err(error) => {
            return support::validation_error(error.public_message());
        }
    };

    let session = support::optional_session(&service, &headers).await;
    let organization = support::active_organization(&service, session.as_ref()).await;

    let Some(secret_key) = state.options.resolved_secret_key() else {
        return support::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no_secret_key",
            "Autumn secret key not found in ENV variables or passed into autumnHandler",
        );
    };

    let identity = match resolve_identity(&state, session.as_ref(), organization.as_ref()).await {
        Ok(identity) => identity,
        Err(error) => {
            tracing::error!(message = %error, "Autumn identity callback failed");
            return support::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.message(),
            );
        }
    };

    let request = match prepare_request(operation.transport, body, identity) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let base_url = match state.options.resolved_base_url() {
        Ok(base_url) => base_url,
        Err(error) => {
            tracing::error!(message = %error, "Autumn base URL was invalid");
            return support::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            );
        }
    };

    match state
        .client
        .execute(operation.transport, request, &secret_key, &base_url)
        .await
    {
        Ok(value) => support::success(value),
        Err(error) => provider_error(error),
    }
}

async fn resolve_identity(
    state: &AutumnRouteState,
    session: Option<&crate::SessionWithUser>,
    organization: Option<&crate::Organization>,
) -> Result<Option<AutumnIdentity>, crate::autumn::AutumnIdentityError> {
    if let Some(identify) = &state.options.identify {
        return identify.identify(session, organization).await;
    }
    let Some(session) = session else {
        return Ok(None);
    };
    let user_identity = || {
        let mut customer_data = Map::new();
        customer_data.insert("name".into(), Value::String(session.user.name.clone()));
        customer_data.insert("email".into(), Value::String(session.user.email.clone()));
        AutumnIdentity::new(session.user.id.to_string()).with_customer_data(customer_data)
    };
    let organization_identity = || {
        organization.map(|organization| {
            let mut customer_data = Map::new();
            customer_data.insert("name".into(), Value::String(organization.name.clone()));
            AutumnIdentity::new(organization.id.to_string()).with_customer_data(customer_data)
        })
    };

    Ok(match state.options.customer_scope {
        AutumnCustomerScope::User => Some(user_identity()),
        AutumnCustomerScope::Organization => organization_identity(),
        AutumnCustomerScope::UserAndOrganization => {
            organization_identity().or_else(|| Some(user_identity()))
        }
    })
}

fn prepare_request(
    operation: AutumnOperation,
    body: Value,
    identity: Option<AutumnIdentity>,
) -> Result<Value, Box<Response>> {
    let mut request = support::object(body);
    strip_protected_fields(
        &mut request,
        operation == AutumnOperation::GetOrCreateCustomer,
    );

    if operation == AutumnOperation::GetOrCreateCustomer {
        let error_on_not_found = request
            .get("errorOnNotFound")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let Some(identity) = identity else {
            if error_on_not_found {
                return Err(Box::new(support::error_response(
                    StatusCode::UNAUTHORIZED,
                    "no_customer_id",
                    "customerId not found",
                )));
            }
            return Err(Box::new(support::success(Value::Null)));
        };
        request.insert("customerId".into(), Value::String(identity.customer_id));
        if let Some(customer_data) = identity.customer_data {
            request.extend(customer_data);
        }
        let expand = request
            .entry("expand")
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(expand) = expand {
            expand.push(Value::String("balances.feature".into()));
        }
        return Ok(Value::Object(request));
    }

    if let Some(identity) = identity {
        request.insert("customerId".into(), Value::String(identity.customer_id));
    } else if operation != AutumnOperation::ListPlans {
        return Err(Box::new(support::error_response(
            StatusCode::UNAUTHORIZED,
            "no_customer_id",
            "customerId returned from identify function is null",
        )));
    }
    Ok(Value::Object(request))
}

fn strip_protected_fields(request: &mut Map<String, Value>, get_or_create: bool) {
    for key in ["customerId", "customerData", "name", "email", "stripeId"] {
        request.remove(key);
    }
    if get_or_create {
        request.remove("metadata");
    }
}

fn provider_error(error: crate::autumn::AutumnProviderError) -> Response {
    tracing::error!(message = %error, "Autumn provider request failed");
    let status = error
        .status
        .and_then(|status| StatusCode::from_u16(status).ok())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    support::error_response(status, error.code, error.message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn route_registry_is_exact_and_all_post() {
        assert_eq!(ROUTES.len(), 15);
        assert_eq!(ROUTES[0].0, "/autumn/getOrCreateCustomer");
        assert_eq!(ROUTES[14].0, "/autumn/setupPayment");
        assert_eq!(
            ROUTES
                .iter()
                .filter(|(_, route)| route.optional_body)
                .count(),
            2
        );
    }

    #[test]
    fn public_customer_fields_are_removed_before_trusted_identity_is_injected() {
        let request = prepare_request(
            AutumnOperation::Attach,
            json!({
                "customerId": "attacker",
                "customerData": {"customerId": "attacker"},
                "name": "attacker",
                "email": "attacker@example.com",
                "stripeId": "stripe_attacker",
                "planId": "pro"
            }),
            Some(AutumnIdentity::new("trusted")),
        )
        .unwrap();
        assert_eq!(request["customerId"], "trusted");
        assert_eq!(request["planId"], "pro");
        assert!(request.get("name").is_none());
        assert!(request.get("customerData").is_none());
    }

    #[test]
    fn get_or_create_appends_expand_and_preserves_trusted_override_quirk() {
        let mut customer_data = Map::new();
        customer_data.insert("customerId".into(), json!("callback-override"));
        customer_data.insert("metadata".into(), json!({"trusted": true}));
        let request = prepare_request(
            AutumnOperation::GetOrCreateCustomer,
            json!({
                "customerId": "attacker",
                "metadata": {"attacker": true},
                "expand": ["balances.feature"]
            }),
            Some(AutumnIdentity::new("resolved").with_customer_data(customer_data)),
        )
        .unwrap();

        assert_eq!(request["customerId"], "callback-override");
        assert_eq!(request["metadata"], json!({"trusted": true}));
        assert_eq!(
            request["expand"],
            json!(["balances.feature", "balances.feature"])
        );
    }

    #[test]
    fn list_plans_can_proceed_without_identity_but_other_routes_cannot() {
        assert_eq!(
            prepare_request(AutumnOperation::ListPlans, Value::Null, None).unwrap(),
            json!({})
        );
        assert!(prepare_request(AutumnOperation::ListEvents, Value::Null, None).is_err());
    }
}
