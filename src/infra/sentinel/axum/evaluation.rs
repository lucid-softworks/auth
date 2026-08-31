use super::{contract, email, stale::StaleAccountBlocked};
use crate::infra::{dash::IdentificationContext, sentinel::SentinelPlugin};
use crate::infra::sentinel::events::SecurityCheckObservation;
use axum::response::Response;
use serde_json::{Value, json};

pub(super) struct Evaluation {
    outcome: &'static str,
    checks: Vec<&'static str>,
    triggered_by: Option<&'static str>,
    details: Option<Value>,
    identifier: Option<String>,
    user_agent: Option<String>,
}

pub(super) fn prepare(
    plugin: &SentinelPlugin,
    request: &crate::PluginRequestContext,
    identification: &IdentificationContext,
    response: &Response,
) -> Option<Evaluation> {
    if request.method.eq_ignore_ascii_case("GET") {
        return None;
    }
    let body = request.body.as_ref();
    let checks = evaluated_checks(plugin, request, identification, response);
    let (outcome, triggered_by, details) = outcome(response);
    Some(Evaluation {
        outcome,
        checks,
        triggered_by,
        details,
        identifier: contract::request_identifier(body),
        user_agent: request.headers.get("user-agent").cloned(),
    })
}

fn evaluated_checks(
    plugin: &SentinelPlugin,
    request: &crate::PluginRequestContext,
    identification: &IdentificationContext,
    response: &Response,
) -> Vec<&'static str> {
    let body = request.body.as_ref();
    let mut checks = Vec::new();
    if email::is_email_path(&request.path)
        && super::super::email_validation_enabled(&plugin.options().security)
    {
        checks.push("email_validity");
    }
    if contract::is_protected(&request.path) {
        if identification.visitor_id.is_some() || identification.ip.is_some() {
            checks.push("credential_stuffing");
        }
        if response_message(response)
            != Some("Too many failed attempts. Please try again later.")
        {
            checks.push("server_security_check");
        }
    }
    if contract::checks_breached_password(&request.path)
        && contract::password_to_check(body).is_some()
        && plugin
            .options()
            .security
            .compromised_password
            .as_ref()
            .is_some_and(|options| options.enabled)
    {
        checks.push("compromised_password");
    }
    if request.path == "/sign-up/email"
        && plugin
            .options()
            .security
            .free_trial_abuse
            .as_ref()
            .is_some_and(|options| options.enabled)
    {
        checks.push("free_trial_abuse");
    }
    if response
        .extensions()
        .get::<crate::axum::http::BoundSession>()
        .is_some()
        && plugin
            .options()
            .security
            .impossible_travel
            .as_ref()
            .is_some_and(|options| options.enabled)
    {
        checks.push("impossible_travel");
    }
    if response.extensions().get::<StaleAccountBlocked>().is_some()
        || (response
            .extensions()
            .get::<crate::axum::http::BoundSession>()
            .is_some()
            && plugin
                .options()
                .security
                .stale_users
                .as_ref()
                .is_some_and(|options| options.enabled))
    {
        checks.push("stale_users");
    }
    if response.headers().contains_key("x-pow-challenge") {
        checks.push("pow_challenge");
    }
    checks
}

impl Evaluation {
    pub(super) async fn emit(
        self,
        plugin: &SentinelPlugin,
        request: &crate::PluginRequestContext,
        identification: &IdentificationContext,
    ) {
        plugin
            .security_client()
            .track_security_check(SecurityCheckObservation {
                identification,
                path: &request.path,
                identifier: self.identifier.as_deref(),
                user_agent: self.user_agent.as_deref(),
                outcome: self.outcome,
                checks: &self.checks,
                triggered_by: self.triggered_by,
                details: self.details,
            })
            .await;
    }
}

fn outcome(response: &Response) -> (&'static str, Option<&'static str>, Option<Value>) {
    if response.headers().contains_key("x-pow-challenge") {
        return (
            "challenged",
            Some("server_security_check"),
            Some(json!({ "reason": response
                .headers()
                .get("x-pow-reason")
                .and_then(|value| value.to_str().ok()) })),
        );
    }
    if !response.status().is_client_error() && !response.status().is_server_error() {
        return ("passed", None, None);
    }
    let message = response_message(response);
    let triggered_by = if response.extensions().get::<StaleAccountBlocked>().is_some() {
        "stale_users"
    } else if message == Some("Invalid email")
        || message == Some("Disposable email addresses are not allowed")
        || message == Some("This email domain cannot receive emails")
        || message == Some("This email address appears to be invalid")
    {
        "email_validity"
    } else if message
        == Some("This password has been found in data breaches. Please choose a different password.")
    {
        "compromised_password"
    } else if message == Some("Too many failed attempts. Please try again later.") {
        "credential_stuffing"
    } else {
        "server_security_check"
    };
    (
        "blocked",
        Some(triggered_by),
        Some(json!({ "reason": triggered_by })),
    )
}

fn response_message(response: &Response) -> Option<&str> {
    response
        .extensions()
        .get::<crate::axum::ApiErrorResponse>()
        .map(|error| error.message.as_str())
}
