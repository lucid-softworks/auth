use super::support;
use crate::{AuthService, SsoPlugin};
use axum::{
    Extension,
    extract::Query,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::sync::Arc;

const POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const REDIRECT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MetadataQuery {
    provider_id: String,
}

pub(super) async fn metadata(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    Query(query): Query<MetadataQuery>,
) -> Response {
    let provider = match plugin
        .store()
        .find_by_provider_id(&query.provider_id)
        .await
    {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            return support::error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "No provider found for the given providerId",
            );
        }
        Err(error) => return support::storage(error),
    };
    let Some(config) = provider.saml_config.as_ref().and_then(Value::as_object) else {
        return support::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid SAML configuration",
        );
    };
    let metadata = custom_metadata(config).unwrap_or_else(|| {
        generated_metadata(
            config,
            &support::base_url(&service),
            &provider.provider_id,
            plugin.options().saml_enable_single_logout,
        )
    });
    ([(header::CONTENT_TYPE, "application/xml")], metadata).into_response()
}

fn custom_metadata(config: &Map<String, Value>) -> Option<String> {
    config
        .get("spMetadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("metadata"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn generated_metadata(
    config: &Map<String, Value>,
    base_url: &str,
    provider_id: &str,
    single_logout: bool,
) -> String {
    let sp = config.get("spMetadata").and_then(Value::as_object);
    let entity_id = sp
        .and_then(|metadata| metadata.get("entityID"))
        .and_then(Value::as_str)
        .or_else(|| config.get("issuer").and_then(Value::as_str))
        .unwrap_or_default();
    let want_assertions = boolean(config, "wantAssertionsSigned");
    let authn_signed = boolean(config, "authnRequestsSigned");
    let acs = format!("{base_url}/sso/saml2/sp/acs/{provider_id}");
    let slo = format!("{base_url}/sso/saml2/sp/slo/{provider_id}");
    let mut descriptor = format!(
        "<EntityDescriptor entityID=\"{}\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:assertion=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><SPSSODescriptor AuthnRequestsSigned=\"{authn_signed}\" WantAssertionsSigned=\"{want_assertions}\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">",
        escape(entity_id),
    );
    if let Some(format) = config.get("identifierFormat").and_then(Value::as_str) {
        descriptor.push_str(&format!("<NameIDFormat>{}</NameIDFormat>", escape(format)));
    }
    if single_logout {
        descriptor.push_str(&format!(
            "<SingleLogoutService Binding=\"{POST_BINDING}\" Location=\"{}\"></SingleLogoutService><SingleLogoutService Binding=\"{REDIRECT_BINDING}\" Location=\"{}\"></SingleLogoutService>",
            escape(&slo),
            escape(&slo),
        ));
    }
    descriptor.push_str(&format!(
        "<AssertionConsumerService index=\"0\" Binding=\"{POST_BINDING}\" Location=\"{}\"></AssertionConsumerService></SPSSODescriptor></EntityDescriptor>",
        escape(&acs),
    ));
    descriptor
}

fn boolean(config: &Map<String, Value>, field: &str) -> bool {
    config.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
