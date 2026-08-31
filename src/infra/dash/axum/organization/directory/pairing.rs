use crate::{AuthService, DashPlugin, SsoProvider};
use axum::{http::StatusCode, response::Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DirectoryPairing {
    pub sso_provider_id: String,
    pub protocol: PairingProtocol,
    pub external_id_source: ExternalIdSource,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PairingProtocol {
    Oidc,
    Saml,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum ExternalIdSource {
    Subject,
    VerifiedIdTokenClaim { name: String },
    NameId,
    Attribute { name: String },
}

pub(super) struct ResolvedPairing {
    pub pairing: DirectoryPairing,
    pub provider: SsoProvider,
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(super) async fn resolve(
    service: &AuthService,
    dash: &DashPlugin,
    organization_id: &str,
    pairing: DirectoryPairing,
) -> Result<ResolvedPairing, Response> {
    if !dash.options().managed_directory_sync.sso_pairing {
        return Err(bad_request("Paired directory sync is disabled"));
    }
    validate(&pairing)?;
    let Some(sso) = service.sso_plugin() else {
        return Err(bad_request("Paired directory sync requires the SSO plugin"));
    };
    let provider = sso
        .store()
        .find_by_provider_id(&pairing.sso_provider_id)
        .await
        .map_err(|error| super::super::support::route_error(crate::AuthError::SsoStore(error)))?
        .filter(|provider| provider.organization_id.as_deref() == Some(organization_id))
        .ok_or_else(|| bad_request("The selected SSO provider is not available"))?;
    match pairing.protocol {
        PairingProtocol::Oidc if provider.oidc_config.is_none() || provider.saml_config.is_some() => {
            return Err(bad_request("The selected SSO provider is not an OIDC provider"));
        }
        PairingProtocol::Saml if provider.saml_config.is_none() || provider.oidc_config.is_some() => {
            return Err(bad_request("The selected SSO provider is not a SAML provider"));
        }
        PairingProtocol::Saml if !requires_signed_assertions(&provider) => {
            return Err(bad_request("Paired SAML providers must require cryptographically signed assertions"));
        }
        _ => {}
    }
    Ok(ResolvedPairing { pairing, provider })
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
fn validate(pairing: &DirectoryPairing) -> Result<(), Response> {
    let provider_length = pairing.sso_provider_id.trim().len();
    if provider_length == 0 || provider_length > 255 {
        return Err(bad_request("The selected SSO provider is not available"));
    }
    let source_matches = matches!(
        (&pairing.protocol, &pairing.external_id_source),
        (PairingProtocol::Oidc, ExternalIdSource::Subject)
            | (PairingProtocol::Oidc, ExternalIdSource::VerifiedIdTokenClaim { .. })
            | (PairingProtocol::Saml, ExternalIdSource::NameId)
            | (PairingProtocol::Saml, ExternalIdSource::Attribute { .. })
    );
    if !source_matches {
        return Err(bad_request("SSO pairing protocol and external ID source do not match"));
    }
    let name = match &pairing.external_id_source {
        ExternalIdSource::VerifiedIdTokenClaim { name } | ExternalIdSource::Attribute { name } => {
            Some(name.trim())
        }
        _ => None,
    };
    if name.is_some_and(|name| name.is_empty() || name.len() > 255) {
        return Err(bad_request("SSO pairing external ID claim is invalid"));
    }
    Ok(())
}

fn requires_signed_assertions(provider: &SsoProvider) -> bool {
    let Some(config) = provider.saml_config.as_ref().and_then(Value::as_object) else {
        return false;
    };
    if config.get("wantAssertionsSigned") == Some(&Value::Bool(true)) {
        return true;
    }
    config
        .get("spMetadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("metadata"))
        .and_then(Value::as_str)
        .is_some_and(|metadata| {
            metadata.contains("WantAssertionsSigned=\"true\"")
                || metadata.contains("WantAssertionsSigned=\"1\"")
        })
}

fn bad_request(message: &'static str) -> Response {
    super::super::support::error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
}
