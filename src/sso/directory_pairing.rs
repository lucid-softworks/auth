use super::{SsoProviderSource, SsoUserProfilePolicy, SsoUserResolution, SsoUserResolutionInput};
use crate::{
    DashAdapterOperator, DashAdapterWhere, DatabaseTransaction, ScimTransactionContext,
    ScimUserExternalIdReference, acquire_active_scim_user_link,
};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

const REJECTION_CODE: &str = "DIRECTORY_SYNC_AUTHENTICATION_FAILED";
const REJECTION_MESSAGE: &str = "Unable to sign in with this SSO connection";

pub(super) async fn resolve(
    input: &SsoUserResolutionInput,
    database: Arc<dyn DatabaseTransaction>,
) -> Result<SsoUserResolution, crate::AuthError> {
    let (provider_id, source, protocol) = input_identity(input);
    let SsoProviderSource::Persisted { record_id } = source else {
        return Ok(SsoUserResolution::Continue);
    };
    let rows = database
        .find_records(
            "directorySyncConnection",
            &[
                equal("ssoProviderRecordId", json!(record_id)),
                equal("ssoProviderId", json!(provider_id)),
                equal("pairingEnforced", json!(true)),
            ],
            None,
            0,
            None,
            &[],
        )
        .await?;
    if rows.is_empty() {
        return Ok(SsoUserResolution::Continue);
    }
    if rows.len() != 1 {
        return Ok(rejection());
    }
    resolve_row(input, database, &rows[0], record_id, provider_id, protocol).await
}

async fn resolve_row(
    input: &SsoUserResolutionInput,
    database: Arc<dyn DatabaseTransaction>,
    row: &Map<String, Value>,
    record_id: &str,
    provider_id: &str,
    protocol: &str,
) -> Result<SsoUserResolution, crate::AuthError> {
    if string(row, "status") != Some("active")
        || string(row, "activeSsoProviderKey") != Some(&active_key(record_id))
    {
        return Ok(rejection());
    }
    let pairing = row
        .get("serializedSsoPairing")
        .and_then(Value::as_str)
        .and_then(|value| serde_json::from_str::<Value>(value).ok());
    let Some(pairing) = pairing.as_ref().and_then(Value::as_object) else {
        return Ok(rejection());
    };
    if string(pairing, "ssoProviderId") != Some(provider_id)
        || string(pairing, "protocol") != Some(protocol)
    {
        return Ok(rejection());
    }
    let Some(connection_id) = string(row, "connectionId") else {
        return Ok(rejection());
    };
    let Some(external_id) = external_id(input, pairing) else {
        return Ok(rejection());
    };
    let link = acquire_active_scim_user_link(
        ScimUserExternalIdReference {
            connection_id: connection_id.into(),
            external_id,
        },
        ScimTransactionContext { database },
    )
    .await;
    Ok(match link {
        Ok(Some(link)) => SsoUserResolution::Link {
            user_id: link.user_id,
            profile: SsoUserProfilePolicy::Preserve,
        },
        _ => rejection(),
    })
}

fn input_identity(input: &SsoUserResolutionInput) -> (&str, &SsoProviderSource, &'static str) {
    match input {
        SsoUserResolutionInput::Oidc {
            provider_id,
            provider_reference,
            ..
        } => (provider_id, &provider_reference.source, "oidc"),
        SsoUserResolutionInput::Saml {
            provider_id,
            provider_reference,
            ..
        } => (provider_id, &provider_reference.source, "saml"),
    }
}

fn external_id(input: &SsoUserResolutionInput, pairing: &Map<String, Value>) -> Option<String> {
    let source = pairing.get("externalIdSource")?.as_object()?;
    let kind = string(source, "kind")?;
    match input {
        SsoUserResolutionInput::Oidc {
            account_id,
            ..
        } if kind == "subject" => nonempty(account_id),
        SsoUserResolutionInput::Oidc {
            verified_id_token_claims,
            ..
        } if kind == "verifiedIdTokenClaim" => {
            verified_id_token_claims.get(string(source, "name")?).and_then(scalar)
        }
        SsoUserResolutionInput::Saml { account_id, .. } if kind == "nameId" => nonempty(account_id),
        SsoUserResolutionInput::Saml {
            provider_attributes,
            ..
        } if kind == "attribute" => provider_attributes.get(string(source, "name")?).and_then(saml_scalar),
        _ => None,
    }
}

fn scalar(value: &Value) -> Option<String> {
    value.as_str().and_then(nonempty)
}

fn saml_scalar(value: &Value) -> Option<String> {
    scalar(value).or_else(|| {
        let values = value.as_array()?;
        (values.len() == 1).then(|| scalar(&values[0])).flatten()
    })
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn string<'a>(row: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    row.get(field).and_then(Value::as_str)
}

fn active_key(record_id: &str) -> String {
    format!("directory-sync-sso-active:{}", hex::encode(Sha256::digest(record_id.as_bytes())))
}

fn equal(field: &str, value: Value) -> DashAdapterWhere {
    DashAdapterWhere {
        field: field.into(),
        value,
        operator: DashAdapterOperator::Eq,
        connector: None,
    }
}

fn rejection() -> SsoUserResolution {
    SsoUserResolution::Reject {
        code: REJECTION_CODE.into(),
        message: Some(REJECTION_MESSAGE.into()),
    }
}
