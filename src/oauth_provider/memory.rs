use super::model::{
    OAuthProviderAccessToken, OAuthProviderClient, OAuthProviderClientAssertion,
    OAuthProviderClientResource, OAuthProviderConsent, OAuthProviderRefreshToken,
    OAuthProviderResource,
};
use crate::{AuthError, DatabaseIdSupplier, PreparedDatabaseId};
use std::collections::HashMap;
use tokio::sync::RwLock;

mod assertion;
mod client;
mod consent;
#[cfg(test)]
mod id_contract_tests;
mod resource;
mod token;
#[cfg(test)]
mod token_tests;

#[derive(Default)]
pub struct MemoryOAuthProviderStore {
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    clients: HashMap<String, OAuthProviderClient>,
    resources: HashMap<String, OAuthProviderResource>,
    client_resources: HashMap<(String, String), OAuthProviderClientResource>,
    refresh_tokens: HashMap<String, OAuthProviderRefreshToken>,
    refresh_tokens_by_token: HashMap<String, String>,
    access_tokens: HashMap<String, OAuthProviderAccessToken>,
    access_tokens_by_token: HashMap<String, String>,
    consents: HashMap<String, OAuthProviderConsent>,
    client_assertions: HashMap<String, OAuthProviderClientAssertion>,
    serial_ids: HashMap<&'static str, u64>,
}

impl MemoryOAuthProviderStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn create_id(
    state: &mut State,
    model: &'static str,
    supplier: &dyn DatabaseIdSupplier,
) -> Result<String, AuthError> {
    match supplier.prepare()? {
        PreparedDatabaseId::Value(value) => Ok(value.into_output_string()),
        PreparedDatabaseId::DeferredSerial => {
            let next = state.serial_ids.entry(model).or_default();
            *next = next.saturating_add(1);
            Ok(next.to_string())
        }
        PreparedDatabaseId::Deferred => Err(AuthError::Storage(format!(
            "database adapter did not return an id for model '{model}'"
        ))),
    }
}

#[cfg(test)]
mod id_tests {
    use super::*;

    const MODELS: &[&str] = &[
        "oauthClient",
        "oauthResource",
        "oauthClientResource",
        "oauthRefreshToken",
        "oauthAccessToken",
        "oauthConsent",
        "oauthClientAssertion",
    ];

    #[test]
    fn serial_ids_are_decimal_and_scoped_per_oauth_model() {
        let mut state = State::default();
        let serial = || Ok(PreparedDatabaseId::DeferredSerial);
        for model in MODELS {
            assert_eq!(create_id(&mut state, model, &serial).unwrap(), "1");
        }
        for model in MODELS {
            assert_eq!(create_id(&mut state, model, &serial).unwrap(), "2");
        }
    }

    #[test]
    fn database_generated_ids_fail_explicitly_in_memory_for_every_oauth_model() {
        let mut state = State::default();
        let deferred = || Ok(PreparedDatabaseId::Deferred);
        for model in MODELS {
            let error = create_id(&mut state, model, &deferred).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "authentication storage failed: database adapter did not return an id for model '{model}'"
                )
            );
        }
    }

    #[test]
    fn callback_values_remain_exact_strings_for_every_oauth_model() {
        let mut state = State::default();
        for model in MODELS {
            let expected = format!("callback:{model}:not-a-uuid");
            let supplier = || {
                Ok(PreparedDatabaseId::Value(crate::DatabaseIdValue::String(
                    expected.clone(),
                )))
            };
            assert_eq!(create_id(&mut state, model, &supplier).unwrap(), expected);
        }
    }
}
