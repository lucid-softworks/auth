use super::model::{
    OAuthProviderAccessToken, OAuthProviderClient, OAuthProviderClientAssertion,
    OAuthProviderClientResource, OAuthProviderConsent, OAuthProviderRefreshToken,
    OAuthProviderResource,
};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

mod assertion;
mod client;
mod consent;
mod resource;
mod token;

#[derive(Default)]
pub struct MemoryOAuthProviderStore {
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    clients: HashMap<String, OAuthProviderClient>,
    resources: HashMap<String, OAuthProviderResource>,
    client_resources: HashMap<(String, String), OAuthProviderClientResource>,
    refresh_tokens: HashMap<Uuid, OAuthProviderRefreshToken>,
    refresh_tokens_by_token: HashMap<String, Uuid>,
    access_tokens: HashMap<Uuid, OAuthProviderAccessToken>,
    access_tokens_by_token: HashMap<String, Uuid>,
    consents: HashMap<Uuid, OAuthProviderConsent>,
    client_assertions: HashMap<String, OAuthProviderClientAssertion>,
}

impl MemoryOAuthProviderStore {
    pub fn new() -> Self {
        Self::default()
    }
}
