use super::AuthService;
use crate::AuthError;
use std::collections::BTreeSet;

impl AuthService {
    pub(crate) async fn sign_out_with_provider_logout(
        &self,
        token: &str,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
    ) -> Result<Option<String>, AuthError> {
        let current = self.find_stored_session(token).await?;
        self.sign_out(token).await?;
        let Some(current) = current else {
            return Ok(None);
        };
        let mut accounts = self.store.list_user_accounts(&current.user.id).await?;
        accounts.sort_by_key(|account| std::cmp::Reverse(account.updated_at));
        let mut seen = BTreeSet::new();
        for account in accounts {
            if !seen.insert(account.provider_id.clone()) {
                continue;
            }
            let Some(provider) = self.social_provider_for_logout(&account.provider_id) else {
                continue;
            };
            let Some(base_url) = self.config.base_url() else {
                continue;
            };
            let requested_redirect = post_logout_redirect_uri
                .filter(|redirect| !redirect.is_empty())
                .and_then(|redirect| base_url.join(redirect).ok())
                .map(String::from);
            let id_token = account.id_token;
            if let Ok(Some(url)) = provider
                .create_end_session_url(
                    id_token.as_deref(),
                    requested_redirect.as_deref(),
                    state,
                    base_url,
                )
                .await
            {
                return Ok(Some(url.into()));
            }
        }
        Ok(None)
    }
}
