use super::AuthService;
use crate::{
    AuthError, AuthUser, DatabaseCreate, DatabaseIdInput, OAuthAccount, SiweError,
    SiweIdentityWrite, SiweIdentityWriteOutcome, VerificationValue, WalletAddress,
};
use chrono::{Duration, Utc};

const EMAIL_CLAIM_IDENTIFIER_PREFIX: &str = "siwe-email-claim-";

struct SiweEmailChoice {
    wallet: String,
    preferred: String,
    claim: Option<String>,
}

impl AuthService {
    pub(super) async fn resolve_siwe_user(
        &self,
        address: &str,
        chain_id: f64,
        supplied_email: Option<&str>,
        _request_base_origin: Option<&str>,
    ) -> Result<AuthUser, AuthError> {
        if let Some(user) = self.existing_siwe_user(address, chain_id).await? {
            return Ok(user);
        }
        let email = self.siwe_email_choice(address, supplied_email).await?;
        let profile = self.siwe_ens_profile(address).await?;
        let result = self
            .create_siwe_user(address, chain_id, email.preferred.clone(), profile.clone())
            .await;
        let resolved = match result {
            Ok(user) => Ok(user),
            Err(error) if email.preferred != email.wallet => {
                match self.store.find_user_by_email(&email.preferred).await {
                    Ok(Some(_)) => {
                        self.create_siwe_user(address, chain_id, email.wallet, profile)
                            .await
                    }
                    Ok(None) => Err(error),
                    Err(find_error) => Err(find_error),
                }
            }
            Err(error) => Err(error),
        };
        self.release_siwe_email_claim(email.claim.as_deref()).await;
        resolved
    }

    async fn existing_siwe_user(
        &self,
        address: &str,
        chain_id: f64,
    ) -> Result<Option<AuthUser>, AuthError> {
        let plugin = self.siwe_plugin()?;
        if let Some(owner) = plugin
            .store
            .find_wallet_owner(&plugin.config.schema, address, Some(chain_id))
            .await?
        {
            return Ok(Some(owner.user));
        }
        let Some(owner) = plugin
            .store
            .find_wallet_owner(&plugin.config.schema, address, None)
            .await?
        else {
            return Ok(None);
        };
        self.write_siwe_identity(SiweIdentityWrite::AddChain {
            expected_user_id: owner.user.id.clone(),
            wallet: self.wallet_create(owner.user.id.clone(), address, chain_id, false)?,
            account: self
                .prepare_account_create(siwe_account(owner.user.id, address, chain_id))
                .await?,
        })
        .await
        .map(Some)
    }

    async fn siwe_email_choice(
        &self,
        address: &str,
        supplied_email: Option<&str>,
    ) -> Result<SiweEmailChoice, AuthError> {
        let wallet = self.siwe_wallet_email(address)?;
        if self.siwe_plugin()?.config.anonymous {
            return Ok(SiweEmailChoice {
                preferred: wallet.clone(),
                wallet,
                claim: None,
            });
        }
        let email = supplied_email
            .ok_or(SiweError::EmailRequired)?
            .to_lowercase();
        let claimed = self
            .reserve_siwe_email(&email, address)
            .await
            .unwrap_or(false);
        let available = claimed && self.store.find_user_by_email(&email).await?.is_none();
        Ok(SiweEmailChoice {
            preferred: if available {
                email.clone()
            } else {
                wallet.clone()
            },
            wallet,
            claim: claimed.then_some(email),
        })
    }

    async fn release_siwe_email_claim(&self, email: Option<&str>) {
        let Some(email) = email else {
            return;
        };
        let _ = self
            .consume_verification_value(
                &format!("{EMAIL_CLAIM_IDENTIFIER_PREFIX}{email}"),
                Utc::now(),
            )
            .await;
    }

    async fn create_siwe_user(
        &self,
        address: &str,
        chain_id: f64,
        email: String,
        profile: crate::SiweEnsProfile,
    ) -> Result<AuthUser, AuthError> {
        let now = Utc::now();
        let user = self
            .prepare_user_create(AuthUser {
                id: String::new(),
                username: None,
                display_username: None,
                name: profile.name.unwrap_or_else(|| address.into()),
                email,
                email_verified: false,
                image: Some(profile.avatar.unwrap_or_default()),
                additional_fields: serde_json::Map::new(),
                role: self.default_user_role(),
                is_anonymous: false,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            })
            .await?;
        let account = self.oauth_account_create(siwe_account(String::new(), address, chain_id));
        let outcome = self
            .siwe_plugin()?
            .store
            .create_wallet_identity(
                &self.siwe_plugin()?.config.schema,
                user,
                self.wallet_create(String::new(), address, chain_id, true)?,
                &account,
            )
            .await?;
        self.finish_siwe_identity_write(outcome, true).await
    }

    async fn siwe_ens_profile(&self, address: &str) -> Result<crate::SiweEnsProfile, AuthError> {
        match &self.siwe_plugin()?.config.ens_lookup {
            Some(lookup) => lookup.lookup(address).await,
            None => Ok(crate::SiweEnsProfile::default()),
        }
    }

    fn wallet_create(
        &self,
        user_id: String,
        address: &str,
        chain_id: f64,
        is_primary: bool,
    ) -> Result<DatabaseCreate<WalletAddress>, AuthError> {
        self.prepare_database_create(
            "walletAddress",
            DatabaseIdInput::Absent,
            false,
            wallet(user_id, address, chain_id, is_primary),
        )
    }

    async fn write_siwe_identity(&self, write: SiweIdentityWrite) -> Result<AuthUser, AuthError> {
        let outcome = self
            .siwe_plugin()?
            .store
            .write_wallet_identity(&self.siwe_plugin()?.config.schema, write)
            .await?;
        self.finish_siwe_identity_write(outcome, false).await
    }

    async fn finish_siwe_identity_write(
        &self,
        outcome: SiweIdentityWriteOutcome,
        creating_user: bool,
    ) -> Result<AuthUser, AuthError> {
        match outcome {
            SiweIdentityWriteOutcome::Created { user, account, .. } => {
                self.finish_user_create(&user).await?;
                self.finish_account_create(&account).await?;
                Ok(user)
            }
            SiweIdentityWriteOutcome::AddedChain { user, account, .. } => {
                self.finish_account_create(&account).await?;
                Ok(user)
            }
            SiweIdentityWriteOutcome::Existing(owner) => Ok(owner.user),
            SiweIdentityWriteOutcome::EmailTaken if creating_user => {
                Err(AuthError::UserAlreadyExists)
            }
            SiweIdentityWriteOutcome::EmailTaken => Err(AuthError::Storage(
                "SIWE chain link unexpectedly conflicted on email".into(),
            )),
        }
    }

    async fn reserve_siwe_email(&self, email: &str, address: &str) -> Result<bool, AuthError> {
        let now = Utc::now();
        self.reserve_verification_value(VerificationValue::new(
            format!("{EMAIL_CLAIM_IDENTIFIER_PREFIX}{email}"),
            address,
            now + Duration::seconds(60),
        ))
        .await
    }

    fn siwe_wallet_email(&self, address: &str) -> Result<String, AuthError> {
        let plugin = self.siwe_plugin()?;
        match plugin.config.email_domain_name.as_deref() {
            Some(domain) => Ok(format!("{address}@{domain}")),
            None => crate::email::placeholder_email(address, "siwe"),
        }
    }
}

fn wallet(user_id: String, address: &str, chain_id: f64, is_primary: bool) -> WalletAddress {
    WalletAddress {
        id: String::new(),
        user_id,
        address: address.into(),
        chain_id,
        is_primary,
        created_at: Utc::now(),
    }
}

fn siwe_account(user_id: String, address: &str, chain_id: f64) -> OAuthAccount {
    let now = Utc::now();
    OAuthAccount {
        id: String::new(),
        user_id,
        issuer: "local:siwe".into(),
        account_id: format!("{address}:{}", javascript_number(chain_id)),
        provider_id: "siwe".into(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
        additional_fields: serde_json::Map::new(),
        created_at: now,
        updated_at: now,
    }
}

fn javascript_number(value: f64) -> String {
    if value == 0.0 {
        return "0".into();
    }
    ryu_js::Buffer::new().format(value).into()
}
