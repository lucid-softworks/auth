use super::{AuthService, SignInResult};
use crate::{
    AdminListCondition, AdminListOperator, AdminListUsersQuery, AdminSortDirection,
    AdminUserUpdate, AuthError, AuthUser, DashSortDirection, DashUserListQuery,
    DashAdapterAction, DashAdapterWhere, PasswordCredentialChanged, PasswordCredentialSource,
    UserProfileUpdate,
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

impl AuthService {
    pub(crate) fn dash_plugin(&self) -> Option<&crate::DashPlugin> {
        self.plugins.find::<crate::DashPlugin>()
    }

    pub(crate) fn dash_config_snapshot(&self) -> Value {
        let config = &self.config;
        let plugins = self
            .plugins
            .descriptors()
            .iter()
            .map(|plugin| {
                json!({
                    "id": plugin.id,
                    "schema": Value::Null,
                    "version": plugin.version,
                    "options": Value::Null,
                })
            })
            .collect::<Vec<_>>();
        let user_fields = config
            .user
            .additional_fields
            .iter()
            .map(|(name, field)| dash_field(name, field))
            .collect::<Vec<_>>();
        let secret_entropy = if config.secret == b"better-auth-secret-12345678901234567890"
            || config.secret.len() < 32
        {
            0.0
        } else {
            estimate_entropy(&config.secret)
        };
        json!({
            "version": crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            "socialProviders": config.social_providers.iter().map(|provider| provider.id()).collect::<Vec<_>>(),
            "emailAndPassword": {
                "enabled": config.email_and_password.enabled,
                "disableSignUp": config.email_and_password.disable_sign_up,
                "autoSignIn": config.email_and_password.auto_sign_in,
                "requireEmailVerification": config.email_and_password.require_email_verification,
                "minPasswordLength": config.email_and_password.min_password_length,
                "maxPasswordLength": config.email_and_password.max_password_length,
            },
            "plugins": plugins,
            "organization": {
                "sendInvitationEmailEnabled": false,
                "additionalFields": [],
            },
            "user": {
                "fields": [],
                "additionalFields": user_fields,
                "deleteUserEnabled": config.user.delete_user.enabled,
                "modelName": config.user.model_name,
            },
            "baseURL": config.base_url.as_ref().map(ToString::to_string),
            "basePath": config.base_path,
            "emailVerification": {
                "sendVerificationEmailEnabled": config.email_verification.sender.is_some(),
            },
            "insights": {
                "hasDatabase": true,
                "cookies": Value::Null,
                "hasIpAddressHeaders": !config.ip_address.ip_address_headers.is_empty(),
                "ipAddressHeaders": (!config.ip_address.ip_address_headers.is_empty()).then_some(&config.ip_address.ip_address_headers),
                "disableIpTracking": config.ip_address.disable_ip_tracking,
                "disableCSRFCheck": false,
                "disableOriginCheck": false,
                "allowDifferentEmails": config.account.account_linking.enabled && config.account.account_linking.allow_different_emails,
                "identityStrategy": "issuer",
                "skipStateCookieCheck": config.account.skip_state_cookie_check,
                "storeStateCookieStrategy": match config.account.store_state_strategy { crate::OAuthStateStrategy::Database => "database", crate::OAuthStateStrategy::Cookie => "cookie" },
                "cookieCache": {
                    "enabled": config.session.cookie_cache.enabled,
                    "strategy": config.session.cookie_cache.enabled.then_some(match config.session.cookie_cache.strategy { crate::CookieCacheStrategy::Compact => "compact", crate::CookieCacheStrategy::Jwt => "jwt", crate::CookieCacheStrategy::Jwe => "jwe" }),
                    "refreshCache": config.session.cookie_cache.enabled.then_some(!matches!(config.session.cookie_cache.refresh_cache, crate::CookieCacheRefresh::Disabled)),
                },
                "sessionFreshAge": config.session_fresh_age.num_seconds(),
                "disableVerificationCleanup": config.verification.disable_cleanup,
                "minPasswordLength": config.email_and_password.enabled.then_some(config.email_and_password.min_password_length),
                "maxPasswordLength": config.email_and_password.enabled.then_some(config.email_and_password.max_password_length),
                "hasRateLimitDisabled": !config.rate_limit.enabled,
                "rateLimitStorage": Value::Null,
                "storeSessionInDatabase": config.session.store_session_in_database,
                "preserveSessionInDatabase": config.session.preserve_session_in_database,
                "secretEntropy": secret_entropy,
                "useSecureCookies": config.use_secure_cookies,
                "crossSubDomainCookiesEnabled": config.cookies.cross_subdomain_enabled(),
                "crossSubDomainCookiesDomain": config.cookies.cross_subdomain_domain(),
                "defaultCookieAttributes": Value::Null,
                "appName": Value::Null,
                "hasJoinsEnabled": false,
                "hasErrorURLConfigured": false,
            },
        })
    }

    pub(crate) async fn dash_list_users(
        &self,
        query: &DashUserListQuery,
    ) -> Result<(Vec<AuthUser>, i64), AuthError> {
        let list_conditions = dash_conditions(query.where_clause.as_deref().unwrap_or(&[]))?;
        let count_conditions = dash_conditions(query.count_where.as_deref().unwrap_or(&[]))?;
        let list = AdminListUsersQuery {
            limit: query.adapter_limit(),
            offset: query.adapter_offset(),
            sort_by: Some(query.sort_by.clone().unwrap_or_else(|| "createdAt".into())),
            sort_direction: match query.sort_order.unwrap_or(DashSortDirection::Desc) {
                DashSortDirection::Asc => AdminSortDirection::Asc,
                DashSortDirection::Desc => AdminSortDirection::Desc,
            },
            conditions: list_conditions,
        };
        let users = self.store.list_users(&list).await?;
        let total = self.store.count_users(&count_conditions).await?;
        Ok((users, total))
    }

    pub(crate) async fn dash_find_user(&self, user_id: &str) -> Result<AuthUser, AuthError> {
        self.store
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::NotFound)
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn dash_user_json(&self, user: &AuthUser) -> Result<Value, AuthError> {
        let mut value = serde_json::to_value(self.better_auth_user(user).await?)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        let object = value.as_object_mut().expect("a Better Auth user is an object");
        let admin_enabled = self.plugins.find::<crate::AdminPlugin>().is_some();
        object.insert("banned".into(), Value::Bool(admin_enabled && user.banned));
        object.insert(
            "banReason".into(),
            admin_enabled
                .then(|| user.ban_reason.clone())
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        object.insert(
            "banExpires".into(),
            admin_enabled
                .then(|| user.ban_expires)
                .flatten()
                .map(|date| json!(date))
                .unwrap_or(Value::Null),
        );
        Ok(value)
    }

    pub(crate) async fn dash_user_details(
        &self,
        user_id: &str,
        session_only: bool,
        account_only: bool,
        minimal: bool,
    ) -> Result<Value, AuthError> {
        if session_only && account_only {
            return Err(AuthError::InvalidRequest(
                "Cannot use sessionOnly and accountOnly together".into(),
            ));
        }
        let user = self.dash_find_user(user_id).await?;
        let mut output = serde_json::to_value(&user)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        let object = output
            .as_object_mut()
            .expect("an AuthUser serializes as an object");
        object.insert(
            "lastActiveAt".into(),
            user.additional_fields
                .get("lastActiveAt")
                .cloned()
                .unwrap_or(Value::Null),
        );
        let accounts = if session_only || minimal {
            Vec::new()
        } else {
            self.store.list_user_accounts(user_id).await?
        };
        let sessions = if account_only || minimal {
            Vec::new()
        } else {
            self.store.list_sessions(user_id).await?
        };
        object.insert(
            "account".into(),
            serde_json::to_value(accounts).map_err(|error| AuthError::Storage(error.to_string()))?,
        );
        object.insert(
            "session".into(),
            Value::Array(
                sessions
                    .into_iter()
                    .map(|session| {
                        let mut value = serde_json::to_value(session)
                            .expect("an AuthSession serializes as an object");
                        value
                            .as_object_mut()
                            .expect("an AuthSession serializes as an object")
                            .remove("token");
                        value
                    })
                    .collect(),
            ),
        );
        Ok(output)
    }

    pub(crate) async fn dash_user_organizations(
        &self,
        user_id: &str,
    ) -> Result<Value, AuthError> {
        let Some(plugin) = self.plugins.find::<crate::OrganizationPlugin>() else {
            return Ok(json!({"organizations": []}));
        };
        let organizations = plugin.store.list_organizations(user_id).await?;
        let teams = plugin.store.list_user_teams(user_id).await?;
        let mut output = Vec::new();
        for organization in organizations {
            let Some(member) = plugin.store.find_member(&organization.id, user_id).await? else {
                continue;
            };
            output.push(json!({
                "id": organization.id,
                "name": organization.name,
                "logo": organization.logo,
                "createdAt": organization.created_at,
                "slug": organization.slug,
                "role": member.role,
                "teams": teams.iter().filter(|team| team.organization_id == organization.id).collect::<Vec<_>>(),
            }));
        }
        Ok(json!({"organizations": output}))
    }

    pub(crate) async fn dash_create_user(
        &self,
        mut input: crate::AdminCreateUser,
    ) -> Result<AuthUser, AuthError> {
        let role = if input.roles.is_empty() {
            "user".to_owned()
        } else {
            input.roles.join(",")
        };
        let user = super::user::admin_user_from_input(&mut input, role)?;
        if self.store.find_user_by_email(&user.email).await?.is_some() {
            return Err(AuthError::UserAlreadyExistsEmail);
        }
        let has_password = input.password.is_some();
        let user = self.persist_admin_user(user, input.password).await?;
        if has_password {
            self.plugins
                .password_credential_changed(&PasswordCredentialChanged {
                    user_id: user.id.clone(),
                    source: PasswordCredentialSource::AdministratorCreated,
                })
                .await?;
        }
        Ok(user)
    }

    pub(crate) async fn dash_create_user_body(
        &self,
        mut body: Map<String, Value>,
    ) -> Result<AuthUser, AuthError> {
        let name = take_required_string(&mut body, "name")?;
        let email = take_required_string(&mut body, "email")?;
        let password = take_optional_string(&mut body, "password")?;
        let generate_password = body
            .remove("generatePassword")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        for denied in [
            "id",
            "createdAt",
            "updatedAt",
            "banned",
            "banReason",
            "banExpires",
            "role",
            "twoFactorEnabled",
            "twoFactorSecret",
            "sendVerificationEmail",
            "sendOrganizationInvite",
            "organizationRole",
            "organizationId",
        ] {
            body.remove(denied);
        }
        retain_writable_user_fields(&mut body, &self.config.user.additional_fields, true)?;
        let password = match (password, generate_password) {
            (Some(password), _) if !password.trim().is_empty() => Some(password),
            (None, true) => Some(random_password()),
            _ => None,
        };
        self.dash_create_user(crate::AdminCreateUser {
            email,
            password,
            name,
            roles: Vec::new(),
            data: body,
        })
        .await
    }

    pub(crate) async fn dash_update_user(
        &self,
        user_id: &str,
        update: AdminUserUpdate,
    ) -> Result<AuthUser, AuthError> {
        let target = self.dash_find_user(user_id).await?;
        let candidate = self
            .prepare_user_update(&target, super::admin_update::admin_update_candidate(&target, &update))
            .await?;
        let updated = self
            .store
            .admin_update_user(user_id, super::admin_update::admin_update_from_candidate(candidate))
            .await?;
        self.after_database_update(&crate::DatabaseRecord::User(updated.clone()))
            .await?;
        Ok(updated)
    }

    pub(crate) async fn dash_update_user_body(
        &self,
        user_id: &str,
        mut body: Map<String, Value>,
    ) -> Result<AuthUser, AuthError> {
        for denied in [
            "id",
            "createdAt",
            "updatedAt",
            "banned",
            "banReason",
            "banExpires",
            "role",
            "password",
            "twoFactorEnabled",
            "twoFactorSecret",
        ] {
            body.remove(denied);
        }
        retain_writable_user_fields(&mut body, &self.config.user.additional_fields, false)?;
        if body.is_empty() {
            return Err(AuthError::InvalidRequest("No valid fields to update".into()));
        }
        let update = dash_user_update(body)?;
        self.dash_update_user(user_id, update).await
    }

    pub(crate) async fn dash_delete_user(&self, user_id: &str) -> Result<(), AuthError> {
        let user = self.dash_find_user(user_id).await?;
        self.delete_user_with_hooks(user).await
    }

    pub(crate) async fn dash_set_password(
        &self,
        user_id: &str,
        password: String,
    ) -> Result<(), AuthError> {
        self.set_password_hash_with_database_id(user_id, self.hash_password(password).await?)
            .await?;
        self.plugins
            .password_credential_changed(&PasswordCredentialChanged {
                user_id: user_id.to_owned(),
                source: PasswordCredentialSource::AdministratorReset,
            })
            .await
    }

    pub(crate) async fn dash_unlink_account(
        &self,
        user_id: &str,
        provider_id: &str,
        account_id: &str,
    ) -> Result<(), AuthError> {
        let accounts = self.store.list_user_accounts(user_id).await?;
        if accounts.len() == 1 && !self.config.account.account_linking.allow_unlinking_all {
            return Err(AuthError::InvalidRequest(
                "Cannot unlink the last account. This would lock the user out.".into(),
            ));
        }
        let account = accounts
            .iter()
            .find(|account| account.provider_id == provider_id && account.id == account_id)
            .ok_or(AuthError::NotFound)?;
        match self
            .store
            .delete_user_account(user_id, &account.id, true)
            .await?
        {
            crate::AccountDeleteOutcome::Deleted => Ok(()),
            crate::AccountDeleteOutcome::NotFound => Err(AuthError::NotFound),
            crate::AccountDeleteOutcome::LastAccount => Err(AuthError::InvalidRequest(
                "Cannot unlink the last account. This would lock the user out.".into(),
            )),
        }
    }

    pub(crate) async fn dash_revoke_owned_session(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> Result<(), AuthError> {
        let found = self
            .store
            .list_sessions(user_id)
            .await?
            .into_iter()
            .find(|session| session.id == session_id || session.token == session_id)
            .ok_or(AuthError::NotFound)?;
        self.delete_session_id_with_hooks(&found.id).await
    }

    pub(crate) async fn dash_revoke_all_sessions(&self, user_id: &str) -> Result<(), AuthError> {
        self.delete_user_sessions_with_hooks(user_id).await
    }

    pub(crate) async fn dash_impersonate_user(
        &self,
        user_id: &str,
        impersonated_by: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let user = self.dash_find_user(user_id).await?;
        self.create_session_until(
            user,
            None,
            impersonated_by,
            Some(Utc::now() + chrono::Duration::minutes(10)),
            None,
            None,
        )
        .await
    }

    pub(crate) async fn dash_ban_user(
        &self,
        user_id: &str,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
        delete_sessions: bool,
    ) -> Result<(), AuthError> {
        self.dash_find_user(user_id).await?;
        let updated = self
            .store
            .update_user_ban(user_id, true, reason, expires_at)
            .await?;
        self.after_database_update(&crate::DatabaseRecord::User(updated))
            .await?;
        if delete_sessions {
            self.delete_user_sessions_with_hooks(user_id).await?;
        }
        Ok(())
    }

    pub(crate) async fn dash_unban_user(&self, user_id: &str) -> Result<(), AuthError> {
        self.dash_find_user(user_id).await?;
        let updated = self
            .store
            .update_user_ban(user_id, false, None, None)
            .await?;
        self.after_database_update(&crate::DatabaseRecord::User(updated))
            .await
    }

    pub(crate) async fn dash_send_verification_email(
        &self,
        user_id: &str,
        callback_url: &str,
    ) -> Result<(), AuthError> {
        let user = self.dash_find_user(user_id).await?;
        if user.email_verified {
            return Err(AuthError::EmailAlreadyVerified);
        }
        self.deliver_verification_email(user, Some(callback_url)).await
    }

    pub(crate) fn dash_verification_email_enabled(&self) -> bool {
        self.config.email_verification.sender.is_some() || self.email_otp_overrides_verification()
    }

    pub(crate) async fn dash_send_reset_password_email(
        &self,
        user_id: &str,
        callback_url: &str,
    ) -> Result<(), AuthError> {
        let user = self.dash_find_user(user_id).await?;
        self.request_password_reset(&user.email, Some(callback_url)).await
    }

    pub(crate) async fn dash_touch_user_activity(&self, user_id: &str) -> Result<(), AuthError> {
        let mut additional_fields = Map::new();
        additional_fields.insert("lastActiveAt".into(), json!(Utc::now()));
        self.store
            .update_user_profile(
                user_id,
                UserProfileUpdate {
                    additional_fields,
                    ..UserProfileUpdate::default()
                },
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn dash_user_stats(&self) -> Result<Value, AuthError> {
        let now = Utc::now();
        let day = chrono::Duration::days(1);
        let week = chrono::Duration::weeks(1);
        let month = chrono::Duration::days(30);
        let daily = self.dash_signup_window(now - day, None).await?;
        let previous_daily = self.dash_signup_window(now - day * 2, Some(now - day)).await?;
        let weekly = self.dash_signup_window(now - week, None).await?;
        let previous_weekly = self.dash_signup_window(now - week * 2, Some(now - week)).await?;
        let monthly = self.dash_signup_window(now - month, None).await?;
        let previous_monthly = self.dash_signup_window(now - month * 2, Some(now - month)).await?;
        let total = self.store.count_users(&[]).await?;
        let daily_active = self.dash_active_users(now - day, None).await?;
        let previous_daily_active = self.dash_active_users(now - day * 2, Some(now - day)).await?;
        let weekly_active = self.dash_active_users(now - week, None).await?;
        let previous_weekly_active = self.dash_active_users(now - week * 2, Some(now - week)).await?;
        let monthly_active = self.dash_active_users(now - month, None).await?;
        let previous_monthly_active = self.dash_active_users(now - month * 2, Some(now - month)).await?;
        Ok(json!({
            "daily": signup_period(daily, previous_daily),
            "weekly": signup_period(weekly, previous_weekly),
            "monthly": signup_period(monthly, previous_monthly),
            "total": total,
            "activeUsers": {
                "daily": active_period(daily_active, previous_daily_active),
                "weekly": active_period(weekly_active, previous_weekly_active),
                "monthly": active_period(monthly_active, previous_monthly_active),
            },
        }))
    }

    pub(crate) async fn dash_user_graph(&self, period: crate::DashPeriod) -> Result<Value, AuthError> {
        use chrono::Datelike as _;
        let now = Utc::now();
        let (intervals, duration) = match period {
            crate::DashPeriod::Daily => (7, chrono::Duration::days(1)),
            crate::DashPeriod::Weekly => (8, chrono::Duration::weeks(1)),
            crate::DashPeriod::Monthly => (6, chrono::Duration::days(30)),
        };
        let mut data = Vec::with_capacity(intervals);
        for index in (0..intervals).rev() {
            let end = now - duration * index as i32;
            let start = end - duration;
            let total = self.store.count_users(&[AdminListCondition {
                field: "createdAt".into(),
                operator: AdminListOperator::Lte,
                value: json!(end),
            }]).await?;
            let new_users = self.dash_signup_window(start, Some(end)).await?;
            let active = self.dash_active_users(start, Some(end)).await?;
            let label = match period {
                crate::DashPeriod::Daily => end.format("%a").to_string(),
                crate::DashPeriod::Weekly => format!("{} {}", end.format("%b"), end.day()),
                crate::DashPeriod::Monthly => end.format("%b").to_string(),
            };
            data.push(json!({
                "date": end,
                "label": label,
                "totalUsers": total,
                "newUsers": new_users,
                "activeUsers": active,
            }));
        }
        Ok(json!({"data": data, "period": period}))
    }

    pub(crate) async fn dash_user_retention(
        &self,
        period: crate::DashPeriod,
    ) -> Result<Value, AuthError> {
        use chrono::{Datelike as _, NaiveDate, TimeZone as _, Weekday};
        let now = Utc::now();
        let day = now.date_naive();
        let active_start_date = match period {
            crate::DashPeriod::Daily => day,
            crate::DashPeriod::Weekly => {
                let days = match day.weekday() {
                    Weekday::Mon => 0,
                    Weekday::Tue => 1,
                    Weekday::Wed => 2,
                    Weekday::Thu => 3,
                    Weekday::Fri => 4,
                    Weekday::Sat => 5,
                    Weekday::Sun => 6,
                };
                day - chrono::Duration::days(days)
            }
            crate::DashPeriod::Monthly => NaiveDate::from_ymd_opt(day.year(), day.month(), 1)
                .expect("current month is valid"),
        };
        let active_start = Utc.from_utc_datetime(
            &active_start_date.and_hms_opt(0, 0, 0).expect("midnight is valid"),
        );
        let active_end = add_period(active_start, period, 1);
        let horizons = match period {
            crate::DashPeriod::Daily => 7,
            crate::DashPeriod::Weekly => 8,
            crate::DashPeriod::Monthly => 6,
        };
        let prefix = match period {
            crate::DashPeriod::Daily => "D",
            crate::DashPeriod::Weekly => "W",
            crate::DashPeriod::Monthly => "M",
        };
        let mut data = Vec::with_capacity(horizons);
        for n in 1..=horizons {
            let cohort_start = add_period(active_start, period, -(n as i32));
            let cohort_end = add_period(cohort_start, period, 1);
            let cohort = self.store.list_users(&AdminListUsersQuery {
                limit: usize::MAX,
                conditions: vec![
                    AdminListCondition {
                        field: "createdAt".into(),
                        operator: AdminListOperator::Gte,
                        value: json!(cohort_start),
                    },
                    AdminListCondition {
                        field: "createdAt".into(),
                        operator: AdminListOperator::Lt,
                        value: json!(cohort_end),
                    },
                ],
                ..AdminListUsersQuery::default()
            }).await?;
            let cohort_size = cohort.len();
            let mut retained = 0_usize;
            for user in &cohort {
                let active = if self
                    .dash_plugin()
                    .is_some_and(|plugin| plugin.options().activity_tracking.enabled)
                {
                    user.additional_fields
                        .get("lastActiveAt")
                        .and_then(|value| serde_json::from_value::<DateTime<Utc>>(value.clone()).ok())
                        .is_some_and(|last| last >= active_start && last < active_end)
                } else {
                    self.store.list_sessions(&user.id).await?.iter().any(|session| {
                        session.updated_at >= active_start && session.updated_at < active_end
                    })
                };
                retained += usize::from(active);
            }
            let rate = if cohort_size == 0 {
                0.0
            } else {
                ((retained as f64 / cohort_size as f64 * 100.0) * 10.0).round() / 10.0
            };
            data.push(json!({
                "n": n,
                "label": format!("{prefix}{n}"),
                "cohortStart": cohort_start,
                "cohortEnd": cohort_end,
                "activeStart": active_start,
                "activeEnd": active_end,
                "cohortSize": cohort_size,
                "retained": retained,
                "retentionRate": rate,
            }));
        }
        Ok(json!({"data": data, "period": period}))
    }

    pub(crate) async fn dash_execute_adapter(
        &self,
        action: DashAdapterAction,
    ) -> Result<Value, AuthError> {
        match action {
            DashAdapterAction::FindOne {
                model,
                where_clause,
                select,
                join,
            } => {
                let mut records = self
                    .dash_adapter_find_many(
                        &model,
                        where_clause.as_deref().unwrap_or(&[]),
                        Some(1),
                        0,
                        join.as_ref(),
                    )
                    .await?;
                let result = records.pop().map(|value| project(value, select.as_deref()));
                Ok(json!({"result": result}))
            }
            DashAdapterAction::FindMany {
                model,
                where_clause,
                limit,
                offset,
                sort_by: _,
                join,
            } => {
                let records = self
                    .dash_adapter_find_many(
                        &model,
                        where_clause.as_deref().unwrap_or(&[]),
                        limit.map(js_index),
                        offset.map(js_index).unwrap_or(0),
                        join.as_ref(),
                    )
                    .await?;
                Ok(json!({"result": records}))
            }
            DashAdapterAction::Create { model, data } if model == "user" => {
                Ok(json!({"result": self.dash_create_user_body(data).await?}))
            }
            DashAdapterAction::Update {
                model,
                where_clause,
                update,
            } if model == "user" => {
                let user_id = equality_string(&where_clause, "id")?;
                Ok(json!({"result": self.dash_update_user_body(user_id, update).await?}))
            }
            DashAdapterAction::Count {
                model,
                where_clause,
            } => {
                let count = self
                    .dash_adapter_find_many(
                        &model,
                        where_clause.as_deref().unwrap_or(&[]),
                        None,
                        0,
                        None,
                    )
                    .await?
                    .len();
                Ok(json!({"count": count}))
            }
            _ => Err(AuthError::Storage(
                "the configured adapter does not expose this model mutation".into(),
            )),
        }
    }

    async fn dash_adapter_find_many(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        join: Option<&std::collections::BTreeMap<String, bool>>,
    ) -> Result<Vec<Value>, AuthError> {
        let mut values = match model {
            "user" => {
                let conditions = where_clause
                    .iter()
                    .map(dash_adapter_condition)
                    .collect::<Result<Vec<_>, _>>()?;
                let users = self
                    .store
                    .list_users(&AdminListUsersQuery {
                        limit: limit.unwrap_or(usize::MAX),
                        offset,
                        conditions,
                        ..AdminListUsersQuery::default()
                    })
                    .await?;
                let mut output = Vec::with_capacity(users.len());
                for user in users {
                    let mut value = serde_json::to_value(&user)
                        .map_err(|error| AuthError::Storage(error.to_string()))?;
                    if join.is_some_and(|join| join.get("account") == Some(&true)) {
                        value.as_object_mut().expect("user object").insert(
                            "account".into(),
                            serde_json::to_value(self.store.list_user_accounts(&user.id).await?)
                                .map_err(|error| AuthError::Storage(error.to_string()))?,
                        );
                    }
                    if join.is_some_and(|join| join.get("session") == Some(&true)) {
                        value.as_object_mut().expect("user object").insert(
                            "session".into(),
                            serde_json::to_value(self.store.list_sessions(&user.id).await?)
                                .map_err(|error| AuthError::Storage(error.to_string()))?,
                        );
                    }
                    output.push(value);
                }
                output
            }
            "account" => {
                let user_id = equality_string(where_clause, "userId")?;
                self.store
                    .list_user_accounts(user_id)
                    .await?
                    .into_iter()
                    .map(|account| serde_json::to_value(account).expect("account value"))
                    .filter(|value| dash_matches(value, where_clause))
                    .collect()
            }
            "session" => {
                let user_id = equality_string(where_clause, "userId")?;
                self.store
                    .list_sessions(user_id)
                    .await?
                    .into_iter()
                    .map(|session| serde_json::to_value(session).expect("session value"))
                    .filter(|value| dash_matches(value, where_clause))
                    .collect()
            }
            _ => {
                return Err(AuthError::Storage(format!(
                    "the configured adapter does not expose model '{model}'"
                )));
            }
        };
        if model != "user" {
            values = values
                .into_iter()
                .skip(offset)
                .take(limit.unwrap_or(usize::MAX))
                .collect();
        }
        Ok(values)
    }

    async fn dash_signup_window(
        &self,
        from: DateTime<Utc>,
        to: Option<DateTime<Utc>>,
    ) -> Result<i64, AuthError> {
        let mut conditions = vec![AdminListCondition {
            field: "createdAt".into(),
            operator: AdminListOperator::Gte,
            value: json!(from),
        }];
        if let Some(to) = to {
            conditions.push(AdminListCondition {
                field: "createdAt".into(),
                operator: AdminListOperator::Lt,
                value: json!(to),
            });
        }
        self.store.count_users(&conditions).await
    }

    async fn dash_active_users(
        &self,
        from: DateTime<Utc>,
        to: Option<DateTime<Utc>>,
    ) -> Result<i64, AuthError> {
        let plugin = self.dash_plugin().expect("Dash routes require DashPlugin");
        if plugin.options().activity_tracking.enabled {
            let mut conditions = vec![AdminListCondition {
                field: "lastActiveAt".into(),
                operator: AdminListOperator::Gte,
                value: json!(from),
            }];
            if let Some(to) = to {
                conditions.push(AdminListCondition {
                    field: "lastActiveAt".into(),
                    operator: AdminListOperator::Lt,
                    value: json!(to),
                });
            }
            return self.store.count_users(&conditions).await;
        }
        let users = self
            .store
            .list_users(&AdminListUsersQuery {
                limit: usize::MAX,
                ..AdminListUsersQuery::default()
            })
            .await?;
        let mut active = 0_i64;
        for user in users {
            if self.store.list_sessions(&user.id).await?.iter().any(|session| {
                session.updated_at >= from && to.is_none_or(|to| session.updated_at < to)
            }) {
                active += 1;
            }
        }
        Ok(active)
    }
}

fn percentage(current: i64, previous: i64) -> f64 {
    if previous == 0 {
        return if current > 0 { 100.0 } else { 0.0 };
    }
    (current - previous) as f64 / previous as f64 * 100.0
}

fn signup_period(current: i64, previous: i64) -> Value {
    json!({"signUps": current, "percentage": percentage(current, previous)})
}

fn active_period(current: i64, previous: i64) -> Value {
    json!({"active": current, "percentage": percentage(current, previous)})
}

fn add_period(
    value: DateTime<Utc>,
    period: crate::DashPeriod,
    amount: i32,
) -> DateTime<Utc> {
    match period {
        crate::DashPeriod::Daily => value + chrono::Duration::days(i64::from(amount)),
        crate::DashPeriod::Weekly => value + chrono::Duration::weeks(i64::from(amount)),
        crate::DashPeriod::Monthly if amount >= 0 => value
            .checked_add_months(chrono::Months::new(amount as u32))
            .expect("Dash month horizon remains representable"),
        crate::DashPeriod::Monthly => value
            .checked_sub_months(chrono::Months::new(amount.unsigned_abs()))
            .expect("Dash month horizon remains representable"),
    }
}

fn dash_field(name: &str, field: &crate::AdditionalField) -> Value {
    json!({
        "name": name,
        "type": match field.field_type {
            crate::AdditionalFieldType::String | crate::AdditionalFieldType::StringLiteral(_) => "string",
            crate::AdditionalFieldType::Number => "number",
            crate::AdditionalFieldType::Boolean => "boolean",
            crate::AdditionalFieldType::Date => "date",
            crate::AdditionalFieldType::Json => "json",
            crate::AdditionalFieldType::StringArray => "string[]",
            crate::AdditionalFieldType::NumberArray => "number[]",
        },
        "required": field.required,
        "input": field.input,
        "unique": field.unique,
        "hasDefaultValue": field.has_default_value(),
        "references": field.references.as_ref().map(|reference| json!({"model": reference.model, "field": reference.field})),
        "returned": field.returned,
        "bigInt": field.bigint,
    })
}

fn estimate_entropy(secret: &[u8]) -> f64 {
    let unique = secret.iter().copied().collect::<std::collections::BTreeSet<_>>().len();
    if unique == 0 {
        return 0.0;
    }
    secret.len() as f64 * (unique as f64).log2()
}

fn dash_conditions(values: &[Value]) -> Result<Vec<AdminListCondition>, AuthError> {
    values
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| AuthError::InvalidRequest("where clause is invalid".into()))?;
            let field = object
                .get("field")
                .and_then(Value::as_str)
                .ok_or_else(|| AuthError::InvalidRequest("where field is invalid".into()))?;
            let operator = match object.get("operator").and_then(Value::as_str).unwrap_or("eq") {
                "eq" => AdminListOperator::Eq,
                "ne" => AdminListOperator::Ne,
                "lt" => AdminListOperator::Lt,
                "lte" => AdminListOperator::Lte,
                "gt" => AdminListOperator::Gt,
                "gte" => AdminListOperator::Gte,
                "in" => AdminListOperator::In,
                "not_in" => AdminListOperator::NotIn,
                "contains" => AdminListOperator::Contains,
                "starts_with" => AdminListOperator::StartsWith,
                "ends_with" => AdminListOperator::EndsWith,
                _ => return Err(AuthError::InvalidRequest("where operator is invalid".into())),
            };
            Ok(AdminListCondition {
                field: field.into(),
                operator,
                value: object.get("value").cloned().unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn take_required_string(body: &mut Map<String, Value>, key: &str) -> Result<String, AuthError> {
    let value = take_optional_string(body, key)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthError::InvalidRequest(format!("{key} is required")))?;
    Ok(value)
}

fn take_optional_string(
    body: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<String>, AuthError> {
    body.remove(key)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| AuthError::InvalidRequest(format!("{key} is invalid")))
        })
        .transpose()
}

fn retain_writable_user_fields(
    body: &mut Map<String, Value>,
    fields: &crate::AdditionalFieldSet,
    require_configured: bool,
) -> Result<(), AuthError> {
    body.retain(|name, _| {
        matches!(name.as_str(), "name" | "email" | "image" | "emailVerified")
            || fields
                .get(name)
                .is_some_and(|field| field.input && field.references.is_none())
    });
    for (name, field) in fields {
        if !field.input || field.references.is_some() {
            continue;
        }
        if require_configured && field.required && !field.has_default_value() && !body.contains_key(name)
        {
            return Err(AuthError::InvalidRequest(format!("{name} is required")));
        }
        if let Some(value) = body.get_mut(name) {
            coerce_dash_field(name, field, value)?;
        }
    }
    Ok(())
}

fn coerce_dash_field(
    name: &str,
    field: &crate::AdditionalField,
    value: &mut Value,
) -> Result<(), AuthError> {
    use crate::AdditionalFieldType;
    let valid = match field.field_type {
        AdditionalFieldType::Number => {
            if value.is_number() {
                true
            } else if let Some(raw) = value.as_str() {
                raw.parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map(|number| *value = Value::Number(number))
                    .is_some()
            } else {
                false
            }
        }
        AdditionalFieldType::Boolean => {
            if value.is_boolean() {
                true
            } else if let Some(raw) = value.as_str() {
                *value = Value::Bool(!raw.is_empty());
                true
            } else if let Some(number) = value.as_f64() {
                *value = Value::Bool(number != 0.0);
                true
            } else {
                false
            }
        }
        AdditionalFieldType::Date => value
            .as_str()
            .is_some_and(|raw| !field.required || !raw.is_empty()),
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => value
            .as_str()
            .is_some_and(|raw| !field.required || !raw.is_empty()),
        AdditionalFieldType::Json => true,
        AdditionalFieldType::StringArray => value
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string)),
        AdditionalFieldType::NumberArray => value
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_number)),
    };
    if valid {
        Ok(())
    } else {
        Err(AuthError::InvalidRequest(format!("{name} is invalid")))
    }
}

fn dash_user_update(mut data: Map<String, Value>) -> Result<AdminUserUpdate, AuthError> {
    let name = nullable_string(&mut data, "name")?.flatten();
    let email = nullable_string(&mut data, "email")?
        .flatten()
        .map(|email| email.to_lowercase());
    let image = nullable_string(&mut data, "image")?;
    let email_verified = data
        .remove("emailVerified")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| AuthError::InvalidRequest("emailVerified is invalid".into()))
        })
        .transpose()?;
    Ok(AdminUserUpdate {
        name,
        email,
        email_verified,
        image,
        additional_fields: data,
        ..AdminUserUpdate::default()
    })
}

fn nullable_string(
    data: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<Option<String>>, AuthError> {
    data.remove(key)
        .map(|value| match value {
            Value::Null => Ok(None),
            Value::String(value) => Ok(Some(value)),
            _ => Err(AuthError::InvalidRequest(format!("{key} is invalid"))),
        })
        .transpose()
}

fn random_password() -> String {
    use rand::distr::{Alphanumeric, SampleString as _};
    Alphanumeric.sample_string(&mut rand::rng(), 12)
}

fn js_index(value: f64) -> usize {
    if !value.is_finite() || value <= 0.0 {
        0
    } else {
        value.floor().min(usize::MAX as f64) as usize
    }
}

fn equality_string<'a>(
    where_clause: &'a [DashAdapterWhere],
    field: &str,
) -> Result<&'a str, AuthError> {
    where_clause
        .iter()
        .find(|condition| {
            condition.field == field
                && matches!(condition.operator, crate::DashAdapterOperator::Eq)
        })
        .and_then(|condition| condition.value.as_str())
        .ok_or_else(|| {
            AuthError::Storage(format!(
                "the configured adapter requires an equality filter for '{field}'"
            ))
        })
}

fn dash_adapter_condition(condition: &DashAdapterWhere) -> Result<AdminListCondition, AuthError> {
    let operator = match condition.operator {
        crate::DashAdapterOperator::Eq => AdminListOperator::Eq,
        crate::DashAdapterOperator::Ne => AdminListOperator::Ne,
        crate::DashAdapterOperator::Gt => AdminListOperator::Gt,
        crate::DashAdapterOperator::Gte => AdminListOperator::Gte,
        crate::DashAdapterOperator::Lt => AdminListOperator::Lt,
        crate::DashAdapterOperator::Lte => AdminListOperator::Lte,
        crate::DashAdapterOperator::In => AdminListOperator::In,
        crate::DashAdapterOperator::Contains => AdminListOperator::Contains,
        crate::DashAdapterOperator::StartsWith => AdminListOperator::StartsWith,
        crate::DashAdapterOperator::EndsWith => AdminListOperator::EndsWith,
    };
    Ok(AdminListCondition {
        field: condition.field.clone(),
        operator,
        value: condition.value.clone(),
    })
}

fn dash_matches(value: &Value, conditions: &[DashAdapterWhere]) -> bool {
    conditions.iter().all(|condition| {
        let candidate = value.get(&condition.field).unwrap_or(&Value::Null);
        match condition.operator {
            crate::DashAdapterOperator::Eq => candidate == &condition.value,
            crate::DashAdapterOperator::Ne => candidate != &condition.value,
            crate::DashAdapterOperator::In => condition
                .value
                .as_array()
                .is_some_and(|values| values.contains(candidate)),
            crate::DashAdapterOperator::Contains => candidate
                .as_str()
                .zip(condition.value.as_str())
                .is_some_and(|(candidate, expected)| candidate.contains(expected)),
            crate::DashAdapterOperator::StartsWith => candidate
                .as_str()
                .zip(condition.value.as_str())
                .is_some_and(|(candidate, expected)| candidate.starts_with(expected)),
            crate::DashAdapterOperator::EndsWith => candidate
                .as_str()
                .zip(condition.value.as_str())
                .is_some_and(|(candidate, expected)| candidate.ends_with(expected)),
            crate::DashAdapterOperator::Gt
            | crate::DashAdapterOperator::Gte
            | crate::DashAdapterOperator::Lt
            | crate::DashAdapterOperator::Lte => compare_values(candidate, &condition.value)
                .is_some_and(|ordering| match condition.operator {
                    crate::DashAdapterOperator::Gt => ordering.is_gt(),
                    crate::DashAdapterOperator::Gte => !ordering.is_lt(),
                    crate::DashAdapterOperator::Lt => ordering.is_lt(),
                    crate::DashAdapterOperator::Lte => !ordering.is_gt(),
                    _ => false,
                }),
        }
    })
}

fn compare_values(left: &Value, right: &Value) -> Option<std::cmp::Ordering> {
    if let (Some(left), Some(right)) = (left.as_f64(), right.as_f64()) {
        return left.partial_cmp(&right);
    }
    left.as_str()?.partial_cmp(right.as_str()?)
}

fn project(mut value: Value, select: Option<&[String]>) -> Value {
    let Some(select) = select else {
        return value;
    };
    let object = value
        .as_object_mut()
        .expect("adapter records serialize as objects");
    object.retain(|field, _| select.iter().any(|selected| selected == field));
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_matches_the_javascript_unique_character_estimate() {
        assert_eq!(estimate_entropy(b""), 0.0);
        assert_eq!(estimate_entropy(b"aaaa"), 0.0);
        assert_eq!(estimate_entropy(b"abab"), 4.0);
    }
}
