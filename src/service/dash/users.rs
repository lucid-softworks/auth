use super::*;

impl AuthService {
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

    pub(crate) async fn dash_export_users(
        &self,
        query: &DashUserListQuery,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AuthUser>, AuthError> {
        self.store
            .list_users(&AdminListUsersQuery {
                limit,
                offset,
                sort_by: Some(query.sort_by.clone().unwrap_or_else(|| "createdAt".into())),
                sort_direction: match query.sort_order.unwrap_or(DashSortDirection::Desc) {
                    DashSortDirection::Asc => AdminSortDirection::Asc,
                    DashSortDirection::Desc => AdminSortDirection::Desc,
                },
                conditions: dash_conditions(query.where_clause.as_deref().unwrap_or(&[]))?,
            })
            .await
    }

    pub(crate) async fn dash_online_users(&self) -> Result<i64, AuthError> {
        if !self
            .dash_plugin()
            .is_some_and(|plugin| plugin.options().activity_tracking.enabled)
        {
            return Ok(0);
        }
        self.store
            .count_users(&[AdminListCondition {
                field: "lastActiveAt".into(),
                operator: AdminListOperator::Gte,
                value: json!(Utc::now() - chrono::Duration::minutes(2)),
            }])
            .await
    }

    pub(crate) async fn dash_find_user(&self, user_id: &str) -> Result<AuthUser, AuthError> {
        self.store
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::NotFound)
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn dash_plain_user_json(&self, user: &AuthUser) -> Result<Value, AuthError> {
        serde_json::to_value(self.better_auth_user(user).await?)
            .map_err(|error| AuthError::Storage(error.to_string()))
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn dash_user_json(&self, user: &AuthUser) -> Result<Value, AuthError> {
        let mut value = self.dash_plain_user_json(user).await?;
        let object = value
            .as_object_mut()
            .expect("a Better Auth user is an object");
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
                .then_some(user.ban_expires)
                .flatten()
                .map(|date| json!(date))
                .unwrap_or(Value::Null),
        );
        Ok(value)
    }

    #[cfg(feature = "axum")]
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
        let mut output = self.dash_user_json(&user).await?;
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
        let latest_session_activity = sessions.iter().map(|session| session.updated_at).max();
        object.insert(
            "account".into(),
            serde_json::to_value(accounts)
                .map_err(|error| AuthError::Storage(error.to_string()))?,
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
        if !session_only && !account_only {
            if let Some(status) = self.dash_two_factor_status(&user).await? {
                object.insert("twoFactorStatus".into(), Value::String(status.into()));
            }
            if !minimal
                && self
                    .dash_plugin()
                    .is_some_and(|plugin| plugin.options().activity_tracking.enabled)
                && object.get("lastActiveAt").is_none_or(Value::is_null)
                && let Some(last_active) = latest_session_activity
            {
                object.insert("lastActiveAt".into(), json!(last_active));
                let _ = self.dash_set_user_activity(&user.id, last_active).await;
            }
        }
        Ok(output)
    }

    async fn dash_two_factor_status(
        &self,
        user: &AuthUser,
    ) -> Result<Option<&'static str>, AuthError> {
        let Some(plugin) = self.plugins.find::<crate::TwoFactorPlugin>() else {
            return Ok(None);
        };
        if user
            .additional_fields
            .get("twoFactorEnabled")
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Ok(Some("enabled"));
        }
        Ok(Some(
            if plugin.store.find_two_factor(&user.id).await?.is_some() {
                "pending"
            } else {
                "disabled"
            },
        ))
    }

    pub(crate) async fn dash_user_organizations(&self, user_id: &str) -> Result<Value, AuthError> {
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
        let user = super::super::user::admin_user_from_input(&mut input, role)?;
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
        let fields = dash_user_additional_fields(self);
        retain_writable_user_fields(&mut body, &fields, true)?;
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
            .prepare_user_update(
                &target,
                super::super::admin_update::admin_update_candidate(&target, &update),
            )
            .await?;
        let updated = self
            .store
            .admin_update_user(
                user_id,
                super::super::admin_update::admin_update_from_candidate(candidate),
            )
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
        let fields = dash_user_additional_fields(self);
        retain_writable_user_fields(&mut body, &fields, false)?;
        if body.is_empty() {
            return Err(AuthError::InvalidRequest(
                "No valid fields to update".into(),
            ));
        }
        let update = dash_user_update(body)?;
        self.dash_update_user(user_id, update).await
    }

    pub(crate) async fn dash_delete_user(&self, user_id: &str) -> Result<(), AuthError> {
        let user = self.dash_find_user(user_id).await?;
        self.delete_user_with_hooks(user).await
    }
}
