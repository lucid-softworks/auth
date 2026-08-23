use super::MemoryStore;
use crate::{
    AccessStore, AdminListCondition, AdminListOperator, AdminListUsersQuery, AdminSortDirection,
    AdminUserUpdate, AuthError, AuthSession, AuthUser,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
impl AccessStore for MemoryStore {
    async fn list_users(&self, query: &AdminListUsersQuery) -> Result<Vec<AuthUser>, AuthError> {
        let mut users: Vec<_> = self
            .state
            .read()
            .await
            .users
            .values()
            .filter(|user| matches_conditions(user, &query.conditions))
            .cloned()
            .collect();
        sort_users(&mut users, query);
        Ok(users
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect())
    }

    async fn count_users(&self, conditions: &[AdminListCondition]) -> Result<i64, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .users
            .values()
            .filter(|user| matches_conditions(user, conditions))
            .count() as i64)
    }

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .users
            .values()
            .filter(|user| user.role == role)
            .count() as i64)
    }

    async fn update_user_role(&self, user_id: Uuid, role: &str) -> Result<AuthUser, AuthError> {
        let mut state = self.state.write().await;
        let user = state.users.get_mut(&user_id).ok_or(AuthError::NotFound)?;
        user.role = role.to_owned();
        user.updated_at = Utc::now();
        Ok(user.clone())
    }

    async fn update_user_ban(
        &self,
        user_id: Uuid,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<AuthUser, AuthError> {
        let mut state = self.state.write().await;
        let user = state.users.get_mut(&user_id).ok_or(AuthError::NotFound)?;
        user.banned = banned;
        user.ban_reason = reason;
        user.ban_expires = expires_at;
        user.updated_at = Utc::now();
        Ok(user.clone())
    }

    async fn admin_update_user(
        &self,
        user_id: Uuid,
        update: AdminUserUpdate,
    ) -> Result<AuthUser, AuthError> {
        let mut state = self.state.write().await;
        let previous_email = state
            .users
            .get(&user_id)
            .ok_or(AuthError::NotFound)?
            .email
            .clone();
        if let Some(email) = &update.email
            && state
                .emails
                .get(email)
                .is_some_and(|existing| *existing != user_id)
        {
            return Err(AuthError::UserAlreadyExistsEmail);
        }
        let user = state.users.get_mut(&user_id).ok_or(AuthError::NotFound)?;
        if let Some(name) = update.name {
            user.name = name;
        }
        if let Some(email) = update.email {
            user.email = email;
        }
        if let Some(verified) = update.email_verified {
            user.email_verified = verified;
        }
        if let Some(image) = update.image {
            user.image = image;
        }
        if let Some(role) = update.role {
            user.role = role;
        }
        if let Some(banned) = update.banned {
            user.banned = banned;
        }
        if let Some(reason) = update.ban_reason {
            user.ban_reason = reason;
        }
        if let Some(expires) = update.ban_expires {
            user.ban_expires = expires;
        }
        user.additional_fields.extend(update.additional_fields);
        user.updated_at = Utc::now();
        let result = user.clone();
        if result.email != previous_email {
            state.emails.remove(&previous_email);
            state.emails.insert(result.email.clone(), user_id);
        }
        Ok(result)
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        let user = state.users.remove(&user_id).ok_or(AuthError::NotFound)?;
        if let Some(username) = user.username {
            state.usernames.remove(&username);
        }
        state.emails.remove(&user.email);
        state.passwords.remove(&user_id);
        state
            .passkeys
            .retain(|_, passkey| passkey.user_id != user_id);
        let removed_grants: Vec<_> = state
            .guest_grants
            .values()
            .filter(|grant| grant.created_by == user_id)
            .map(|grant| grant.id)
            .collect();
        state
            .guest_grants
            .retain(|_, grant| grant.created_by != user_id);
        state
            .api_keys
            .retain(|_, api_key| api_key.reference_id != user_id.to_string());
        let user_id_text = user_id.to_string();
        state.verifications.retain(|_, verification| {
            verification
                .payload
                .get("userId")
                .and_then(|value| value.as_str())
                != Some(user_id_text.as_str())
        });
        let removed_sessions: Vec<_> = state
            .sessions
            .values()
            .filter(|session| session.user_id == user_id || session.actor_user_id == Some(user_id))
            .map(|session| session.id)
            .collect();
        state.sessions.retain(|_, session| {
            session.user_id != user_id && session.actor_user_id != Some(user_id)
        });
        state.guest_sessions.retain(|session_id, grant_id| {
            !removed_sessions.contains(session_id) && !removed_grants.contains(grant_id)
        });
        Ok(())
    }

    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<AuthSession>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .sessions
            .values()
            .filter(|session| session.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_session_by_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        state.sessions.retain(|_, session| session.id != session_id);
        state.guest_sessions.remove(&session_id);
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        state
            .sessions
            .retain(|_, session| session.user_id != user_id);
        let active_sessions: std::collections::HashSet<_> =
            state.sessions.values().map(|session| session.id).collect();
        state
            .guest_sessions
            .retain(|session_id, _| active_sessions.contains(session_id));
        Ok(())
    }
}

fn matches_conditions(user: &AuthUser, conditions: &[AdminListCondition]) -> bool {
    conditions
        .iter()
        .all(|condition| matches_condition(user, condition))
}

fn matches_condition(user: &AuthUser, condition: &AdminListCondition) -> bool {
    let Some(actual) = user_field(user, &condition.field) else {
        return false;
    };
    let expected = &condition.value;
    match condition.operator {
        AdminListOperator::Eq => actual == *expected,
        AdminListOperator::Ne => actual != *expected,
        AdminListOperator::In | AdminListOperator::NotIn => {
            let included = expected
                .as_array()
                .is_some_and(|values| values.contains(&actual));
            if condition.operator == AdminListOperator::In {
                included
            } else {
                !included
            }
        }
        operator => compare_values(&actual, expected, operator),
    }
}

fn compare_values(
    actual: &serde_json::Value,
    expected: &serde_json::Value,
    operator: AdminListOperator,
) -> bool {
    let (Some(actual), Some(expected)) = (actual.as_str(), expected.as_str()) else {
        return false;
    };
    match operator {
        AdminListOperator::Contains => actual.contains(expected),
        AdminListOperator::StartsWith => actual.starts_with(expected),
        AdminListOperator::EndsWith => actual.ends_with(expected),
        AdminListOperator::Lt => actual < expected,
        AdminListOperator::Lte => actual <= expected,
        AdminListOperator::Gt => actual > expected,
        AdminListOperator::Gte => actual >= expected,
        _ => false,
    }
}

fn user_field(user: &AuthUser, field: &str) -> Option<serde_json::Value> {
    Some(match field {
        "id" => serde_json::Value::String(user.id.to_string()),
        "username" => option_string(user.username.as_deref()),
        "displayUsername" => option_string(user.display_username.as_deref()),
        "name" => serde_json::Value::String(user.name.clone()),
        "email" => serde_json::Value::String(user.email.clone()),
        "emailVerified" => serde_json::Value::Bool(user.email_verified),
        "image" => option_string(user.image.as_deref()),
        "role" => serde_json::Value::String(user.role.clone()),
        "isAnonymous" => serde_json::Value::Bool(user.is_anonymous),
        "banned" => serde_json::Value::Bool(user.banned),
        "banReason" => option_string(user.ban_reason.as_deref()),
        "banExpires" => user
            .ban_expires
            .map(|value| serde_json::Value::String(value.to_rfc3339()))
            .unwrap_or(serde_json::Value::Null),
        "createdAt" => serde_json::Value::String(user.created_at.to_rfc3339()),
        "updatedAt" => serde_json::Value::String(user.updated_at.to_rfc3339()),
        _ => user.additional_fields.get(field)?.clone(),
    })
}

fn option_string(value: Option<&str>) -> serde_json::Value {
    value
        .map(|value| serde_json::Value::String(value.to_owned()))
        .unwrap_or(serde_json::Value::Null)
}

fn sort_users(users: &mut [AuthUser], query: &AdminListUsersQuery) {
    let field = query.sort_by.as_deref().unwrap_or("createdAt");
    users.sort_by(|left, right| {
        let left = user_field(left, field).unwrap_or(serde_json::Value::Null);
        let right = user_field(right, field).unwrap_or(serde_json::Value::Null);
        let order = left.to_string().cmp(&right.to_string());
        if query.sort_direction == AdminSortDirection::Desc {
            order.reverse()
        } else {
            order
        }
    });
}
