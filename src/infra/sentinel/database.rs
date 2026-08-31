use super::plugin::ReservationContext;
use super::{SecurityAction, SentinelPlugin, VerdictAction, normalize_email};
use crate::{
    AuthError, BeforeDatabaseCreateHook, BeforeDatabaseUpdateHook, DatabaseCreatePatch,
    DatabaseCreateRecord, DatabaseHookContext, DatabaseHooks, DatabaseModel, DatabaseRecord,
    DatabaseUpdatePatch, DatabaseUpdateRecord, PluginApiError,
};
use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
impl DatabaseHooks for SentinelPlugin {
    async fn before_create(
        &self,
        record: &DatabaseCreateRecord,
        context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseCreateHook, AuthError> {
        let Some(request) = context.request.as_ref() else {
            return Ok(BeforeDatabaseCreateHook::Continue);
        };
        match record.model() {
            DatabaseModel::User => self.before_user_create(record, request).await,
            DatabaseModel::Session => self.before_session_create(record, request).await,
            _ => Ok(BeforeDatabaseCreateHook::Continue),
        }
    }

    async fn after_create(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        let Some(request) = context.request.as_ref() else {
            return Ok(());
        };
        match record {
            DatabaseRecord::User(user) => self.after_user_create(&user.id, request).await,
            DatabaseRecord::Session(session) => {
                self.after_session_create(&session.user_id, request).await;
            }
            _ => {}
        }
        Ok(())
    }

    async fn before_update(
        &self,
        record: &DatabaseUpdateRecord,
        context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseUpdateHook, AuthError> {
        if context.request.is_none() || record.model() != DatabaseModel::User {
            return Ok(BeforeDatabaseUpdateHook::Continue);
        }
        let Some(email) = record.get("email").and_then(Value::as_str) else {
            return Ok(BeforeDatabaseUpdateHook::Continue);
        };
        Ok(BeforeDatabaseUpdateHook::merge(
            DatabaseUpdatePatch::new().with_field(
                "email",
                Value::String(normalize_email(email, &self.options().security)),
            ),
        ))
    }
}

impl SentinelPlugin {
    async fn before_user_create(
        &self,
        record: &DatabaseCreateRecord,
        request: &crate::DatabaseHookRequest,
    ) -> Result<BeforeDatabaseCreateHook, AuthError> {
        if !is_dash_route(&request.path)
            && self
                .options()
                .security
                .free_trial_abuse
                .as_ref()
                .is_some_and(|options| options.enabled)
        {
            self.reserve_signup(request).await?;
        }
        let Some(email) = record.get("email").and_then(Value::as_str) else {
            return Ok(BeforeDatabaseCreateHook::Continue);
        };
        Ok(BeforeDatabaseCreateHook::Merge(
            DatabaseCreatePatch::new().with_field(
                "email",
                Value::String(normalize_email(email, &self.options().security)),
            ),
        ))
    }

    async fn reserve_signup(
        &self,
        request: &crate::DatabaseHookRequest,
    ) -> Result<(), AuthError> {
        let request_id = request_id(request);
        let identification = request_id
            .as_deref()
            .and_then(|request_id| self.request_identification(request_id));
        let Some(visitor_id) = identification
            .as_ref()
            .and_then(|context| context.visitor_id.clone())
        else {
            return Err(api_error(
                "Account creation is not allowed without device identification.",
            ));
        };
        let reservation_id = uuid::Uuid::new_v4().to_string();
        let reservation = self
            .security_client()
            .reserve_free_trial_signup(
                &visitor_id,
                &reservation_id,
                identification
                    .as_ref()
                    .and_then(|context| context.request_id.as_deref()),
            )
            .await;
        if reservation.is_abuse && reservation.action == SecurityAction::Block {
            return Err(api_error(
                "Account creation is not allowed from this device.",
            ));
        }
        if let Some(request_id) = request_id {
            self.remember_reservation(
                request_id,
                ReservationContext {
                    visitor_id,
                    reservation_id,
                    request_id: identification.and_then(|context| context.request_id),
                },
            );
        }
        Ok(())
    }

    async fn after_user_create(&self, user_id: &str, request: &crate::DatabaseHookRequest) {
        if is_dash_route(&request.path) {
            return;
        }
        let Some(reservation) = request_id(request)
            .as_deref()
            .and_then(|request_id| self.take_reservation(request_id))
        else {
            return;
        };
        self.security_client()
            .confirm_free_trial_signup(
                &reservation.visitor_id,
                &reservation.reservation_id,
                user_id,
                reservation.request_id.as_deref(),
            )
            .await;
    }

    async fn before_session_create(
        &self,
        record: &DatabaseCreateRecord,
        request: &crate::DatabaseHookRequest,
    ) -> Result<BeforeDatabaseCreateHook, AuthError> {
        if is_dash_route(&request.path) {
            return Ok(BeforeDatabaseCreateHook::Continue);
        }
        let Some(identification) = request_context(self, request) else {
            return Ok(BeforeDatabaseCreateHook::Continue);
        };
        let Some(visitor_id) = identification.visitor_id.as_deref() else {
            return Ok(BeforeDatabaseCreateHook::Continue);
        };
        let Some(location) = identification
            .identification
            .as_ref()
            .and_then(|identification| identification.location.as_ref())
            .and_then(|location| serde_json::to_value(location).ok())
        else {
            return Ok(BeforeDatabaseCreateHook::Continue);
        };
        let Some(user_id) = record.get("userId").and_then(Value::as_str) else {
            return Ok(BeforeDatabaseCreateHook::Continue);
        };
        let travel = self
            .security_client()
            .check_impossible_travel(
                user_id,
                Some(&location),
                visitor_id,
                identification.ip.as_deref(),
                request.headers.get("x-pow-solution").map(String::as_str),
                identification.request_id.as_deref(),
            )
            .await;
        match travel {
            Some(result) if result.is_impossible && result.action == Some(VerdictAction::Block) => {
                Err(PluginApiError::new(
                    403,
                    "FORBIDDEN",
                    "Login blocked due to suspicious location change.",
                )
                .into())
            }
            Some(result)
                if result.is_impossible
                    && result.action == Some(VerdictAction::Challenge)
                    && result.challenge.is_some() =>
            {
                Err(PluginApiError::new(
                    423,
                    "POW_CHALLENGE_REQUIRED",
                    "Unusual login location detected. Please complete a security check.",
                )
                .into())
            }
            _ => Ok(BeforeDatabaseCreateHook::Continue),
        }
    }

    async fn after_session_create(&self, user_id: &str, request: &crate::DatabaseHookRequest) {
        if is_dash_route(&request.path) {
            return;
        }
        let Some(identification) = request_context(self, request) else {
            return;
        };
        let location = identification
            .identification
            .as_ref()
            .and_then(|identification| identification.location.as_ref())
            .and_then(|location| serde_json::to_value(location).ok());
        self.security_client()
            .store_last_location(user_id, location.as_ref(), identification.ip.as_deref())
            .await;
    }
}

fn request_context(
    plugin: &SentinelPlugin,
    request: &crate::DatabaseHookRequest,
) -> Option<crate::infra::dash::IdentificationContext> {
    request_id(request).and_then(|request_id| plugin.request_identification(&request_id))
}

fn api_error(message: &'static str) -> AuthError {
    PluginApiError::new(403, "FORBIDDEN", message).into()
}

fn is_dash_route(path: &str) -> bool {
    path == "/dash" || path.starts_with("/dash/")
}

fn request_id(request: &crate::DatabaseHookRequest) -> Option<String> {
    request
        .headers
        .get("x-request-id")
        .filter(|value| !value.is_empty())
        .cloned()
        .or_else(|| {
            request.headers.get("cookie").and_then(|cookies| {
                cookies.split(';').find_map(|cookie| {
                    let (name, value) = cookie.trim().split_once('=')?;
                    (name == "__infra-rid" && !value.is_empty()).then(|| value.to_owned())
                })
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, json};
    use std::collections::BTreeMap;

    fn request(path: &str) -> crate::DatabaseHookRequest {
        crate::DatabaseHookRequest {
            method: "POST".into(),
            path: path.into(),
            query: None,
            headers: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn normalizes_request_bound_user_creates() {
        let plugin = SentinelPlugin::default();
        let record = DatabaseCreateRecord::new(
            DatabaseModel::User,
            Map::from_iter([
                ("name".into(), json!("Person")),
                ("email".into(), json!("User.Name+tag@googlemail.com")),
                ("emailVerified".into(), json!(false)),
            ]),
        );
        let context = DatabaseHookContext {
            request: Some(request("/sign-up/email")),
            ..DatabaseHookContext::default()
        };
        let BeforeDatabaseCreateHook::Merge(patch) =
            plugin.before_create(&record, &context).await.unwrap()
        else {
            panic!("normalization must patch the user");
        };
        assert_eq!(patch.fields()["email"], "username@gmail.com");
    }

    #[test]
    fn resolves_header_then_cookie_request_ids() {
        let mut value = request("/sign-up/email");
        value.headers.insert("cookie".into(), "__infra-rid=cookie".into());
        assert_eq!(request_id(&value).as_deref(), Some("cookie"));
        value.headers.insert("x-request-id".into(), "header".into());
        assert_eq!(request_id(&value).as_deref(), Some("header"));
    }
}
