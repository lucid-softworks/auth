use super::{DubLead, DubOptions, cookie};
use crate::{AuthError, AuthUser, DatabaseHookContext, DatabaseHookRequest, DeferredHookResponse};
use std::{future::Future, pin::Pin, sync::Arc};

pub(super) const DELETE_DUB_COOKIE: &str =
    "dub_id=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";

type DeferredLead =
    Pin<Box<dyn Future<Output = Result<DeferredHookResponse, AuthError>> + Send + 'static>>;

pub(super) async fn after_user_create(
    options: Arc<DubOptions>,
    user: &AuthUser,
    context: &DatabaseHookContext,
) -> Result<(), AuthError> {
    let Some(request) = context.request.as_ref() else {
        return Ok(());
    };
    let Some(click_id) = cookie::dub_id(&request.headers) else {
        return Ok(());
    };
    if options.disable_lead_tracking {
        return Ok(());
    }
    let future = lead_future(options, user.clone(), request.clone(), click_id);
    match context.try_defer_after_commit(future) {
        Ok(()) => Ok(()),
        Err(future) => future.await.map(|_| ()),
    }
}

fn lead_future(
    options: Arc<DubOptions>,
    user: AuthUser,
    request: DatabaseHookRequest,
    click_id: String,
) -> DeferredLead {
    Box::pin(async move {
        if let Some(custom) = &options.custom_lead_track {
            custom.track(&user, &request).await.map_err(|_| {
                AuthError::InvalidConfiguration("Dub custom lead tracking failed".into())
            })?;
        } else {
            let lead = DubLead {
                click_id,
                event_name: options.event_name().to_owned(),
                customer_external_id: user.id.to_string(),
                customer_name: user.name,
                customer_email: user.email,
                customer_avatar: user.image,
            };
            if options.lead_tracker.track_lead(&lead).await.is_err() {
                tracing::error!("Dub lead tracking failed");
            }
        }
        Ok(DeferredHookResponse::default().with_header("set-cookie", DELETE_DUB_COOKIE))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DubCustomLeadError, DubLeadError, FnDubCustomLeadTrack, FnDubLeadTracker};
    use chrono::Utc;
    use std::collections::BTreeMap;
    use tokio::sync::Mutex;
    use uuid::Uuid;

    fn user(image: Option<&str>) -> AuthUser {
        AuthUser {
            id: Uuid::nil().to_string(),
            username: None,
            display_username: None,
            name: "Dub User".into(),
            email: "dub@example.test".into(),
            email_verified: false,
            image: image.map(str::to_owned),
            additional_fields: Default::default(),
            role: "user".into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn context(cookie: Option<&str>) -> DatabaseHookContext {
        DatabaseHookContext {
            request: Some(DatabaseHookRequest {
                method: "POST".into(),
                path: "/api/auth/sign-up/email".into(),
                query: None,
                headers: cookie
                    .map(|cookie| BTreeMap::from([("cookie".into(), cookie.into())]))
                    .unwrap_or_default(),
            }),
            creation_method: None,
        }
    }

    #[tokio::test]
    async fn default_tracking_maps_the_exact_payload_and_swallows_provider_rejection() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let mut options = DubOptions::new(Arc::new(FnDubLeadTracker::new(move |lead| {
            let recorded = recorded.clone();
            async move {
                recorded.lock().await.push(lead);
                Err(DubLeadError::new("provider rejected"))
            }
        })));
        options.lead_event_name = Some(String::new());
        let result = after_user_create(
            Arc::new(options),
            &user(Some("https://image.example/avatar.png")),
            &context(Some("dub_id=click%20encoded")),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            calls.lock().await.as_slice(),
            [DubLead {
                click_id: "click encoded".into(),
                event_name: "Sign Up".into(),
                customer_external_id: Uuid::nil().to_string(),
                customer_name: "Dub User".into(),
                customer_email: "dub@example.test".into(),
                customer_avatar: Some("https://image.example/avatar.png".into()),
            }]
        );
    }

    #[tokio::test]
    async fn custom_tracking_is_exclusive_and_rejection_propagates() {
        let provider_calls = Arc::new(Mutex::new(Vec::new()));
        let provider_recorded = provider_calls.clone();
        let mut options = DubOptions::new(Arc::new(FnDubLeadTracker::new(move |lead| {
            let provider_recorded = provider_recorded.clone();
            async move {
                provider_recorded.lock().await.push(lead);
                Ok(())
            }
        })));
        options.custom_lead_track = Some(Arc::new(FnDubCustomLeadTrack::new(|_, _| async {
            Err(DubCustomLeadError::new("custom rejected"))
        })));
        let result = after_user_create(
            Arc::new(options),
            &user(None),
            &context(Some("dub_id=click")),
        )
        .await;
        assert!(result.is_err());
        assert!(provider_calls.lock().await.is_empty());
    }

    #[tokio::test]
    async fn missing_request_cookie_and_disabled_tracking_leave_the_cookie_untouched() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let mut options = DubOptions::new(Arc::new(FnDubLeadTracker::new(move |lead| {
            let recorded = recorded.clone();
            async move {
                recorded.lock().await.push(lead);
                Ok(())
            }
        })));
        options.disable_lead_tracking = true;
        after_user_create(
            Arc::new(options),
            &user(None),
            &context(Some("dub_id=click")),
        )
        .await
        .unwrap();
        assert!(calls.lock().await.is_empty());
    }
}
