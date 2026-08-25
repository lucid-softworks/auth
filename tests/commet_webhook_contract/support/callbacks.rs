use lucid_auth::{
    CommetWebhookCallbackError, CommetWebhookCallbacks, FnCommetWebhookCallback,
    SharedCommetWebhookPayload,
};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) type CallbackLog = Arc<Mutex<Vec<(&'static str, Value)>>>;

pub(crate) fn callbacks(log: CallbackLog, fail_named: bool) -> CommetWebhookCallbacks {
    let named_log = log.clone();
    let named = FnCommetWebhookCallback::new(move |payload: SharedCommetWebhookPayload| {
        let log = named_log.clone();
        async move {
            let payload = payload.lock().await.clone();
            log.lock().await.push(("specific", payload));
            if fail_named {
                Err(CommetWebhookCallbackError::new("sensitive detail"))
            } else {
                Ok(())
            }
        }
    });
    let catch_all = FnCommetWebhookCallback::new(move |payload: SharedCommetWebhookPayload| {
        let log = log.clone();
        async move {
            let payload = payload.lock().await.clone();
            log.lock().await.push(("catch-all", payload));
            Ok(())
        }
    });
    CommetWebhookCallbacks {
        on_payload: Some(Arc::new(catch_all)),
        on_subscription_created: Some(Arc::new(named)),
        ..CommetWebhookCallbacks::default()
    }
}
