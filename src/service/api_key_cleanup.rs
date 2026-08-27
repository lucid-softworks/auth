use super::AuthService;
use chrono::Utc;
use std::{sync::Mutex, time::Instant};

static LAST_CHECKED: Mutex<Option<Instant>> = Mutex::new(None);

impl AuthService {
    pub(crate) fn schedule_api_key_cleanup(&self) {
        let now = Instant::now();
        let mut last_checked = LAST_CHECKED.lock().expect("API-key cleanup lock poisoned");
        if last_checked.is_some_and(|last| now.duration_since(last).as_secs() < 10) {
            return;
        }
        *last_checked = Some(now);
        drop(last_checked);

        let store = self.store.clone();
        crate::DatabaseHookContext::default().run_in_background(async move {
            if let Err(error) = store.delete_expired_api_keys(Utc::now()).await {
                tracing::error!("Failed to delete expired API keys: {}", error);
            }
        });
    }
}
