use super::ScimPlugin;
use crate::{AuthError, scim::ScimError};
use std::{future::Future, pin::Pin, sync::Arc};

impl ScimPlugin {
    pub(crate) async fn run_mutation<T, F>(&self, operation: F) -> Result<T, ScimError>
    where
        T: Send + 'static,
        F: Fn() -> Pin<Box<dyn Future<Output = Result<T, ScimError>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        let Some(store) = self.store.backing_auth_store() else {
            return operation().await;
        };
        let operation = Arc::new(operation);
        for attempt in 1..=3 {
            let current = operation.clone();
            let result = crate::run_database_transaction(store.as_ref(), move |_| {
                Box::pin(async move { current().await.map_err(encode_error) })
            })
            .await
            .map_err(decode_error);
            match result {
                Err(error) if attempt < 3 && error.retryable => continue,
                result => return result,
            }
        }
        unreachable!("the third SCIM mutation attempt always returns")
    }
}

fn encode_error(error: ScimError) -> AuthError {
    let serialized = serde_json::to_string(&error)
        .unwrap_or_else(|_| "{\"status\":500,\"detail\":\"SCIM mutation failed\"}".into());
    AuthError::Storage(format!("{ERROR_PREFIX}{serialized}"))
}

fn decode_error(error: AuthError) -> ScimError {
    let detail = error.to_string();
    detail
        .split_once(ERROR_PREFIX)
        .and_then(|(_, serialized)| serde_json::from_str(serialized).ok())
        .unwrap_or_else(|| ScimError::new(500, detail))
}

const ERROR_PREFIX: &str = "__lucid_scim_mutation_error__:";

#[cfg(test)]
mod tests {
    #[test]
    fn only_marked_concurrency_conflicts_are_retryable() {
        let detail = "The SCIM resource changed concurrently; retry the request";
        let retryable = crate::scim::ScimError::retryable_conflict(detail);
        assert!(retryable.retryable);
        assert!(super::decode_error(super::encode_error(retryable)).retryable);
        assert!(!crate::scim::ScimError::new(409, detail).retryable);
    }
}
