use super::AuthService;
use crate::{
    AuthError, DatabaseIdGenerationResult, DatabaseIdGenerationSize, generate_database_id,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ContextIdFallback {
    DeferOnly,
    Falsey,
}

impl AuthService {
    #[cfg(feature = "axum")]
    pub(crate) fn generate_plugin_database_id(&self, model: &str) -> Result<String, AuthError> {
        self.generate_special_database_id(model, ContextIdFallback::Falsey, 32.0)
    }

    pub(super) fn generate_special_database_id(
        &self,
        model: &str,
        fallback: ContextIdFallback,
        fallback_size: f64,
    ) -> Result<String, AuthError> {
        let generated = self
            .config
            .generate_context_id(model, DatabaseIdGenerationSize::Undefined)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        match generated {
            DatabaseIdGenerationResult::Id(id)
                if fallback == ContextIdFallback::DeferOnly || !id.is_empty() =>
            {
                Ok(id)
            }
            DatabaseIdGenerationResult::Id(_) | DatabaseIdGenerationResult::Defer => {
                generate_database_id(DatabaseIdGenerationSize::Value(fallback_size))
                    .map_err(|error| AuthError::Storage(error.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerator,
        MemoryStore,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct Callback {
        result: DatabaseIdGenerationResult,
        calls: Mutex<Vec<(String, DatabaseIdGenerationSize)>>,
    }

    impl DatabaseIdGenerator for Callback {
        fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            self.calls
                .lock()
                .unwrap()
                .push((request.model.into(), request.size));
            self.result.clone()
        }
    }

    fn service(result: DatabaseIdGenerationResult) -> (AuthService, Arc<Callback>) {
        let callback = Arc::new(Callback {
            result,
            calls: Mutex::new(Vec::new()),
        });
        let mut config = AuthConfig::new([b'C'; 32]).unwrap();
        config.database_id_generation = DatabaseIdGeneration::Callback(callback.clone());
        (
            AuthService::new(Arc::new(MemoryStore::default()), config),
            callback,
        )
    }

    #[test]
    fn special_paths_distinguish_strict_false_from_javascript_falsey() {
        let (service, callback) = service(DatabaseIdGenerationResult::Id(String::new()));
        assert_eq!(
            service
                .generate_special_database_id("session", ContextIdFallback::DeferOnly, 32.0)
                .unwrap(),
            ""
        );
        let fallback = service
            .generate_special_database_id("user", ContextIdFallback::Falsey, 32.0)
            .unwrap();
        assert_base62(&fallback, 32);
        assert_eq!(
            *callback.calls.lock().unwrap(),
            [
                ("session".into(), DatabaseIdGenerationSize::Undefined),
                ("user".into(), DatabaseIdGenerationSize::Undefined),
            ]
        );
    }

    #[test]
    fn strict_false_uses_the_requested_direct_fallback() {
        let (service, callback) = service(DatabaseIdGenerationResult::Defer);
        let id = service
            .generate_special_database_id("session", ContextIdFallback::DeferOnly, 32.0)
            .unwrap();
        assert_base62(&id, 32);
        assert_eq!(callback.calls.lock().unwrap().len(), 1);
    }

    fn assert_base62(value: &str, length: usize) {
        assert_eq!(value.len(), length);
        assert!(value.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    }
}
