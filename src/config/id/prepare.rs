use super::{
    DatabaseIdAdapterCapabilities, DatabaseIdGeneration, DatabaseIdGenerationRequest,
    DatabaseIdGenerationResult, DatabaseIdGenerationSize, DatabaseIdGenerationSource,
    DatabaseIdGenerator, generate_database_id,
};
use crate::store::{DatabaseIdInput, DatabaseIdValue, PreparedDatabaseId};

mod forced;

/// Applies Better Auth's create-time ID default and input transform.
///
/// `force_allow_id` is effective only when the input has an own `id` value.
/// Ordinary creates therefore ignore any legacy constructor value and prepare
/// a fresh ID after create hooks have completed.
pub(super) fn prepare_database_id(
    strategy: &DatabaseIdGeneration,
    adapter_name: &str,
    model: &str,
    capabilities: DatabaseIdAdapterCapabilities,
    adapter_generator: Option<&dyn DatabaseIdGenerator>,
    force_allow_id: bool,
    input: DatabaseIdInput,
) -> Result<PreparedDatabaseId, crate::AuthError> {
    if !force_allow_id && !matches!(input, DatabaseIdInput::Absent) {
        tracing::warn!(
            "[{adapter_name}] - You are trying to create a record with an id. This is not allowed as we handle id generation for you, unless you pass in the `forceAllowId` parameter. The id will be ignored."
        );
    }
    if force_allow_id && !matches!(input, DatabaseIdInput::Absent | DatabaseIdInput::Null) {
        return Ok(forced::prepare_forced_id(strategy, capabilities, input));
    }
    let value = match strategy.adapter_source(capabilities, adapter_generator.is_some()) {
        DatabaseIdGenerationSource::Disabled => {
            return Ok(PreparedDatabaseId::Deferred);
        }
        DatabaseIdGenerationSource::Deferred => return Ok(deferred_id(strategy)),
        DatabaseIdGenerationSource::Callback => match strategy {
            DatabaseIdGeneration::Callback(generator) => {
                generator.generate(DatabaseIdGenerationRequest {
                    model,
                    size: DatabaseIdGenerationSize::Omitted,
                })
            }
            _ => unreachable!("callback source requires callback strategy"),
        },
        DatabaseIdGenerationSource::Uuid => {
            return Ok(string_id(uuid::Uuid::new_v4().to_string()));
        }
        DatabaseIdGenerationSource::Adapter => adapter_generator
            .expect("adapter source requires a custom generator")
            .generate(DatabaseIdGenerationRequest {
                model,
                size: DatabaseIdGenerationSize::Omitted,
            }),
        DatabaseIdGenerationSource::Default => {
            return generate_database_id(DatabaseIdGenerationSize::Omitted)
                .map(string_id)
                .map_err(|error| crate::AuthError::Storage(error.to_string()));
        }
    };
    Ok(match value {
        DatabaseIdGenerationResult::Id(value) if value.is_empty() => PreparedDatabaseId::Deferred,
        DatabaseIdGenerationResult::Id(value) => string_id(value),
        DatabaseIdGenerationResult::Defer => PreparedDatabaseId::Deferred,
    })
}

pub(super) fn deferred_id(strategy: &DatabaseIdGeneration) -> PreparedDatabaseId {
    if matches!(strategy, DatabaseIdGeneration::Serial) {
        PreparedDatabaseId::DeferredSerial
    } else {
        PreparedDatabaseId::Deferred
    }
}

pub(super) fn string_id(value: String) -> PreparedDatabaseId {
    PreparedDatabaseId::Value(DatabaseIdValue::String(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct Counting(AtomicUsize);

    impl DatabaseIdGenerator for Counting {
        fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            self.0.fetch_add(1, Ordering::Relaxed);
            DatabaseIdGenerationResult::Id(format!("{}-id", request.model))
        }
    }

    #[derive(Debug)]
    struct Deferring(AtomicUsize);

    impl DatabaseIdGenerator for Deferring {
        fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            assert_eq!(request.model, "user");
            assert_eq!(request.size, DatabaseIdGenerationSize::Omitted);
            self.0.fetch_add(1, Ordering::Relaxed);
            DatabaseIdGenerationResult::Defer
        }
    }

    #[derive(Debug)]
    struct Empty(AtomicUsize);

    impl DatabaseIdGenerator for Empty {
        fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            assert_eq!(request.model, "user");
            assert_eq!(request.size, DatabaseIdGenerationSize::Omitted);
            self.0.fetch_add(1, Ordering::Relaxed);
            DatabaseIdGenerationResult::Id(String::new())
        }
    }

    #[test]
    fn ordinary_create_invokes_model_callback_once() {
        let generator = Arc::new(Counting(AtomicUsize::new(0)));
        let strategy = DatabaseIdGeneration::Callback(generator.clone());
        assert_eq!(
            prepare_database_id(
                &strategy,
                "Test Adapter",
                "user",
                DatabaseIdAdapterCapabilities::default(),
                None,
                false,
                DatabaseIdInput::Absent,
            )
            .unwrap(),
            PreparedDatabaseId::Value(DatabaseIdValue::String("user-id".into()))
        );
        assert_eq!(generator.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn ordinary_create_ignores_every_supplied_id_value() {
        for input in [
            DatabaseIdInput::Null,
            DatabaseIdInput::Boolean(false),
            DatabaseIdInput::Boolean(true),
            DatabaseIdInput::Number(0.0),
            DatabaseIdInput::Number(42.0),
            DatabaseIdInput::String(String::new()),
            DatabaseIdInput::String("caller-id".into()),
        ] {
            let generator = Arc::new(Counting(AtomicUsize::new(0)));
            let result = prepare_database_id(
                &DatabaseIdGeneration::Callback(generator.clone()),
                "Test Adapter",
                "user",
                DatabaseIdAdapterCapabilities::default(),
                None,
                false,
                input,
            )
            .unwrap();
            assert_eq!(
                result,
                PreparedDatabaseId::Value(DatabaseIdValue::String("user-id".into()))
            );
            assert_eq!(generator.0.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn callback_false_and_disabled_adapter_defer_without_fallback() {
        let generator = Arc::new(Deferring(AtomicUsize::new(0)));
        let strategy = DatabaseIdGeneration::Callback(generator.clone());
        assert_eq!(
            prepare_database_id(
                &strategy,
                "Test Adapter",
                "user",
                DatabaseIdAdapterCapabilities::default(),
                None,
                false,
                DatabaseIdInput::Absent,
            )
            .unwrap(),
            PreparedDatabaseId::Deferred
        );
        assert_eq!(generator.0.load(Ordering::Relaxed), 1);

        let disabled = DatabaseIdAdapterCapabilities {
            disable_id_generation: true,
            ..DatabaseIdAdapterCapabilities::default()
        };
        assert_eq!(
            prepare_database_id(
                &strategy,
                "Test Adapter",
                "user",
                disabled,
                None,
                false,
                DatabaseIdInput::Absent,
            )
            .unwrap(),
            PreparedDatabaseId::Deferred
        );
        assert_eq!(generator.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn empty_callback_and_custom_adapter_ids_defer_without_fallback() {
        let callback = Arc::new(Empty(AtomicUsize::new(0)));
        assert_eq!(
            prepare_database_id(
                &DatabaseIdGeneration::Callback(callback.clone()),
                "Test Adapter",
                "user",
                DatabaseIdAdapterCapabilities::default(),
                None,
                false,
                DatabaseIdInput::Absent,
            )
            .unwrap(),
            PreparedDatabaseId::Deferred
        );
        assert_eq!(callback.0.load(Ordering::Relaxed), 1);

        let adapter = Empty(AtomicUsize::new(0));
        assert_eq!(
            prepare_database_id(
                &DatabaseIdGeneration::Default,
                "Test Adapter",
                "user",
                DatabaseIdAdapterCapabilities::default(),
                Some(&adapter),
                false,
                DatabaseIdInput::Absent,
            )
            .unwrap(),
            PreparedDatabaseId::Deferred
        );
        assert_eq!(adapter.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn serial_deferral_remains_distinguishable_from_disabled_generation() {
        let capabilities = DatabaseIdAdapterCapabilities::default();
        let prepare = |capabilities| {
            prepare_database_id(
                &DatabaseIdGeneration::Serial,
                "Test Adapter",
                "user",
                capabilities,
                None,
                false,
                DatabaseIdInput::Absent,
            )
            .unwrap()
        };
        assert_eq!(prepare(capabilities), PreparedDatabaseId::DeferredSerial);
        assert_eq!(
            prepare(DatabaseIdAdapterCapabilities {
                disable_id_generation: true,
                ..capabilities
            }),
            PreparedDatabaseId::Deferred
        );
    }

    #[test]
    fn adapter_generator_precedes_the_builtin_default() {
        let generator = Counting(AtomicUsize::new(0));
        assert_eq!(
            prepare_database_id(
                &DatabaseIdGeneration::Default,
                "Test Adapter",
                "session",
                DatabaseIdAdapterCapabilities::default(),
                Some(&generator),
                false,
                DatabaseIdInput::Absent,
            )
            .unwrap(),
            PreparedDatabaseId::Value(DatabaseIdValue::String("session-id".into()))
        );
        assert_eq!(generator.0.load(Ordering::Relaxed), 1);
    }
}
