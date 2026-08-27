use crate::{
    AuthConfig, DatabaseIdGenerationResult, DatabaseIdGenerationSize, generate_database_id,
};

pub(super) fn generate(config: &AuthConfig, model: &str) -> String {
    let generated = config
        .generate_context_id(model, DatabaseIdGenerationSize::Undefined)
        .expect("Test Utils requests an undefined or fixed positive ID length");
    match generated {
        DatabaseIdGenerationResult::Id(id) => id,
        DatabaseIdGenerationResult::Defer => {
            random_id(DatabaseIdGenerationSize::Value(TEST_UTILS_FALLBACK_SIZE))
        }
    }
}

const TEST_UTILS_FALLBACK_SIZE: f64 = 24.0;

fn random_id(size: DatabaseIdGenerationSize) -> String {
    generate_database_id(size).expect("fixed Test Utils ID lengths are valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerationResult};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct Callback {
        calls: AtomicUsize,
        result: DatabaseIdGenerationResult,
    }

    impl crate::DatabaseIdGenerator for Callback {
        fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            assert_eq!(request.model, "user");
            assert_eq!(request.size, DatabaseIdGenerationSize::Undefined);
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.result.clone()
        }
    }

    #[test]
    fn false_is_the_only_callback_result_that_uses_the_24_character_fallback() {
        for (result, expected) in [
            (DatabaseIdGenerationResult::Id(String::new()), Some("")),
            (DatabaseIdGenerationResult::Defer, None),
        ] {
            let callback = Arc::new(Callback {
                calls: AtomicUsize::new(0),
                result,
            });
            let mut config = AuthConfig::new([b'I'; 32]).unwrap();
            config.database_id_generation = DatabaseIdGeneration::Callback(callback.clone());
            let id = generate(&config, "user");
            match expected {
                Some(expected) => assert_eq!(id, expected),
                None => assert!(is_base62(&id, 24)),
            }
            assert_eq!(callback.calls.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn default_and_database_strategies_keep_their_distinct_context_lengths() {
        for (strategy, length) in [
            (DatabaseIdGeneration::Default, 32),
            (DatabaseIdGeneration::Database, 24),
            (DatabaseIdGeneration::Serial, 24),
        ] {
            let mut config = AuthConfig::new([b'I'; 32]).unwrap();
            config.database_id_generation = strategy;
            let first = generate(&config, "user");
            let second = generate(&config, "user");
            assert!(is_base62(&first, length));
            assert!(is_base62(&second, length));
            assert_ne!(first, second);
        }
    }

    fn is_base62(value: &str, length: usize) -> bool {
        value.len() == length && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }
}
