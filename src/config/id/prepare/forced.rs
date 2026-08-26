use super::*;
use num_bigint::BigUint;
use num_traits::ToPrimitive as _;
use std::sync::LazyLock;

pub(super) fn prepare_forced_id(
    strategy: &DatabaseIdGeneration,
    capabilities: DatabaseIdAdapterCapabilities,
    input: DatabaseIdInput,
) -> PreparedDatabaseId {
    if capabilities.disable_id_generation {
        return PreparedDatabaseId::Deferred;
    }
    if is_falsey(&input) {
        return deferred_id(strategy);
    }
    if matches!(strategy, DatabaseIdGeneration::Serial) {
        return javascript_number(&input).map_or(PreparedDatabaseId::DeferredSerial, |value| {
            PreparedDatabaseId::Value(DatabaseIdValue::Number(value))
        });
    }
    if matches!(strategy, DatabaseIdGeneration::Uuid) {
        if let DatabaseIdInput::String(value) = input {
            return if valid_uuid(&value) {
                string_id(value)
            } else {
                tracing::warn!(
                    "[Adapter Factory] - Invalid UUID value for field `id` provided when `forceAllowId` is true. Generating a new UUID."
                );
                PreparedDatabaseId::Deferred
            };
        }
        return if capabilities.supports_uuids {
            PreparedDatabaseId::Deferred
        } else {
            string_id(uuid::Uuid::new_v4().to_string())
        };
    }
    match input {
        DatabaseIdInput::Boolean(value) => {
            PreparedDatabaseId::Value(DatabaseIdValue::Boolean(value))
        }
        DatabaseIdInput::Number(value) => PreparedDatabaseId::Value(DatabaseIdValue::Number(value)),
        DatabaseIdInput::String(value) => string_id(value),
        DatabaseIdInput::Absent | DatabaseIdInput::Null => deferred_id(strategy),
    }
}

fn is_falsey(input: &DatabaseIdInput) -> bool {
    match input {
        DatabaseIdInput::Absent | DatabaseIdInput::Null => true,
        DatabaseIdInput::Boolean(value) => !value,
        DatabaseIdInput::Number(value) => *value == 0.0 || value.is_nan(),
        DatabaseIdInput::String(value) => value.is_empty(),
    }
}

fn javascript_number(input: &DatabaseIdInput) -> Option<f64> {
    match input {
        DatabaseIdInput::Boolean(value) => Some(u8::from(*value).into()),
        DatabaseIdInput::Number(value) => (!value.is_nan()).then_some(*value),
        DatabaseIdInput::String(value) => javascript_number_string(value),
        DatabaseIdInput::Absent | DatabaseIdInput::Null => Some(0.0),
    }
}

fn javascript_number_string(input: &str) -> Option<f64> {
    let input = input.trim();
    if input.is_empty() {
        return Some(0.0);
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = input.strip_prefix(prefix) {
            if digits.is_empty() {
                return None;
            }
            return BigUint::parse_bytes(digits.as_bytes(), radix).and_then(|value| value.to_f64());
        }
    }
    if matches!(input, "Infinity" | "+Infinity") {
        return Some(f64::INFINITY);
    }
    if input == "-Infinity" {
        return Some(f64::NEG_INFINITY);
    }
    static DECIMAL: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?)|(?:\.[0-9]+))(?:[eE][+-]?[0-9]+)?$")
            .expect("the JavaScript decimal expression is valid")
    });
    DECIMAL
        .is_match(input)
        .then(|| input.parse().ok())
        .flatten()
}

fn valid_uuid(value: &str) -> bool {
    static UUID: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        .expect("the Better Auth UUID expression is valid")
    });
    UUID.is_match(value)
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
        fn generate(&self, _: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            self.0.fetch_add(1, Ordering::Relaxed);
            DatabaseIdGenerationResult::Id("generated".into())
        }
    }

    fn prepare(strategy: &DatabaseIdGeneration, input: DatabaseIdInput) -> PreparedDatabaseId {
        prepare_database_id(
            strategy,
            "Test Adapter",
            "user",
            DatabaseIdAdapterCapabilities::default(),
            None,
            true,
            input,
        )
        .unwrap()
    }

    #[test]
    fn falsey_values_defer() {
        for input in [
            DatabaseIdInput::Boolean(false),
            DatabaseIdInput::Number(0.0),
            DatabaseIdInput::Number(-0.0),
            DatabaseIdInput::Number(f64::NAN),
            DatabaseIdInput::String(String::new()),
        ] {
            assert_eq!(
                prepare(&DatabaseIdGeneration::Default, input),
                PreparedDatabaseId::Deferred
            );
        }
    }

    #[test]
    fn truthy_forced_values_bypass_the_configured_callback() {
        let generator = Arc::new(Counting(AtomicUsize::new(0)));
        let strategy = DatabaseIdGeneration::Callback(generator.clone());
        for (input, expected) in [
            (
                DatabaseIdInput::Boolean(true),
                DatabaseIdValue::Boolean(true),
            ),
            (DatabaseIdInput::Number(7.5), DatabaseIdValue::Number(7.5)),
            (
                DatabaseIdInput::String("forced".into()),
                DatabaseIdValue::String("forced".into()),
            ),
        ] {
            assert_eq!(
                prepare(&strategy, input),
                PreparedDatabaseId::Value(expected)
            );
        }
        assert_eq!(generator.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn adapter_disable_generation_overrides_a_truthy_forced_id() {
        let disabled = DatabaseIdAdapterCapabilities {
            disable_id_generation: true,
            ..DatabaseIdAdapterCapabilities::default()
        };
        assert_eq!(
            prepare_forced_id(
                &DatabaseIdGeneration::Default,
                disabled,
                DatabaseIdInput::String("forced".into()),
            ),
            PreparedDatabaseId::Deferred
        );
    }

    #[test]
    fn serial_matches_javascript_number_conversion() {
        for (input, expected) in [
            (DatabaseIdInput::Boolean(true), Some(1.0)),
            (DatabaseIdInput::String("  ".into()), Some(0.0)),
            (DatabaseIdInput::String("0x2a".into()), Some(42.0)),
            (
                DatabaseIdInput::String("0x10000001eb3d4a841c931".into()),
                Some(1.208_925_828_256_604_5e24),
            ),
            (
                DatabaseIdInput::String(
                    "0b100000000000000000000000000011110101100111101010010101000010000011100100100110001".into(),
                ),
                Some(1.208_925_828_256_604_5e24),
            ),
            (
                DatabaseIdInput::String("0o400000000365475225020344461".into()),
                Some(1.208_925_828_256_604_5e24),
            ),
            (DatabaseIdInput::String("+Infinity".into()), Some(f64::INFINITY)),
            (DatabaseIdInput::String("-Infinity".into()), Some(f64::NEG_INFINITY)),
            (DatabaseIdInput::String("-0x1".into()), None),
            (DatabaseIdInput::String("bad".into()), None),
        ] {
            assert_eq!(
                prepare(&DatabaseIdGeneration::Serial, input),
                expected.map_or(PreparedDatabaseId::DeferredSerial, |value| {
                    PreparedDatabaseId::Value(DatabaseIdValue::Number(value))
                })
            );
        }
    }

    #[test]
    fn uuid_validation_and_native_fallback_match_adapter_factory() {
        let native = DatabaseIdAdapterCapabilities {
            supports_uuids: true,
            ..DatabaseIdAdapterCapabilities::default()
        };
        let valid = "123e4567-e89b-12d3-a456-426614174000";
        assert_eq!(
            prepare_forced_id(
                &DatabaseIdGeneration::Uuid,
                native,
                DatabaseIdInput::String(valid.into()),
            ),
            PreparedDatabaseId::Value(DatabaseIdValue::String(valid.into()))
        );
        for invalid in [
            "123e4567-e89b-02d3-a456-426614174000",
            "123e4567-e89b-12d3-c456-426614174000",
            "{123e4567-e89b-12d3-a456-426614174000}",
        ] {
            assert_eq!(
                prepare_forced_id(
                    &DatabaseIdGeneration::Uuid,
                    native,
                    DatabaseIdInput::String(invalid.into()),
                ),
                PreparedDatabaseId::Deferred
            );
        }
    }
}
