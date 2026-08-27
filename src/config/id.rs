use std::sync::Arc;

use rand::RngExt as _;

mod prepare;

const ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Better Auth `advanced.database.generateId` behavior.
#[derive(Clone, Default)]
pub enum DatabaseIdGeneration {
    /// Generate Better Auth's default base-62-style application IDs.
    #[default]
    Default,
    /// Defer ID generation to the database or adapter (`generateId: false`).
    Database,
    /// Use database-generated numeric IDs (`generateId: "serial"`).
    Serial,
    /// Use UUID IDs (`generateId: "uuid"`).
    Uuid,
    /// Invoke the configured model-aware Better Auth callback.
    Callback(Arc<dyn DatabaseIdGenerator>),
}

/// Stable policy identity used by adapter binding and schema fingerprints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DatabaseIdGenerationKind {
    #[default]
    Default,
    Database,
    Serial,
    Uuid,
    Callback,
}

impl std::fmt::Debug for DatabaseIdGeneration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => formatter.write_str("Default"),
            Self::Database => formatter.write_str("Database"),
            Self::Serial => formatter.write_str("Serial"),
            Self::Uuid => formatter.write_str("Uuid"),
            Self::Callback(_) => formatter.write_str("Callback(..)"),
        }
    }
}

impl DatabaseIdGeneration {
    pub fn kind(&self) -> DatabaseIdGenerationKind {
        match self {
            Self::Default => DatabaseIdGenerationKind::Default,
            Self::Database => DatabaseIdGenerationKind::Database,
            Self::Serial => DatabaseIdGenerationKind::Serial,
            Self::Uuid => DatabaseIdGenerationKind::Uuid,
            Self::Callback(_) => DatabaseIdGenerationKind::Callback,
        }
    }

    /// Applies Better Auth's adapter ID-source precedence.
    pub fn adapter_source(
        &self,
        capabilities: DatabaseIdAdapterCapabilities,
        has_custom_generator: bool,
    ) -> DatabaseIdGenerationSource {
        if capabilities.disable_id_generation {
            return DatabaseIdGenerationSource::Disabled;
        }
        match self {
            Self::Database | Self::Serial => DatabaseIdGenerationSource::Deferred,
            Self::Callback(_) => DatabaseIdGenerationSource::Callback,
            Self::Uuid if capabilities.supports_uuids => DatabaseIdGenerationSource::Deferred,
            Self::Uuid => DatabaseIdGenerationSource::Uuid,
            Self::Default if has_custom_generator => DatabaseIdGenerationSource::Adapter,
            Self::Default => DatabaseIdGenerationSource::Default,
        }
    }

    /// Validates the capability check performed when Better Auth constructs an adapter.
    pub fn validate_adapter(
        &self,
        adapter_name: &str,
        capabilities: DatabaseIdAdapterCapabilities,
    ) -> Result<(), crate::AuthError> {
        if matches!(self, Self::Serial) && !capabilities.supports_numeric_ids {
            return Err(crate::AuthError::InvalidConfiguration(format!(
                "[{adapter_name}] Your database or database adapter does not support numeric ids. Please disable \"useNumberId\" in your config."
            )));
        }
        Ok(())
    }

    pub(crate) fn prepare(
        &self,
        adapter_name: &str,
        model: &str,
        capabilities: DatabaseIdAdapterCapabilities,
        adapter_generator: Option<&dyn DatabaseIdGenerator>,
        force_allow_id: bool,
        input: crate::store::DatabaseIdInput,
    ) -> Result<crate::store::PreparedDatabaseId, crate::AuthError> {
        prepare::prepare_database_id(
            self,
            adapter_name,
            model,
            capabilities,
            adapter_generator,
            force_allow_id,
            input,
        )
    }

    pub(crate) fn generate_context_id(
        &self,
        model: &str,
        size: DatabaseIdGenerationSize,
    ) -> Result<DatabaseIdGenerationResult, DatabaseIdGenerationError> {
        Ok(match self {
            Self::Default => DatabaseIdGenerationResult::Id(generate_database_id(size)?),
            Self::Database | Self::Serial => DatabaseIdGenerationResult::Defer,
            Self::Uuid => DatabaseIdGenerationResult::Id(uuid::Uuid::new_v4().to_string()),
            Self::Callback(generator) => {
                generator.generate(DatabaseIdGenerationRequest { model, size })
            }
        })
    }
}

/// Better Auth adapter capabilities that affect database ID generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatabaseIdAdapterCapabilities {
    pub disable_id_generation: bool,
    pub supports_numeric_ids: bool,
    pub supports_uuids: bool,
}

impl Default for DatabaseIdAdapterCapabilities {
    fn default() -> Self {
        Self {
            disable_id_generation: false,
            supports_numeric_ids: true,
            supports_uuids: false,
        }
    }
}

/// Selected application-side source after applying adapter capability precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseIdGenerationSource {
    Disabled,
    Deferred,
    Callback,
    Uuid,
    Adapter,
    Default,
}

/// Presence-sensitive representation of Better Auth's optional callback `size` property.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DatabaseIdGenerationSize {
    /// The callback argument object has no own `size` property.
    Omitted,
    /// The callback argument object has an own `size` property whose value is undefined.
    Undefined,
    /// The callback argument object has an own numeric `size` property.
    Value(f64),
}

/// Input passed to a Better Auth database ID callback.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DatabaseIdGenerationRequest<'a> {
    pub model: &'a str,
    pub size: DatabaseIdGenerationSize,
}

/// Result of a Better Auth database ID callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseIdGenerationResult {
    Id(String),
    /// Equivalent to returning `false`: omit the ID and defer generation.
    Defer,
}

/// Model-aware callback used by Better Auth database ID generation.
pub trait DatabaseIdGenerator: std::fmt::Debug + Send + Sync {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult;
}

/// Error returned by Better Auth's built-in random ID generator for an invalid length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Length must be a positive integer.")]
pub struct DatabaseIdGenerationError;

/// Generates a Better Auth base-62-style database ID with `size || 32` semantics.
pub fn generate_database_id(
    size: DatabaseIdGenerationSize,
) -> Result<String, DatabaseIdGenerationError> {
    let size = match size {
        DatabaseIdGenerationSize::Omitted | DatabaseIdGenerationSize::Undefined => 32,
        DatabaseIdGenerationSize::Value(value) if value == 0.0 || value.is_nan() => 32,
        DatabaseIdGenerationSize::Value(value)
            if value.is_finite()
                && value > 0.0
                && value.fract() == 0.0
                && value <= usize::MAX as f64 =>
        {
            value as usize
        }
        DatabaseIdGenerationSize::Value(_) => return Err(DatabaseIdGenerationError),
    };
    let mut rng = rand::rng();
    Ok((0..size)
        .map(|_| char::from(ID_ALPHABET[rng.random_range(0..ID_ALPHABET.len())]))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Fixed;

    impl DatabaseIdGenerator for Fixed {
        fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            DatabaseIdGenerationResult::Id(format!("{}:{:?}", request.model, request.size))
        }
    }

    #[test]
    fn callback_input_distinguishes_absent_undefined_and_numeric_sizes() {
        let callback = Fixed;
        for (size, expected) in [
            (DatabaseIdGenerationSize::Omitted, "user:Omitted"),
            (DatabaseIdGenerationSize::Undefined, "user:Undefined"),
            (DatabaseIdGenerationSize::Value(0.0), "user:Value(0.0)"),
            (DatabaseIdGenerationSize::Value(-1.0), "user:Value(-1.0)"),
        ] {
            assert_eq!(
                callback.generate(DatabaseIdGenerationRequest {
                    model: "user",
                    size,
                }),
                DatabaseIdGenerationResult::Id(expected.into())
            );
        }
    }

    #[test]
    fn context_generation_uses_undefined_shape_and_literal_false() {
        assert_eq!(
            DatabaseIdGeneration::Callback(Arc::new(Fixed))
                .generate_context_id("user", DatabaseIdGenerationSize::Undefined)
                .unwrap(),
            DatabaseIdGenerationResult::Id("user:Undefined".into())
        );
        assert_eq!(
            DatabaseIdGeneration::Database
                .generate_context_id("user", DatabaseIdGenerationSize::Undefined)
                .unwrap(),
            DatabaseIdGenerationResult::Defer
        );
    }

    #[test]
    fn default_strategy_is_not_uuid() {
        assert!(matches!(
            DatabaseIdGeneration::default(),
            DatabaseIdGeneration::Default
        ));
    }

    #[test]
    fn built_in_generator_matches_javascript_size_or_32_policy() {
        for size in [
            DatabaseIdGenerationSize::Omitted,
            DatabaseIdGenerationSize::Undefined,
            DatabaseIdGenerationSize::Value(0.0),
            DatabaseIdGenerationSize::Value(-0.0),
            DatabaseIdGenerationSize::Value(f64::NAN),
        ] {
            let value = generate_database_id(size).unwrap();
            assert_eq!(value.len(), 32);
            assert!(value.bytes().all(|byte| ID_ALPHABET.contains(&byte)));
        }
        assert_eq!(
            generate_database_id(DatabaseIdGenerationSize::Value(7.0))
                .unwrap()
                .len(),
            7
        );
        for invalid in [-1.0, 1.5, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                generate_database_id(DatabaseIdGenerationSize::Value(invalid))
                    .unwrap_err()
                    .to_string(),
                "Length must be a positive integer."
            );
        }
    }

    #[test]
    fn adapter_source_follows_better_auth_precedence() {
        let default = DatabaseIdAdapterCapabilities::default();
        let disabled = DatabaseIdAdapterCapabilities {
            disable_id_generation: true,
            ..default
        };
        assert_eq!(
            DatabaseIdGeneration::Uuid.adapter_source(disabled, true),
            DatabaseIdGenerationSource::Disabled
        );
        assert_eq!(
            DatabaseIdGeneration::Database.adapter_source(default, true),
            DatabaseIdGenerationSource::Deferred
        );
        assert_eq!(
            DatabaseIdGeneration::Serial.adapter_source(default, true),
            DatabaseIdGenerationSource::Deferred
        );
        assert_eq!(
            DatabaseIdGeneration::Callback(Arc::new(Fixed)).adapter_source(default, true),
            DatabaseIdGenerationSource::Callback
        );
        assert_eq!(
            DatabaseIdGeneration::Uuid.adapter_source(default, true),
            DatabaseIdGenerationSource::Uuid
        );
        assert_eq!(
            DatabaseIdGeneration::Uuid.adapter_source(
                DatabaseIdAdapterCapabilities {
                    supports_uuids: true,
                    ..default
                },
                true,
            ),
            DatabaseIdGenerationSource::Deferred
        );
        assert_eq!(
            DatabaseIdGeneration::Default.adapter_source(default, true),
            DatabaseIdGenerationSource::Adapter
        );
        assert_eq!(
            DatabaseIdGeneration::Default.adapter_source(default, false),
            DatabaseIdGenerationSource::Default
        );
    }

    #[test]
    fn serial_rejects_adapters_without_numeric_id_support() {
        let error = DatabaseIdGeneration::Serial
            .validate_adapter(
                "Pinned Adapter",
                DatabaseIdAdapterCapabilities {
                    supports_numeric_ids: false,
                    ..DatabaseIdAdapterCapabilities::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            crate::AuthError::InvalidConfiguration(message)
                if message == "[Pinned Adapter] Your database or database adapter does not support numeric ids. Please disable \"useNumberId\" in your config."
        ));
    }
}
