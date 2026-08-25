use super::{DeviceAuthorizationSchema, OAUTH_FIELDS, STANDALONE_FIELDS};
use crate::device_authorization::DeviceAuthorizationConfigError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub(crate) struct ResolvedDeviceAuthorizationModel {
    table: Identifier,
    fields: BTreeMap<&'static str, Identifier>,
}

impl ResolvedDeviceAuthorizationModel {
    pub(crate) fn table(&self) -> &str {
        &self.table.quoted
    }

    pub(crate) fn column(&self, logical: &str) -> &str {
        if logical == "id" {
            return "\"id\"";
        }
        &self
            .fields
            .get(logical)
            .expect("Device Authorization SQL requested a declared Better Auth field")
            .quoted
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn columns(&self, fields: &[(&str, &str)]) -> String {
        fields
            .iter()
            .map(|(logical, _)| self.column(logical))
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn projection(&self, fields: &[(&str, &str)]) -> String {
        fields
            .iter()
            .map(|(logical, rust_name)| format!("{} AS \"{rust_name}\"", self.column(logical)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedDeviceAuthorizationSchema {
    model: ResolvedDeviceAuthorizationModel,
    oauth_mode: bool,
    fingerprint: String,
}

impl ResolvedDeviceAuthorizationSchema {
    pub(crate) fn new(
        schema: &DeviceAuthorizationSchema,
        oauth_mode: bool,
    ) -> Result<Self, DeviceAuthorizationConfigError> {
        let configured = &schema.device_code;
        let table = Identifier::new(
            "model",
            configured
                .model_name
                .as_deref()
                .unwrap_or("lucid_auth_device_codes"),
        )?;
        let known = STANDALONE_FIELDS
            .iter()
            .map(|(logical, _, _)| *logical)
            .collect::<BTreeSet<_>>();
        if let Some(field) = configured
            .fields
            .keys()
            .find(|field| !known.contains(field.as_str()))
        {
            return Err(DeviceAuthorizationConfigError::UnknownSchemaField {
                field: field.clone(),
            });
        }

        let mut fields = BTreeMap::new();
        let mut physical_fields = BTreeSet::from(["id".to_owned()]);
        for (logical, default_column, _) in STANDALONE_FIELDS {
            let identifier = Identifier::new(
                "field",
                configured
                    .fields
                    .get(*logical)
                    .map(String::as_str)
                    .unwrap_or(default_column),
            )?;
            if !physical_fields.insert(identifier.raw.clone()) {
                return Err(DeviceAuthorizationConfigError::DuplicateSchemaIdentifier {
                    identifier: identifier.raw,
                });
            }
            fields.insert(*logical, identifier);
        }
        if oauth_mode {
            for (logical, default_column, _) in OAUTH_FIELDS {
                let identifier = Identifier::new("field", default_column)?;
                if !physical_fields.insert(identifier.raw.clone()) {
                    return Err(DeviceAuthorizationConfigError::DuplicateSchemaIdentifier {
                        identifier: identifier.raw,
                    });
                }
                fields.insert(*logical, identifier);
            }
        }
        let mut digest = Sha256::new();
        digest.update(table.raw.as_bytes());
        let mode: &[u8] = if oauth_mode {
            b":oauth"
        } else {
            b":standalone"
        };
        digest.update(mode);
        for (logical, field) in &fields {
            digest.update(logical.as_bytes());
            digest.update(b":");
            digest.update(field.raw.as_bytes());
            digest.update(b";");
        }
        let fingerprint = hex::encode(digest.finalize())[..12].to_owned();
        Ok(Self {
            model: ResolvedDeviceAuthorizationModel { table, fields },
            oauth_mode,
            fingerprint,
        })
    }

    pub(crate) fn model(&self) -> &ResolvedDeviceAuthorizationModel {
        &self.model
    }

    pub(crate) fn migration_sql(&self) -> String {
        super::migration::render_migration(self)
    }

    pub(crate) fn oauth_mode(&self) -> bool {
        self.oauth_mode
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

#[derive(Debug, Clone)]
struct Identifier {
    raw: String,
    quoted: String,
}

impl Identifier {
    fn new(kind: &'static str, value: &str) -> Result<Self, DeviceAuthorizationConfigError> {
        let reason = if value.is_empty() {
            Some("must not be empty")
        } else if value.len() > 63 {
            Some("must not exceed PostgreSQL's 63-byte identifier limit")
        } else if value.chars().any(char::is_control) {
            Some("must not contain control characters")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(DeviceAuthorizationConfigError::InvalidSchemaIdentifier {
                kind,
                identifier: value.to_owned(),
                reason,
            });
        }
        Ok(Self {
            raw: value.to_owned(),
            quoted: format!("\"{}\"", value.replace('"', "\"\"")),
        })
    }
}
