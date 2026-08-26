use sha2::{Digest, Sha256};

use super::AuthSchemaCatalog;

/// Stable identity for one ordered logical Better Auth schema.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SchemaFingerprint(pub(super) String);

impl SchemaFingerprint {
    pub(super) fn from_catalog(catalog: &AuthSchemaCatalog) -> Self {
        let mut digest = Sha256::new();
        for (logical, table) in catalog.tables() {
            frame(&mut digest, logical.as_bytes());
            frame(&mut digest, table.model_name.as_bytes());
            digest.update([
                u8::from(table.disable_migrations),
                match table.id_type {
                    crate::DatabaseIdType::Uuid => 0,
                    crate::DatabaseIdType::String => 1,
                },
            ]);
            for (field_name, field) in &table.fields {
                frame(&mut digest, field_name.as_bytes());
                frame(
                    &mut digest,
                    field.field_name.as_deref().unwrap_or("").as_bytes(),
                );
                frame(&mut digest, format!("{:?}", field.field_type).as_bytes());
                digest.update([
                    u8::from(field.required),
                    u8::from(field.input),
                    u8::from(field.returned),
                    u8::from(field.unique),
                    u8::from(field.bigint),
                    u8::from(field.sortable),
                    u8::from(field.index),
                    u8::from(field.has_default_factory()),
                    u8::from(field.has_on_update()),
                    u8::from(field.has_input_transform()),
                    u8::from(field.has_output_transform()),
                    u8::from(field.has_input_validator()),
                    u8::from(field.has_output_validator()),
                ]);
                if let Some(value) = field.static_default_value() {
                    frame(&mut digest, value.to_string().as_bytes());
                } else {
                    frame(&mut digest, &[]);
                }
                if let Some(reference) = &field.references {
                    frame(&mut digest, reference.model.as_bytes());
                    frame(&mut digest, reference.field.as_bytes());
                    frame(&mut digest, format!("{:?}", reference.on_delete).as_bytes());
                } else {
                    frame(&mut digest, &[]);
                }
            }
            for index in &table.indexes {
                frame(&mut digest, index.name.as_deref().unwrap_or("").as_bytes());
                digest.update([u8::from(index.unique)]);
                for field in &index.fields {
                    frame(&mut digest, field.as_bytes());
                }
            }
        }
        Self(hex::encode(digest.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn for_adapter(catalog: &AuthSchemaCatalog, use_plural: bool) -> Self {
        let mut digest = Sha256::new();
        frame(&mut digest, catalog.fingerprint().as_str().as_bytes());
        digest.update([u8::from(use_plural)]);
        for (logical, table) in catalog.tables() {
            frame(&mut digest, logical.as_bytes());
            let physical = if use_plural {
                format!("{}s", table.model_name)
            } else {
                table.model_name.clone()
            };
            frame(&mut digest, physical.as_bytes());
            for (field_name, field) in &table.fields {
                frame(&mut digest, field_name.as_bytes());
                frame(
                    &mut digest,
                    field
                        .field_name
                        .as_deref()
                        .filter(|name| !name.is_empty())
                        .unwrap_or(field_name)
                        .as_bytes(),
                );
            }
        }
        Self(hex::encode(digest.finalize()))
    }
}

fn frame(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}
