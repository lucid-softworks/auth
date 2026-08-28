use super::{DatabaseModel, DatabaseRecord};
use crate::AuthError;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// Cumulative logical data passed through Better Auth before-update hooks.
///
/// Values use canonical model field names. Explicit JavaScript `undefined` is
/// tracked separately from omission because object spread makes the property
/// observable to later hooks even though the adapter skips it on update.
#[derive(Debug, Clone, PartialEq)]
pub struct DatabaseUpdateRecord {
    model: DatabaseModel,
    baseline: Map<String, Value>,
    fields: Map<String, Value>,
    undefined: BTreeSet<String>,
    patched: BTreeSet<String>,
}

impl DatabaseUpdateRecord {
    pub fn new(record: DatabaseRecord) -> Result<Self, AuthError> {
        let model = record.model();
        let fields = encode_record(record)?;
        Ok(Self {
            model,
            baseline: fields.clone(),
            fields,
            undefined: BTreeSet::new(),
            patched: BTreeSet::new(),
        })
    }

    pub const fn model(&self) -> DatabaseModel {
        self.model
    }

    pub fn get(&self, field: &str) -> Option<&Value> {
        self.fields.get(field)
    }

    pub fn contains_field(&self, field: &str) -> bool {
        self.fields.contains_key(field) || self.undefined.contains(field)
    }

    pub fn is_undefined(&self, field: &str) -> bool {
        self.undefined.contains(field)
    }

    pub fn fields(&self) -> &Map<String, Value> {
        &self.fields
    }

    pub fn merge(&mut self, patch: DatabaseUpdatePatch) {
        let (fields, undefined) = patch.into_parts();
        for field in undefined {
            self.fields.remove(&field);
            self.undefined.insert(field.clone());
            self.patched.insert(field);
        }
        for (field, value) in fields {
            self.undefined.remove(&field);
            self.patched.insert(field.clone());
            self.fields.insert(field, value);
        }
    }

    pub(crate) fn apply_additional_fields(
        &mut self,
        configured: &crate::AdditionalFieldSet,
    ) -> Result<(), AuthError> {
        for name in self.patched.clone() {
            if crate::additional_fields::reserved_field_names(self.model).contains(&name.as_str()) {
                continue;
            }
            let undefined = self.undefined.contains(&name);
            let value = self.fields.remove(&name);
            match crate::additional_fields::transform_update_hook_field(
                configured, &name, value, undefined,
            )? {
                Some(value) => {
                    self.undefined.remove(&name);
                    self.fields.insert(name, value);
                }
                None if !configured.contains_key(&name) => {
                    self.undefined.remove(&name);
                    self.baseline.remove(&name);
                }
                None => {}
            }
        }
        Ok(())
    }

    pub fn into_record(mut self) -> Result<DatabaseRecord, AuthError> {
        for field in self.undefined {
            if let Some(value) = self.baseline.remove(&field) {
                self.fields.insert(field, value);
            }
        }
        decode_record(self.model, self.fields)
    }
}

/// Partial top-level data returned by a Better Auth before-update hook.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DatabaseUpdatePatch {
    fields: Map<String, Value>,
    undefined: BTreeSet<String>,
}

impl DatabaseUpdatePatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_fields(fields: Map<String, Value>) -> Self {
        Self {
            fields,
            undefined: BTreeSet::new(),
        }
    }

    pub fn with_field(mut self, name: impl Into<String>, value: Value) -> Self {
        let name = name.into();
        self.undefined.remove(&name);
        self.fields.insert(name, value);
        self
    }

    pub fn with_undefined_field(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        self.fields.remove(&name);
        self.undefined.insert(name);
        self
    }

    pub fn fields(&self) -> &Map<String, Value> {
        &self.fields
    }

    pub fn is_undefined(&self, field: &str) -> bool {
        self.undefined.contains(field)
    }

    fn into_parts(self) -> (Map<String, Value>, BTreeSet<String>) {
        (self.fields, self.undefined)
    }
}

/// Better Auth before-update result: continue, shallow-merge a partial patch,
/// or return `false` and cancel the database operation.
#[derive(Debug, Clone, PartialEq)]
pub enum BeforeDatabaseUpdateHook {
    Continue,
    Merge(DatabaseUpdatePatch),
    Cancel,
}

impl BeforeDatabaseUpdateHook {
    pub fn merge(patch: DatabaseUpdatePatch) -> Self {
        Self::Merge(patch)
    }
}

fn encode_record(record: DatabaseRecord) -> Result<Map<String, Value>, AuthError> {
    let value = match record {
        DatabaseRecord::User(record) => serde_json::to_value(record),
        DatabaseRecord::Session(record) => serde_json::to_value(record),
        DatabaseRecord::Verification(record) => serde_json::to_value(record),
        DatabaseRecord::Account(record) => serde_json::to_value(record),
    }
    .map_err(|error| {
        AuthError::Storage(format!("database update hook encoding failed: {error}"))
    })?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::Storage("database update hook record is not an object".into()))
}

fn decode_record(
    model: DatabaseModel,
    fields: Map<String, Value>,
) -> Result<DatabaseRecord, AuthError> {
    let value = Value::Object(fields);
    let record = match model {
        DatabaseModel::User => serde_json::from_value(value).map(DatabaseRecord::User),
        DatabaseModel::Session => serde_json::from_value(value).map(DatabaseRecord::Session),
        DatabaseModel::Account => serde_json::from_value(value).map(DatabaseRecord::Account),
        DatabaseModel::Verification => {
            serde_json::from_value(value).map(DatabaseRecord::Verification)
        }
        DatabaseModel::Organization => {
            return Err(AuthError::InvalidConfiguration(
                "organization update hooks require a plugin-owned record boundary".into(),
            ));
        }
    }
    .map_err(|error| {
        AuthError::InvalidConfiguration(format!(
            "a {model:?} before-update hook returned incompatible fields: {error}"
        ))
    })?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn user() -> DatabaseRecord {
        DatabaseRecord::User(crate::AuthUser {
            id: "user-1".into(),
            username: None,
            display_username: None,
            name: "Initial".into(),
            email: "initial@example.com".into(),
            email_verified: false,
            image: None,
            additional_fields: Map::from_iter([(
                "metadata".into(),
                json!({ "left": true, "right": true }),
            )]),
            role: "user".into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }

    #[test]
    fn patches_merge_shallowly_and_track_explicit_undefined() {
        let mut record = DatabaseUpdateRecord::new(user()).unwrap();
        record.merge(
            DatabaseUpdatePatch::new()
                .with_field("name", json!("First"))
                .with_field("metadata", json!({ "left": false }))
                .with_undefined_field("email"),
        );
        assert_eq!(record.get("name"), Some(&json!("First")));
        assert_eq!(record.get("metadata"), Some(&json!({ "left": false })));
        assert!(record.contains_field("email"));
        assert!(record.is_undefined("email"));
        assert_eq!(record.get("email"), None);

        record.merge(
            DatabaseUpdatePatch::new()
                .with_field("name", Value::Null)
                .with_field("email", json!("final@example.com")),
        );
        assert_eq!(record.get("name"), Some(&Value::Null));
        assert!(!record.is_undefined("email"));
        assert_eq!(record.get("email"), Some(&json!("final@example.com")));
    }

    #[test]
    fn final_explicit_undefined_is_skipped_by_the_adapter_update() {
        let mut record = DatabaseUpdateRecord::new(user()).unwrap();
        record.merge(DatabaseUpdatePatch::new().with_undefined_field("email"));
        let DatabaseRecord::User(user) = record.into_record().unwrap() else {
            panic!("user record")
        };
        assert_eq!(user.email, "initial@example.com");
    }
}
