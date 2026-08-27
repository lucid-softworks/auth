use super::DatabaseModel;
use crate::store::DatabaseIdInput;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// ID-less data passed through Better Auth before-create hooks.
///
/// `fields` contains canonical logical model fields other than `id`. Core
/// service code converts this draft to a typed persisted record only after the
/// adapter has selected and returned its string ID.
#[derive(Debug, Clone, PartialEq)]
pub struct DatabaseCreateRecord {
    model: DatabaseModel,
    id: DatabaseIdInput,
    id_present: bool,
    fields: Map<String, Value>,
    undefined: BTreeSet<String>,
    patched: BTreeSet<String>,
}

impl DatabaseCreateRecord {
    /// Creates ordinary adapter input whose `id` property is absent.
    pub fn new(model: DatabaseModel, fields: Map<String, Value>) -> Self {
        assert_no_id_field(&fields);
        Self {
            model,
            id: DatabaseIdInput::Absent,
            id_present: false,
            fields,
            undefined: BTreeSet::new(),
            patched: BTreeSet::new(),
        }
    }

    /// Creates adapter input with an explicitly supplied ID value.
    pub fn with_id(model: DatabaseModel, id: DatabaseIdInput, fields: Map<String, Value>) -> Self {
        assert_no_id_field(&fields);
        Self {
            model,
            id,
            id_present: true,
            fields,
            undefined: BTreeSet::new(),
            patched: BTreeSet::new(),
        }
    }

    pub const fn model(&self) -> DatabaseModel {
        self.model
    }

    pub const fn id(&self) -> &DatabaseIdInput {
        &self.id
    }

    pub const fn has_id(&self) -> bool {
        self.id_present
    }

    pub const fn fields(&self) -> &Map<String, Value> {
        &self.fields
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

    /// Applies Better Auth's top-level object-spread semantics.
    ///
    /// An omitted patch ID preserves the current ID. An explicit ID value,
    /// including `Absent` or `Null`, replaces it. Field objects are not merged
    /// recursively.
    pub fn merge(&mut self, patch: DatabaseCreatePatch) {
        let (id, fields, undefined) = patch.into_parts();
        if let Some(id) = id {
            self.id = id;
            self.id_present = true;
        }
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

    pub fn into_parts(self) -> (DatabaseModel, DatabaseIdInput, bool, Map<String, Value>) {
        (self.model, self.id, self.id_present, self.fields)
    }

    pub(crate) fn into_adapter_parts(
        self,
    ) -> (
        DatabaseModel,
        DatabaseIdInput,
        bool,
        Map<String, Value>,
        BTreeSet<String>,
    ) {
        (
            self.model,
            self.id,
            self.id_present,
            self.fields,
            self.undefined,
        )
    }
}

/// Partial top-level data returned by a Better Auth before-create hook.
///
/// `None` in the private ID slot means the patch omitted `id`. Supplying
/// [`DatabaseIdInput::Absent`] models an explicit JavaScript `undefined` ID.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DatabaseCreatePatch {
    id: Option<DatabaseIdInput>,
    fields: Map<String, Value>,
    undefined: BTreeSet<String>,
}

impl DatabaseCreatePatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_fields(fields: Map<String, Value>) -> Self {
        assert_no_id_field(&fields);
        Self {
            id: None,
            fields,
            undefined: BTreeSet::new(),
        }
    }

    pub fn with_id(mut self, id: DatabaseIdInput) -> Self {
        self.id = Some(id);
        self
    }

    pub fn with_field(mut self, name: impl Into<String>, value: Value) -> Self {
        let name = name.into();
        assert_ne!(
            name, "id",
            "`id` is reserved; use DatabaseCreatePatch::with_id"
        );
        self.undefined.remove(&name);
        self.fields.insert(name, value);
        self
    }

    pub fn with_undefined_field(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        assert_ne!(
            name, "id",
            "`id` is reserved; use DatabaseCreatePatch::with_id"
        );
        self.fields.remove(&name);
        self.undefined.insert(name);
        self
    }

    pub const fn id(&self) -> Option<&DatabaseIdInput> {
        self.id.as_ref()
    }

    pub const fn fields(&self) -> &Map<String, Value> {
        &self.fields
    }

    pub fn is_undefined(&self, field: &str) -> bool {
        self.undefined.contains(field)
    }

    fn into_parts(
        self,
    ) -> (
        Option<DatabaseIdInput>,
        Map<String, Value>,
        BTreeSet<String>,
    ) {
        (self.id, self.fields, self.undefined)
    }
}

/// Better Auth before-create result: continue, shallow-merge a partial patch,
/// or return `false` and cancel the database operation.
#[derive(Debug, Clone, PartialEq)]
pub enum BeforeDatabaseCreateHook {
    Continue,
    Merge(DatabaseCreatePatch),
    Cancel,
}

impl BeforeDatabaseCreateHook {
    pub fn merge(patch: DatabaseCreatePatch) -> Self {
        Self::Merge(patch)
    }
}

fn assert_no_id_field(fields: &Map<String, Value>) {
    assert!(
        !fields.contains_key("id"),
        "`id` is reserved; supply it through DatabaseIdInput"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn patch_distinguishes_omitted_and_explicit_id_values() {
        let mut record = DatabaseCreateRecord::new(
            DatabaseModel::User,
            Map::from_iter([("name".into(), json!("initial"))]),
        );
        assert_eq!(record.id(), &DatabaseIdInput::Absent);
        assert!(!record.has_id());

        record.merge(
            DatabaseCreatePatch::new()
                .with_id(DatabaseIdInput::String("hook-id".into()))
                .with_field("name", json!("first")),
        );
        record.merge(DatabaseCreatePatch::new().with_field("email", json!("a@example.com")));
        assert_eq!(record.id(), &DatabaseIdInput::String("hook-id".into()));

        record.merge(DatabaseCreatePatch::new().with_id(DatabaseIdInput::Null));
        assert_eq!(record.id(), &DatabaseIdInput::Null);
        record.merge(DatabaseCreatePatch::new().with_id(DatabaseIdInput::Absent));
        assert_eq!(record.id(), &DatabaseIdInput::Absent);
        assert!(record.has_id());
    }

    #[test]
    fn patch_uses_shallow_object_spread_semantics() {
        let mut record = DatabaseCreateRecord::new(
            DatabaseModel::User,
            Map::from_iter([
                ("name".into(), json!("initial")),
                ("metadata".into(), json!({ "left": true, "right": true })),
            ]),
        );
        record.merge(
            DatabaseCreatePatch::new()
                .with_field("name", json!("patched"))
                .with_field("metadata", json!({ "left": false })),
        );

        assert_eq!(record.get("name"), Some(&json!("patched")));
        assert_eq!(record.get("metadata"), Some(&json!({ "left": false })));
    }

    #[test]
    fn explicit_undefined_overwrites_and_remains_observable() {
        let mut record = DatabaseCreateRecord::new(
            DatabaseModel::User,
            Map::from_iter([("name".into(), json!("initial"))]),
        );
        record.merge(DatabaseCreatePatch::new().with_undefined_field("name"));
        assert!(record.contains_field("name"));
        assert!(record.is_undefined("name"));
        assert_eq!(record.get("name"), None);

        record.merge(DatabaseCreatePatch::new().with_field("name", json!("restored")));
        assert!(!record.is_undefined("name"));
        assert_eq!(record.get("name"), Some(&json!("restored")));
    }

    #[test]
    fn id_input_preserves_javascript_value_kinds() {
        for id in [
            DatabaseIdInput::Absent,
            DatabaseIdInput::Null,
            DatabaseIdInput::Boolean(false),
            DatabaseIdInput::Number(f64::NAN),
            DatabaseIdInput::String("id".into()),
        ] {
            let record =
                DatabaseCreateRecord::with_id(DatabaseModel::Session, id.clone(), Map::new());
            if let DatabaseIdInput::Number(_value) = id {
                assert!(matches!(record.id(), DatabaseIdInput::Number(actual) if actual.is_nan()));
            } else {
                assert_eq!(record.id(), &id);
            }
        }
    }

    #[test]
    #[should_panic(expected = "`id` is reserved; use DatabaseCreatePatch::with_id")]
    fn patch_rejects_id_in_the_generic_field_map() {
        let _ = DatabaseCreatePatch::new().with_field("id", json!("bypassed"));
    }
}
