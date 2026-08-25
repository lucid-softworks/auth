use super::{CreemModelSchema, CreemSchema, CreemSchemaError, SUBSCRIPTION_FIELDS, USER_FIELDS};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedModel {
    table: Identifier,
    fields: BTreeMap<&'static str, Identifier>,
}

impl ResolvedModel {
    pub(crate) fn table(&self) -> &str {
        &self.table.quoted
    }

    pub(crate) fn column(&self, logical: &str) -> &str {
        if logical == "id" {
            return "\"id\"";
        }
        &self.fields[logical].quoted
    }

    pub(crate) fn unquoted_column(&self, logical: &str) -> String {
        self.fields[logical].raw.clone()
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn projection(&self) -> String {
        let mut columns = vec!["\"id\" AS \"id\"".to_owned()];
        columns.extend(
            self.fields
                .iter()
                .map(|(logical, field)| format!("{} AS \"{}\"", field.quoted, rust_name(logical))),
        );
        columns.join(", ")
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedCreemSchema {
    user: Option<ResolvedModel>,
    subscription: Option<ResolvedModel>,
    fingerprint: String,
}

impl ResolvedCreemSchema {
    pub(crate) fn new(
        schema: &CreemSchema,
        persist_subscriptions: bool,
    ) -> Result<Self, CreemSchemaError> {
        if !persist_subscriptions {
            if !schema.is_empty() {
                return Err(CreemSchemaError::PersistenceDisabled);
            }
            return Ok(Self {
                user: None,
                subscription: None,
                fingerprint: disabled_fingerprint(),
            });
        }
        if let Some(unknown) = schema
            .models
            .keys()
            .find(|model| !matches!(model.as_str(), "user" | "creem_subscription"))
        {
            return Err(CreemSchemaError::UnknownModel(unknown.clone()));
        }

        let fallback = CreemModelSchema::default();
        let user = resolve_model(
            "lucid_auth_users",
            schema.models.get("user").unwrap_or(&fallback),
            USER_FIELDS,
        )?;
        let subscription = resolve_model(
            "lucid_auth_creem_subscriptions",
            schema.models.get("creem_subscription").unwrap_or(&fallback),
            SUBSCRIPTION_FIELDS,
        )?;
        let mut digest = Sha256::new();
        fingerprint_model(&mut digest, "user", &user);
        fingerprint_model(&mut digest, "creem_subscription", &subscription);
        let fingerprint = hex::encode(digest.finalize())[..12].to_owned();
        Ok(Self {
            user: Some(user),
            subscription: Some(subscription),
            fingerprint,
        })
    }

    pub(crate) fn user(&self) -> Option<&ResolvedModel> {
        self.user.as_ref()
    }

    pub(crate) fn subscription(&self) -> Option<&ResolvedModel> {
        self.subscription.as_ref()
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn migration_sql(&self) -> String {
        super::migration::render(self)
    }
}

fn resolve_model(
    default_table: &str,
    configured: &CreemModelSchema,
    definitions: &[(&'static str, &'static str, &'static str)],
) -> Result<ResolvedModel, CreemSchemaError> {
    let configured_table = configured
        .model_name
        .as_deref()
        .filter(|name| !name.is_empty());
    let table = Identifier::new("model", configured_table.unwrap_or(default_table))?;
    let fields = definitions
        .iter()
        .map(|(logical, default_column, _)| {
            let configured_column = configured
                .fields
                .get(*logical)
                .map(String::as_str)
                .filter(|name| !name.is_empty());
            Identifier::new("field", configured_column.unwrap_or(default_column))
                .map(|identifier| (*logical, identifier))
        })
        .collect::<Result<_, _>>()?;
    Ok(ResolvedModel { table, fields })
}

fn fingerprint_model(digest: &mut Sha256, name: &str, model: &ResolvedModel) {
    digest.update(name.as_bytes());
    digest.update(b":");
    digest.update(model.table.raw.as_bytes());
    for (logical, field) in &model.fields {
        digest.update(b";");
        digest.update(logical.as_bytes());
        digest.update(b"=");
        digest.update(field.raw.as_bytes());
    }
}

fn disabled_fingerprint() -> String {
    hex::encode(Sha256::digest(b"creem:persistence-disabled"))[..12].to_owned()
}

#[cfg(feature = "postgres")]
fn rust_name(logical: &str) -> String {
    logical
        .chars()
        .fold(String::new(), |mut result, character| {
            if character.is_ascii_uppercase() {
                result.push('_');
                result.push(character.to_ascii_lowercase());
            } else {
                result.push(character);
            }
            result
        })
}

#[derive(Debug, Clone)]
struct Identifier {
    raw: String,
    quoted: String,
}

impl Identifier {
    fn new(kind: &'static str, value: &str) -> Result<Self, CreemSchemaError> {
        let reason = if value.len() > 63 {
            Some("must not exceed PostgreSQL's 63-byte identifier limit")
        } else if value.chars().any(char::is_control) {
            Some("must not contain control characters")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(CreemSchemaError::InvalidIdentifier {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_is_isolated_between_instances() {
        let mut custom = CreemSchema::default();
        custom.insert_model(
            "creem_subscription",
            CreemModelSchema {
                model_name: Some("billing rows".into()),
                fields: BTreeMap::from([("referenceId".into(), "owner key".into())]),
            },
        );
        let custom = ResolvedCreemSchema::new(&custom, true).unwrap();
        let default = ResolvedCreemSchema::new(&CreemSchema::default(), true).unwrap();

        assert_eq!(custom.subscription().unwrap().table(), "\"billing rows\"");
        assert_eq!(
            custom.subscription().unwrap().column("referenceId"),
            "\"owner key\""
        );
        assert_eq!(
            default.subscription().unwrap().table(),
            "\"lucid_auth_creem_subscriptions\""
        );
        assert_ne!(custom.fingerprint(), default.fingerprint());
    }

    #[test]
    fn ignored_mappings_do_not_change_the_effective_fingerprint() {
        let default = ResolvedCreemSchema::new(&CreemSchema::default(), true).unwrap();
        let mut ignored = CreemSchema::default();
        ignored.insert_model(
            "user",
            CreemModelSchema {
                model_name: Some(String::new()),
                fields: BTreeMap::from([
                    ("hadTrial".into(), String::new()),
                    ("unknown".into(), "ignored".into()),
                ]),
            },
        );
        let ignored = ResolvedCreemSchema::new(&ignored, true).unwrap();
        assert_eq!(ignored.fingerprint(), default.fingerprint());
    }
}
