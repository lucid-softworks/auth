use super::{SUBSCRIPTION_FIELDS, StripeModelSchema, StripeSchema, StripeSchemaError};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

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
pub(crate) struct ResolvedStripeSchema {
    #[cfg(feature = "postgres")]
    user: ResolvedModel,
    organization: Option<ResolvedModel>,
    subscription: Option<ResolvedModel>,
    fingerprint: String,
}

impl ResolvedStripeSchema {
    pub(crate) fn new(
        schema: &StripeSchema,
        subscriptions_enabled: bool,
        organization_enabled: bool,
    ) -> Result<Self, StripeSchemaError> {
        let user = resolve_model(
            "user",
            "lucid_auth_users",
            &schema.user,
            &[("stripeCustomerId", "stripe_customer_id", "TEXT")],
        )?;
        let organization = organization_enabled
            .then(|| {
                resolve_model(
                    "organization",
                    "lucid_auth_organizations",
                    &schema.organization,
                    &[("stripeCustomerId", "stripe_customer_id", "TEXT")],
                )
            })
            .transpose()?;
        // Better Auth deliberately ignores a supplied subscription remap when
        // subscriptions are disabled, including unknown fields inside it.
        let subscription = subscriptions_enabled
            .then(|| {
                resolve_model(
                    "subscription",
                    "lucid_auth_stripe_subscriptions",
                    &schema.subscription,
                    SUBSCRIPTION_FIELDS,
                )
            })
            .transpose()?;

        let mut digest = Sha256::new();
        fingerprint_model(&mut digest, "user", &user);
        if let Some(model) = &organization {
            fingerprint_model(&mut digest, "organization", model);
        }
        if let Some(model) = &subscription {
            fingerprint_model(&mut digest, "subscription", model);
        }
        let fingerprint = hex::encode(digest.finalize())[..12].to_owned();
        Ok(Self {
            #[cfg(feature = "postgres")]
            user,
            organization,
            subscription,
            fingerprint,
        })
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn user(&self) -> &ResolvedModel {
        &self.user
    }

    pub(crate) fn organization(&self) -> Option<&ResolvedModel> {
        self.organization.as_ref()
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
    logical_model: &'static str,
    default_table: &str,
    configured: &StripeModelSchema,
    definitions: &[(&'static str, &'static str, &'static str)],
) -> Result<ResolvedModel, StripeSchemaError> {
    let table = Identifier::new(
        "model",
        configured.model_name.as_deref().unwrap_or(default_table),
    )?;
    let known = definitions
        .iter()
        .map(|(logical, _, _)| *logical)
        .collect::<BTreeSet<_>>();
    if let Some(field) = configured
        .fields
        .keys()
        .find(|field| !known.contains(field.as_str()))
    {
        return Err(StripeSchemaError::UnknownField {
            model: logical_model,
            field: field.clone(),
        });
    }
    let mut fields = BTreeMap::new();
    let mut physical = BTreeSet::from(["id".to_owned()]);
    for (logical, default_column, _) in definitions {
        let field = Identifier::new(
            "field",
            configured
                .fields
                .get(*logical)
                .map(String::as_str)
                .unwrap_or(default_column),
        )?;
        if !physical.insert(field.raw.clone()) {
            return Err(StripeSchemaError::DuplicateIdentifier {
                model: logical_model,
                identifier: field.raw,
            });
        }
        fields.insert(*logical, field);
    }
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
    fn new(kind: &'static str, value: &str) -> Result<Self, StripeSchemaError> {
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
            return Err(StripeSchemaError::InvalidIdentifier {
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
