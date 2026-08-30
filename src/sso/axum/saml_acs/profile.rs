use crate::OAuthUserInfo;
use samlet::SsoSession;
use serde_json::{Map, Value};

pub(super) fn user_info(
    session: &SsoSession,
    config: &Map<String, Value>,
    trust_email_verified: bool,
) -> Result<OAuthUserInfo, ()> {
    let attributes = attributes(session);
    let mapping = config.get("mapping").and_then(Value::as_object);
    let account_id = session.name_id().value().to_owned();
    let email = first(
        &attributes,
        mapped(mapping, "email").unwrap_or("email"),
    )
    .filter(|email| !email.is_empty())
    .unwrap_or(&account_id)
    .to_lowercase();
    if account_id.is_empty() || email.is_empty() {
        return Err(());
    }
    let name = mapped_name(&attributes, mapping).unwrap_or_else(|| account_id.clone());
    let email_verified = trust_email_verified
        && mapped(mapping, "emailVerified")
            .and_then(|field| first_value(&attributes, field))
            .is_some_and(provider_true);
    let additional_fields = extra_fields(&attributes, mapping);
    let image = additional_fields
        .get("image")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(OAuthUserInfo {
        account_id,
        issuer: session.issuer().as_str().into(),
        name,
        email,
        email_verified,
        image,
        additional_fields,
        profile: attributes,
    })
}

fn attributes(session: &SsoSession) -> Map<String, Value> {
    session
        .attributes()
        .as_slice()
        .iter()
        .map(|attribute| {
            let values = attribute
                .values()
                .iter()
                .map(|value| Value::String(value.as_str().into()))
                .collect::<Vec<_>>();
            let value = match values.as_slice() {
                [single] => single.clone(),
                _ => Value::Array(values),
            };
            (attribute.name().to_owned(), value)
        })
        .collect()
}

fn mapped_name(
    attributes: &Map<String, Value>,
    mapping: Option<&Map<String, Value>>,
) -> Option<String> {
    let first_name = first(
        attributes,
        mapped(mapping, "firstName").unwrap_or("givenName"),
    );
    let last_name = first(
        attributes,
        mapped(mapping, "lastName").unwrap_or("surname"),
    );
    let joined = [first_name, last_name]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if !joined.is_empty() {
        Some(joined)
    } else {
        first(
            attributes,
            mapped(mapping, "name").unwrap_or("displayName"),
        )
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    }
}

fn extra_fields(
    attributes: &Map<String, Value>,
    mapping: Option<&Map<String, Value>>,
) -> Map<String, Value> {
    mapping
        .and_then(|mapping| mapping.get("extraFields"))
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(target, source)| {
            let source = source.as_str()?;
            attributes
                .get(source)
                .cloned()
                .map(|value| (target.clone(), value))
        })
        .collect()
}

fn mapped<'a>(mapping: Option<&'a Map<String, Value>>, field: &str) -> Option<&'a str> {
    mapping?.get(field).and_then(Value::as_str)
}

fn first<'a>(attributes: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    first_value(attributes, field).and_then(Value::as_str)
}

fn first_value<'a>(attributes: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    match attributes.get(field)? {
        Value::Array(values) => values.first(),
        value => Some(value),
    }
}

fn provider_true(value: &Value) -> bool {
    value == &Value::Bool(true) || value.as_str() == Some("true")
}
