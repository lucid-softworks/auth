use crate::scim::{ScimEmail, ScimError, ScimErrorType};
use regex::Regex;
use serde_json::Value;
use std::{collections::HashSet, sync::OnceLock};

pub(super) fn apply(
    root: &mut Value,
    op: &str,
    path: &str,
    value: Option<Value>,
) -> Result<bool, ScimError> {
    if path.eq_ignore_ascii_case("emails") {
        patch_set(root, op, value)?;
        return Ok(true);
    }
    if path.eq_ignore_ascii_case("emails.value") {
        replace_all_values(root, op, value)?;
        return Ok(true);
    }
    if let Some(captures) = type_path().captures(path) {
        patch_selected_type(root, op, captures[1].trim(), value)?;
        return Ok(true);
    }
    if primary_path().is_match(path) {
        patch_primary(root, op, value)?;
        return Ok(true);
    }
    if path
        .trim_start()
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("emails"))
    {
        return Err(ScimError::typed(
            400,
            format!("User PATCH path {path} is not supported"),
            ScimErrorType::InvalidPath,
        ));
    }
    Ok(false)
}

fn type_path() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)^emails\s*\[\s*type\s+eq\s+\"([^\"]+)\"\s*\]\s*\.\s*value$"#)
            .expect("the email type PATCH path regex is valid")
    })
}

fn primary_path() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?i)^emails\s*\[\s*primary\s+eq\s+\"?true\"?\s*\]\s*\.\s*value$"#,
        )
        .expect("the primary email PATCH path regex is valid")
    })
}

fn patch_set(root: &mut Value, op: &str, value: Option<Value>) -> Result<(), ScimError> {
    if op == "remove" {
        return Err(invalid("emails cannot be removed"));
    }
    let additions = parse_email_set(value)?;
    if op != "add" {
        set_emails(root, additions);
        return Ok(());
    }
    let mut additions = coalesce_tuples(additions);
    if additions.iter().filter(|email| email.primary == Some(true)).count() > 1 {
        return Err(invalid("emails cannot contain multiple primary values"));
    }
    let mut emails = emails_mut(root)?;
    let existing = emails.iter().map(tuple_key).collect::<HashSet<_>>();
    additions.retain(|email| !existing.contains(&tuple_key(email)));
    if additions.is_empty() {
        return Ok(());
    }
    if additions.iter().any(|email| email.primary == Some(true)) {
        for email in emails.iter_mut() {
            email.primary = Some(false);
        }
    }
    emails.extend(additions);
    set_emails(root, emails);
    Ok(())
}

fn replace_all_values(
    root: &mut Value,
    op: &str,
    value: Option<Value>,
) -> Result<(), ScimError> {
    if op == "remove" {
        return Err(invalid("emails.value cannot be removed"));
    }
    let value = email_value(value)?;
    let mut emails = emails_mut(root)?;
    for email in &mut emails {
        email.value.clone_from(&value);
    }
    set_emails(root, emails);
    Ok(())
}

fn patch_selected_type(
    root: &mut Value,
    op: &str,
    selector: &str,
    value: Option<Value>,
) -> Result<(), ScimError> {
    let selector = selector.trim().to_ascii_lowercase();
    let mut emails = emails_mut(root)?;
    if op == "remove" {
        emails.retain(|email| email.kind.as_deref() != Some(&selector));
        if emails.is_empty() {
            return Err(invalid("emails must contain between 1 and 20 valid emails"));
        }
    } else {
        let replacement = email_value(value)?;
        let mut matched = false;
        for email in &mut emails {
            if email.kind.as_deref() == Some(&selector) {
                email.value.clone_from(&replacement);
                matched = true;
            }
        }
        if !matched {
            emails.push(ScimEmail {
                value: replacement,
                primary: Some(false),
                kind: Some(selector),
            });
        }
    }
    set_emails(root, emails);
    Ok(())
}

fn patch_primary(root: &mut Value, op: &str, value: Option<Value>) -> Result<(), ScimError> {
    if op == "remove" {
        return Err(invalid("emails.value cannot be removed"));
    }
    let replacement = email_value(value)?;
    let mut emails = emails_mut(root)?;
    let mut matched = false;
    for email in &mut emails {
        if email.primary == Some(true) {
            email.value.clone_from(&replacement);
            matched = true;
        }
    }
    if !matched {
        return Err(ScimError::typed(
            400,
            "No primary email matches the PATCH path",
            ScimErrorType::NoTarget,
        ));
    }
    set_emails(root, emails);
    Ok(())
}

fn parse_email_set(value: Option<Value>) -> Result<Vec<ScimEmail>, ScimError> {
    let Some(Value::Array(values)) = value else {
        return Err(invalid("emails must contain between 1 and 20 valid emails"));
    };
    if values.is_empty() || values.len() > 20 {
        return Err(invalid("emails must contain between 1 and 20 valid emails"));
    }
    values
        .into_iter()
        .map(|value| {
            let email = serde_json::from_value::<ScimEmail>(value)
                .map_err(|_| invalid("emails must contain between 1 and 20 valid emails"))?;
            normalize_email(email)
        })
        .collect()
}

fn normalize_email(mut email: ScimEmail) -> Result<ScimEmail, ScimError> {
    if !is_email(&email.value) || email.value.chars().count() > 254 {
        return Err(invalid("emails must contain between 1 and 20 valid emails"));
    }
    email.value = email.value.to_ascii_lowercase();
    email.kind = email.kind.map(|kind| kind.trim().to_ascii_lowercase());
    if email.kind.as_deref() == Some("") {
        return Err(invalid("emails must contain between 1 and 20 valid emails"));
    }
    email.primary = Some(email.primary == Some(true));
    Ok(email)
}

fn email_value(value: Option<Value>) -> Result<String, ScimError> {
    let Some(Value::String(value)) = value else {
        return Err(invalid("emails.value must be an email"));
    };
    if !is_email(&value) || value.chars().count() > 254 {
        return Err(invalid("emails.value must be an email"));
    }
    Ok(value.to_ascii_lowercase())
}

fn emails_mut(root: &mut Value) -> Result<Vec<ScimEmail>, ScimError> {
    serde_json::from_value(root.get("emails").cloned().unwrap_or_else(|| Value::Array(Vec::new())))
        .map_err(|_| invalid("emails must contain between 1 and 20 valid emails"))
}

fn set_emails(root: &mut Value, emails: Vec<ScimEmail>) {
    root.as_object_mut()
        .expect("SCIM User is an object")
        .insert("emails".into(), serde_json::to_value(emails).unwrap());
}

fn coalesce_tuples(emails: Vec<ScimEmail>) -> Vec<ScimEmail> {
    let mut output: Vec<ScimEmail> = Vec::new();
    for email in emails {
        if let Some(existing) = output.iter_mut().find(|existing| tuple_key(existing) == tuple_key(&email)) {
            if email.primary == Some(true) {
                existing.primary = Some(true);
            }
        } else {
            output.push(email);
        }
    }
    output
}

fn tuple_key(email: &ScimEmail) -> (Option<String>, String) {
    (
        email.kind.as_deref().map(str::to_ascii_lowercase),
        email.value.to_ascii_lowercase(),
    )
}

fn is_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.chars().any(char::is_whitespace)
}

fn invalid(detail: impl Into<String>) -> ScimError {
    ScimError::typed(400, detail, ScimErrorType::InvalidValue)
}
