use crate::scim::{ScimError, ScimErrorType};
use serde_json::Value;
use std::collections::HashMap;

mod filter;
mod projection;

pub(super) use filter::filter;
pub(super) use projection::{project_value, projection};

#[derive(Debug, Clone, Copy)]
pub(super) struct Pagination {
    pub start_index: usize,
    pub offset: usize,
    pub count: usize,
}

pub(super) fn pagination(query: &HashMap<String, String>) -> Result<Pagination, ScimError> {
    let start = integer(query.get("startIndex"), "startIndex")?
        .unwrap_or(1)
        .max(1) as usize;
    let count = integer(query.get("count"), "count")?
        .unwrap_or(100)
        .clamp(0, 100) as usize;
    Ok(Pagination {
        start_index: start,
        offset: start - 1,
        count,
    })
}

fn integer(value: Option<&String>, name: &str) -> Result<Option<i64>, ScimError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty()
        || !trimmed
            .strip_prefix('-')
            .unwrap_or(trimmed)
            .chars()
            .all(|character| character.is_ascii_digit())
    {
        return Err(invalid_value(format!("{name} must be an integer")));
    }
    trimmed
        .parse::<i64>()
        .map(Some)
        .map_err(|_| invalid_value(format!("{name} must be an integer")))
}

fn invalid_value(detail: impl Into<String>) -> ScimError {
    ScimError::typed(400, detail, ScimErrorType::InvalidValue)
}

pub(super) fn page(values: Vec<Value>, pagination: Pagination) -> (usize, Vec<Value>) {
    let total = values.len();
    let page = values
        .into_iter()
        .skip(pagination.offset)
        .take(pagination.count)
        .collect();
    (total, page)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(values: &[(&str, &str)]) -> HashMap<String, String> {
        values
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    #[test]
    fn pagination_clamps_and_rejects_non_integers() {
        let parsed =
            pagination(&query(&[("startIndex", "-4"), ("count", "900")])).unwrap();
        assert_eq!(parsed.start_index, 1);
        assert_eq!(parsed.offset, 0);
        assert_eq!(parsed.count, 100);

        let error = pagination(&query(&[("count", "1.5")])).unwrap_err();
        assert_eq!(error.scim_type, Some(ScimErrorType::InvalidValue));
        assert_eq!(error.detail, "count must be an integer");
    }
}
