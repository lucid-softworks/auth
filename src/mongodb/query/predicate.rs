use super::{
    MongoComparisonMode, MongoFilter, MongoFilterConnector, MongoFilterOperator,
};
use crate::{AuthError, mongodb::schema::MongoModel};
use mongodb::bson::{Bson, Document, doc};
use regex::escape;
use serde_json::Value;

pub(super) fn build(
    model: &MongoModel<'_>,
    filters: &[MongoFilter],
) -> Result<Document, AuthError> {
    let conditions = filters
        .iter()
        .map(|filter| build_filter(model, filter).map(|value| (filter.connector, value)))
        .collect::<Result<Vec<_>, _>>()?;
    if conditions.is_empty() {
        return Ok(Document::new());
    }
    if conditions.len() == 1 {
        return Ok(conditions.into_iter().next().expect("one condition").1);
    }
    let and = conditions
        .iter()
        .filter(|(connector, _)| *connector == MongoFilterConnector::And)
        .map(|(_, condition)| Bson::Document(condition.clone()))
        .collect::<Vec<_>>();
    let or = conditions
        .into_iter()
        .filter(|(connector, _)| *connector == MongoFilterConnector::Or)
        .map(|(_, condition)| Bson::Document(condition))
        .collect::<Vec<_>>();
    let mut clause = Document::new();
    if !and.is_empty() {
        clause.insert("$and", and);
    }
    if !or.is_empty() {
        clause.insert("$or", or);
    }
    Ok(clause)
}

fn build_filter(
    model: &MongoModel<'_>,
    filter: &MongoFilter,
) -> Result<Document, AuthError> {
    let field = model.physical_field(&filter.field)?.to_owned();
    let insensitive = !model.is_id(&filter.field)?
        && filter.mode == MongoComparisonMode::Insensitive
        && (filter.value.is_string()
            || filter
                .value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string)));
    match filter.operator {
        MongoFilterOperator::Eq if insensitive => regex_scalar(&field, &filter.value, "^", "$", true),
        MongoFilterOperator::Ne if insensitive => {
            let regex = regex_document(&filter.value, "^", "$", true)?;
            Ok(doc! { field: { "$not": regex } })
        }
        MongoFilterOperator::In if insensitive => insensitive_set(&field, &filter.value, false),
        MongoFilterOperator::NotIn if insensitive => insensitive_set(&field, &filter.value, true),
        MongoFilterOperator::Contains => regex_scalar(&field, &filter.value, ".*", ".*", insensitive),
        MongoFilterOperator::StartsWith => regex_scalar(&field, &filter.value, "^", "", insensitive),
        MongoFilterOperator::EndsWith => regex_scalar(&field, &filter.value, "", "$", insensitive),
        MongoFilterOperator::In | MongoFilterOperator::NotIn => {
            let values = filter
                .value
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![filter.value.clone()]);
            let values = values
                .into_iter()
                .map(|value| model.encode(&filter.field, value))
                .collect::<Result<Vec<_>, _>>()?;
            let operator = if filter.operator == MongoFilterOperator::In {
                "$in"
            } else {
                "$nin"
            };
            Ok(doc! { field: { operator: values } })
        }
        operator => {
            let value = model.encode(&filter.field, filter.value.clone())?;
            let operator = match operator {
                MongoFilterOperator::Eq => return Ok(doc! { field: value }),
                MongoFilterOperator::Ne => "$ne",
                MongoFilterOperator::Gt => "$gt",
                MongoFilterOperator::Gte => "$gte",
                MongoFilterOperator::Lt => "$lt",
                MongoFilterOperator::Lte => "$lte",
                MongoFilterOperator::In
                | MongoFilterOperator::NotIn
                | MongoFilterOperator::Contains
                | MongoFilterOperator::StartsWith
                | MongoFilterOperator::EndsWith => unreachable!(),
            };
            Ok(doc! { field: { operator: value } })
        }
    }
}

fn insensitive_set(field: &str, value: &Value, negate: bool) -> Result<Document, AuthError> {
    let values = value
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![value.clone()]);
    if values.is_empty() {
        return Ok(if negate {
            Document::new()
        } else {
            doc! { "$expr": { "$eq": [1, 0] } }
        });
    }
    let conditions = values
        .iter()
        .map(|value| regex_scalar(field, value, "^", "$", true).map(Bson::Document))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(if negate {
        doc! { "$nor": conditions }
    } else {
        doc! { "$or": conditions }
    })
}

fn regex_scalar(
    field: &str,
    value: &Value,
    prefix: &str,
    suffix: &str,
    insensitive: bool,
) -> Result<Document, AuthError> {
    Ok(doc! { field: regex_document(value, prefix, suffix, insensitive)? })
}

fn regex_document(
    value: &Value,
    prefix: &str,
    suffix: &str,
    insensitive: bool,
) -> Result<Document, AuthError> {
    let value = value.as_str().ok_or_else(|| {
        AuthError::InvalidConfiguration("MongoDB pattern predicates require a string".into())
    })?;
    let truncated = value.chars().take(256).collect::<String>();
    let mut regex = doc! { "$regex": format!("{prefix}{}{suffix}", escape(&truncated)) };
    if insensitive {
        regex.insert("$options", "i");
    }
    Ok(regex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterSchemaOptions, AuthConfig, AuthSchemaCatalog, ResolvedAdapterSchema};
    use serde_json::json;
    use std::sync::Arc;

    fn schema() -> super::super::super::schema::MongoSchema {
        let config = AuthConfig::new([63; 32]).unwrap();
        let resolved = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, []).unwrap()),
            AdapterSchemaOptions::default(),
        )
        .unwrap();
        super::super::super::schema::MongoSchema::new(&resolved).unwrap()
    }

    #[test]
    fn regex_values_are_truncated_then_escaped() {
        let schema = schema();
        let model = schema.model("user").unwrap();
        let value = format!("{}.*", "a".repeat(255));
        let filter = MongoFilter {
            field: "email".into(),
            value: json!(value),
            operator: MongoFilterOperator::Contains,
            connector: MongoFilterConnector::And,
            mode: MongoComparisonMode::Insensitive,
        };
        let clause = build(&model, &[filter]).unwrap();
        let regex = clause.get_document("email").unwrap();
        assert_eq!(regex.get_str("$options").unwrap(), "i");
        assert!(regex.get_str("$regex").unwrap().ends_with("\\..*"));
    }

    #[test]
    fn empty_insensitive_sets_match_upstream_truth_tables() {
        let schema = schema();
        let model = schema.model("user").unwrap();
        let filter = |operator| MongoFilter {
            field: "email".into(),
            value: json!([]),
            operator,
            connector: MongoFilterConnector::And,
            mode: MongoComparisonMode::Insensitive,
        };
        assert!(build(&model, &[filter(MongoFilterOperator::In)])
            .unwrap()
            .contains_key("$expr"));
        assert!(build(&model, &[filter(MongoFilterOperator::NotIn)])
            .unwrap()
            .is_empty());
    }
}
