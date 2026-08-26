use super::super::PostgresModel;
use crate::{AdminListCondition, AdminListOperator, AuthError};
use serde_json::Value;
use sqlx::{Postgres, QueryBuilder};

pub(super) fn push_conditions(
    query: &mut QueryBuilder<'static, Postgres>,
    model: &PostgresModel<'_>,
    conditions: &[AdminListCondition],
) -> Result<(), AuthError> {
    if conditions.is_empty() {
        return Ok(());
    }
    query.push(" WHERE ");
    for (index, condition) in conditions.iter().enumerate() {
        if index > 0 {
            query.push(" AND ");
        }
        let column = model.quoted_column(&condition.field)?;
        match condition.operator {
            AdminListOperator::Contains
            | AdminListOperator::StartsWith
            | AdminListOperator::EndsWith => push_text_condition(query, condition, column),
            AdminListOperator::In | AdminListOperator::NotIn => {
                push_list_condition(query, model, condition, column)?;
            }
            operator => {
                query.push(column).push(match operator {
                    AdminListOperator::Eq => " = ",
                    AdminListOperator::Ne => " <> ",
                    AdminListOperator::Lt => " < ",
                    AdminListOperator::Lte => " <= ",
                    AdminListOperator::Gt => " > ",
                    AdminListOperator::Gte => " >= ",
                    _ => unreachable!(),
                });
                model
                    .encode(&condition.field, condition.value.clone())?
                    .push_bind(query);
            }
        }
    }
    Ok(())
}

fn push_text_condition(
    query: &mut QueryBuilder<'static, Postgres>,
    condition: &AdminListCondition,
    column: &str,
) {
    let value = condition_text(&condition.value);
    query.push("CAST(").push(column).push(" AS TEXT) ILIKE ");
    query.push_bind(match condition.operator {
        AdminListOperator::Contains => format!("%{value}%"),
        AdminListOperator::StartsWith => format!("{value}%"),
        AdminListOperator::EndsWith => format!("%{value}"),
        _ => unreachable!(),
    });
}

fn push_list_condition(
    query: &mut QueryBuilder<'static, Postgres>,
    model: &PostgresModel<'_>,
    condition: &AdminListCondition,
    column: &str,
) -> Result<(), AuthError> {
    let values = condition
        .value
        .as_array()
        .ok_or_else(|| AuthError::InvalidRequest("filter list is invalid".into()))?;
    query
        .push(column)
        .push(if condition.operator == AdminListOperator::NotIn {
            " NOT IN ("
        } else {
            " IN ("
        });
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        model
            .encode(&condition.field, value.clone())?
            .push_bind(query);
    }
    query.push(")");
    Ok(())
}

fn condition_text(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AdditionalField, AdditionalFieldType, AuthConfig, AuthSchemaCatalog,
        PluginSchemaTable, ResolvedAdapterSchema,
    };
    use serde_json::json;
    use std::sync::Arc;

    fn physical(admin: bool) -> super::super::super::physical_schema::PostgresPhysicalSchema {
        let mut config = AuthConfig::new([32; 32]).unwrap();
        config.user.model_name = Some("user\" records".into());
        config.user.fields.email = Some("email address".into());
        let plugins = admin.then(|| {
            PluginSchemaTable::new("user").field(
                "role",
                AdditionalField::new(AdditionalFieldType::String)
                    .optional()
                    .field_name("admin role"),
            )
        });
        let catalog = Arc::new(AuthSchemaCatalog::build(&config, plugins).unwrap());
        let resolved =
            ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
        super::super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap()
    }

    #[test]
    fn hostile_values_stay_bound_and_catalog_identifiers_are_quoted() {
        let physical = physical(true);
        let model = physical.model("user").unwrap();
        let mut query = super::super::super::rows::select_query(&model);
        push_conditions(
            &mut query,
            &model,
            &[AdminListCondition {
                field: "email".into(),
                operator: AdminListOperator::Eq,
                value: json!("hostile' OR true --"),
            }],
        )
        .unwrap();
        query
            .push(" ORDER BY ")
            .push(model.quoted_column("role").unwrap());
        let sql = query.sql();
        assert!(sql.contains("FROM \"user\"\" records\""));
        assert!(sql.contains("\"email address\" = $1"));
        assert!(sql.contains("ORDER BY \"admin role\""));
        assert!(!sql.contains("hostile"));
        assert!(!sql.contains("lucid_auth_") && !sql.contains("additional_fields"));
    }

    #[test]
    fn absent_plugin_field_is_rejected() {
        let physical = physical(false);
        let model = physical.model("user").unwrap();
        let mut query = super::super::super::rows::select_query(&model);
        assert!(
            push_conditions(
                &mut query,
                &model,
                &[AdminListCondition {
                    field: "role".into(),
                    operator: AdminListOperator::Eq,
                    value: json!("admin"),
                }]
            )
            .is_err()
        );
    }
}
