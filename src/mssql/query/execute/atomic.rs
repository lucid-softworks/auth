use super::find_one;
use crate::{
    AuthError,
    mssql::{
        MssqlFilter,
        adapter::MssqlClient,
        query::predicate,
        schema::MssqlSchema,
        statement::MssqlStatement,
    },
};
use serde_json::{Map, Value};

pub(in crate::mssql) async fn consume_one(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = MssqlStatement::new("delete top (1) from ");
    query
        .push(model.quoted_table())
        .push(" output ")
        .push(model.all_projection_for("deleted"));
    predicate::push(&mut query, &model, filters)?;
    query
        .query(connection)
        .await?
        .into_iter()
        .next()
        .map(|row| model.decode_all(&row))
        .transpose()
}

pub(in crate::mssql) async fn consume_latest(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    sort_field: &str,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = MssqlStatement::new("with [target] as (select top (1) * from ");
    query.push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query
        .push(" order by ")
        .push(model.quoted_column(sort_field)?)
        .push(" desc, [id] desc) delete from [target] output ")
        .push(model.all_projection_for("deleted"));
    query
        .query(connection)
        .await?
        .into_iter()
        .next()
        .map(|row| model.decode_all(&row))
        .transpose()
}

pub(in crate::mssql) async fn increment_one(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    increments: Map<String, Value>,
    mut set: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    for field in increments.keys() {
        set.remove(field);
    }
    if set.is_empty() && increments.is_empty() {
        return find_one(connection, schema, model_name, filters, &[]).await;
    }
    let mut query = MssqlStatement::new("update top (1) ");
    query.push(model.quoted_table()).push(" set ");
    let mut position = 0;
    for (field, value) in set {
        separator(&mut query, &mut position);
        query
            .push(model.quoted_column(&field)?)
            .push(" = ")
            .bind(model.encode(&field, value)?);
    }
    for (field, delta) in increments {
        separator(&mut query, &mut position);
        let column = model.quoted_column(&field)?;
        query
            .push(column)
            .push(" = ")
            .push(column)
            .push(" + ")
            .bind(model.encode(&field, delta)?);
    }
    query
        .push(" output ")
        .push(model.all_projection_for("inserted"));
    predicate::push(&mut query, &model, filters)?;
    query
        .query(connection)
        .await?
        .into_iter()
        .next()
        .map(|row| model.decode_all(&row))
        .transpose()
}

fn separator(query: &mut MssqlStatement, position: &mut usize) {
    if *position > 0 {
        query.push(", ");
    }
    *position += 1;
}
