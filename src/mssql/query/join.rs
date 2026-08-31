use super::{MssqlFilter, MssqlFindOptions, MssqlJoin, MssqlJoinRelation, MssqlSortDirection};
use crate::{
    AuthError,
    mssql::{
        adapter::MssqlClient,
        schema::{MssqlModel, MssqlSchema, quote},
        statement::MssqlStatement,
    },
};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use tiberius::Row;

pub(super) async fn find(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    options: &MssqlFindOptions,
    find_one: bool,
    lock: bool,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let joins = prepare(schema, &options.joins)?;
    let requested = requested_fields(&model, options);
    let inner_fields = inner_fields(&requested, options);
    let main_projection =
        model.logical_projection_for("[primary]", requested.iter().map(String::as_str))?;
    let mut query = MssqlStatement::new("select ");
    query.push(main_projection);
    if !requested.iter().any(|field| field == "id") {
        query.push(", [primary].[id] as [__lucid_primary_id]");
    }
    let joined_projection = projection(&joins);
    if !joined_projection.is_empty() {
        query.push(", ").push(joined_projection);
    }
    push_primary_query(
        &mut query,
        &model,
        filters,
        options,
        &inner_fields,
        QueryMode { find_one, lock },
    )?;
    push_clauses(&mut query, &model, &joins)?;
    push_outer_order(&mut query, options);
    let rows = query.query(connection).await?;
    decode(&model, &rows, &options.select, &joins)
}

#[derive(Clone, Copy)]
struct QueryMode {
    find_one: bool,
    lock: bool,
}

fn requested_fields(model: &MssqlModel<'_>, options: &MssqlFindOptions) -> Vec<String> {
    if options.select.is_empty() {
        model.logical_fields().map(str::to_owned).collect()
    } else {
        options.select.clone()
    }
}

fn inner_fields(requested: &[String], options: &MssqlFindOptions) -> Vec<String> {
    let mut fields = requested.to_vec();
    push_distinct(&mut fields, "id");
    for join in &options.joins {
        push_distinct(&mut fields, &join.local_field);
    }
    if let Some(sort) = &options.sort {
        push_distinct(&mut fields, &sort.field);
    }
    fields
}

fn push_primary_query(
    query: &mut MssqlStatement,
    model: &MssqlModel<'_>,
    filters: &[MssqlFilter],
    options: &MssqlFindOptions,
    fields: &[String],
    mode: QueryMode,
) -> Result<(), AuthError> {
    query.push(" from (select ");
    if mode.find_one {
        query.push("top (1) ");
    } else if options.offset.is_none()
        && let Some(limit) = options.limit
    {
        query
            .push("top (")
            .bind(super::execute::integer_parameter(limit)?)
            .push(") ");
    }
    query
        .push(model.projection(fields.iter().map(String::as_str))?)
        .push(" from ")
        .push(model.quoted_table());
    if mode.lock {
        query.push(" with (updlock, holdlock)");
    }
    super::predicate::push(query, model, filters)?;
    if mode.find_one || options.limit.is_some() || options.offset.is_some() {
        push_inner_order(query, model, options)?;
    }
    push_offset(query, options, mode.find_one)?;
    query.push(") as [primary]");
    Ok(())
}

fn push_inner_order(
    query: &mut MssqlStatement,
    model: &MssqlModel<'_>,
    options: &MssqlFindOptions,
) -> Result<(), AuthError> {
    if let Some(sort) = &options.sort {
        query
            .push(" order by ")
            .push(model.quoted_column(&sort.field)?)
            .push(direction(sort.direction));
    }
    Ok(())
}

fn push_offset(
    query: &mut MssqlStatement,
    options: &MssqlFindOptions,
    find_one: bool,
) -> Result<(), AuthError> {
    let Some(offset) = options.offset.filter(|_| !find_one) else {
        return Ok(());
    };
    if options.sort.is_none() {
        query.push(" order by [id] asc");
    }
    query
        .push(" offset ")
        .bind(super::execute::integer_parameter(offset)?)
        .push(" rows fetch next ")
        .bind(super::execute::integer_parameter(
            options.limit.filter(|limit| *limit > 0).unwrap_or(100),
        )?)
        .push(" rows only");
    Ok(())
}

fn push_outer_order(query: &mut MssqlStatement, options: &MssqlFindOptions) {
    if let Some(sort) = &options.sort {
        query
            .push(" order by [primary].")
            .push(quote(&sort.field))
            .push(direction(sort.direction));
    }
}

fn direction(direction: MssqlSortDirection) -> &'static str {
    match direction {
        MssqlSortDirection::Ascending => " asc",
        MssqlSortDirection::Descending => " desc",
    }
}

fn push_distinct(fields: &mut Vec<String>, field: &str) {
    if !fields.iter().any(|existing| existing == field) {
        fields.push(field.to_owned());
    }
}

pub(super) struct PreparedJoin<'a> {
    config: &'a MssqlJoin,
    model: MssqlModel<'a>,
    alias: String,
    output_prefix: String,
}

pub(super) fn prepare<'a>(
    schema: &'a MssqlSchema,
    joins: &'a [MssqlJoin],
) -> Result<Vec<PreparedJoin<'a>>, AuthError> {
    let mut prepared = Vec::with_capacity(joins.len());
    for join in joins {
        if prepared
            .iter()
            .any(|existing: &PreparedJoin<'_>| existing.config.model == join.model)
        {
            return Err(AuthError::InvalidConfiguration(format!(
                "MSSQL join model '{}' is configured more than once",
                join.model
            )));
        }
        let model = schema.model(&join.model)?;
        model.quoted_column(&join.foreign_field)?;
        prepared.push(PreparedJoin {
            alias: quote(&format!("join_{}", model.logical_name())),
            output_prefix: format!("_joined_{}", model.logical_name()),
            config: join,
            model,
        });
    }
    Ok(prepared)
}

pub(super) fn projection(joins: &[PreparedJoin<'_>]) -> String {
    joins
        .iter()
        .map(|join| {
            join.model.aliased_projection_for(
                &join.alias,
                &format!("{}_", join.output_prefix),
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn push_clauses(
    query: &mut MssqlStatement,
    main: &MssqlModel<'_>,
    joins: &[PreparedJoin<'_>],
) -> Result<(), AuthError> {
    for join in joins {
        query
            .push(" left join ")
            .push(join.model.quoted_table())
            .push(" as ")
            .push(&join.alias)
            .push(" on ")
            .push(&join.alias)
            .push(".")
            .push(join.model.quoted_column(&join.config.foreign_field)?)
            .push(" = [primary].")
            .push(quote(&join.config.local_field));
        main.quoted_column(&join.config.local_field)?;
    }
    Ok(())
}

pub(super) fn decode(
    main: &MssqlModel<'_>,
    rows: &[Row],
    select: &[String],
    joins: &[PreparedJoin<'_>],
) -> Result<Vec<Map<String, Value>>, AuthError> {
    let mut grouped = IndexMap::<String, Map<String, Value>>::new();
    for row in rows {
        let main_values = super::execute::decode_row(main, row, select)?;
        let main_id = if let Some(id) = main_values.get("id") {
            id.clone()
        } else {
            main.decode_field_as(row, "id", "__lucid_primary_id")?
        };
        let key = serde_json::to_string(&main_id).map_err(storage)?;
        let entry = grouped.entry(key).or_insert_with(|| {
            let mut entry = main_values;
            for join in joins {
                entry.insert(
                    join.config.model.clone(),
                    match join.config.relation {
                        MssqlJoinRelation::OneToOne => Value::Null,
                        MssqlJoinRelation::OneToMany => Value::Array(Vec::new()),
                    },
                );
            }
            entry
        });
        for join in joins {
            let joined = decode_join(row, join)?;
            if joined.values().all(Value::is_null) {
                continue;
            }
            match join.config.relation {
                MssqlJoinRelation::OneToOne => {
                    entry.insert(join.config.model.clone(), Value::Object(joined));
                }
                MssqlJoinRelation::OneToMany => {
                    let values = entry
                        .get_mut(&join.config.model)
                        .and_then(Value::as_array_mut)
                        .expect("one-to-many MSSQL joins initialize an array");
                    let limit = join.config.limit.unwrap_or(100);
                    if values.len() as u64 >= limit {
                        continue;
                    }
                    let id = joined.get("id");
                    if id.is_some_and(|id| {
                        values
                            .iter()
                            .filter_map(Value::as_object)
                            .any(|existing| existing.get("id") == Some(id))
                    }) {
                        continue;
                    }
                    values.push(Value::Object(joined));
                }
            }
        }
    }
    Ok(grouped.into_values().collect())
}

fn decode_join(row: &Row, join: &PreparedJoin<'_>) -> Result<Map<String, Value>, AuthError> {
    let mut values = Map::new();
    for field in join.model.logical_fields() {
        let source = format!("{}_{field}", join.output_prefix);
        values.insert(
            field.to_owned(),
            join.model.decode_field_as(row, field, &source)?,
        );
    }
    Ok(values)
}

fn storage(error: serde_json::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
