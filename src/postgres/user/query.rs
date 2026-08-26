use super::super::{PostgresModel, PostgresWrite};
use sqlx::{Postgres, QueryBuilder};

pub(in crate::postgres) fn select_query(
    model: &PostgresModel<'_>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table());
    query
}

pub(in crate::postgres) fn insert_query(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = insert_query_prefix(model, writes);
    query.push(" RETURNING ").push(model.all_projection());
    query
}

pub(in crate::postgres) fn insert_query_prefix(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("INSERT INTO ");
    query.push(model.quoted_table()).push(" (");
    for (index, write) in writes.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query.push(write.quoted_column());
    }
    query.push(") VALUES (");
    for (index, write) in writes.into_iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        write.push_bind(&mut query);
    }
    query.push(")");
    query
}

pub(in crate::postgres) fn update_query(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("UPDATE ");
    query.push(model.quoted_table()).push(" SET ");
    for (index, write) in writes.into_iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query.push(write.quoted_column()).push(" = ");
        write.push_bind(&mut query);
    }
    query
}
