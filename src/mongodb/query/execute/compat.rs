use super::{
    consume_latest_with_session, consume_one_with_session, count_with_session,
    delete_many_with_session, find_many_with_session, find_one_with_session,
    increment_one_with_session, insert_with_session, update_many_with_session,
    update_one_with_session,
};
use crate::{
    AuthError,
    mongodb::{
        MongoFilter, MongoFindOptions,
        query::MongoExecution,
        schema::MongoSchema,
    },
};
use serde_json::{Map, Value};

pub(in crate::mongodb) async fn insert(
    connection: &mut impl MongoExecution,
    _schema: &MongoSchema,
    model: &str,
    record: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let (store, session) = connection.parts();
    insert_with_session(store, session, model, record).await
}

pub(in crate::mongodb) async fn insert_required(
    connection: &mut impl MongoExecution,
    schema: &MongoSchema,
    model: &str,
    record: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    insert(connection, schema, model, record)
        .await?
        .ok_or(AuthError::NotFound)
}

pub(in crate::mongodb) async fn find_one(
    connection: &mut impl MongoExecution,
    _schema: &MongoSchema,
    model: &str,
    filters: &[MongoFilter],
    select: &[String],
) -> Result<Option<Map<String, Value>>, AuthError> {
    let (store, session) = connection.parts();
    find_one_with_session(store, session, model, filters, select, &[]).await
}

pub(in crate::mongodb) async fn find_one_for_update(
    connection: &mut impl MongoExecution,
    schema: &MongoSchema,
    model: &str,
    filters: &[MongoFilter],
    select: &[String],
) -> Result<Option<Map<String, Value>>, AuthError> {
    find_one(connection, schema, model, filters, select).await
}

pub(in crate::mongodb) async fn find_many(
    connection: &mut impl MongoExecution,
    _schema: &MongoSchema,
    model: &str,
    filters: &[MongoFilter],
    options: &MongoFindOptions,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    let (store, session) = connection.parts();
    find_many_with_session(store, session, model, filters, options).await
}

pub(in crate::mongodb) async fn find_many_for_update(
    connection: &mut impl MongoExecution,
    schema: &MongoSchema,
    model: &str,
    filters: &[MongoFilter],
    options: &MongoFindOptions,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    find_many(connection, schema, model, filters, options).await
}

macro_rules! mutation_wrapper {
    ($name:ident, $core:ident, $result:ty, $( $arg:ident : $kind:ty ),* $(,)?) => {
        pub(in crate::mongodb) async fn $name(
            connection: &mut impl MongoExecution,
            _schema: &MongoSchema,
            model: &str,
            filters: &[MongoFilter],
            $( $arg: $kind, )*
        ) -> Result<$result, AuthError> {
            let (store, session) = connection.parts();
            $core(store, session, model, filters, $( $arg, )*).await
        }
    };
}

mutation_wrapper!(update_one, update_one_with_session, Option<Map<String, Value>>, values: Map<String, Value>);
mutation_wrapper!(update_many, update_many_with_session, u64, values: Map<String, Value>);
mutation_wrapper!(count, count_with_session, u64,);
mutation_wrapper!(delete_many, delete_many_with_session, u64,);
mutation_wrapper!(consume_one, consume_one_with_session, Option<Map<String, Value>>,);
mutation_wrapper!(consume_latest, consume_latest_with_session, Option<Map<String, Value>>, sort_field: &str);
mutation_wrapper!(increment_one, increment_one_with_session, Option<Map<String, Value>>, increments: Map<String, Value>, set: Map<String, Value>);
