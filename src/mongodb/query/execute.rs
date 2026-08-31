use super::{
    MongoFilter, MongoFindOptions, MongoJoin, MongoSortDirection,
    join::{decode_document, push_joins},
    predicate, projection,
};
use crate::{AuthError, mongodb::{MongoStore, schema::MongoModel}};
use futures_util::TryStreamExt;
use mongodb::{
    ClientSession, Collection, IndexModel,
    bson::{Bson, Document, doc},
    options::{IndexOptions, ReturnDocument},
};
use serde_json::{Map, Value};

const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

mod compat;
pub(in crate::mongodb) use compat::*;

pub(in crate::mongodb) async fn insert_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    record: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = store.physical_schema()?.model(model_name)?;
    ensure_indexes(store, &model).await?;
    let mut document = model.encode_fields(record)?;
    let collection = collection(store, &model);
    let result = match session {
        Some(session) => collection.insert_one(&document).session(session).await,
        None => collection.insert_one(&document).await,
    }
    .map_err(storage)?;
    document.entry("_id".into()).or_insert(result.inserted_id);
    model.decode(document).map(Some)
}

pub(in crate::mongodb) async fn find_one_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
    select: &[String],
    joins: &[MongoJoin],
) -> Result<Option<Map<String, Value>>, AuthError> {
    let schema = store.physical_schema()?;
    let model = schema.model(model_name)?;
    let mut pipeline = vec![doc! { "$match": predicate::build(&model, filters)? }];
    push_joins(schema, &model, joins, &mut pipeline, true)?;
    if let Some(mut fields) = projection(&model, select)? {
        for join in joins {
            fields.insert(&join.model, 1);
        }
        pipeline.push(doc! { "$project": fields });
    }
    pipeline.push(doc! { "$limit": 1_i64 });
    let documents = aggregate(collection(store, &model), pipeline, session).await?;
    documents
        .into_iter()
        .next()
        .map(|document| decode_document(schema, &model, document, select, joins))
        .transpose()
}

pub(in crate::mongodb) async fn find_many_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
    options: &MongoFindOptions,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    let schema = store.physical_schema()?;
    let model = schema.model(model_name)?;
    let mut pipeline = vec![doc! { "$match": predicate::build(&model, filters)? }];
    push_joins(schema, &model, &options.joins, &mut pipeline, false)?;
    if let Some(mut fields) = projection(&model, &options.select)? {
        for join in &options.joins {
            fields.insert(&join.model, 1);
        }
        pipeline.push(doc! { "$project": fields });
    }
    if let Some(sort) = &options.sort {
        pipeline.push(doc! {
            "$sort": { model.physical_field(&sort.field)?: match sort.direction {
                MongoSortDirection::Ascending => 1_i32,
                MongoSortDirection::Descending => -1_i32,
            }}
        });
    }
    if let Some(offset) = options.offset.filter(|offset| *offset > 0) {
        pipeline.push(doc! { "$skip": checked_i64("offset", offset)? });
    }
    if let Some(limit) = options.limit.filter(|limit| *limit > 0) {
        pipeline.push(doc! { "$limit": checked_i64("limit", limit)? });
    }
    aggregate(collection(store, &model), pipeline, session)
        .await?
        .into_iter()
        .map(|document| {
            decode_document(
                schema,
                &model,
                document,
                &options.select,
                &options.joins,
            )
        })
        .collect()
}

pub(in crate::mongodb) async fn count_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
) -> Result<u64, AuthError> {
    let model = store.physical_schema()?.model(model_name)?;
    let pipeline = vec![
        doc! { "$match": predicate::build(&model, filters)? },
        doc! { "$count": "total" },
    ];
    let documents = aggregate(collection(store, &model), pipeline, session).await?;
    Ok(documents
        .first()
        .and_then(|document| document.get("total"))
        .and_then(number_as_u64)
        .unwrap_or(0)
        .min(JAVASCRIPT_MAX_SAFE_INTEGER))
}

pub(in crate::mongodb) async fn update_one_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
    values: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    if filters.is_empty() {
        return Ok(None);
    }
    let model = store.physical_schema()?.model(model_name)?;
    ensure_indexes(store, &model).await?;
    let values = model.encode_fields(values)?;
    if values.is_empty() {
        return find_one_with_session(store, session, model_name, filters, &[], &[]).await;
    }
    let filter = predicate::build(&model, filters)?;
    let collection = collection(store, &model);
    let result = match session {
        Some(session) => collection
            .find_one_and_update(filter, doc! { "$set": values })
            .return_document(ReturnDocument::After)
            .session(session)
            .await,
        None => collection
            .find_one_and_update(filter, doc! { "$set": values })
            .return_document(ReturnDocument::After)
            .await,
    }
    .map_err(storage)?;
    result.map(|document| model.decode(document)).transpose()
}

pub(in crate::mongodb) async fn update_many_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
    values: Map<String, Value>,
) -> Result<u64, AuthError> {
    let model = store.physical_schema()?.model(model_name)?;
    ensure_indexes(store, &model).await?;
    let values = model.encode_fields(values)?;
    if values.is_empty() {
        return Ok(0);
    }
    let filter = predicate::build(&model, filters)?;
    let collection = collection(store, &model);
    let result = match session {
        Some(session) => collection
            .update_many(filter, doc! { "$set": values })
            .session(session)
            .await,
        None => collection.update_many(filter, doc! { "$set": values }).await,
    }
    .map_err(storage)?;
    Ok(result.modified_count.min(JAVASCRIPT_MAX_SAFE_INTEGER))
}

pub(in crate::mongodb) async fn delete_one_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
) -> Result<(), AuthError> {
    let model = store.physical_schema()?.model(model_name)?;
    let filter = predicate::build(&model, filters)?;
    let collection = collection(store, &model);
    match session {
        Some(session) => collection.delete_one(filter).session(session).await,
        None => collection.delete_one(filter).await,
    }
    .map_err(storage)?;
    Ok(())
}

pub(in crate::mongodb) async fn delete_many_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
) -> Result<u64, AuthError> {
    let model = store.physical_schema()?.model(model_name)?;
    let filter = predicate::build(&model, filters)?;
    let collection = collection(store, &model);
    let result = match session {
        Some(session) => collection.delete_many(filter).session(session).await,
        None => collection.delete_many(filter).await,
    }
    .map_err(storage)?;
    Ok(result.deleted_count.min(JAVASCRIPT_MAX_SAFE_INTEGER))
}

pub(in crate::mongodb) async fn consume_one_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
) -> Result<Option<Map<String, Value>>, AuthError> {
    consume_one_sorted(store, session, model_name, filters, None).await
}

pub(in crate::mongodb) async fn consume_latest_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
    sort_field: &str,
) -> Result<Option<Map<String, Value>>, AuthError> {
    consume_one_sorted(store, session, model_name, filters, Some(sort_field)).await
}

async fn consume_one_sorted(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
    sort_field: Option<&str>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = store.physical_schema()?.model(model_name)?;
    let filter = predicate::build(&model, filters)?;
    let collection = collection(store, &model);
    let sort = sort_field
        .map(|field| model.physical_field(field).map(|field| doc! { field: -1_i32 }))
        .transpose()?;
    let result = match (session, sort) {
        (Some(session), Some(sort)) => collection
            .find_one_and_delete(filter)
            .sort(sort)
            .session(session)
            .await,
        (Some(session), None) => collection.find_one_and_delete(filter).session(session).await,
        (None, Some(sort)) => collection.find_one_and_delete(filter).sort(sort).await,
        (None, None) => collection.find_one_and_delete(filter).await,
    }
    .map_err(storage)?;
    result.map(|document| model.decode(document)).transpose()
}

pub(in crate::mongodb) async fn increment_one_with_session(
    store: &MongoStore,
    session: Option<&mut ClientSession>,
    model_name: &str,
    filters: &[MongoFilter],
    increments: Map<String, Value>,
    set: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = store.physical_schema()?.model(model_name)?;
    ensure_indexes(store, &model).await?;
    if increments.is_empty() && set.is_empty() {
        return find_one_with_session(store, session, model_name, filters, &[], &[]).await;
    }
    let mut update = Document::new();
    if !increments.is_empty() {
        update.insert("$inc", model.encode_fields(increments)?);
    }
    if !set.is_empty() {
        update.insert("$set", model.encode_fields(set)?);
    }
    let filter = predicate::build(&model, filters)?;
    let collection = collection(store, &model);
    let result = match session {
        Some(session) => collection
            .find_one_and_update(filter, update)
            .return_document(ReturnDocument::After)
            .session(session)
            .await,
        None => collection
            .find_one_and_update(filter, update)
            .return_document(ReturnDocument::After)
            .await,
    }
    .map_err(storage)?;
    result.map(|document| model.decode(document)).transpose()
}

async fn ensure_indexes(store: &MongoStore, model: &MongoModel<'_>) -> Result<(), AuthError> {
    for index in model.indexes() {
        let physical_columns = index
            .columns
            .iter()
            .map(|field| if field == "id" { "_id" } else { field.as_str() })
            .collect::<Vec<_>>();
        let definition = format!(
            "{}\u{0}{}\u{0}{}\u{0}{}",
            model.collection(),
            index.name,
            physical_columns.join("\u{1f}"),
            index.unique
        );
        let mut setup = store.index_setup.lock().await;
        if setup.contains(&definition) {
            continue;
        }
        let keys = physical_columns
            .into_iter()
            .map(|field| (field.to_owned(), Bson::Int32(1)))
            .collect::<Document>();
        let index_model = IndexModel::builder()
            .keys(keys)
            .options(
                IndexOptions::builder()
                    .name(index.name.clone())
                    .unique(index.unique)
                    .build(),
            )
            .build();
        // Keep the guard across creation: concurrent writers share one attempt.
        store
            .database
            .collection::<Document>(model.collection())
            .create_index(index_model)
            .await
            .map_err(storage)?;
        setup.insert(definition);
    }
    Ok(())
}

async fn aggregate(
    collection: Collection<Document>,
    pipeline: Vec<Document>,
    session: Option<&mut ClientSession>,
) -> Result<Vec<Document>, AuthError> {
    match session {
        Some(session) => {
            let mut cursor = collection
                .aggregate(pipeline)
                .session(&mut *session)
                .await
                .map_err(storage)?;
            cursor.stream(session).try_collect().await.map_err(storage)
        }
        None => collection
            .aggregate(pipeline)
            .await
            .map_err(storage)?
            .try_collect()
            .await
            .map_err(storage),
    }
}

fn collection(store: &MongoStore, model: &MongoModel<'_>) -> Collection<Document> {
    store.database.collection(model.collection())
}

fn checked_i64(name: &str, value: u64) -> Result<i64, AuthError> {
    i64::try_from(value).map_err(|_| {
        AuthError::InvalidConfiguration(format!("MongoDB {name} exceeds the signed 64-bit range"))
    })
}

fn number_as_u64(value: &Bson) -> Option<u64> {
    match value {
        Bson::Int32(value) => u64::try_from(*value).ok(),
        Bson::Int64(value) => u64::try_from(*value).ok(),
        Bson::Double(value) if value.is_finite() && *value >= 0.0 => Some(*value as u64),
        _ => None,
    }
}

fn storage(error: mongodb::error::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
