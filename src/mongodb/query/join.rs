use super::{MongoJoin, MongoJoinRelation};
use crate::{
    AuthError,
    mongodb::schema::{MongoModel, MongoSchema},
};
use mongodb::bson::{Bson, Document, doc};
use serde_json::{Map, Value};

pub(super) fn push_joins(
    schema: &MongoSchema,
    model: &MongoModel<'_>,
    joins: &[MongoJoin],
    pipeline: &mut Vec<Document>,
    find_one: bool,
) -> Result<(), AuthError> {
    for join in joins {
        let joined = schema.model(&join.model)?;
        let local = model.physical_field(&join.local_field)?;
        let foreign = joined.physical_field(&join.foreign_field)?;
        let is_unique = joined.unique(&join.foreign_field)?;
        let should_limit = if find_one {
            !is_unique && join.limit.is_some()
        } else {
            join.relation != MongoJoinRelation::OneToOne && join.limit.is_some()
        };
        if should_limit {
            let limit = join.limit.unwrap_or(100);
            if limit > 0 {
                pipeline.push(doc! { "$lookup": {
                    "from": joined.collection(),
                    "let": { "localFieldValue": format!("${local}") },
                    "pipeline": [
                        { "$match": { "$expr": { "$eq": [format!("${foreign}"), "$$localFieldValue"] } } },
                        { "$limit": checked_i64(limit)? }
                    ],
                    "as": &join.model,
                }});
            } else {
                push_simple_lookup(join, joined.collection(), local, foreign, pipeline);
            }
        } else {
            push_simple_lookup(join, joined.collection(), local, foreign, pipeline);
        }
        if is_unique {
            pipeline.push(doc! { "$unwind": {
                "path": format!("${}", join.model),
                "preserveNullAndEmptyArrays": true,
            }});
        }
    }
    Ok(())
}

fn push_simple_lookup(
    join: &MongoJoin,
    collection: &str,
    local: &str,
    foreign: &str,
    pipeline: &mut Vec<Document>,
) {
    pipeline.push(doc! { "$lookup": {
        "from": collection,
        "localField": local,
        "foreignField": foreign,
        "as": &join.model,
    }});
}

pub(super) fn decode_document(
    schema: &MongoSchema,
    model: &MongoModel<'_>,
    mut document: Document,
    select: &[String],
    joins: &[MongoJoin],
) -> Result<Map<String, Value>, AuthError> {
    let joined = joins
        .iter()
        .filter_map(|join| document.remove(&join.model).map(|value| (join, value)))
        .collect::<Vec<_>>();
    let mut decoded = if select.is_empty() {
        model.decode(document)?
    } else {
        model.decode_selection(document, select)?
    };
    for (join, value) in joined {
        let joined_model = schema.model(&join.model)?;
        let value = match value {
            Bson::Document(document) => Value::Object(joined_model.decode(document)?),
            Bson::Array(documents) => Value::Array(
                documents
                    .into_iter()
                    .filter_map(|value| value.as_document().cloned())
                    .map(|document| joined_model.decode(document).map(Value::Object))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Bson::Null => Value::Null,
            value => crate::mongodb::value::decode(value)?,
        };
        decoded.insert(join.model.clone(), value);
    }
    Ok(decoded)
}

fn checked_i64(value: u64) -> Result<i64, AuthError> {
    i64::try_from(value).map_err(|_| {
        AuthError::InvalidConfiguration("MongoDB join limit exceeds the signed 64-bit range".into())
    })
}
