use super::PostgresPhysicalSchema;
use crate::ResolvedAdapterSchema;
use std::collections::BTreeSet;

pub(super) fn schema_objects(
    physical: &PostgresPhysicalSchema,
    schema: &ResolvedAdapterSchema,
) -> Vec<super::super::schema::PostgresSchemaObject> {
    use super::super::schema::PostgresSchemaObject;

    let mut objects = BTreeSet::new();
    for model in physical
        .models
        .values()
        .filter(|model| !model.disable_migrations)
    {
        objects.insert(PostgresSchemaObject::Table {
            name: model.table.clone(),
        });
        objects.insert(PostgresSchemaObject::Column {
            table: model.table.clone(),
            name: "id".into(),
            data_type: match model.id_type {
                crate::DatabaseIdType::Uuid => "uuid",
                crate::DatabaseIdType::String => "text",
            }
            .into(),
        });
        objects.extend(model.columns.iter().map(|(column, physical)| {
            PostgresSchemaObject::Column {
                table: model.table.clone(),
                name: column.clone(),
                data_type: super::ddl::catalog_type(schema, &physical.field).into(),
            }
        }));
        if let Some(indexes) = schema.field_indexes_by_table().get(&model.table) {
            objects.extend(indexes.iter().filter(|index| !index.unique).map(|index| {
                PostgresSchemaObject::Index {
                    table: model.table.clone(),
                    name: index.name.clone(),
                    unique: false,
                }
            }));
        }
        if let Some(indexes) = schema.indexes_by_table().get(&model.table) {
            objects.extend(indexes.iter().map(|index| PostgresSchemaObject::Index {
                table: model.table.clone(),
                name: index.name.clone(),
                unique: index.unique,
            }));
        }
    }
    objects.into_iter().collect()
}
