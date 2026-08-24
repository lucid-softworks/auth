use super::{
    PostgresMigrationDescriptor, PostgresMigrationPlan, PostgresSchemaIssue, PostgresSchemaObject,
    PostgresSchemaReport, catalog::Catalog,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn compare(plan: &PostgresMigrationPlan, catalog: &Catalog) -> PostgresSchemaReport {
    let mut pending = Vec::new();
    let mut issues = Vec::new();
    compare_objects(&plan.schema, catalog, &mut issues);
    compare_migrations(plan, catalog, &mut pending, &mut issues);
    issues.sort_by_key(|issue| format!("{issue:?}"));
    PostgresSchemaReport {
        compatible: pending.is_empty() && issues.is_empty(),
        pending_migrations: pending,
        issues,
    }
}

fn compare_objects(
    expected: &[PostgresSchemaObject],
    catalog: &Catalog,
    issues: &mut Vec<PostgresSchemaIssue>,
) {
    let tables = catalog
        .columns
        .keys()
        .map(|(table, _)| table.as_str())
        .collect::<BTreeSet<_>>();
    for object in expected {
        match object {
            PostgresSchemaObject::Table { name } if !tables.contains(name.as_str()) => {
                issues.push(PostgresSchemaIssue::MissingTable {
                    table: name.clone(),
                });
            }
            PostgresSchemaObject::Column {
                table,
                name,
                data_type,
            } => compare_column(catalog, table, name, data_type, issues),
            PostgresSchemaObject::Index {
                table,
                name,
                unique,
            } => compare_index(catalog, table, name, *unique, issues),
            PostgresSchemaObject::Table { .. } => {}
        }
    }
}

fn compare_column(
    catalog: &Catalog,
    table: &str,
    name: &str,
    data_type: &str,
    issues: &mut Vec<PostgresSchemaIssue>,
) {
    match catalog.columns.get(&(table.into(), name.into())) {
        None => issues.push(PostgresSchemaIssue::MissingColumn {
            table: table.into(),
            column: name.into(),
        }),
        Some(actual) if actual != data_type => {
            issues.push(PostgresSchemaIssue::ColumnTypeMismatch {
                table: table.into(),
                column: name.into(),
                expected: data_type.into(),
                actual: actual.clone(),
            });
        }
        Some(_) => {}
    }
}

fn compare_index(
    catalog: &Catalog,
    table: &str,
    name: &str,
    unique: bool,
    issues: &mut Vec<PostgresSchemaIssue>,
) {
    match catalog.indexes.get(&(table.into(), name.into())) {
        None => issues.push(PostgresSchemaIssue::MissingIndex {
            table: table.into(),
            index: name.into(),
        }),
        Some(actual) if *actual != unique => {
            issues.push(PostgresSchemaIssue::IndexUniquenessMismatch {
                table: table.into(),
                index: name.into(),
                expected: unique,
                actual: *actual,
            });
        }
        Some(_) => {}
    }
}

fn compare_migrations(
    plan: &PostgresMigrationPlan,
    catalog: &Catalog,
    pending: &mut Vec<String>,
    issues: &mut Vec<PostgresSchemaIssue>,
) {
    let expected_core = expected_core(plan);
    let expected_plugins = expected_plugins(plan);
    let applied_core = catalog
        .core_migrations
        .iter()
        .map(|migration| (migration.version, migration))
        .collect::<BTreeMap<_, _>>();
    let applied_plugins = catalog
        .plugin_migrations
        .iter()
        .map(|migration| {
            (
                (
                    migration.plugin_id.as_str(),
                    migration.migration_id.as_str(),
                ),
                migration,
            )
        })
        .collect::<BTreeMap<_, _>>();

    for (version, (description, checksum)) in &expected_core {
        let id = format!("core:{version}");
        match applied_core.get(version) {
            None => pending.push(id),
            Some(applied) => compare_applied(
                &id,
                description,
                checksum,
                &applied.description,
                applied.checksum.as_deref(),
                issues,
            ),
        }
    }
    for version in applied_core.keys() {
        if !expected_core.contains_key(version) {
            issues.push(PostgresSchemaIssue::UnknownCoreMigration { version: *version });
        }
    }
    compare_plugins(&expected_plugins, &applied_plugins, pending, issues);
}

fn compare_plugins<'a>(
    expected: &BTreeMap<(&'a str, &'a str), (&'a String, &'a String)>,
    applied: &BTreeMap<(&str, &str), &super::catalog::AppliedPluginMigration>,
    pending: &mut Vec<String>,
    issues: &mut Vec<PostgresSchemaIssue>,
) {
    let enabled_ids = expected
        .keys()
        .map(|(plugin_id, _)| *plugin_id)
        .collect::<BTreeSet<_>>();
    for ((plugin_id, migration_id), (description, checksum)) in expected {
        let id = format!("plugin:{plugin_id}:{migration_id}");
        match applied.get(&(*plugin_id, *migration_id)) {
            None => pending.push(id),
            Some(applied) => compare_applied(
                &id,
                description,
                checksum,
                &applied.description,
                applied.checksum.as_deref(),
                issues,
            ),
        }
    }
    for (plugin_id, migration_id) in applied.keys() {
        if enabled_ids.contains(plugin_id) && !expected.contains_key(&(*plugin_id, *migration_id)) {
            issues.push(PostgresSchemaIssue::UnknownEnabledPluginMigration {
                plugin_id: (*plugin_id).into(),
                migration_id: (*migration_id).into(),
            });
        }
    }
}

fn expected_core(plan: &PostgresMigrationPlan) -> BTreeMap<i64, (&String, &String)> {
    plan.migrations
        .iter()
        .filter_map(|migration| match migration {
            PostgresMigrationDescriptor::Core {
                version,
                description,
                checksum,
            } => Some((*version, (description, checksum))),
            PostgresMigrationDescriptor::Plugin { .. } => None,
        })
        .collect()
}

fn expected_plugins(plan: &PostgresMigrationPlan) -> BTreeMap<(&str, &str), (&String, &String)> {
    plan.migrations
        .iter()
        .filter_map(|migration| match migration {
            PostgresMigrationDescriptor::Plugin {
                plugin_id,
                migration_id,
                description,
                checksum,
            } => Some((
                (plugin_id.as_str(), migration_id.as_str()),
                (description, checksum),
            )),
            PostgresMigrationDescriptor::Core { .. } => None,
        })
        .collect()
}

fn compare_applied(
    id: &str,
    expected_description: &str,
    expected_checksum: &str,
    actual_description: &str,
    actual_checksum: Option<&str>,
    issues: &mut Vec<PostgresSchemaIssue>,
) {
    if actual_description != expected_description {
        issues.push(PostgresSchemaIssue::DescriptionMismatch {
            migration: id.into(),
            expected: expected_description.into(),
            actual: actual_description.into(),
        });
    }
    match actual_checksum {
        None => issues.push(PostgresSchemaIssue::MigrationChecksumMissing {
            migration: id.into(),
        }),
        Some(actual) if actual != expected_checksum => {
            issues.push(PostgresSchemaIssue::MigrationChecksumMismatch {
                migration: id.into(),
                expected: expected_checksum.into(),
                actual: actual.into(),
            });
        }
        Some(_) => {}
    }
}
