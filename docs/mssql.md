# Microsoft SQL Server storage

The optional `mssql` feature is a native, in-process implementation of Better
Auth `1.7.1`'s `type: "mssql"` Kysely adapter path. Production code uses
Tiberius through a BB8 pool; Kysely, Tedious, Node, and helper processes appear
only in the pinned conformance oracle.

## Connection and startup

`MssqlStore::connect` accepts an ADO-style connection string and constructs a
default BB8 pool. `MssqlStore::connect_with` accepts a caller-built
`tiberius::Config` and maximum pool size, while `MssqlStore::new` preserves all
policy on a caller-owned pool. The backend does not add retry, timeout,
isolation, failover, TLS-certificate, or connection-reset policy.

```rust,no_run
use lucid_auth::mssql::{MssqlAdapterConfig, MssqlStore};

# async fn build() -> Result<(), lucid_auth::AuthError> {
let store = MssqlStore::connect(
    "server=tcp:db.internal,1433;database=auth;user=auth_app;password=SECRET;TrustServerCertificate=false",
    MssqlAdapterConfig::default(),
).await?;
store.ready().await?;
# Ok(())
# }
```

Use an application login scoped to the target database. Keep connection
strings in a secret manager and do not include them in errors or query logs.
Validate the server certificate in production; the quickstart's
`TrustServerCertificate=true` is for its local container only.

## Better Auth options and transactions

`MssqlAdapterConfig` preserves `use_plural`, `transaction`, and `debug_logs`.
Literal pluralization and all model/field remapping are resolved before any SQL
is produced. Bound request values are never interpolated into SQL.

`transaction` defaults to `false`, matching a bare MSSQL dialect and wrappers
whose transaction option is absent or false. Multi-operation callbacks then
reuse one connection sequentially without issuing `BEGIN`; a later failure does
not undo earlier statements. Set `transaction: true` only when the deployment
explicitly wants the entire callback to commit or roll back together. Atomic
single-statement consumes and increments do not depend on this option.

The backend does not choose an isolation level, add deadlock retries, or create
savepoints. Driver and database failures surface as storage errors.

## Values, IDs, and queries

The native boundary follows the pinned adapter rather than substituting more
SQL-Server-specific types:

- ordinary strings, JSON, and arrays use `varchar` text; booleans use
  `smallint`; dates use `datetime2(3)`;
- booleans cross the adapter boundary as `1`/`0`, dates as ISO strings, and
  JSON/arrays as serialized text;
- default, database-deferred, UUID, and callback IDs are `varchar(36)` strings;
  UUID values are application-generated;
- only the serial strategy uses an integer identity, normalized to a public
  string together with its references.

Create/update use `OUTPUT inserted`, consume uses `OUTPUT deleted`, and atomic
target selection uses `TOP (1)`. Offset pagination uses `OFFSET ... FETCH` and
orders by the resolved ID when no sort is supplied. Enabled joins use left
joins over the paged primary subquery, return null/array relation shapes,
de-duplicate related rows by ID, and enforce Better Auth's default relation
limit of 100 in memory. Callers that do not request joins retain the ordinary
separate-query paths used by the typed stores.

## Additive migrations

Always build the service first and pass its complete resolved catalog to the
same store before traffic starts:

```rust,no_run
# use lucid_auth::{AuthConfig, AuthService, mssql::{MssqlAdapterConfig, MssqlStore}};
# use std::sync::Arc;
# async fn migrate() -> Result<(), Box<dyn std::error::Error>> {
# let store = Arc::new(MssqlStore::connect("server=tcp:localhost,1433;database=auth;user=sa;password=SECRET;TrustServerCertificate=true", MssqlAdapterConfig::default()).await?);
# let service = AuthService::try_new(store.clone(), AuthConfig::new([7; 32])?)?;
let plan = store
    .migrate(Arc::new(service.database_schema().clone()))
    .await?;
assert!(plan.unsafe_changes.is_empty());
# Ok(())
# }
```

The planner discovers the active schema with `SCHEMA_NAME()` (falling back to
`dbo`) and reads tables, columns, bounds, and ordered index metadata from the
SQL Server system catalog. It creates only missing tables, columns, and
indexes, sequentially, with no migration ledger. It never drops, renames,
alters, backfills, or weakens existing objects.

Use `migration_plan(..., MssqlMigrationMode::Compile)` during deployment review.
Nullable/type drift remains a warning. Required columns without usable defaults
on populated tables, conflicting indexes, unbounded indexed strings, and keys
over the pinned 1700-byte budget remain unsafe instead of being applied.
Nullable unique columns added to an existing table use a filtered unique index;
new-table unique constraints retain the upstream form. Back up and test restore
before applying a plan.

## Security checklist

- Grant only target-schema DDL during the migration phase; runtime instances
  need only the DML permissions used by enabled auth/plugin models.
- Keep all request values bound. Identifiers must come only from the validated
  resolved schema and remain bracket-quoted.
- Do not log credentials, cookies, tokens, or bound query values. Treat debug
  diagnostics as operational metadata, not a request-value trace.
- Review transaction-off partial-failure behavior and opt in explicitly where
  a multi-operation callback must be atomic.
- Treat unsafe migration output as manual deployment work; do not bypass index
  bounds or required-column checks.
