# Migrating database ID strategies

This is a breaking migration for applications created before lucid-auth matched
Better Auth 1.7.2's `advanced.database.generateId` contract. The old lucid
default generated UUIDs and exposed UUID-specific configuration and Rust types.
The Better Auth default generates 32-character `a-zA-Z0-9` strings instead.

Back up the database and rehearse this migration against a restore. Do not run
`PostgresStore::migrate` against an old UUID schema and expect it to rewrite
keys: the migrator reports incompatible physical types but deliberately does
not transform application data.

## Choose the target before changing schema

To retain UUID IDs, explicitly select the Better Auth UUID strategy before
constructing `AuthService` or running any migration:

```rust
use lucid_auth::DatabaseIdGeneration;

config.database_id_generation = DatabaseIdGeneration::Uuid;
```

This keeps PostgreSQL primary IDs and their references as `UUID`, with
`pg_catalog.gen_random_uuid()` defaults. It is the only no-data-conversion path
for an existing UUID schema.

To adopt Better Auth's default, select `DatabaseIdGeneration::Default` (or
leave the field at its default), then convert every bound ID and reference
column from `UUID` to `TEXT`. The exact table set depends on installed plugins,
model remapping, and disabled migrations. Generate or inspect the service's
resolved schema rather than using a fixed table list.

For each foreign-key graph, the operational sequence is:

1. Stop writes and take a verified backup.
2. Drop the affected foreign-key constraints.
3. Convert referenced primary IDs and referencing columns with
   `ALTER COLUMN ... TYPE TEXT USING ...::text`.
4. Remove UUID-only defaults from converted primary IDs.
5. Recreate the foreign keys and indexes against the converted columns.
6. Start the service with `DatabaseIdGeneration::Default`, run schema
   diagnosis/migration, and verify user, account, session, Organization, and
   every installed plugin round trip before restoring traffic.

A single unremapped table pair illustrates the type conversion only; it is not
a complete migration script:

```sql
ALTER TABLE "session" DROP CONSTRAINT "session_userId_fkey";
ALTER TABLE "user" ALTER COLUMN "id" DROP DEFAULT;
ALTER TABLE "user" ALTER COLUMN "id" TYPE TEXT USING "id"::text;
ALTER TABLE "session" ALTER COLUMN "userId" TYPE TEXT USING "userId"::text;
ALTER TABLE "session"
  ADD CONSTRAINT "session_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE;
```

Existing UUID text values remain valid opaque IDs after conversion. New rows
use Better Auth's 32-character default. Applications must never infer an ID's
format or parse new IDs as UUIDs.

## Other target strategies

- `DatabaseIdGeneration::Serial` requires converting every primary ID and
  reference to an integer identity graph. This needs an application-specific
  mapping from every old UUID to a new integer and is not a cast-in-place
  migration. Update all references transactionally.
- `DatabaseIdGeneration::Database` keeps `TEXT` columns but omits IDs on
  inserts. Install a database default for every generated core and plugin model
  before enabling it. It is unsupported with memory storage because no database
  can return the omitted ID.
- `DatabaseIdGeneration::Callback` keeps `TEXT` columns. Ensure the callback is
  globally unique for every logical model and returns `Defer` only where the
  database has a valid default.

## Rust API changes

Replace the removed `AuthIdGenerator` and `AuthConfig::id_generator` with
`DatabaseIdGenerator` and `AuthConfig::database_id_generation`. Replace UUID
fields in authentication record consumers with opaque `String` values. Test
Utils user and Organization overrides, helper arguments, store traits, plugin
references, filters, and joins all use those public strings.

There are no compatibility aliases or implicit UUID fallback. Code that still
requires UUID semantics must choose `DatabaseIdGeneration::Uuid` explicitly;
code that accepts the Better Auth default must stop parsing IDs as UUIDs.

This migration affects database IDs and their references only. It does not
change session tokens, reset/verification values, OAuth values, OTPs, passkey
credential IDs, API-key secrets, or device bearer values. Their exact lifecycle
formats are tracked separately by
[#98](https://github.com/lucid-softworks/auth/issues/98).
