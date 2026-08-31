# Install lucid-auth

This guide starts a native Rust server that the official Better Auth `1.7.1`
client can use at its default `/api/auth` path. Check the
[compatibility matrix](../COMPATIBILITY.md) before enabling a Better Auth
plugin: the client plugin and the native server plugin must both be supported.

## Versions and features

| Component | Supported version |
| --- | --- |
| lucid-auth | `0.1.x` source release line |
| Better Auth clients | exactly `1.7.1` |
| Rust | `1.90` or newer |
| Axum | `0.8` |
| PostgreSQL | `16` in CI |
| MySQL fixture | `mysql:8.4` in CI |
| MySQL adapter | Better Auth / `@better-auth/kysely-adapter` `1.7.1` |
| SQLite adapter | Better Auth / `@better-auth/kysely-adapter` `1.7.1` |
| Cloudflare D1 adapter | Better Auth / `@better-auth/kysely-adapter` `1.7.1` |

The crate is not currently published to crates.io. Pin a reviewed Git commit;
do not use a moving branch in production:

```toml
[dependencies]
axum = "0.8"
lucid-auth = { git = "https://github.com/lucid-softworks/auth", rev = "d4d0e9961dff60b9d490e020eb6e7dfd2f9034f6", features = ["axum"] }
tokio = { version = "1", features = ["macros", "net", "rt-multi-thread"] }
```

Enable `sqlite`, `mysql`, or `postgres` for a bundled SQLx store. The feature
surface is intentionally small:

| Cargo feature | Default | Adds |
| --- | --- | --- |
| `axum` | yes | Better Auth HTTP router, cookies, browser security, CORS |
| `sqlite` | no | Native local `SqliteStore` and additive schema migration |
| `d1` | no | Native non-transactional `D1Store` and Workers D1 binding |
| `mysql` | no | Native SQLx `MySqlStore` and additive schema migration |
| `postgres` | no | `PostgresStore`, bound-schema migration, Lucid extension operations |

`--no-default-features` is useful only for native in-process service calls; it
does not expose an HTTP server for the official JavaScript client.

## Required configuration

Generate a high-entropy secret of at least 32 bytes and keep it stable across
deployments:

```sh
export BETTER_AUTH_SECRET="$(openssl rand -base64 32)"
export BETTER_AUTH_URL="http://localhost:3000"
export FRONTEND_ORIGIN="http://localhost:5173"
```

`BETTER_AUTH_URL` in these examples is read by the host application and passed
to `AuthConfig::set_base_url`; lucid-auth does not implicitly read Better Auth
environment variables. Set it to the public auth origin, not an internal
container address. A path in the URL changes the route mount; otherwise the
default remains `/api/auth`.

Email/password authentication is disabled by default, as it is in Better Auth.
Both runnable examples enable it explicitly.

## Memory quickstart

From a lucid-auth checkout:

```sh
cargo run --example http_memory --features axum
```

The [memory HTTP example](../examples/http_memory.rs) binds only to
`127.0.0.1:3000`. It is suitable for local development and tests, not multiple
processes or durable accounts.

Create an account through the Better Auth route:

```sh
curl --fail-with-body \
  -H 'content-type: application/json' \
  -H 'origin: http://localhost:5173' \
  -c cookies.txt \
  -d '{"email":"person@example.com","password":"correct-horse-battery-staple","name":"Example Person"}' \
  http://localhost:3000/api/auth/sign-up/email
```

Then read the cookie-bound session:

```sh
curl --fail-with-body -b cookies.txt \
  http://localhost:3000/api/auth/get-session
```

## SQLite quickstart

SQLite is a native in-process backend; it does not run Node, Bun,
`better-sqlite3`, or a helper process. The JavaScript driver families are
conformance references for `@better-auth/kysely-adapter@1.7.1`, not Rust APIs.

```sh
export DATABASE_URL="sqlite://lucid-auth.db"
cargo run --example http_sqlite --features axum,sqlite
```

The [SQLite HTTP example](../examples/http_sqlite.rs) creates the file if it is
missing, binds the store to `AuthService::database_schema()`, and executes the
derived additive plan before serving. You may instead supply an existing
`sqlx::SqlitePool`, call `SqliteStore::connect`, or call
`SqliteStore::connect_with` with your own pool and connection options.

For a process-local ephemeral database, use `DATABASE_URL=sqlite::memory:`.
That ordinary URL names a separate database per connection, so the example
limits it to one connection. A file database supports a normal multi-connection
pool; an explicitly selected shared-memory URI is also the caller's choice.

The store intentionally does not change `foreign_keys`, `journal_mode`,
`synchronous`, `busy_timeout`, shared-cache, retry, checkpoint, or vacuum
policy. Configure those through SQLx for the deployment. Foreign-key DDL is
generated exactly, but SQLite enforces it only when the supplied connection
configuration enables enforcement. Migrations inspect ordinary tables only;
this matches the pinned Node and Bun dialects, while the pinned standard Kysely
SQLite introspector also reports views.

Migration planning is additive: it creates missing tables, columns, and the
indexes supported by the pinned adapter, reports drift/conflicts, and never
renames, drops, rewrites, or backfills existing objects. It uses no migration
ledger. Review `unsafe_changes` from compile mode before manually resolving a
required-column addition on a populated table.

## Cloudflare D1 quickstart

D1 is a separate backend, not a `SqliteStore` mode. Enable only `d1` for the
adapter; it does not enable SQLx or a local SQLite driver:

```toml
[dependencies]
lucid-auth = { git = "https://github.com/lucid-softworks/auth", rev = "REVIEWED_COMMIT", default-features = false, features = ["d1"] }
worker = { version = "0.8.5", features = ["d1"] }
```

Declare the binding in `wrangler.toml`:

```toml
[[d1_databases]]
binding = "AUTH_DB"
database_name = "auth-production"
database_id = "YOUR_DATABASE_ID"
```

Construct the adapter directly from the environment binding:

```rust,no_run
use lucid_auth::{AuthSchemaCatalog, d1::{D1AdapterConfig, D1Store, WorkersD1Database}};
use std::sync::Arc;
use worker::{Env, Result};

async fn d1_store(env: &Env, schema: Arc<AuthSchemaCatalog>) -> Result<D1Store> {
    let binding = env.d1("AUTH_DB")?;
    let store = D1Store::new(
        Arc::new(WorkersD1Database::new(binding)),
        D1AdapterConfig::default(),
    );
    store.bind_schema(schema)
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    Ok(store)
}
```

The schema argument is the complete ordered Better Auth catalog for the core and
enabled plugin models in that deployment. A native `AuthService` integration
passes `service.database_schema()`; a Workers-only integration constructs the
same catalog with `AuthSchemaCatalog::new`. No built-in or legacy model aliases
are added. Bind one catalog before adapter calls and run `migrate` with it during
deployment.
`migration_plan` introspects tables and views while excluding `sqlite_%`,
`_cf_%`, and Kysely migration tables. It batches only the finite
`pragma_table_info` set, then executes approved migration statements one at a
time. D1 has no interactive transaction or streaming API; those attempts fail
explicitly. `consume_record` and `increment_record` remain one bound statement.

Do not log D1 credentials, tokens, cookies, or bound values. SCIM is not
supported on D1; its separate work is tracked in
[#32](https://github.com/lucid-softworks/auth/issues/32).

## MySQL quickstart

The native MySQL backend targets Better Auth and
`@better-auth/kysely-adapter` `1.7.1`. The project tests `mysql:8.4`; that image
is a reproducible CI fixture, not a claimed MySQL or MariaDB support range.

```sh
docker run --rm --name lucid-auth-mysql \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=lucid_auth \
  -e MYSQL_USER=user \
  -e MYSQL_PASSWORD=password \
  -p 3306:3306 mysql:8.4

export DATABASE_URL="mysql://user:password@127.0.0.1:3306/lucid_auth"
cargo run --example http_mysql --features axum,mysql
```

The [MySQL HTTP example](../examples/http_mysql.rs) verifies the SQLx session
timezone, binds the exact service schema, and executes the additive migration
plan before serving. SQLx negotiates MySQL's matched-row `FOUND_ROWS`
capability and initializes its own connections at `+00:00`. A caller-supplied
pool must preserve both invariants; call `MySqlStore::ready` during startup.
The store fails readiness when `@@session.time_zone` is not `+00:00`.

Migrations inspect ordinary tables, columns, and table-scoped indexes in
`information_schema`, execute approved statements sequentially, and keep no
release ledger. Compile mode records unsafe required-column changes without
executing them. Runtime one-time claims and increments use `FOR UPDATE` on the
exact selected row. Values remain bound, configured identifiers are quoted,
and the production implementation does not run mysql2, Kysely, Node, or a
helper process.

## PostgreSQL quickstart

Start an ephemeral local PostgreSQL 16 instance:

```sh
docker run --rm --name lucid-auth-postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=lucid_auth \
  -p 5432:5432 postgres:16-alpine
```

In another shell, export the common variables plus the database URL and run the
compiled example:

```sh
export BETTER_AUTH_SECRET="$(openssl rand -base64 32)"
export BETTER_AUTH_URL="http://localhost:3000"
export FRONTEND_ORIGIN="http://localhost:5173"
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/lucid_auth"
cargo run --example http_postgres --features axum,postgres
```

The [PostgreSQL HTTP example](../examples/http_postgres.rs) creates the pool,
constructs the validated service, binds its exact resolved schema to the store,
applies that schema plus enabled Lucid extension operations, and then binds the
router. Apply and validate the complete plan during every deployment before new
application instances serve traffic:

```rust
let report = store.migrate_all(&service.plugin_migrations()).await?;
assert!(report.compatible);
```

Schema evolution and extension operations use the same PostgreSQL advisory lock
and are transactional and idempotent. `migration_plan` provides read-only discovery and `diagnose_schema`
checks the deployed catalog without executing a subprocess or including the
database URL in its serializable report. Do not run Better Auth's TypeScript CLI
against this schema.

## Install the official client

Pin the client compatibility target exactly:

```sh
npm install --save-exact better-auth@1.7.1
```

For a separate frontend origin, keep `config.trust_origin(...)` and
`config.enable_cors()` in the Rust service and set the public server origin on
the client:

```ts
import { createAuthClient } from "better-auth/client";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
});
```

For a same-origin deployment, omit `baseURL` and reverse-proxy `/api/auth/*` to
the Rust service. See the [framework client guide](frameworks.md) for React,
Vue, Svelte, Solid, SSR, browser extension, Expo, and Electron details, and the
[production checklist](production.md) before deploying.

## What is native and what is not

The official browser client talks to lucid-auth over HTTP. TypeScript examples
that construct `betterAuth(...)`, call `auth.api`, register JavaScript server
callbacks/plugins, mount `auth.handler`, or run the Better Auth CLI do not run
inside this Rust server. Use the corresponding Rust configuration, traits,
plugins, service methods, router, and migrations documented by this repository.

The examples are compiled by `cargo test --all-targets --all-features` in CI.
The repository conformance suite installs the exact Better Auth client lockfile
and exercises it against an ephemeral native server.
