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

The crate is not currently published to crates.io. Pin a reviewed Git commit;
do not use a moving branch in production:

```toml
[dependencies]
axum = "0.8"
lucid-auth = { git = "https://github.com/lucid-softworks/auth", rev = "d4d0e9961dff60b9d490e020eb6e7dfd2f9034f6", features = ["axum"] }
tokio = { version = "1", features = ["macros", "net", "rt-multi-thread"] }
```

Enable `postgres` as well for the bundled SQLx/PostgreSQL store. The feature
surface is intentionally small:

| Cargo feature | Default | Adds |
| --- | --- | --- |
| `axum` | yes | Better Auth HTTP router, cookies, browser security, CORS |
| `postgres` | no | `PostgresStore`, core migrations, plugin migrations |

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
constructs the validated service, applies core migrations, applies enabled
plugin migrations, and then binds the router. Apply and validate the complete
plan during every deployment before new application instances serve traffic:

```rust
let report = store.migrate_all(&service.plugin_migrations()).await?;
assert!(report.compatible);
```

Both operations use the same PostgreSQL advisory lock and are transactional and
idempotent. `migration_plan` provides read-only discovery and `diagnose_schema`
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
