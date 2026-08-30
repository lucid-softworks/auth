# Production deployment checklist

Use this checklist after the [installation guide](installation.md). The runnable
SQLite and PostgreSQL examples demonstrate the correct startup order, but production hosts
must supply their own process supervision, TLS edge, observability, and secret
management.

## Public URL and routes

- Set `AuthConfig::set_base_url` to the stable public HTTPS URL. Do not use an
  internal container hostname or infer it from untrusted forwarding headers.
- Keep the default `/api/auth` path unless every client is configured with the
  complete custom path.
- Route both `GET` and `POST` for the entire auth path. OAuth providers must use
  the callback URL derived from the same public base URL.
- Construct with `AuthService::try_new` so invalid plugin graphs, conflicting
  routes/cookies, and incompatible metadata fail before serving traffic.

## Secret handling

- Generate at least 32 high-entropy bytes. Store the value in a secret manager,
  not source control or an image layer.
- Use the same secret on every instance and keep it stable across restarts.
- lucid-auth currently accepts one active secret. Plan rotation as a coordinated
  session/cookie invalidation until multi-secret rollover is implemented.
- Keep OAuth client secrets, email-provider credentials, and database URLs
  under the same operational controls.

## TLS and cookies

An HTTPS base URL selects Better Auth's `__Secure-` cookie names and Secure
attributes by default. Terminating TLS at a trusted reverse proxy is fine as
long as the configured public URL remains HTTPS. Do not force insecure cookies
in production.

Same-origin routing is the safest default. For sibling subdomains, explicitly
enable the intended cookie domain:

```rust
config
    .cookies
    .set_cross_subdomain(true, Some(".example.com".into()));
```

For genuinely cross-site frontends, browsers require `SameSite=None` and
`Secure`; set that only with an explicit trusted origin:

```rust
use lucid_auth::SameSite;

config.trust_origin("https://app.example.net")?;
config.enable_cors();
config.cookies.default_attributes.same_site = Some(SameSite::None);
config.cookies.default_attributes.secure = Some(true);
```

Cookies remain HttpOnly by default. Do not make session cookies readable by
JavaScript to work around a deployment-origin mistake.

## Reverse proxies and client IPs

Serve Axum with transport connection information:

```rust
axum::serve(
    listener,
    app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
)
.await?;
```

Then trust only the exact proxy address or network that connects to Axum:

```rust
config.ip_address.trust_proxy("10.42.0.0/16")?;
```

lucid-auth walks forwarding chains from the trusted edge to the first untrusted
hop. Without a trusted proxy list it accepts only a single configured header
value. Never trust a broad Internet-facing CIDR merely to make rate-limit logs
look correct. Configure `ip_address_headers` only for headers your edge
overwrites, not ones it appends from arbitrary clients.

Keep `config.trusted_proxy_headers` false unless the authentication service must
derive its public URL from `x-forwarded-host` and `x-forwarded-proto` and the
trusted edge overwrites both headers. Prefer a fixed `set_base_url` in
production; proxy-header URL derivation is a separate opt-in from client-IP
proxy trust.

## Origins, CORS, and redirects

- Add each browser application origin with `trust_origin`; prefer exact
  production origins over wildcards.
- Call `enable_cors` only when the frontend origin differs from the auth origin.
- Preserve browser `Origin` and `Referer` headers through the proxy. Do not
  synthesize trusted values at the edge.
- Keep callback inputs in Better Auth's exact casing: `callbackURL`,
  `redirectTo`, `errorCallbackURL`, and `newUserCallbackURL`.
- Pin custom-scheme origins to the intended authority/path where possible.

## Database storage and migrations

- Use D1 for Cloudflare, SQLite for a local single-host database, or PostgreSQL for conventional
  multi-instance deployments. `MemoryStore` is
  process-local and loses users, sessions, challenges, and rate limits on exit.
- For SQLite, construct `SqliteStore` with the same resolved service schema and
  run its additive migration plan before accepting traffic. It intentionally
  has no release ledger, all-plan transaction, retry, WAL, busy-timeout,
  synchronous, shared-cache, checkpoint, vacuum, or foreign-key policy.
  Configure those choices on the supplied SQLx pool and test the resulting file
  locking and backup behavior on the actual host filesystem.
- A plain SQLite `:memory:` URL belongs to one connection. Limit that pool to
  one connection unless the application explicitly selects a shared-memory
  configuration. Enable `foreign_keys` in caller connection options when the
  generated `REFERENCES` clauses must be enforced; the store never toggles it.
- SQLite schema evolution only adds the objects supported by the pinned Better
  Auth 1.7.1 Kysely migration behavior. Treat unsafe required-column additions,
  type/nullable warnings, and index conflicts as manual deployment work. It
  never drops, renames, rewrites, or backfills existing objects.
- Apply `store.migrate_all(&service.plugin_migrations())` and require its schema
  report to be compatible before PostgreSQL traffic reaches a new version. Use the
  read-only `diagnose_schema` API for readiness checks and drift inspection.
- Back up and test restore procedures before upgrades. Bound-schema evolution
  and Lucid extension operations are idempotent, transactional, and serialized
  with an advisory lock, but they are not a substitute for database backups.
- Select `AuthConfig::database_id_generation` before the first migration and
  keep it identical on every instance. Older lucid-auth UUID schemas require
  the [breaking database ID migration](database-id-migration.md); the migrator
  reports incompatible ID/reference types but does not rewrite their data.
- Configure enough SQL connections for authentication and plugin workloads;
  bound the pool rather than allowing unbounded connections per instance.
- Use database rate-limit storage when more than one service instance accepts
  requests. The memory limiter is not shared across instances.
- A configured `SecondaryStorage` becomes authoritative for sessions and the
  default rate limiter, and for verification values unless
  `verification.store_in_database` enables a database mirror. Verification
  entries use remaining-expiry TTLs and require atomic `getAndDelete` for
  single-use consumption. Secondary-only deployments reject verification
  reservation flows that require database uniqueness.
- Choose `verification.store_identifier.default` and its ordered prefix
  `overrides` deliberately. `Plain` is the Better Auth default; `Hashed` uses
  SHA-256 base64url without padding, and `Custom` delegates to a native async
  hasher. Switching modes invalidates outstanding short-lived values except for
  Better Auth's hashed-to-plain lookup fallback.
- Enable `store_session_in_database` only when a session DB mirror is required;
  enable `preserve_session_in_database` when ended rows must remain as expired
  audit records.
- Database and secondary sessions slide after `session.update_age` (one day by
  default). Use `disable_session_refresh` for fully fixed expiry, or
  `defer_session_refresh` when GET session reads must remain write-free; the
  official client follows `needsRefresh` with POST `/get-session`.
- `rememberMe: false` creates Better Auth's signed `dont_remember` marker and a
  non-persistent, non-sliding one-day session. Preserve that cookie through
  reverse proxies just like the primary session cookie.
- Pure `SessionStorageMode::Stateless` deployments cannot centrally revoke one
  issued cache. Keep `cookie_cache.max_age` short and rotate
  `cookie_cache.version` for deterministic fleet-wide invalidation.
- Treat incompatible pre-schema-bound session layouts as an application-managed
  data migration; lucid-auth does not retain compatibility columns or fallback
  readers for shapes Better Auth does not support.

## Runtime defaults to review

- Email/password and user deletion are disabled until explicitly enabled.
- Production release builds enable Better Auth's default request rate limit;
  debug builds leave it disabled unless configured.
- Email verification and password reset require native delivery callbacks.
- CORS is disabled until explicitly enabled.
- Session cookies are seven days by default, database `update_age` and session
  freshness are each one day by default.
- Only register server plugins that the application uses, apply their
  migrations, and install their matching Better Auth client plugins.

Before an upgrade, re-check the [compatibility matrix](../COMPATIBILITY.md), run
the official-client conformance suite, and review any Planned or Partial row
used by the application.
