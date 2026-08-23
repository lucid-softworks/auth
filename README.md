# lucid-auth

`lucid-auth` is a native Rust authentication backend for applications using
the official Better Auth JavaScript client. It implements a deliberately
tested Better Auth-compatible HTTP and session surface without executing or
embedding a JavaScript authentication server.

The compatibility target is Better Auth `1.7.1`. See the
[compatibility matrix](COMPATIBILITY.md) for method-level coverage, known
limitations, upgrade audit, and links to every tracked gap. The currently
supported surface covers:

- `getSession` and `useSession`
- core email/password signup, signin, and current-password verification
- durable email verification with a native async delivery callback
- enumeration-resistant password-reset email and single-use reset redemption
- username/password sign-in
- sign-out
- anonymous guest sign-in
- the current `@better-auth/passkey` enrollment, listing and sign-in route subset
- passkey MFA enforcement by role and the backup-code methods exposed by Better
  Auth's official `twoFactorClient`
- password changes plus current-user session listing and revocation
- passkey rename and removal
- the documented admin-client subset for user lifecycle, session revocation and
  bounded impersonation
- owner-issued, time-bounded guest capability grants and security audit events
- optional HIBP Pwned Passwords screening with Better Auth-compatible errors
- durable account and client-address sign-in throttling through the configured store
- enforced password replacement for administrator-created and reset credentials
- native user-owned API keys with ownership, expiry, permissions, prefixes, rate
  limits, and one-time secret display; official API-key client routes are planned
- Better Auth-compatible cookies and response shapes for the supported routes
- native, dependency-ordered plugin routes, middleware, hooks, migrations, and
  client compatibility metadata

The library keeps authentication protocol details separate from host-product
authorization. Applications provide their own permission vocabulary while
using the authenticated principal's role, actor, subject, guest grant and
assurance metadata.

Passkey enrollment requires an existing session. Roles listed in
`AuthConfig::required_mfa_roles` must enroll a passkey during their next
password sign-in. Once enrolled, password verification produces
`password_pending_passkey` assurance until either the passkey ceremony upgrades
it to `password_and_passkey` or a one-time recovery code upgrades it to
`recovery`. Existing password-only sessions are invalidated when their role is
configured to require MFA. Security-sensitive owner operations additionally
require strong authentication no older than `AuthConfig::step_up_ttl`. Recovery
codes are only shown when generated, stored as keyed hashes, replaced as a set,
and consumed atomically. Adding another passkey or removing one requires recent
strong authentication. Required-MFA accounts cannot remove their final passkey,
and deleting the final optional passkey also clears now-unusable recovery codes.
These lifecycle checks are atomic in both stores. An administrative password reset clears sessions,
passkeys, and recovery codes so the account can enroll again.

The session response includes `stepUpRequired` so an official Better Auth client
can prompt for passkey authentication before submitting sensitive changes.

Core email/password authentication is disabled by default, matching Better
Auth. Enable it with `config.email_and_password.enabled = true`; the same
configuration exposes signup enablement, auto-sign-in, verification-required
mode, and password length bounds. Email identities are stored lowercase and
enforced case-insensitively by both adapters. Wire input accepts Better Auth's
exact `callbackURL` spelling only.

Email delivery is supplied in-process by implementing
`VerificationEmailSender` and assigning it to
`config.email_verification.sender`. The callback receives a typed
`VerificationEmail` containing the user, verification URL, and one-time token.
Configure `AuthConfig::set_base_url` as well so delivered links use the public
authentication origin and base path.
`send_on_sign_up`, `send_on_sign_in`, `auto_sign_in_after_verification`, and
`expires_in` mirror Better Auth's verification lifecycle. Only a SHA-256 token
identifier is persisted; verification consumes it and updates `emailVerified`
atomically, so replay and concurrent redemption fail.

Password reset delivery is supplied by implementing `PasswordResetEmailSender`
and assigning it to `config.email_and_password.send_reset_password`. The sender
receives the user, reset URL, and one-time token. The default expiry is one hour;
`reset_password_token_expires_in`, `revoke_sessions_on_password_reset`, and the
native async `on_password_reset` callback mirror Better Auth's lifecycle options.
Reset requests accept Better Auth's exact `redirectTo` field, while the emailed
callback endpoint accepts exact `callbackURL`; incorrectly cased aliases are not
supported. Only a SHA-256 token identifier is stored, and password replacement,
single-use token consumption, and optional session revocation are atomic.

Magic Link is an optional native plugin. Implement `MagicLinkSender`, construct
`MagicLinkConfig`, and register `MagicLinkPlugin` with `AuthConfig::add_plugin`.
Its two routes work with Better Auth 1.7.1's official `magicLinkClient`:

```rust
let mut magic_link = MagicLinkConfig::new(Arc::new(MyMagicLinkSender));
magic_link.token_storage = MagicLinkTokenStorage::Hashed;
config.add_plugin(MagicLinkPlugin::new(magic_link))?;
```

The default five-minute link is purpose-bound, atomically single-use, and uses
Better Auth's plain-token storage default; select `Hashed` or provide a native
custom hasher when persisted token secrecy is required. Delivery receives the
email, verification URL, token, metadata, and a narrowed request context.
`callbackURL`, `newUserCallbackURL`, and `errorCallbackURL` use Better Auth's
exact casing, and all redirects pass the configured trusted-origin policy.

API-key secrets contain 384 random bits and are never stored. The database keeps
only a salted Argon2id verifier plus a random public key identifier used for a
single-row lookup. Issuance and revocation require a real, non-impersonated
account session and recent strong authentication when the account's role is
configured for MFA. Verification checks the owning account, expiry,
configuration ID, permissions, revocation state, and an atomic per-key rate
limit. Hosts decide which permission resources and actions are meaningful.

Native plugins implement `AuthPlugin` and are registered with
`AuthConfig::add_plugin`. Construct plugin-enabled services with
`AuthService::try_new` so invalid IDs, missing or cyclic dependencies,
conflicts, duplicate/core route ownership, cookie collisions, migration IDs,
rate limits, middleware declarations, and mismatched Better Auth client
versions fail before the router starts. Plugin routes remain inside the normal
origin/CORS security boundary, while plugin middleware is scoped to the routes
that plugin owns. Session lifecycle hooks run in validated dependency order.

PostgreSQL hosts apply core migrations and then the service's validated plugin
contributions:

```rust
store.migrate().await?;
store.migrate_plugins(&service.plugin_migrations()).await?;
```

Plugin migrations are keyed by `(plugin_id, migration_id)`, share the core
advisory migration lock, and are transactional and idempotent. See the
[native plugin example](examples/native_plugin.rs) for a route, middleware,
migration, cookie/rate-limit declarations, and official-client metadata.

Accounts created by an owner and passwords reset by an owner are marked
`must_change_password`. The Better Auth-compatible user response exposes that
state as `mustChangePassword`; hosts must allow the official change-password
route while denying application and administrative access until the account
chooses a replacement. Configured bootstrap users may opt into the same state,
which is reapplied only while the configured password hash remains active.

`AuthService::local_recover_sole_owner` is an explicitly out-of-band operator
primitive for a host CLI. It atomically refuses multi-owner installations,
replaces the sole owner's password, clears bans, sessions, passkeys, and recovery
codes, marks the password temporary, and appends an actorless audit event. It is
not routed by the crate's Axum compatibility surface.

WebAuthn relying-party configuration is explicit and must use HTTPS except for
the browser's `localhost` development exception. Registration and authentication
challenges are stored through the configured backend, expire after five minutes,
and are atomically consumed once, including across service instances.

Cookie-authenticated browser mutations require a trusted `Origin` or `Referer`
and reject cross-site navigation login attempts. Same-origin requests are
matched against the request host. Add an explicit cross-origin frontend with
`AuthConfig::trust_origin`. It follows Better Auth's pattern rules: exact
HTTP(S) origins, host or full-origin `*`/`?` globs such as
`https://*.example.com` and `http://localhost:*`, and path-pinned custom schemes
are supported. The exact Better Auth redirect fields (`callbackURL`,
`redirectTo`, `errorCallbackURL`, and `newUserCallbackURL`) must contain an
accepted relative path or use a trusted origin.

Client IPs come from Axum's transport `ConnectInfo`, never from an unverified
forwarding header. Serve the router with
`into_make_service_with_connect_info::<std::net::SocketAddr>()`. Deployments
behind a reverse proxy must add its exact address or CIDR with
`config.ip_address.trust_proxy(...)`; forwarding headers are then walked from
the trusted edge to the first untrusted hop. `ip_address_headers`,
`ipv6_subnet`, and `disable_ip_tracking` correspond to Better Auth's advanced
IP-address options.

Routes mount at `/api/auth` by default. `AuthConfig::set_base_url` and
`set_base_path` configure HTTPS production origins and custom mounts; an HTTPS
base URL also selects Better Auth's `__Secure-` cookie names. `CookieConfig`
supports the Better Auth prefix, per-cookie names and attributes, and optional
cross-subdomain scope. Call `AuthConfig::enable_cors` to answer credentialed
preflights for trusted origins; untrusted origins remain blocked by the same
CSRF policy.

## Conformance tests

The black-box suite installs the exact official Better Auth client versions in
`conformance/package-lock.json` and runs them against an ephemeral native Rust
server:

```sh
npm ci --prefix conformance --ignore-scripts
npm test --prefix conformance
```

It currently exercises session, username, anonymous, admin, passkey ceremony
startup/listing, and two-factor backup-code client behavior. The fixture and
Node dependencies are excluded from the published crate.

This project is not affiliated with Better Auth.
