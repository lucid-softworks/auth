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
- the complete Better Auth username lifecycle as an optional native plugin
- sign-out
- anonymous guest sign-in
- the complete `@better-auth/passkey` client surface as an optional native plugin
- passkey MFA enforcement by role and the backup-code methods exposed by Better
  Auth's official `twoFactorClient`
- password changes plus current-user session listing and revocation
- password, fresh-session, and email-confirmed current-user deletion
- passkey rename and removal
- the documented admin-client subset for user lifecycle, session revocation and
  bounded impersonation
- owner-issued, time-bounded guest capability grants and security audit events
- optional HIBP Pwned Passwords screening with Better Auth-compatible errors
- durable account and client-address sign-in throttling through the configured store
- enforced password replacement for administrator-created and reset credentials
- the complete user-owned `@better-auth/api-key` client surface as an optional
  native plugin, including pagination, metadata, permissions, quotas, rate limits,
  configuration profiles, and API-key-backed sessions
- Better Auth-compatible cookies and response shapes for the supported routes
- native, dependency-ordered plugin routes, middleware, hooks, migrations, and
  client compatibility metadata

The library keeps authentication protocol details separate from host-product
authorization. Applications provide their own permission vocabulary while
using the authenticated principal's role, actor, subject, guest grant and
assurance metadata.

Username is an optional native plugin. Register it explicitly to add username
fields to email signup and current-user updates and to mount the official
username sign-in and availability routes:

```rust
config.add_plugin(UsernamePlugin::default())?;
```

This route boundary is separate from `AuthService::provision_password_user`, so
closed-registration applications can still provision and authenticate native
username accounts without exposing Better Auth's public username plugin.

Passkey is also optional. Register it explicitly; without the plugin, its seven
routes do not exist:

```rust
let passkeys = PasskeyConfig {
    rp_id: Some("example.com".into()),
    rp_name: Some("Example".into()),
    origins: Some(vec!["https://app.example.com".into()]),
    ..PasskeyConfig::default()
};
config.add_plugin(PasskeyPlugin::new(passkeys))?;
```

`origins: None` uses the verification request's `Origin`, matching Better Auth;
an explicit vector accepts any configured origin. Registration supports the
official `name`, `context`, `authenticatorAttachment`, authenticator-selection,
extension, fresh-session, `createSession`, and passkey-first `resolveUser`
semantics through native Rust configuration and callbacks. The official client
schema includes `publicKey`, exact `credentialID`, counters, device type, backup
state, transports, and AAGUID. Challenges are durable and single-use, while
signature counters use compare-and-swap persistence.

The existing role-driven assurance, backup-code, sole-owner, guest-grant, and
audit policies are project-specific extensions rather than Better Auth passkey
behavior. Their extraction into optional native plugins is tracked in
[#71](https://github.com/lucid-softworks/auth/issues/71) through
[#75](https://github.com/lucid-softworks/auth/issues/75); the Better Auth
passkey endpoints do not impose those custom deletion or step-up rules.

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

Current-user deletion is disabled by default. Enable it with
`config.user.delete_user.enabled = true`. Better Auth's password and fresh-session
flows then work immediately; configure a native
`DeleteAccountVerificationSender` to require a purpose-bound, single-use email
token instead. `before_delete` and `after_delete` callbacks compose with plugin
user-deletion hooks, and successful deletion clears the session cookie and all
adapter-owned account data. Deletion links and requests accept only the exact
`callbackURL` spelling.

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

API Key is an optional native plugin. Register it explicitly; without the plugin,
its routes and PostgreSQL table do not exist:

```rust
let api_keys = ApiKeyConfiguration {
    enable_metadata: true,
    enable_session_for_api_keys: true,
    ..ApiKeyConfiguration::default()
};
config.add_plugin(ApiKeyPlugin::new(api_keys))?;
```

The official `apiKeyClient` create/get/list/update/delete methods work against
the Better Auth 1.7.1 paths and schemas. The server-only verify and expired-key
cleanup endpoints are also present. Secrets use Better Auth's 64-character
letter-only default generator, optional prefixes, and SHA-256 base64url hashing;
only creation returns the plaintext key. Stored hashes never appear in get,
list, update, or verify responses. Ownership and `configId` are enforced for
management operations, while quota and rate-limit claims are atomic in both the
memory and PostgreSQL stores.

Set `enable_session_for_api_keys` to accept the configured headers (default
`x-api-key`) as Better Auth sessions. Multiple named configurations, custom key
generation, starting-character display, expiry bounds/defaults, metadata,
permissions, refills, and per-key rate limits are supported. Organization-owned
keys depend on the Organization plugin tracked in
[#30](https://github.com/lucid-softworks/auth/issues/30); advanced request
callbacks and secondary/custom-storage profiles are tracked in
[#76](https://github.com/lucid-softworks/auth/issues/76).

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

WebAuthn relying-party and origin configuration lives on `PasskeyConfig`.
Registration and authentication challenges are stored through the configured
backend, expire after five minutes, and are atomically consumed once, including
across service instances.

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

It currently exercises session, the full username lifecycle, anonymous, admin,
all official passkey and user-owned API-key client methods, magic links, and
two-factor backup-code behavior. Passkey registration and authentication use
complete signatures through an in-process virtual authenticator. The fixture
and Node dependencies are excluded from the published crate.

This project is not affiliated with Better Auth.
