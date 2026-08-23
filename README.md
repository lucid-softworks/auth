# lucid-auth

`lucid-auth` is a native Rust authentication backend for applications using
the official Better Auth JavaScript client. It implements a deliberately
tested Better Auth-compatible HTTP and session surface without executing or
embedding a JavaScript authentication server.

The initial compatibility target is Better Auth `1.6.29`. See the
[compatibility matrix](COMPATIBILITY.md) for method-level coverage, known
limitations, the Better Auth `1.7.1` upgrade plan, and links to every tracked
gap. The currently supported surface covers:

- `getSession` and `useSession`
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

API-key secrets contain 384 random bits and are never stored. The database keeps
only a salted Argon2id verifier plus a random public key identifier used for a
single-row lookup. Issuance and revocation require a real, non-impersonated
account session and recent strong authentication when the account's role is
configured for MFA. Verification checks the owning account, expiry,
configuration ID, permissions, revocation state, and an atomic per-key rate
limit. Hosts decide which permission resources and actions are meaningful.

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
the browser's `localhost` development exception.

Cookie-authenticated browser mutations require a trusted `Origin` or `Referer`
and reject cross-site navigation login attempts. Same-origin requests are
matched against the request host. Add an explicit cross-origin frontend with
`AuthConfig::trust_origin`. It follows Better Auth's pattern rules: exact
HTTP(S) origins, host or full-origin `*`/`?` globs such as
`https://*.example.com` and `http://localhost:*`, and path-pinned custom schemes
are supported. The exact Better Auth redirect fields (`callbackURL`,
`redirectTo`, `errorCallbackURL`, and `newUserCallbackURL`) must contain an
accepted relative path or use a trusted origin.

This project is not affiliated with Better Auth.
