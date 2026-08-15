# lucid-auth

`lucid-auth` is a native Rust authentication library with a deliberately
tested compatibility surface for the official Better Auth JavaScript client.
It does not execute or embed a JavaScript authentication server.

The initial compatibility target is Better Auth `1.6.29` and covers:

- `getSession` and `useSession`
- username/password sign-in
- sign-out
- anonymous guest sign-in
- passkey enrollment, listing and sign-in through `@better-auth/passkey`
- passkey MFA enforcement by role and one-time recovery codes through Better Auth's
  official `twoFactorClient`
- password changes plus current-user session listing and revocation
- passkey rename and removal
- admin user listing, creation, role assignment, disabling, password reset and removal
- admin session revocation and bounded impersonation
- owner-issued, time-bounded guest capability grants and security audit events
- optional HIBP Pwned Passwords screening with Better Auth-compatible errors
- durable account and client-address sign-in throttling through the configured store
- Better Auth session cookies and response shapes

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

WebAuthn relying-party configuration is explicit and must use HTTPS except for
the browser's `localhost` development exception.

This project is not affiliated with Better Auth.
