# Better Auth compatibility

`lucid-auth` is a native Rust authentication server that targets the wire
contracts used by the official Better Auth JavaScript browser clients. It does
not execute the Better Auth TypeScript server, so TypeScript-only APIs such as
`auth.api`, arbitrary npm plugins, JavaScript hooks, and Better Auth CLI commands
are not automatically available.

This matrix describes released repository behavior. A matching route name alone
does not count as support: request and response bodies, cookies, errors, security
semantics, persistence, and an end-to-end client test must all agree.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| Supported | Implemented and covered by a Rust HTTP contract test. |
| Partial | Useful behavior exists, but documented Better Auth behavior or wire fields are missing. |
| Native only | A Rust service API exists, but the official JavaScript client cannot call it. |
| Planned | Tracked, but not implemented. |
| Not applicable | The feature belongs to the TypeScript server/runtime and needs a native equivalent rather than wire emulation. |

## Version and verification

| Capability | Status | Notes |
| --- | --- | --- |
| Better Auth 1.7.1 wire baseline | Partial | This is the sole declared target. Partial plugin rows below qualify the claim; [#3](https://github.com/lucid-softworks/auth/issues/3). |
| Official JavaScript client conformance | Supported | CI drives the pinned `1.7.1` vanilla email/password, email-verification, and password-reset clients plus username, anonymous, admin, every passkey and API-key client method, two-factor, and a native test-client plugin against an ephemeral server. Passkey registration/authentication use real signatures from an in-process virtual authenticator; [#2](https://github.com/lucid-softworks/auth/issues/2). |
| Native plugin extension API | Supported | Typed routes, middleware, lifecycle hooks, ordered PostgreSQL migrations, cookies/rate-limit declarations, dependency/conflict checks, and exact-version client metadata; [#4](https://github.com/lucid-softworks/auth/issues/4). |
| Community plugin SDK | Planned | Native plugin packaging and certification policy: [#67](https://github.com/lucid-softworks/auth/issues/67). |

### Better Auth 1.7.1 upgrade audit

| Upstream change area | Native compatibility impact |
| --- | --- |
| Sessions | Supported session, sign-out, and cookie paths pass the 1.7.1 client. Client-side `hydrateSession` needs no server endpoint. Fresh session-list semantics remain explicitly partial in [#58](https://github.com/lucid-softworks/auth/issues/58). |
| OAuth identity and schema | Supported issuer-qualified `(issuer, accountId)` identity, atomic user/account creation, implicit-link verification policy, and encrypted provider-token storage. Migration `0015` removes the obsolete provider-qualified uniqueness model rather than retaining a fallback; social sign-in is [#14](https://github.com/lucid-softworks/auth/issues/14), while explicit account/token management remains [#15](https://github.com/lucid-softworks/auth/issues/15). |
| Two-factor responses | Supported through optional `TwoFactorPlugin`: the official 1.7.1 discriminated enable response, all eight browser-client endpoints, server-only TOTP generation and backup-code viewing, challenge/trust cookies, and encrypted factor storage are covered by [#20](https://github.com/lucid-softworks/auth/issues/20). |
| Passwordless cleanup | Magic Link implements the 1.7 mailbox-proven account/session cleanup and atomic token lifecycle. Email OTP and phone OTP remain [#23](https://github.com/lucid-softworks/auth/issues/23) and [#24](https://github.com/lucid-softworks/auth/issues/24). |
| Custom and secondary storage | The native memory/PostgreSQL contracts are unaffected by TypeScript adapter internals. Secondary storage and stateless sessions remain [#58](https://github.com/lucid-softworks/auth/issues/58); hooks remain [#60](https://github.com/lucid-softworks/auth/issues/60). |
| Dynamic base URL and proxies | Forwarded host/IP data is accepted only through explicitly trusted proxies, matching 1.7 hardening; see [#6](https://github.com/lucid-softworks/auth/issues/6) and [#7](https://github.com/lucid-softworks/auth/issues/7). |
| Error contracts | The 1.7.1 official client suite asserts structured status/code handling, including enumeration-safe `401 INVALID_EMAIL_OR_PASSWORD` and `401 INVALID_USERNAME_OR_PASSWORD`; each new endpoint must add its own error regressions before becoming Supported. |

Migration `0010_email_password.sql` normalizes persisted email addresses, adds
case-insensitive uniqueness, and allows core email/password users without a
username. Migration `0015_oauth_accounts.sql` applies Better Auth 1.7's
issuer-qualified OAuth identity and encrypted access-, refresh-, and ID-token
columns. The incompatible `(providerId, accountId)` uniqueness constraint is
removed rather than supported as a legacy identity fallback.

## Core client API

| Client method or route | Status | Tracking and limitations |
| --- | --- | --- |
| `getSession`, `useSession` (`GET /get-session`) | Supported | Stateful cookie session; cache/stateless modes are tracked in [#58](https://github.com/lucid-softworks/auth/issues/58). |
| `signOut` (`POST /sign-out`) | Supported | Clears the default session cookie. Configurable cookie attributes are tracked in [#6](https://github.com/lucid-softworks/auth/issues/6). |
| `signUp.email` (`POST /sign-up/email`) | Supported | JSON/form bodies, exact 1.7.1 `callbackURL`, image, auto-sign-in, password bounds, disabled-signup behavior, normalized uniqueness, generic duplicate mode, configured send-on-signup delivery, and username-plugin additional fields; [#9](https://github.com/lucid-softworks/auth/issues/9), [#10](https://github.com/lucid-softworks/auth/issues/10), [#16](https://github.com/lucid-softworks/auth/issues/16). |
| `signIn.email` (`POST /sign-in/email`) | Supported | JSON/form bodies, case-normalized lookup, generic credential errors, verification-required rejection, `rememberMe`, and callback response/location; [#9](https://github.com/lucid-softworks/auth/issues/9). Password sign-in does not acquire custom passkey assurance. |
| `verifyPassword` (`POST /verify-password`) | Supported | Session-bound credential verification with the 1.7.1 status/error body; [#9](https://github.com/lucid-softworks/auth/issues/9). |
| `sendVerificationEmail` (`POST /send-verification-email`) | Supported | Native async sender, authenticated mismatch/already-verified errors, enumeration-resistant anonymous responses, exact `callbackURL`, and one-hour default expiry; [#10](https://github.com/lucid-softworks/auth/issues/10). |
| `verifyEmail` (`GET /verify-email`) | Supported | Purpose-bound hashed tokens, atomic single-use verification, expiry/replay errors, compatible success/error redirects, and optional auto-sign-in; [#10](https://github.com/lucid-softworks/auth/issues/10). |
| `requestPasswordReset` (`POST /request-password-reset`) | Supported | Native async `sendResetPassword`, exact `redirectTo`, enumeration-resistant response/timing work, one-hour default expiry, and hashed persisted token identifiers; [#11](https://github.com/lucid-softworks/auth/issues/11). |
| `resetPassword` (`GET /reset-password/:token`, `POST /reset-password`) | Supported | Exact `callbackURL`, compatible callback/error redirects, body and query tokens, password policy, atomic single-use replacement, optional session revocation, and native `onPasswordReset`; [#11](https://github.com/lucid-softworks/auth/issues/11). |
| `changePassword` (`POST /change-password`) | Supported | Current-password flow and optional other-session revocation are implemented. |
| `updateUser` (`POST /update-user`) | Supported | Core name/image, username-plugin fields, and typed configured additional fields; input-disabled and output-only fields are protected, returned-false fields are omitted, and the session cookie is refreshed; [#12](https://github.com/lucid-softworks/auth/issues/12). General database lifecycle hooks remain [#60](https://github.com/lucid-softworks/auth/issues/60). |
| `updateSession` (`POST /update-session`) | Supported | Typed configured additional fields persist in memory/PostgreSQL, protected core fields cannot be overwritten, returned-false fields are omitted, and the updated session/cookie shape passes the official client; [#12](https://github.com/lucid-softworks/auth/issues/12). |
| `changeEmail` (`POST /change-email`) | Supported | Disabled-by-default, immediate unverified-account updates, verified one-step changes, optional current-address confirmation, enumeration-resistant existing-address handling, atomic uniqueness, callback URLs, and session refresh; [#12](https://github.com/lucid-softworks/auth/issues/12). |
| `deleteUser` and deletion callback | Supported | Disabled by default; password, fresh-session, and purpose-bound verification-token modes; exact `callbackURL`, callback redirects, cookie clearing, native before/after callbacks, plugin hooks, and transactional adapter cleanup; [#13](https://github.com/lucid-softworks/auth/issues/13). |
| `listSessions` (`GET /list-sessions`) | Partial | Listing works, but freshness and returned token semantics differ; [#58](https://github.com/lucid-softworks/auth/issues/58). |
| `revokeSession` (`POST /revoke-session`) | Partial | Works with the opaque session identifier returned by this server. Full session parity is [#58](https://github.com/lucid-softworks/auth/issues/58). |
| `revokeOtherSessions` | Supported | Stateful sessions only. |
| `revokeSessions` | Supported | Stateful sessions only. |
| `signIn.social` and provider callback | Supported | Exact `callbackURL`, `newUserCallbackURL`, and `errorCallbackURL` casing; redirect and direct ID-token branches; durable cookie-bound one-time state; reserved-parameter rejection; PKCE; provider-driven nonce and OIDC signature/issuer/audience/age checks; GET/form-POST callbacks; verified-email implicit-link policy; issuer-qualified accounts; encrypted tokens; all 35 Better Auth 1.7.1 built-ins plus the native `SocialProvider` extension trait. The official client and OAuth/OIDC attack fixtures cover the complete flow; [#14](https://github.com/lucid-softworks/auth/issues/14). |
| `listAccounts`, `accountInfo` | Planned | [#15](https://github.com/lucid-softworks/auth/issues/15). |
| `linkSocial`, `unlinkAccount` | Planned | [#15](https://github.com/lucid-softworks/auth/issues/15). |
| `getAccessToken`, `refreshToken` | Planned | Encrypted provider-token lifecycle: [#15](https://github.com/lucid-softworks/auth/issues/15). |
| Core rate limiting | Partial | Durable username/IP throttling exists; configurable per-endpoint parity is [#59](https://github.com/lucid-softworks/auth/issues/59). |
| Database hooks and additional fields | Partial | Typed user/session additional fields are persisted, filtered, and supported by the update routes. Create defaults/transforms/validators, account/verification fields, and full before/after database hooks remain [#60](https://github.com/lucid-softworks/auth/issues/60). |

## Authentication plugins

| Plugin | Status | Tracking and limitations |
| --- | --- | --- |
| Username | Supported | Optional `UsernamePlugin`; official signup, normalized sign-in, availability, and update lifecycle; configurable length, async validation, normalization order, display usernames, immutable usernames, exact errors, and atomic duplicate prevention; [#16](https://github.com/lucid-softworks/auth/issues/16). |
| Anonymous | Partial | Sign-in works; deletion and conversion/linking are [#17](https://github.com/lucid-softworks/auth/issues/17). |
| Passkey | Supported | Optional `PasskeyPlugin`; all seven official methods, exact schema/casing, origin arrays or request-origin fallback, fresh and passkey-first registration, context/resolver/callback options, authenticator selection, extensions, `createSession`, durable single-use challenges, atomic counters, and lossless legacy credential migration; [#19](https://github.com/lucid-softworks/auth/issues/19). |
| Two-Factor Authentication | Supported | Optional `TwoFactorPlugin`; all official `twoFactorClient` methods, exact 1.7.1 response fields and error codes, TOTP and delivered OTP, encrypted TOTP secrets/backup codes, one-time TOTP counters, atomic backup-code use, challenge attempt budgets, account lockout, rotating expiring trusted devices, server-only TOTP generation/backup-code viewing, and memory/PostgreSQL plugin stores; [#20](https://github.com/lucid-softworks/auth/issues/20). Role-driven step-up is a separate optional lucid extension. |
| Magic Link | Supported | Official `magicLinkClient` sign-in and verification pass. Native delivery receives email, token, URL, metadata, and request context; exact callback fields, signup policy, expiry, plain/hashed/custom token storage, custom generation, durable single-use redemption, redirects, and 1.7 mailbox cleanup are covered by [#22](https://github.com/lucid-softworks/auth/issues/22). |
| Email OTP | Planned | [#23](https://github.com/lucid-softworks/auth/issues/23). |
| Phone Number | Planned | [#24](https://github.com/lucid-softworks/auth/issues/24). |
| Google One Tap | Planned | [#25](https://github.com/lucid-softworks/auth/issues/25). |
| Sign In With Ethereum | Planned | [#26](https://github.com/lucid-softworks/auth/issues/26). |
| Generic OAuth | Planned | [#27](https://github.com/lucid-softworks/auth/issues/27). |
| Multi Session | Planned | Core session listing is not this plugin. Tracked in [#28](https://github.com/lucid-softworks/auth/issues/28). |
| Last Login Method | Planned | [#29](https://github.com/lucid-softworks/auth/issues/29). |
| OAuth Popup | Planned | [#70](https://github.com/lucid-softworks/auth/issues/70). |

## Authorization and management plugins

| Plugin | Status | Tracking and limitations |
| --- | --- | --- |
| Admin | Supported | Optional `AdminPlugin`; all 15 official `adminClient` methods pass against Better Auth 1.7.1. This includes passwordless creation, flattened additional user fields, get/update, permission checks, safe filtering/sorting/pagination, multiple roles, configurable access-control statements and admin IDs, ban defaults/messages, bounded impersonation, and exact response/error shapes. Its routes and user fields are absent when disabled; [#18](https://github.com/lucid-softworks/auth/issues/18), [#75](https://github.com/lucid-softworks/auth/issues/75). |
| Lucid owner policy | Native only | Optional `OwnerPolicyPlugin`, composed with `AdminPlugin::new(OwnerPolicyPlugin::admin_config())`, owns lucid-auth's fixed owner/member/viewer vocabulary, owner-only gates, last-owner protection, and owner-promotion session revocation. Invalid or mismatched composition is rejected before serving; [#75](https://github.com/lucid-softworks/auth/issues/75). |
| Organization | Planned | Organizations, members, invitations, teams, and roles: [#30](https://github.com/lucid-softworks/auth/issues/30). |
| SSO | Planned | Native OIDC/OAuth2/SAML and provisioning: [#31](https://github.com/lucid-softworks/auth/issues/31). |
| SCIM | Planned | Users, Groups, PATCH/filtering, credentials, and role projection: [#32](https://github.com/lucid-softworks/auth/issues/32). |

## API and token plugins

| Plugin | Status | Tracking and limitations |
| --- | --- | --- |
| API Key | Partial | Optional `ApiKeyPlugin`; all official `apiKeyClient` methods, server verification/cleanup, exact fields/errors, named configurations, user ownership, pagination/sorting, metadata, enabled/expiry state, permissions, refills, one-time plaintext display, SHA-256 base64url storage, atomic quotas/rate limits, and header sessions are covered by [#21](https://github.com/lucid-softworks/auth/issues/21). Organization ownership awaits [#30](https://github.com/lucid-softworks/auth/issues/30); advanced callbacks and secondary/custom storage await [#76](https://github.com/lucid-softworks/auth/issues/76). |
| JWT | Planned | Token/JWKS profiles and key rotation: [#33](https://github.com/lucid-softworks/auth/issues/33). |
| Bearer | Planned | [#34](https://github.com/lucid-softworks/auth/issues/34). |
| One-Time Token | Planned | [#35](https://github.com/lucid-softworks/auth/issues/35). |
| OAuth Proxy | Planned | [#36](https://github.com/lucid-softworks/auth/issues/36). |
| OAuth 2.1 / OIDC Provider | Planned | [#37](https://github.com/lucid-softworks/auth/issues/37). |
| Device Authorization | Planned | [#38](https://github.com/lucid-softworks/auth/issues/38). |
| MCP | Planned | [#39](https://github.com/lucid-softworks/auth/issues/39). |
| Agent Auth | Planned | [#40](https://github.com/lucid-softworks/auth/issues/40). |
| Client ID Metadata Document | Planned | [#69](https://github.com/lucid-softworks/auth/issues/69). |

## Security, utility, and developer plugins

| Plugin | Status | Tracking and limitations |
| --- | --- | --- |
| Have I Been Pwned | Partial | Native k-anonymity checker exists for current password flows. Endpoint/configuration parity is [#45](https://github.com/lucid-softworks/auth/issues/45). |
| Captcha | Planned | [#41](https://github.com/lucid-softworks/auth/issues/41). |
| i18n | Planned | [#42](https://github.com/lucid-softworks/auth/issues/42). |
| Open API | Planned | Schema generation from enabled endpoint metadata: [#43](https://github.com/lucid-softworks/auth/issues/43). |
| Test Utils | Planned | Native development-only fixtures: [#44](https://github.com/lucid-softworks/auth/issues/44). |
| Tracing / instrumentation | Planned | [#66](https://github.com/lucid-softworks/auth/issues/66). |

## Payments, analytics, and Better Auth Infrastructure

| Integration | Status | Tracking |
| --- | --- | --- |
| Stripe | Planned | [#46](https://github.com/lucid-softworks/auth/issues/46). |
| Polar | Planned | [#47](https://github.com/lucid-softworks/auth/issues/47). |
| Autumn | Planned | [#48](https://github.com/lucid-softworks/auth/issues/48). |
| Creem | Planned | [#49](https://github.com/lucid-softworks/auth/issues/49). |
| Dodo Payments | Planned | [#50](https://github.com/lucid-softworks/auth/issues/50). |
| Commet | Planned | [#51](https://github.com/lucid-softworks/auth/issues/51). |
| Chargebee | Planned | [#52](https://github.com/lucid-softworks/auth/issues/52). |
| Dub | Planned | [#53](https://github.com/lucid-softworks/auth/issues/53). |
| Dashboard and audit logs | Planned | [#54](https://github.com/lucid-softworks/auth/issues/54). |
| Sentinel security | Planned | [#55](https://github.com/lucid-softworks/auth/issues/55). |
| Managed email service | Planned | [#56](https://github.com/lucid-softworks/auth/issues/56). |
| Managed SMS service | Planned | [#57](https://github.com/lucid-softworks/auth/issues/57). |

Provider integrations are opt-in native Rust configurations. An unregistered or
unavailable provider does not affect password, passkey, or other configured
authentication methods.

## Storage and deployment

| Capability | Status | Tracking and limitations |
| --- | --- | --- |
| In-memory store | Supported | Intended for tests and single-process development. |
| PostgreSQL | Supported | Core migrations include normalized email uniqueness, username-optional credential accounts, and Better Auth 1.7 issuer-qualified OAuth accounts with encrypted-token columns. Optional plugins contribute their own tables. Lifecycle, same-subject/different-issuer identity, concurrent case-variant signup, plugin migration idempotence, atomic API-key claims, and atomic two-factor replay/backup-code/lockout writes run in the live contract. Broader schema generation is [#68](https://github.com/lucid-softworks/auth/issues/68). |
| Verification challenges | Supported | Purpose-scoped, expiring values are persisted by both stores and consumed atomically across service instances; [#8](https://github.com/lucid-softworks/auth/issues/8). |
| SQLite | Planned | [#61](https://github.com/lucid-softworks/auth/issues/61). |
| MySQL | Planned | [#62](https://github.com/lucid-softworks/auth/issues/62). |
| MongoDB | Planned | [#63](https://github.com/lucid-softworks/auth/issues/63). |
| MS SQL and generic relational adapters | Planned | [#64](https://github.com/lucid-softworks/auth/issues/64). |
| Secondary storage and stateless sessions | Planned | [#58](https://github.com/lucid-softworks/auth/issues/58). |
| Programmatic schema/migration diagnostics | Planned | [#68](https://github.com/lucid-softworks/auth/issues/68). |
| Trusted origins, CSRF, redirect validation | Supported | Better Auth exact, wildcard, custom-scheme, and relative-path matching; same-origin requests; Fetch Metadata checks; and validation of all four redirect fields; [#5](https://github.com/lucid-softworks/auth/issues/5). |
| Base URL/path, CORS, and configurable cookies | Supported | Static base URL, custom route mount, trusted credentialed CORS, secure-name inference, cross-subdomain and per-cookie policy; [#6](https://github.com/lucid-softworks/auth/issues/6). |
| Trusted-proxy client IP resolution | Supported | Transport-peer verification, custom headers, trusted IP/CIDR chains, IPv4-mapped IPv6 and subnet normalization, and disabled tracking; [#7](https://github.com/lucid-softworks/auth/issues/7). |
| Framework and production installation guides | Planned | [#65](https://github.com/lucid-softworks/auth/issues/65). |

## TypeScript server and framework boundary

The official browser clients can target an HTTP-compatible Rust server. In
contrast, Better Auth server examples that import `betterAuth`, call `auth.api`,
register JavaScript callbacks, run Better Auth CLI migrations, or install an npm
server plugin are **not applicable directly**. The corresponding behavior must
be implemented through native Rust service APIs, traits, routes, and migrations.

Framework client integrations for React, Vue, Svelte, Solid, and vanilla clients
are compatibility targets. Framework server adapters for Next.js, SvelteKit,
Nuxt, Astro, Hono, Express, and similar TypeScript runtimes remain their native
framework concerns; deployment guidance is tracked in
[#65](https://github.com/lucid-softworks/auth/issues/65).

## Project-specific extensions

The following are supported lucid-auth features, not Better Auth compatibility
claims:

- optional `GuestCapabilityPlugin` with owner-issued, time-bounded grants,
  atomic use limits and revocation, plugin-owned routes and PostgreSQL migration
  ([#71](https://github.com/lucid-softworks/auth/issues/71));
- optional `StepUpPolicyPlugin` for role-driven passkey/two-factor assurance,
  freshness enforcement, typed native session projection, recovery codes,
  plugin-owned memory/PostgreSQL state, and migration of legacy assurance data
  ([#72](https://github.com/lucid-softworks/auth/issues/72));
- optional `OperatorSecurityPlugin` for administrator-issued temporary
  credentials, bootstrap policy, application/sensitive-operation enforcement,
  atomic local sole-owner recovery, factor cleanup hooks, and plugin-owned
  memory/PostgreSQL state ([#73](https://github.com/lucid-softworks/auth/issues/73));
- optional `AuditPlugin` with a versioned action vocabulary, typed outcomes,
  structurally validated metadata, fail-open lifecycle recording, bounded
  memory/PostgreSQL retention, identity anonymization, and a plugin-owned
  `/access/audit` route ([#74](https://github.com/lucid-softworks/auth/issues/74));
- optional `OwnerPolicyPlugin` layered around Admin, with fixed roles,
  last-owner protection, typed authorization hooks, and no core/official-client
  fields of its own ([#75](https://github.com/lucid-softworks/auth/issues/75)).

These extensions must continue to compose safely with compatibility work, but a
Better Auth client is not expected to know about them unless an application adds
its own client methods. In particular, `AuditPlugin` is not the Better Auth
Infrastructure Dashboard audit-log integration tracked in
[#54](https://github.com/lucid-softworks/auth/issues/54).
