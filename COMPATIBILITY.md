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
| Official JavaScript client conformance | Supported | CI drives the pinned `1.7.1` vanilla email/password, email-verification, password-reset, social OAuth, generic OAuth, linked-account/token, OAuth Popup, OAuth Proxy ordinary-social-client, OAuth Provider management, standalone Device Authorization, and OAuth Device Authorization flows plus the official MCP v2 discovery/client-credentials/initialize round trip, username, anonymous, email OTP, phone number, Google One Tap, SIWE, admin, every passkey, API-key, organization, team, and dynamic-role client method, two-factor, and a native test-client plugin against an ephemeral server. Passkey registration/authentication use real signatures from an in-process virtual authenticator; [#2](https://github.com/lucid-softworks/auth/issues/2), [#14](https://github.com/lucid-softworks/auth/issues/14), [#15](https://github.com/lucid-softworks/auth/issues/15), [#23](https://github.com/lucid-softworks/auth/issues/23), [#24](https://github.com/lucid-softworks/auth/issues/24), [#25](https://github.com/lucid-softworks/auth/issues/25), [#26](https://github.com/lucid-softworks/auth/issues/26), [#27](https://github.com/lucid-softworks/auth/issues/27), [#30](https://github.com/lucid-softworks/auth/issues/30), [#36](https://github.com/lucid-softworks/auth/issues/36), [#37](https://github.com/lucid-softworks/auth/issues/37), [#38](https://github.com/lucid-softworks/auth/issues/38), [#39](https://github.com/lucid-softworks/auth/issues/39), and [#70](https://github.com/lucid-softworks/auth/issues/70). |
| Native plugin extension API | Supported | Typed routes, middleware, lifecycle hooks, ordered PostgreSQL migrations, cookies/rate-limit declarations, dependency/conflict checks, and exact-version client metadata; [#4](https://github.com/lucid-softworks/auth/issues/4). |
| Community plugin SDK | Planned | Native plugin packaging and certification policy: [#67](https://github.com/lucid-softworks/auth/issues/67). |

### Better Auth 1.7.1 upgrade audit

| Upstream change area | Native compatibility impact |
| --- | --- |
| Sessions | Opaque list/revoke tokens, database and secondary-backed sessions, stateless cookie sessions, all three cookie-cache strategies, sliding `updateAge`, both refresh-disable controls, signed non-remembered sessions, and deferred GET/POST refresh pass Rust, PostgreSQL, and official 1.7.1 contracts; [#58](https://github.com/lucid-softworks/auth/issues/58) and [#81](https://github.com/lucid-softworks/auth/issues/81). |
| OAuth identity and schema | Supported issuer-qualified `(issuer, accountId)` identity, atomic user/account creation, safe implicit and explicit linking, Better Auth's opt-in access/refresh-token encryption, owner-bound token access, concurrency-safe refresh rotation, and final-account unlink protection. ID tokens remain unencrypted as in Better Auth. Migration `0015` removes the obsolete provider-qualified uniqueness model rather than retaining a fallback; [#14](https://github.com/lucid-softworks/auth/issues/14) and [#15](https://github.com/lucid-softworks/auth/issues/15). |
| Account-data cookie | Supported opt-in A256CBC-HS512 JWE storage with Better Auth's salt, name/attribute overrides, session-cache lifetime, numbered chunking, stale cleanup, user/session binding, explicit cookie selection, refresh, tamper rejection, and sign-out cleanup; [#80](https://github.com/lucid-softworks/auth/issues/80). |
| Two-factor responses | Supported through optional `TwoFactorPlugin`: the official 1.7.1 discriminated enable response, all eight browser-client endpoints, server-only TOTP generation and backup-code viewing, challenge/trust cookies, and encrypted factor storage are covered by [#20](https://github.com/lucid-softworks/auth/issues/20). |
| Passwordless cleanup | Magic Link, Email OTP, and Phone Number implement Better Auth 1.7.1's atomic one-time token lifecycle. Phone Number keeps password sign-in separate from passwordless OTP verification/signup; [#22](https://github.com/lucid-softworks/auth/issues/22), [#23](https://github.com/lucid-softworks/auth/issues/23), and [#24](https://github.com/lucid-softworks/auth/issues/24). |
| Google One Tap | The optional native plugin verifies Google's RS256 ID token against Google's JWKS, issuer, audience, expiry, and one-hour maximum age; applies Google hosted-domain, signup, linking, email-verification, anonymous-upgrade, and session policy; and exposes Better Auth's exact browser callback contract. The official 1.7.1 GIS/FedCM client flow is covered by [#25](https://github.com/lucid-softworks/auth/issues/25). |
| Custom and secondary storage | Typed database hooks/schema fields plus secondary-backed sessions, verification values, and rate limits are supported. Verification keys use ordered plain/hashed/custom identifier processing, remaining-expiry TTLs, atomic `getAndDelete`, optional database mirroring, and reservation fail-closed behavior; [#79](https://github.com/lucid-softworks/auth/issues/79). |
| Dynamic base URL and proxies | Forwarded host/IP data is accepted only through explicitly trusted proxies, matching 1.7 hardening; see [#6](https://github.com/lucid-softworks/auth/issues/6) and [#7](https://github.com/lucid-softworks/auth/issues/7). |
| Error contracts | The 1.7.1 official client suite asserts structured status/code handling, including enumeration-safe `401 INVALID_EMAIL_OR_PASSWORD` and `401 INVALID_USERNAME_OR_PASSWORD`; each new endpoint must add its own error regressions before becoming Supported. |

Migration `0010_email_password.sql` normalizes persisted email addresses, adds
case-insensitive uniqueness, and allows core email/password users without a
username. Migration `0015_oauth_accounts.sql` applies Better Auth 1.7's
issuer-qualified OAuth identity and optionally encrypted access-/refresh-token
columns. The incompatible `(providerId, accountId)` uniqueness constraint is
removed rather than supported as a legacy identity fallback.

## Core client API

| Client method or route | Status | Tracking and limitations |
| --- | --- | --- |
| `getSession`, `useSession` (`GET`/deferred `POST /get-session`) | Supported | Database, secondary, stateless, cache bypass/version/expiry/token binding, compact, HS256 JWT, JWT-plugin asymmetric JWKS caching, A256CBC-HS512 JWE, exact inclusive `updateAge`, `disableSessionRefresh`, request `disableRefresh`, signed `dont_remember`, camelCase `needsRefresh`, write-free deferred GET, guarded refresh POST, cookie renewal, and no-resurrection updates; [#33](https://github.com/lucid-softworks/auth/issues/33), [#58](https://github.com/lucid-softworks/auth/issues/58), and [#81](https://github.com/lucid-softworks/auth/issues/81). |
| `signOut` (`POST /sign-out`) | Supported | Revokes stateful/secondary sessions and clears primary, cache, and enabled account-data cookies, including numbered chunks. Pure stateless sessions use cache expiry/version invalidation, matching Better Auth; [#58](https://github.com/lucid-softworks/auth/issues/58) and [#80](https://github.com/lucid-softworks/auth/issues/80). |
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
| `listSessions` (`GET /list-sessions`) | Supported | Returns Better Auth's stored opaque tokens for database and secondary-backed sessions; [#58](https://github.com/lucid-softworks/auth/issues/58). |
| `revokeSession` (`POST /revoke-session`) | Supported | Accepts the exact opaque token returned by `listSessions`; [#58](https://github.com/lucid-softworks/auth/issues/58). |
| `revokeOtherSessions` | Supported | Database and secondary-backed sessions. Pure stateless sessions cannot be individually revoked server-side. |
| `revokeSessions` | Supported | Database and secondary-backed sessions. Pure stateless sessions use cache version/expiry invalidation. |
| `signIn.social` and provider callback | Supported | Exact `callbackURL`, `newUserCallbackURL`, and `errorCallbackURL` casing; redirect and direct ID-token branches; database/signed-cookie or encrypted-cookie one-time state; reserved-parameter rejection; PKCE; provider-driven nonce and OIDC signature/issuer/audience/age checks; GET/form-POST callbacks; verified-email implicit-link policy; issuer-qualified accounts; opt-in access/refresh-token encryption; optional selected-account cookie; all 35 Better Auth 1.7.1 built-ins plus the native `SocialProvider` extension trait. The official client and OAuth/OIDC attack fixtures cover the complete flow; [#14](https://github.com/lucid-softworks/auth/issues/14) and [#80](https://github.com/lucid-softworks/auth/issues/80). |
| `listAccounts`, `accountInfo` | Supported | Exact account identifiers, issuer/subject identity, parsed scopes, provider user/profile data, owner-bound durable account-ID selection, automatic near-expiry refresh, and explicit `useAccountCookie: true` selection pass the official client; [#15](https://github.com/lucid-softworks/auth/issues/15) and [#80](https://github.com/lucid-softworks/auth/issues/80). |
| `linkSocial`, `unlinkAccount` | Supported | Direct ID-token and redirect linking use Better Auth's explicit-link email/trusted-provider rules and exact response casing. Conflicting identities are rejected, atomic unlinking prevents removal of the final account unless explicitly configured, and successful links select the opt-in account cookie; [#15](https://github.com/lucid-softworks/auth/issues/15) and [#80](https://github.com/lucid-softworks/auth/issues/80). |
| `getAccessToken`, `refreshToken` | Supported | Access and refresh tokens use Better Auth's `account.encryptOAuthTokens` opt-in; ID tokens are stored directly. Strict account-ID or explicit `useAccountCookie: true` selection, owner binding, near-expiry refresh, cookie refresh, scope preservation, request-aware generic-OAuth refresh parameters, and atomic concurrent rotation pass the official client; [#15](https://github.com/lucid-softworks/auth/issues/15), [#27](https://github.com/lucid-softworks/auth/issues/27), and [#80](https://github.com/lucid-softworks/auth/issues/80). |
| Core rate limiting | Supported | Better Auth production/development defaults, global and built-in special rules, plugin overrides, ordered exact/wildcard static or request-resolved custom rules and exclusions, normalized IP/path keys, shared unknown-IP buckets, disabled tracking, atomic memory/PostgreSQL/secondary/custom consumption, cleanup, exact 429 body and `X-Retry-After`, concurrency boundaries, and native in-process opt-out; [#59](https://github.com/lucid-softworks/auth/issues/59). |
| Database hooks and additional fields | Supported | Typed before/after create, update, and delete hooks run plugin-first then host with mutation/veto semantics and HTTP request context. User/session/account/verification fields support required/input/returned/default/on-update/transform/validator/reference/index descriptors, plugin schema contributions, durable JSONB storage, and official signup/update response boundaries; [#60](https://github.com/lucid-softworks/auth/issues/60). |

## Authentication plugins

| Plugin | Status | Tracking and limitations |
| --- | --- | --- |
| Username | Supported | Optional `UsernamePlugin`; official signup, normalized sign-in, availability, and update lifecycle; configurable length, async validation, normalization order, display usernames, immutable usernames, exact errors, and atomic duplicate prevention; [#16](https://github.com/lucid-softworks/auth/issues/16). |
| Anonymous | Supported | Optional `AnonymousPlugin`; both official client methods, plugin-owned routes and `isAnonymous` field, exact replay/deletion errors, domain and async name/email generation, deletion policy, typed `on_link_account`, email/username/social conversion, one-time concurrent cleanup, and memory/PostgreSQL persistence; [#17](https://github.com/lucid-softworks/auth/issues/17). Lucid guest capability grants deliberately remain separate. |
| Passkey | Supported | Optional `PasskeyPlugin`; all seven official methods, exact schema/casing, origin arrays or request-origin fallback, fresh and passkey-first registration, context/resolver/callback options, authenticator selection, extensions, `createSession`, durable single-use challenges, atomic counters, and lossless legacy credential migration; [#19](https://github.com/lucid-softworks/auth/issues/19). |
| Two-Factor Authentication | Supported | Optional `TwoFactorPlugin`; all official `twoFactorClient` methods, exact 1.7.1 response fields and error codes, TOTP and delivered OTP, encrypted TOTP secrets/backup codes, one-time TOTP counters, atomic backup-code use, challenge attempt budgets, account lockout, rotating expiring trusted devices, server-only TOTP generation/backup-code viewing, and memory/PostgreSQL plugin stores; [#20](https://github.com/lucid-softworks/auth/issues/20). Role-driven step-up is a separate optional lucid extension. |
| Magic Link | Supported | Official `magicLinkClient` sign-in and verification pass. Native delivery receives email, token, URL, metadata, and request context; exact callback fields, signup policy, expiry, plain/hashed/custom token storage, custom generation, durable single-use redemption, redirects, and 1.7 mailbox cleanup are covered by [#22](https://github.com/lucid-softworks/auth/issues/22). |
| Email OTP | Supported | Optional `EmailOtpPlugin`; all nine public `emailOTPClient` routes plus native server-only create/get methods, exact four-purpose vocabulary, numeric/custom generation, 300-second expiry, three-attempt enforcement, rotate/reuse resend strategies, plain/SHA-256/encrypted/custom storage, atomic single-use redemption, enumeration-safe delivery, signup and core-verification overrides, password reset, fresh-session email change, configured rate limits, and exact errors are covered by Rust and official 1.7.1 client contracts; [#23](https://github.com/lucid-softworks/auth/issues/23). |
| Phone Number | Supported | Optional `PhoneNumberPlugin`; all five public `phoneNumberClient` routes plus native server-only OTP consumption, opaque phone strings with opt-in validation, six-digit/300-second/three-attempt defaults, custom verification, verification callbacks, OTP signup/session creation, password sign-in and reset, authenticated replacement, clear-only `updateUser`, atomic replay/attempt enforcement, and memory/PostgreSQL uniqueness are covered by Rust and official 1.7.1 client contracts; [#24](https://github.com/lucid-softworks/auth/issues/24). |
| Google One Tap | Supported | Optional `OneTapPlugin`; the plugin ID is `one-tap`, the official factory/action are `oneTapClient`/`oneTap`, and `POST /one-tap/callback` returns `{ token, user }`. The server audience uses `OneTapConfig.client_id` or falls back to the registered Google provider, while the browser factory receives the matching Google web client ID. Google JWKS signature, issuer, audience, expiry, one-hour age, hosted-domain, signup/linking, email-verification, session, and anonymous-upgrade behavior are covered. GIS prompting is browser-only, FedCM is enabled by the official client by default, and trusted `callbackURL` navigation is performed by the client after the server responds rather than by a server redirect; [#25](https://github.com/lucid-softworks/auth/issues/25). |
| Sign In With Ethereum | Supported | Optional `SiwePlugin`; both nonce aliases and `verify` pass the official `siweClient` against the native server. The 8–250 ASCII-alphanumeric nonce, 15-minute single-use storage, Better Auth 1.7.1 line parser/checksum behavior and pinned JavaScript-compatible time forms, consume-before-verification ordering, callback payload, anonymous/email user resolution, ENS profile lookup, CAIP-122 projection, same-wallet cross-chain linking, `local:siwe` accounts, normal sessions, exact validation/errors, and memory/PostgreSQL atomic persistence are covered by [#26](https://github.com/lucid-softworks/auth/issues/26). |
| Generic OAuth | Supported | Optional `GenericOAuthPlugin`; providers are prepended to the ordinary social registry and use only `signIn.social` plus `/callback/:id`. Exact 1.7.1 discovery precedence/failure rules, OAuth/OIDC classification, PKCE and nonce defaults, JOSE algorithm allowlisting including ES512, all four token auth methods, custom token/user/profile/identity callbacks, static or request-aware refresh params, IDP-initiated restart, provider logout, signup/profile controls, duplicate/shadow ordering, database state or Better Auth-compatible XChaCha20-Poly1305 cookie state, both plugin errors, and all ten bundled helper presets are covered by Rust and official-client contracts; [#27](https://github.com/lucid-softworks/auth/issues/27). |
| Multi Session | Supported | Optional `MultiSessionPlugin`; all three official `multiSessionClient` methods, signed per-session selector cookies, same-user replacement, configurable quota boundaries, unique active-device listing, activation without a current session, authenticated revocation with current-session replacement, stateful cookie-cache authorization, and verified-selector cleanup on sign-out are covered against Better Auth 1.7.1 in memory, PostgreSQL, and official-client contracts; [#28](https://github.com/lucid-softworks/auth/issues/28). |
| Last Login Method | Supported | Optional `LastLoginMethodPlugin`; exact email/callback/SIWE/passkey/magic-link default resolution, custom fallback and empty suppression, unsigned URI-encoded session-cookie-scoped tracking, async cookie consent, configurable name and Better Call max-age boundaries, optional input-disabled user schema storage, and the three synchronous `lastLoginMethodClient` actions are covered against Better Auth 1.7.1; [#29](https://github.com/lucid-softworks/auth/issues/29). |
| OAuth Popup | Supported | Optional `OAuthPopupPlugin`; exact `GET /oauth-popup/start`, state strategy, signed `oauth_popup` marker, provider redirect, callback completion document/CSP, session-token relay, popup validation and failure ordering, per-plugin cookie override, and official `oauthPopupClient` browser/storage/fetch behavior are covered against Better Auth 1.7.1. Top-level popup sign-in works independently; cross-origin embedded clients also require Bearer support tracked in [#34](https://github.com/lucid-softworks/auth/issues/34). The marker is deliberately separate from OAuth state and one fixed cookie can be overwritten by concurrent popup starts, matching upstream; [#70](https://github.com/lucid-softworks/auth/issues/70). |

## Authorization and management plugins

| Plugin | Status | Tracking and limitations |
| --- | --- | --- |
| Admin | Supported | Optional `AdminPlugin`; all 15 official `adminClient` methods pass against Better Auth 1.7.1. This includes passwordless creation, flattened additional user fields, get/update, permission checks, safe filtering/sorting/pagination, multiple roles, configurable access-control statements and admin IDs, ban defaults/messages, bounded impersonation, and exact response/error shapes. Its routes and user fields are absent when disabled; [#18](https://github.com/lucid-softworks/auth/issues/18), [#75](https://github.com/lucid-softworks/auth/issues/75). |
| Lucid owner policy | Native only | Optional `OwnerPolicyPlugin`, composed with `AdminPlugin::new(OwnerPolicyPlugin::admin_config())`, owns lucid-auth's fixed owner/member/viewer vocabulary, owner-only gates, last-owner protection, and owner-promotion session revocation. Invalid or mismatched composition is rejected before serving; [#75](https://github.com/lucid-softworks/auth/issues/75). |
| Organization | Supported | Optional `OrganizationPlugin`; every official `organizationClient` method, active organization/team session fields, configurable static and dynamic access control, custom roles, organization/member/invitation/team lifecycle hooks, creation/membership/invitation/team/role limits, email delivery, team assignment on invitation, last-owner protection, and memory/PostgreSQL transactional stores; [#30](https://github.com/lucid-softworks/auth/issues/30). |
| SSO | Planned | Native OIDC/OAuth2/SAML and provisioning: [#31](https://github.com/lucid-softworks/auth/issues/31). |
| SCIM | Planned | Users, Groups, PATCH/filtering, credentials, and role projection: [#32](https://github.com/lucid-softworks/auth/issues/32). |

## API and token plugins

| Plugin | Status | Tracking and limitations |
| --- | --- | --- |
| API Key | Partial | Optional `ApiKeyPlugin`; all official `apiKeyClient` methods, server verification/cleanup, exact fields/errors, named configurations, user and organization ownership, organization `apiKey` permission checks, pagination/sorting, metadata, enabled/expiry state, permissions, refills, one-time plaintext display, SHA-256 base64url storage, atomic quotas/rate limits, and header sessions are covered by [#21](https://github.com/lucid-softworks/auth/issues/21) and [#30](https://github.com/lucid-softworks/auth/issues/30). Advanced callbacks and secondary/custom storage await [#76](https://github.com/lucid-softworks/auth/issues/76). |
| JWT | Supported | Optional `JwtPlugin`; official `jwtClient`, `GET /token`, configurable public JWKS route, server-only sign/verify API, EdDSA/ES256/ES512/PS256/RS256, exact claims and callbacks, remote signing/JWKS metadata, custom adapters/schema names, lazy rotation and grace overlap, encrypted/versioned private JWK storage, and opt-in asymmetric session-cookie caching. Public HTTP never exposes private material; retired stored rows remain usable by internal verification; [#33](https://github.com/lucid-softworks/auth/issues/33). |
| Bearer | Supported | Optional server-only `BearerPlugin`; exact case-insensitive `Bearer ` parsing, raw or Better Call-signed session credentials, `require_signature`, accepted-credential precedence, invalid-signed cookie fallback, ordinary session expiry/revocation/policy, and `set-auth-token` plus CORS exposure are covered. There is no `bearerClient`; official clients use core `fetchOptions.auth` or an `Authorization` header. Bearer accepts Better Auth session credentials, not JWT-plugin service tokens; [#34](https://github.com/lucid-softworks/auth/issues/34). |
| One-Time Token | Supported | Optional `OneTimeTokenPlugin`; official `oneTimeTokenClient` generation and verification, portable existing-session handoff, default three-minute 32-character tokens, plain/SHA-256-base64url/custom identifier storage, custom generation, atomic consume-before-session-lookup behavior, cookie opt-out, and `set-ott` new-session headers are covered against Better Auth 1.7.1. It uses core verification storage and intentionally has no purpose, payload, user, origin, or freshness binding. Pinned 1.7.1 cookie/header ordering on expired-session errors is preserved and regression-tested; [#35](https://github.com/lucid-softworks/auth/issues/35). |
| OAuth Proxy | Supported | Optional `OAuthProxyPlugin`; the ordinary official `signIn.social` client is proxied through preview-to-production-to-preview callbacks, with shared-secret encrypted state/profile envelopes, trusted current-URL resolution, `x-skip-oauth-proxy`, configurable 60-second payload age, provider errors, and final session binding covered against Better Auth 1.7.1. It adds only `GET /oauth-proxy-callback`; upstream has no dedicated client plugin, plugin-owned cookie/schema/migration, rate limit, or error-code export; [#36](https://github.com/lucid-softworks/auth/issues/36). |
| OAuth 2.1 / OIDC Provider | Supported | Optional `OAuthProviderPlugin` matches `@better-auth/oauth-provider@1.7.1`: issuer/root discovery, authorization/consent/continue, authorization-code/client-credentials/refresh grants, public/confidential/private-key client authentication, S256 PKCE, OIDC UserInfo/ID tokens/logout, opaque or JWT access tokens, rotation/replay handling, introspection/revocation, resource indicators/policy, DPoP, dynamic and owner client management, consent management, exact defaults/rate limits, and the official `oauthProviderClient`. Its seven models have dedicated atomic memory/PostgreSQL stores; authorization codes use core verification storage and signing keys stay with `JwtPlugin`. Upstream `SERVER_ONLY` admin routes remain HTTP 404, self-contained JWTs cannot be recalled after issuance, and this is contract compatibility rather than OAuth/OIDC certification. Device authorization is installed separately through its companion plugin; [#37](https://github.com/lucid-softworks/auth/issues/37). |
| Device Authorization | Supported | Optional `DeviceAuthorizationPlugin` and OAuth Provider companion `OAuthDeviceAuthorizationPlugin`; exact standalone session exchange and OAuth device-code grant, official `deviceAuthorizationClient` and `oauthDeviceAuthorizationClient` methods, five public routes, discovery contribution, dedicated remappable storage, atomic bind/consume, exact polling order, duration/code generation, owner redaction, cache headers, and memory/PostgreSQL contracts match Better Auth 1.7.1. OAuth-owned codes intentionally fail at `/device/token` and exchange through `/oauth2/token`; [#38](https://github.com/lucid-softworks/auth/issues/38). |
| MCP | Supported | Optional MCP OAuth preset and framework-neutral protected-request verifier match `@better-auth/mcp@1.7.1`: inherited OAuth Provider identity/surface, one canonical resource and default client binding, 30-second refresh retry overlap, both RFC 9728 discovery aliases, exact cache/method behavior, filtered resource scopes, local JWT or remote introspection, Bearer/DPoP sender binding, scope challenges, JSON-RPC error envelopes, and durable replay reservations. There is no MCP-specific Better Auth client factory, transport, protocol session/SSE bridge, model, migration, cookie, or extra rate limit; applications use `oauthProviderClient()` for management and the official `@modelcontextprotocol/client` v2 for protocol traffic. The convenience verifier's default audience is the auth base URL, so a differing MCP resource must be supplied explicitly; [#39](https://github.com/lucid-softworks/auth/issues/39). |
| Agent Auth | Supported | Optional `AgentAuthPlugin` matches Better Auth `1.7.1`, `@better-auth/agent-auth@0.6.2`, and the compatible portions of `@auth/agent@0.6.2`: all 32 server routes, four remappable models, discovery, lifecycle and approval flows, request verification, events, and documented OpenAPI helpers. See [Agent Auth](#agent-auth) and [#40](https://github.com/lucid-softworks/auth/issues/40). |
| Client ID Metadata Document | Planned | [#69](https://github.com/lucid-softworks/auth/issues/69). |

## Agent Auth

Agent Auth is an opt-in plugin. The compatibility target is exactly Better Auth
`1.7.1`, `@better-auth/agent-auth@0.6.2`, and the official protocol client
`@auth/agent@0.6.2`. Enabling it adds only its own routes, root discovery,
schema, rate limits, and hooks; disabling it leaves core authentication and
other plugins unchanged.

### Setup

The smallest in-process setup uses the public `MemoryAgentAuthStore` through
`AgentAuthPlugin::in_memory`:

```rust
use lucid_auth::{AgentAuthConfig, AgentAuthPlugin, AgentCapability, AuthConfig};

let mut auth = AuthConfig::new(std::env::var("BETTER_AUTH_SECRET")?.into_bytes())?;
auth.set_base_url("https://auth.example.com")?;

let mut agent_auth = AgentAuthConfig::default();
agent_auth.capabilities = vec![
    AgentCapability::new("notes.read", "Read notes"),
    AgentCapability::new("notes.write", "Write notes"),
];
agent_auth.default_host_capabilities = vec!["notes.read".into()];

auth.add_plugin(AgentAuthPlugin::in_memory(agent_auth)?)?;
```

`MemoryAgentAuthStore` is process-local and is intended for development,
testing, and a single service process. With the `postgres` feature, production
deployments can construct
`PostgresAgentAuthStore::new(pool, &agent_auth.schema)` and pass it to
`AgentAuthPlugin::new(agent_auth, store)`. The plugin contributes its ordered
migration for the four remappable models `agentHost`, `agent`,
`agentCapabilityGrant`, and `approvalRequest`.

The JavaScript Better Auth client uses the pinned external client plugin:

```ts
import { createAuthClient } from "better-auth/client";
import { agentAuthClient } from "@better-auth/agent-auth/client";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
  plugins: [agentAuthClient()],
});
```

Do not install the JavaScript `agentAuth()` server plugin into the Rust
service. `AgentAuthPlugin` is its native server equivalent.

### Configuration and defaults

These are the exact public `AgentAuthConfig` fields. Durations are seconds.
`None` means the corresponding optional upstream value or callback is absent.

| Rust field | Default | Behavior |
| --- | --- | --- |
| `schema` | `AgentAuthSchema::default()` | Default names for the four plugin models; every model and field can be remapped. |
| `provider_name` | `None` | Discovery falls back to `agent-auth`. |
| `provider_description` | `None` | Discovery falls back to `Agent Auth enabled service`. |
| `modes` | delegated and autonomous | Advertised and accepted agent modes. |
| `device_authorization_page` | `/device/capabilities` | Verification page returned by device approval responses. |
| `approval_methods` | CIBA and device authorization | Supported approval transports. |
| `jwks_uri` | `None` | Optional provider JWKS URI in discovery. |
| `capabilities` | empty | Configured capability catalog. |
| `require_auth_for_capabilities` | `false` | Makes capability list and description require a host or agent JWT. |
| `allowed_key_algorithms` | `Ed25519` | Accepted JWK curve names; these are not JWA algorithm identifiers. |
| `jwt_format` | `AgentJwtFormat::Simple` | Upstream JWT-format selection; the other public value is `AgentJwtFormat::Aap`. |
| `jwt_max_age` | 60 | Maximum JWT age. |
| `agent_session_ttl` | 3,600 | Sliding active session lifetime. |
| `max_agents_per_user` | 25 | Maximum active agents owned by one user. |
| `agent_max_lifetime` | 86,400 | Maximum active lifetime before reactivation. |
| `absolute_lifetime` | 0 | Disabled; a positive value is a non-renewable lifetime. |
| `fresh_session_window` | 300 | User-session freshness required by `session` approval strength. |
| `allow_dynamic_host_registration` | `false` | Unregistered hosts cannot bootstrap unless explicitly allowed. |
| `default_host_capabilities` | empty | Automatic-grant budget for hosts. |
| `blocked_capabilities` | empty | Capability patterns which can never be granted. |
| `jti_cache_storage` | `AgentCacheStorage::Memory` | Process-local replay reservations. |
| `jwks_cache_storage` | `AgentCacheStorage::Memory` | Process-local remote JWKS cache. |
| `dangerously_skip_jti_check` | `false` | Replay protection remains enabled. This should not be enabled in production. |
| `trust_proxy` | `false` | Forwarded protocol/host data is ignored while deriving JWT audiences. |
| `proof_of_presence` | disabled, no RP ID, no origins | Optional WebAuthn proof for `webauthn` approval strength. |
| `rate_limits` | empty override map | Uses the upstream per-route defaults described below. |

All callback fields default to `None`:

| Rust field and trait | Purpose |
| --- | --- |
| `resolve_fresh_session_window`: `AgentFreshSessionWindowResolver` | Resolve the freshness window for a capability request. |
| `resolve_dynamic_host_registration`: `AgentDynamicHostRegistrationResolver` | Override the static dynamic-registration decision for one request. |
| `resolve_default_host_capabilities`: `AgentDefaultHostCapabilitiesResolver` | Resolve a host's automatic-grant budget from mode, user, host, name, and endpoint context. |
| `resolve_approval_method`: `AgentApprovalMethodResolver` | Choose the approval method from the request and supported methods. |
| `validate_capabilities`: `AgentCapabilityValidator` | Apply an application validation decision to requested capability names. |
| `resolve_autonomous_user`: `AgentAutonomousUserResolver` | Supply the user projection for an autonomous agent session. |
| `on_host_claimed`: `AgentHostClaimedCallback` | Observe host ownership claims and account switches. |
| `resolve_grant_ttl`: `AgentGrantTtlResolver` | Resolve an optional grant expiry when no positive request TTL is supplied; the capability's `grant_ttl` is the fallback when no resolver is installed. |
| `on_event`: `AgentEventCallback` | Receive exact audit and `capability.executed` events. Delivery is asynchronous and callback errors never fail the originating request. |
| `resolve_capabilities`: `AgentCapabilitiesResolver` | Replace the visible capability list using query and optional agent/host sessions. |
| `resolve_query`: `AgentCapabilityQueryResolver` | Replace the built-in capability search result. |
| `on_execute`: `AgentExecuteHandler` | Execute default-location capabilities and return data, async, stream, or an exact API error. |
| `on_autonomous_agent_claimed`: `AgentAutonomousClaimedCallback` | Observe an autonomous agent being claimed by a user. |

The built-in plugin rate limits are 60-second windows: registration is 10,
agent key rotation and cleanup are 5, approval and CIBA authorization are 5,
status and CIBA polling are 300, and the remaining limited routes are 60.
`rate_limits` overrides these values by exact route path. Host routes have no
Agent Auth-specific limits, matching the pinned server runtime; the core global
limiter can still apply.

### Discovery and route ownership

The plugin mounts all 32 authoritative server routes under the configured auth
base path:

```text
GET  /agent-configuration
GET  /capability/list                 GET  /capability/describe
POST /capability/execute              POST /capability/batch-execute
POST /agent/register                  GET  /agent/list
GET  /agent/get                       POST /agent/update
POST /agent/revoke                    POST /agent/revoke-capability
POST /agent/rotate-key                POST /agent/reactivate
GET  /agent/session                   POST /agent/cleanup
POST /agent/request-capability        POST /agent/approve-capability
GET  /agent/status                    POST /agent/introspect
POST /agent/grant-capability          POST /agent/claim
POST /agent/ciba/authorize            GET  /agent/ciba/pending
POST /agent/device/code               POST /host/create
POST /host/enroll                     GET  /host/list
GET  /host/get                        POST /host/revoke
POST /host/switch-account             POST /host/update
POST /host/rotate-key
```

It also mounts origin-root `/.well-known/agent-configuration`, which is the
discovery URL advertised in `WWW-Authenticate`. The plugin-owned
`GET /agent-configuration` and the root route return the same
`version: "1.0-draft"` document with `Cache-Control: public, max-age=3600`, an
issuer without a trailing slash, `default_location` at the absolute execute
endpoint, curve-name algorithms, modes, approval methods, and absolute
`register`, `capabilities`, `describe_capability`, `execute`,
`request_capability`, `status`, `reactivate`, `revoke`, `revoke_host`,
`rotate_key`, `rotate_host_key`, and `introspect` endpoints. `jwks_uri` is
omitted unless configured.

There is deliberately no `/api/auth/agent/agent-configuration` alias. The
Agent Auth before hook is scoped to plugin-owned `/agent/*`, `/capability/*`,
and `/host/*` routes and does not consume Bearer credentials for core or other
plugins. Bootstrap verification for `/agent/register` and `/agent/claim` stays
inside those routes.

### Capabilities, constraints, and application routes

`AgentCapability` contains `name`, `description`, and optional absolute
`location`, input/output JSON Schema maps, `approval_strength`,
`required_constraints`, `grant_ttl`, and flattened metadata. A relative or
otherwise non-absolute `location` is rejected during plugin construction.
Capabilities without `location` execute through `/capability/execute` and
`on_execute`; the pinned runtime reports a missing handler as
`500 execute_not_configured`.

Requests accept either a capability name or `AgentCapabilityRequest::Constrained`.
Constraints support only `eq`, `min`, `max`, `in`, and `not_in`; a primitive is
an `eq` constraint. Matching supports exact names, global `*`, trailing
wildcards such as `github.*`, and provider-prefix stripping. Host defaults are
the automatic-grant budget. Requests inside that budget become active;
out-of-budget requests remain pending for approval. Constraints may only be
narrowed, and blocked capabilities, required constraints, TTL, status,
ownership, and expiry are enforced at the same boundaries as upstream.

A custom capability `location` does not call `on_execute`. The application
route owns delivery and constraint enforcement. Use `AgentRequestVerifier` or
`verify_agent_request(base_url, headers)` to resolve the Agent JWT through the
plugin's `/agent/session` endpoint, then require the expected active grant and
enforce its returned constraints before performing the operation. These
helpers return `None` for a missing or rejected credential; they do not turn a
custom route into an authorization policy automatically.

`AgentExecuteHandler` receives `AgentExecuteContext`, including the resolved
session, active grant, arguments, capability definition, endpoint context, and
an `AgentGrantRevoker` for one-use grants. `AgentExecuteResult::Data` produces
the normal `200` data envelope, `Async` produces the upstream `202` pending
shape and optional retry interval, and `Stream` produces SSE with supplied
headers. `AgentExecuteError::Api` preserves an intentional Agent Auth error;
other execution failures remain internal errors.

### Approval and lifecycle flows

Both upstream approval methods are implemented. Device authorization issues a
hashed, ambiguity-free eight-character user code displayed as `XXXX-XXXX`,
expires after 300 seconds, and polls at a five-second interval. CIBA uses host
authentication, preserves an indistinguishable successful authorization shape
for unknown login hints, and implements pending listing, expiry, interval, and
slow-down behavior. Approval strength `none` can auto-grant, `session` applies
the fresh-session policy, and `webauthn` applies proof of presence.

Lifecycle support includes delegated and autonomous registration, autonomous
claiming, host pre-enrollment and one-time enrollment, dynamic host
registration when explicitly enabled, agent and host key rotation, host account
switching, transparent and explicit reactivation, capability decay to host
defaults, cascading host/agent/grant revocation, and cleanup of expired agents
and approvals. Enrollment tokens are 32 random bytes returned once and stored
only as SHA-256 base64url hashes; device user codes are hash-only too. Agent and
host private keys remain client-held—the server stores only public JWK data or
JWKS URLs.

When `proof_of_presence.enabled` is true, install `PasskeyPlugin` in the same
`AuthConfig`. Agent Auth uses Better Auth passkey rows for user-verifying
WebAuthn assertions. `proof_of_presence.rp_id` may be omitted to use the request
host; configure `origins` when requests must be restricted to known origins.
Service initialization warns when proof of presence is enabled without the
passkey plugin because WebAuthn-gated approval cannot then succeed.

### Persistence and multi-instance security

The memory and PostgreSQL stores implement the same atomic registration,
approval, grant, enrollment, rotation, reactivation, account-switch, cleanup,
and cascading-revocation transitions. PostgreSQL uses transactions and
advisory/row locking for cross-instance state changes. Schema remapping applies
to all four plugin models and their relationships; it is not a second wire
contract.

The Agent Auth data store and its JWT caches are separate choices. In a
multi-instance deployment, use `PostgresAgentAuthStore` for durable plugin data,
set `AuthConfig.secondary_storage`, and select
`AgentCacheStorage::SecondaryStorage` for both `jti_cache_storage` and
`jwks_cache_storage`. This shares replay reservations and remote-JWKS cache
entries across instances. Selecting secondary cache storage without configuring
`AuthConfig.secondary_storage` falls back to process-local behavior, which is
not sufficient for cluster-wide replay protection. Leave
`dangerously_skip_jti_check` false.

JWT verification requires the official `host+jwt` or `agent+jwt` type, issuer
or subject identity, audience, short lifetime, signature, and the route's
ownership rules. Agent JWTs require `jti`; optional `capabilities`, `htm`,
`htu`, and `ath` claims narrow authority and bind a request. Replay reservations
are partitioned by authenticated identity. Remote JWKS URLs must be HTTPS and
pass SSRF, redirect, response-size, timeout, and key-selection controls; the
cache lasts five minutes and refreshes once for a missing `kid`.

### OpenAPI helpers

The public Rust equivalents of the documented `/openapi` exports are
`from_openapi`, `create_openapi_handler`, and `create_from_openapi`.
`from_openapi` converts operations with an `operationId` into capabilities.
It merges path, query, and header parameters with JSON request-body fields and
uses JSON response schemas from status 200 or 201 as capability output.
`create_openapi_handler` builds an `AgentExecuteHandler` which combines path,
query, header, and JSON-body arguments, can resolve additional headers, and
maps JSON, text, async, and SSE upstream responses. `create_from_openapi`
returns an `AgentOpenApiPreset`; call `apply_to(&mut config)` to install its
capabilities and handler, plus static or dynamic default host capabilities and
method-based or dynamic approval strength. A common absolute capability
location can also be assigned.

These helpers are scoped to Agent Auth. They are not a generic core proxy or a
replacement for a complete OpenAPI client.

### External clients and pinned upstream inconsistencies

The native server boundary is `@better-auth/agent-auth@0.6.2`. Its public
JavaScript root exports are `agentAuth`, `verifyAgentRequest`, `agentError`,
`AGENT_AUTH_ERROR_CODES`, `asyncResult`, `streamResult`, and types; `/client`
exports `agentAuthClient`, `agentError`, `agentAuthChallenge`,
`AGENT_AUTH_ERROR_CODES`, and types; `/openapi` exports `fromOpenAPI`,
`createOpenAPIHandler`, and `createFromOpenAPI`. Rust exposes native equivalents
where those operations belong on the server. Unpublished upstream `src/server/*`
modules are not compatibility surface.

`@auth/agent@0.6.2` and `@auth/agent-cli` remain external protocol clients.
Lucid-auth does not reimplement their credential storage, provider directory,
tools, model-provider adapters, CLI, or MCP transport. MCP support remains the
separate optional MCP/OAuth Provider integration.

The pinned official SDK and server disagree in the following places. The
server runtime is authoritative, and lucid-auth intentionally provides no
aliases or permissive alternate request/response shapes:

- `@auth/agent@0.6.2.rotateAgentKey()` sends only `public_key` under an agent JWT, while the server requires `agent_id`, `public_key`, and host-JWT ownership.
- The SDK host-key rotation lookup can disagree with dynamically registered thumbprint-based hosts.
- The published `AgentAuthPath` type omits `/agent/device/code`, although the runtime server route and client method table contain it.
- `agentAuthClient.pathMethods` omits `/agent/claim`, although the runtime server route and SDK contain it.
- SDK typing calls successful request-capability state `granted`, while the server runtime returns `active`.
- `@auth/agent@0.6.2.requestCapability()` replaces its complete locally stored grant list with the server's correctly request-scoped `agent_capability_grants`, so capabilities granted by earlier requests disappear from SDK-local state. Lucid-auth does not broaden the server response; clients must preserve or refresh their full grant view.
- `@auth/agent@0.6.2.claimAgent()` stores a newly generated agent keypair after a successful claim but does not send that public key to the server, replacing any matching local connection key with credentials the server cannot verify. Lucid-auth preserves the authoritative claim request and does not accept that unregistered key.
- SDK discovery probes deprecated `/api/auth/agent/agent-configuration`; lucid-auth exposes only the authoritative plugin route and origin-root well-known document.

## Security, utility, and developer plugins

| Plugin | Status | Tracking and limitations |
| --- | --- | --- |
| Have I Been Pwned | Partial | Native k-anonymity checker exists for current password flows. Endpoint/configuration parity is [#45](https://github.com/lucid-softworks/auth/issues/45). |
| Captcha | Supported | Optional `CaptchaPlugin` matches Better Auth 1.7.1's global `captcha()` server plugin for Cloudflare Turnstile, Google reCAPTCHA, hCaptcha, and CaptchaFox. It protects the exact default or replacement paths before route dispatch, uses the shared trusted client-IP policy, preserves wildcard and all-method interception, runs after the global limiter, sends the exact provider wire fields with a fixed 10-second timeout, and fails closed with the three compatible direct-middleware errors. There is no Captcha client plugin, route, schema, migration, cookie, rate rule, local replay store, custom provider, or fail-open mode; ordinary Better Auth clients supply `x-captcha-response` through `fetchOptions.headers`. Pinned evidence: [server source](https://github.com/better-auth/better-auth/tree/v1.7.1/packages/better-auth/src/plugins/captcha), [documentation](https://github.com/better-auth/better-auth/blob/v1.7.1/docs/content/docs/plugins/captcha.mdx), and [#41](https://github.com/lucid-softworks/auth/issues/41). |
| i18n | Supported | Optional `I18nPlugin` matches `@better-auth/i18n@1.7.1`: one catch-all after hook translates only marked Better Auth API errors by their exact string code, preserves status/code/headers/extensions, emits `originalMessage`, and leaves missing or empty entries untouched without a second default-catalog lookup. Header, cookie, session-user-field, and sync/async callback detection retain configured order and exact 1.7.1 matching quirks; default locale/cookie/field values and the empty-catalog error are compatible. `I18nLocales` ships the exact 22 published catalogs and 34 keys per locale. The official `i18nClient()` remains type-inference-only. There are no routes, locale input/API, locale persistence or cookie writer, models, migrations, owned cookies, rate rules, general response translation, regional negotiation, catalog loader, or global registry. Pinned evidence: [package source](https://github.com/better-auth/better-auth/tree/v1.7.1/packages/i18n), [documentation](https://github.com/better-auth/better-auth/blob/v1.7.1/docs/content/docs/plugins/i18n.mdx), and [#42](https://github.com/lucid-softworks/auth/issues/42). |
| Open API | Supported | Optional server-only `OpenApiPlugin` matches Better Auth 1.7.1's `openAPI()`: `GET /open-api/generate-schema`, the Scalar page at `/reference` or an exact custom path, all 12 themes, nonce placement, disabled-reference behavior, and empty 404s for unsupported methods. The OpenAPI 3.1.1 generator documents the pinned 30 core paths/32 operations plus installed plugin endpoint/model metadata, resolved additional fields, exact disabled paths, schema composition and required-body semantics, standard responses, unique operation IDs, and configured or request-derived auth base URL. `generate_open_api_schema(&AuthService)` provides the same document natively. The two Open API routes exclude themselves; there is no browser `openAPIClient`, generated client, persistence, migration, cookie, middleware, rate rule, or configurable schema path. Pinned evidence: [server source](https://github.com/better-auth/better-auth/tree/v1.7.1/packages/better-auth/src/plugins/open-api), [documentation](https://github.com/better-auth/better-auth/blob/v1.7.1/docs/content/docs/plugins/open-api.mdx), and [#43](https://github.com/lucid-softworks/auth/issues/43). |
| Test Utils | Supported | Optional server-only `TestUtilsPlugin` matches Better Auth 1.7.1's documented `testUtils()`: inert plugin metadata, non-persisting user and Organization factories, privileged core user save/delete, direct persistent sessions, raw `token.<base64-HMAC>` request/browser cookies, Organization-dependent raw save/member/delete helpers, and option-dependent passive OTP capture with instance isolation and the four exact identifier prefixes. `AuthService::test()` is absent unless the plugin is installed, and its Organization/OTP views are explicitly optional. Native IDs retain this crate's UUID representation; a configured `AuthIdGenerator` is honored and `None` uses a UUID fallback rather than JavaScript's 24-character fallback. Use a separate test-only auth configuration: the helper has no HTTP route, client, schema, migration, owned cookie, middleware, or rate rule, but its native methods deliberately bypass route authorization. The separate `better-auth/test` exports are Node/Vitest harness utilities and are not Rust/server compatibility claims. Pinned evidence: [plugin source](https://github.com/better-auth/better-auth/tree/v1.7.1/packages/better-auth/src/plugins/test-utils), [JavaScript harness source](https://github.com/better-auth/better-auth/tree/v1.7.1/packages/better-auth/src/test-utils), [documentation](https://github.com/better-auth/better-auth/blob/v1.7.1/docs/content/docs/plugins/test-utils.mdx), and [#44](https://github.com/lucid-softworks/auth/issues/44). |
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
| PostgreSQL | Supported | Core migrations include normalized email uniqueness, username-optional credential accounts, Better Auth 1.7 issuer-qualified OAuth accounts with optional access/refresh-token encryption, and atomic rolling request-rate-limit state. Optional plugins contribute their own tables. Lifecycle, same-subject/different-issuer identity, atomic provider-token rotation and final-account unlink protection, concurrent case-variant signup, plugin migration idempotence, organization ownership/invitation/team transactions, atomic session refresh/no-resurrection, verification reservation/update/delete/consume, request/API-key claims, and two-factor replay/backup-code/lockout writes run in the live contract. Broader schema generation is [#68](https://github.com/lucid-softworks/auth/issues/68). |
| Verification challenges | Supported | Purpose-scoped, expiring values support database and Better Auth secondary-storage authority, remaining-expiry TTLs, ordered plain/SHA-256-base64url/custom identifier storage, hashed-to-plain fallback, optional database mirroring, atomic consumption and reservation, and no-resurrection behavior; [#8](https://github.com/lucid-softworks/auth/issues/8) and [#79](https://github.com/lucid-softworks/auth/issues/79). |
| SQLite | Planned | [#61](https://github.com/lucid-softworks/auth/issues/61). |
| MySQL | Planned | [#62](https://github.com/lucid-softworks/auth/issues/62). |
| MongoDB | Planned | [#63](https://github.com/lucid-softworks/auth/issues/63). |
| MS SQL and generic relational adapters | Planned | [#64](https://github.com/lucid-softworks/auth/issues/64). |
| Secondary sessions, verification values, rate limits, and stateless sessions | Supported | Exact secondary primitive; authoritative session and verification routing; atomic verification `getAndDelete`; ordered identifier processing; optional database mirrors; update-age refresh with active-reference TTL renewal; stateless compact/JWT/JWE cache profiles; and default secondary rate limiting; [#58](https://github.com/lucid-softworks/auth/issues/58), [#79](https://github.com/lucid-softworks/auth/issues/79), and [#81](https://github.com/lucid-softworks/auth/issues/81). |
| Programmatic schema/migration diagnostics | Supported | Deterministic core/plugin plans derive tables, columns/types, and explicit indexes from migration SQL. In-process PostgreSQL diagnostics report pending/unknown/fingerprint drift and missing/mistyped objects without connection secrets; migration `0018` safely fingerprints existing installations; [#68](https://github.com/lucid-softworks/auth/issues/68). |
| Trusted origins, CSRF, redirect validation | Supported | Better Auth exact, wildcard, custom-scheme, and relative-path matching; same-origin requests; Fetch Metadata checks; and validation of all four redirect fields; [#5](https://github.com/lucid-softworks/auth/issues/5). |
| Base URL/path, CORS, and configurable cookies | Supported | Static base URL, custom route mount, trusted credentialed CORS, secure-name inference, cross-subdomain and per-cookie policy for session, cache, non-remembered, and account-data cookies; [#6](https://github.com/lucid-softworks/auth/issues/6) and [#80](https://github.com/lucid-softworks/auth/issues/80). |
| Trusted-proxy client IP resolution | Supported | Better Auth's ordered configurable headers, single-value handling without a proxy list, right-to-left trusted IP/CIDR chains, development/test localhost fallback, IPv4-mapped IPv6 and subnet normalization, and disabled tracking; [#7](https://github.com/lucid-softworks/auth/issues/7) and [#59](https://github.com/lucid-softworks/auth/issues/59). |
| Framework and production installation guides | Supported | Runnable memory/PostgreSQL Axum examples, explicit Cargo/client pins, React/Vue/Svelte/Solid/vanilla and SSR boundaries, plus proxy/TLS/cookie/CORS/migration guidance; [#65](https://github.com/lucid-softworks/auth/issues/65). |
| Browser extension clients | Supported | Standard official browser clients work with an exact extension trusted origin, credentialed CORS, and manifest host permission. Cookie availability remains subject to the browser/manifest policy. |
| Expo / React Native integration | Planned | The official `@better-auth/expo` client requires a matching native server plugin for cookie transport and deep-link behavior; [#77](https://github.com/lucid-softworks/auth/issues/77). |
| Electron integration | Planned | The official Electron client/proxy pair requires server-side transfer/code-exchange routes and plugin state; [#78](https://github.com/lucid-softworks/auth/issues/78). |

## TypeScript server and framework boundary

The official browser clients can target an HTTP-compatible Rust server. In
contrast, Better Auth server examples that import `betterAuth`, call `auth.api`,
register JavaScript callbacks, run Better Auth CLI migrations, or install an npm
server plugin are **not applicable directly**. The corresponding behavior must
be implemented through native Rust service APIs, traits, routes, and migrations.

Framework client integrations for React, Vue, Svelte, Solid, and vanilla clients
use the supported HTTP surface. Framework server adapters for Next.js,
SvelteKit, Nuxt, Astro, Hono, Express, and similar TypeScript runtimes are
replaced by the Axum router; see the
[framework guide](docs/frameworks.md) for same-origin proxying, SSR session
fetching, and the Expo/Electron protocol boundary.

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
