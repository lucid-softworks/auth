# lucid-auth

`lucid-auth` is a native Rust authentication backend for applications using
the official Better Auth JavaScript client. It implements a deliberately
tested Better Auth-compatible HTTP and session surface without executing or
embedding a JavaScript authentication server.

The compatibility target is Better Auth `1.7.1`. See the
[compatibility matrix](COMPATIBILITY.md) for method-level coverage, known
limitations, upgrade audit, and links to every tracked gap.

## Start here

- [Install and run the memory or PostgreSQL server](docs/installation.md)
- [Connect React, Vue, Svelte, Solid, vanilla, SSR, and extension clients](docs/frameworks.md)
- [Review the production proxy, TLS, cookie, CORS, secret, and migration checklist](docs/production.md)
- [Choose only supported core methods and plugins](COMPATIBILITY.md)

The crate targets Rust 1.90 and Axum 0.8. The official client must be pinned to
Better Auth 1.7.1. From a checkout, this starts the CI-compiled memory example:

```sh
export BETTER_AUTH_SECRET="$(openssl rand -base64 32)"
export BETTER_AUTH_URL="http://localhost:3000"
export FRONTEND_ORIGIN="http://localhost:5173"
cargo run --example http_memory --features axum
```

The currently supported surface covers:

- `getSession` and `useSession`
- core email/password signup, signin, and current-password verification
- durable email verification with a native async delivery callback
- enumeration-resistant password-reset email and single-use reset redemption
- the complete official `emailOTPClient` surface as an optional native plugin
- the complete official `phoneNumberClient` surface as an optional native plugin
- the official Google `oneTapClient` callback surface as an optional native plugin
- the complete official `multiSessionClient` surface as an optional native plugin
- the complete official `lastLoginMethodClient` surface as an optional native plugin
- the complete Better Auth username lifecycle as an optional native plugin
- sign-out
- the complete official anonymous client lifecycle as an optional native plugin
- the complete `@better-auth/passkey` client surface as an optional native plugin
- the complete official `twoFactorClient` surface as an optional native plugin,
  including TOTP, delivered OTP, backup codes, and trusted devices
- password changes plus current-user session listing and revocation
- typed current-user and current-session additional-field updates
- immediate, verified, and current-address-confirmed email changes
- password, fresh-session, and email-confirmed current-user deletion
- native social OAuth/OIDC sign-in and callbacks for every Better Auth 1.7.1
  built-in provider, with issuer-qualified accounts and optional provider-token encryption
- the complete linked-account lifecycle: `listAccounts`, `linkSocial`,
  `unlinkAccount`, `accountInfo`, `getAccessToken`, and `refreshToken`
- passkey rename and removal
- all 15 official admin-client methods, including configurable permissions,
  filtering, additional fields, session revocation, bans, and impersonation
- the complete official `organizationClient` surface as an optional native plugin,
  including invitations, teams, custom roles, and organization-owned API keys
- optional HIBP Pwned Passwords screening with Better Auth-compatible errors
- Better Auth request rate limiting with global, special-route, plugin, and custom rules
- optional operator-security policy for managed password replacement and local recovery
- the complete user-owned `@better-auth/api-key` client surface as an optional
  native plugin, including pagination, metadata, permissions, quotas, rate limits,
  configuration profiles, and API-key-backed sessions
- Better Auth-compatible cookies and response shapes for the supported routes
- native, dependency-ordered plugin routes, middleware, hooks, migrations, and
  client compatibility metadata

The library keeps authentication protocol details separate from host-product
authorization. Core principals contain actor, subject, session, and credential
provenance only. An explicitly enabled host-policy plugin may project a role;
core-only principals leave it unset.

Social providers use the same `signIn.social` and `/callback/:provider` wire
contract as Better Auth. Register a built-in after setting the public base URL:

```rust
config.set_base_url("https://auth.example.com")?;
config.add_social_provider(BuiltinProvider::new(
    BuiltinProviderKind::Google,
    std::env::var("GOOGLE_CLIENT_ID")?,
    std::env::var("GOOGLE_CLIENT_SECRET")?,
))?;
```

The built-in vocabulary is Apple, Atlassian, Cognito, Discord, Dropbox,
Facebook, Figma, GitHub, GitLab, Google, Hugging Face, Kakao, Kick, LINE,
Linear, LinkedIn, Microsoft, Naver, Notion, Paybin, PayPal, Polar, Railway,
Reddit, Roblox, Salesforce, Slack, Spotify, TikTok, Twitch, X/Twitter, Vercel,
VK, WeChat, and Zoom. Cognito, self-hosted GitLab, and tenant-specific Microsoft
setups have focused constructors; `config_mut` exposes documented endpoint,
scope, token-authentication, and profile policies. Implement `SocialProvider`
to add a provider without changing OAuth state, callback, account, token, or
session orchestration.

Better Auth's `genericOAuth` plugin is available through an async initialization
step because discovery is fetched before providers are registered:

```rust
let mut provider = GenericOAuthConfig::new("company-sso", client_id);
provider.client_secret = Some(client_secret);
provider.discovery_url =
    Some("https://id.example.com/.well-known/openid-configuration".into());

config.add_plugin(
    GenericOAuthPlugin::initialize(vec![provider]).await?
)?;
```

Generic providers use only `signIn.social` and `/callback/:id`; there is no
generic-OAuth client plugin or plugin-specific route. `GenericOAuthConfig`
supports Better Auth 1.7.1 discovery, explicit endpoint precedence, stable
subject/issuer resolvers, PKCE, OIDC nonce/JWKS verification, every token
endpoint authentication method (including callback-driven
`private_key_jwt`), custom token/user/profile callbacks, static or
request-aware refresh parameters, provider logout, IDP-initiated restart, and
the signup/profile controls. The exported presets are `auth0`, `gumroad`,
`hubspot`, `keycloak`, `line`, `microsoft_entra_id`, `okta`, `patreon`,
`slack`, and `yandex`. Microsoft Entra's generic preset requires a concrete
tenant GUID; use the built-in Microsoft provider for `common`,
`organizations`, or `consumers`.

OAuth state is expiring and single-use. The default database strategy uses the
verification store plus a signed `state` cookie; the Better Auth encrypted
cookie strategy is selected with:

```rust
config.account.store_state_strategy = OAuthStateStrategy::Cookie;
```

PKCE,
OIDC nonce, signature, issuer, audience, maximum-age, and redirect-URI checks
are provider-driven. Accounts use Better Auth 1.7's `(issuer, accountId)` key;
access and refresh tokens are stored as returned by default and use Better
Auth's randomized XChaCha20-Poly1305 hex envelopes only when
`config.account.encrypt_oauth_tokens = true`. ID tokens follow Better Auth and
remain unencrypted. PostgreSQL migration `0015_oauth_accounts.sql`
deliberately replaces the old provider-qualified uniqueness model rather than
retaining an incompatible fallback.

Linked-account policy lives under `config.account.account_linking`. Explicit
links require a provider-verified email unless the provider is trusted, require
the current user's email by default, and cannot unlink the final account unless
`allow_unlinking_all` is enabled. Provider-token reads and rotations remain
session-bound to the account owner; refresh rotation uses an atomic
compare-and-swap so concurrent requests return the winning token set.

Better Auth's optional encrypted account-data cookie is also supported. It is
disabled by default when using the database-backed account store. Enable it
when clients need explicit `useAccountCookie: true` selection:

```rust
config.account.store_account_cookie = true;
```

Social sign-in and account linking select the provider account in
`better-auth.account_data`. `getAccessToken`, `refreshToken`, and `accountInfo`
accept that cookie only when the request explicitly selects it and an active
session belongs to the same user; the cookie is never a bearer credential.
The A256CBC-HS512 JWE uses Better Auth's `better-auth-account` salt, expires at
`session.cookie_cache.max_age`, refreshes with session/account changes, and is
cleared on session removal or a cross-user session switch. Oversized values use
Better Auth's numbered-cookie chunking and stale-chunk cleanup. Override its
name or scope with `config.cookies.account_data`.

Request rate limiting follows Better Auth's IP-and-path model. Release builds
enable the production default; debug builds mirror Better Auth development and
test mode by leaving it disabled unless explicitly enabled. Better Auth's
10-second/100-request global rule, stricter sign-in/sign-up/password/email
rules, plugin rules, ordered wildcard custom rules, and `false`-equivalent
path exclusions use the same precedence:

```rust
use lucid_auth::{RateLimitCustomRule, RateLimitStorageMode};

config.rate_limit.enabled = true;
config.rate_limit.window = 10;
config.rate_limit.max = 100;
config.rate_limit.storage = RateLimitStorageMode::Database;
config.rate_limit.custom_rules = vec![
    RateLimitCustomRule::limit("/admin/*", 60, 20),
    RateLimitCustomRule::disabled("/health"),
];
```

Use `RateLimitCustomRule::dynamic` with a `RateLimitRuleResolver` when the
decision depends on the request method, normalized path, query, or headers; a
resolver returning `None` is Better Auth's functional `false` result.

`Memory` is the default for a single service process. `Database` uses the
configured `AuthStore` and PostgreSQL advisory locking for atomic limits across
instances. `SecondaryStorage` and `Custom` accept an `Arc<dyn
RateLimitStorage>` whose single `consume` operation must atomically decide and
increment, matching Better Auth's storage hook. A rejected request returns only
`{"message":"Too many requests. Please try again later."}`, status 429, and
`X-Retry-After` in seconds. IP tracking disabled under
`config.ip_address.disable_ip_tracking` disables request limiting too; native
in-process `AuthService` calls are outside the HTTP limiter, matching Better
Auth server-side API behavior.

Username is an optional native plugin. Register it explicitly to add username
fields to email signup and current-user updates and to mount the official
username sign-in and availability routes:

```rust
config.add_plugin(UsernamePlugin::default())?;
```

This route boundary is separate from `AuthService::provision_password_user`, so
closed-registration applications can still provision and authenticate native
username accounts without exposing Better Auth's public username plugin.

Last Login Method is also optional. It writes Better Auth's unsigned,
browser-readable cookie only when an authentication response sets the primary
session cookie:

```rust
config.add_plugin(LastLoginMethodPlugin::default())?;
```

The exact default resolver recognizes email signup/signin, social and Generic
OAuth callbacks, SIWE, passkey verification, and magic-link verification. Set
`custom_resolve_method` to replace or extend that vocabulary, and use
`before_store_cookie` for an async consent decision. Returning `None` from the
custom resolver falls back to the defaults; returning an empty string suppresses
storage. Enable `store_in_database` to add the optional, input-disabled
`lastLoginMethod` user field and update it independently of cookie consent.
The bundled stores persist that logical field in existing user additional-field
storage, so this plugin has no standalone migration. The cookie is plaintext by
design; custom method names must not contain secrets or sensitive attributes.
`cookie_name`, floating-point `max_age`, and the user schema field name follow
Better Auth 1.7.1, including URI encoding and its 400-day cookie limit. The
official client reads and compares the cookie synchronously and can clear it;
its optional `domain` setting affects clearing only.

Additional fields for Better Auth's user, session, account, and verification
models are explicit and typed. Core and plugin schema descriptors are merged in
dependency order and available through `AuthService::database_schema_fields`.
Creation applies required/default rules plus input validators and transforms;
updates also apply `on_update_with`; responses apply returned/output policy.
Core IDs, tokens, ownership, timestamps, expiry, and input-disabled fields are
never writable. Set `returned(false)` for persisted server-only values:

```rust
config.user.additional_fields.insert(
    "timezone".into(),
    AdditionalField::new(AdditionalFieldType::String).default_value(json!("UTC")),
);
config.session.additional_fields.insert(
    "theme".into(),
    AdditionalField::new(AdditionalFieldType::String).optional(),
);
config.account.additional_fields.insert(
    "tenantReference".into(),
    AdditionalField::new(AdditionalFieldType::String).optional(),
);
config.user.additional_fields.insert(
    "managedFlag".into(),
    AdditionalField::new(AdditionalFieldType::Boolean)
        .optional()
        .input(false)
        .returned(false),
);
```

PostgreSQL migrations `0014_session_additional_fields.sql` and
`0017_database_additional_fields.sql` add durable JSONB storage for session,
account, and verification fields. User fields use the existing JSONB store.

Set `AuthConfig::database_hooks` for host hooks or implement
`AuthPlugin::database_hooks` for plugin hooks. Before hooks run in plugin
dependency order and then host order; they can continue, replace a typed record,
or cancel. A cancellation or error prevents the authoritative write. After
hooks run in the same order after persistence has committed, so an after-hook
error is reported but does not roll the write back. HTTP calls include method,
path, query, and headers in `DatabaseHookContext`; native calls have no request.
`run_in_background` schedules non-authoritative follow-up work. Update hooks may
not change protected identity, ownership, or creation fields.

Email changes are disabled by default, matching Better Auth. Enable the
verified flow with the existing verification-email sender:

```rust
config.user.change_email.enabled = true;
config.email_verification.sender = Some(Arc::new(MyVerificationSender));
```

For an unverified current address, setting
`update_email_without_verification = true` changes it immediately and then
sends normal verification when a sender is configured. For verified accounts,
the default sends verification to the new address. Configure
`send_change_email_confirmation` to require approval from the current address
before the new-address verification is sent. Email normalization, uniqueness,
single-use tokens, callback URLs, and session-cookie refresh are enforced in
every mode.

Better Auth anonymous users are an optional plugin and their routes and
`isAnonymous` user field are absent until it is registered:

```rust
config.add_plugin(AnonymousPlugin::new(AnonymousPluginConfig {
    email_domain_name: Some("guests.example.com".into()),
    ..AnonymousPluginConfig::default()
}))?;
```

The plugin supports `signIn.anonymous` and `deleteAnonymousUser`, configurable
name/email generators, deletion policy, and a typed `on_link_account` callback.
Successful email/password, username, and social sign-ins atomically claim the
anonymous upgrade, invoke the callback once, and clean up the anonymous user
and all of its sessions. Abandoned or concurrent attempts cannot invoke the
callback twice.

Guest capability grants are a lucid-auth extension, not part of Better Auth's
Anonymous plugin lifecycle. They are therefore absent by default and are never
claimed or deleted by anonymous-account conversion. Register the optional
plugin with its extension store to mount `/guest-grants`,
`/guest-grants/revoke`, and `/sign-in/guest-grant`:

```rust
let store = Arc::new(MemoryStore::default());
config.add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))?;
config.add_plugin(OwnerPolicyPlugin)?;
config.add_plugin(GuestCapabilityPlugin::new(store.clone()))?;
let auth = AuthService::new(store, config);
```

The bearer token is returned only when a grant is issued. Native hosts can use
`AuthService::guest_capability_principal` to obtain its permissions and resource
scopes. A custom browser client can call the plugin route directly:

```js
await fetch("/api/auth/sign-in/guest-grant", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ token }),
});
```

For PostgreSQL, apply `AuthService::plugin_migrations()` after core migrations.
New core installations do not create guest-capability tables. On an older
lucid-auth database, enabling the plugin preserves existing grants, migrates
legacy session links, and removes the old core session column; leaving it
disabled retains the legacy grant table as unused data.

Product security auditing is another optional lucid-auth extension. Core stores
have no audit methods, core migrations create no audit table, and
`/access/audit` is absent unless `AuditPlugin` is registered. Memory-backed
applications provide a separate sink:

```rust
let auth_store = Arc::new(MemoryStore::default());
let audit_store = Arc::new(MemoryAuditStore::default());
config.add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))?;
config.add_plugin(OwnerPolicyPlugin)?;
config.add_plugin(AuditPlugin::new(audit_store).with_max_events(10_000))?;
let auth = AuthService::new(auth_store, config);
```

For PostgreSQL, pass the same `Arc<PostgresStore>` to `AuditPlugin` and apply the
service's plugin migrations. The plugin owns its table, retention operation,
and owner-only listing route. Both bundled stores return newest-first events,
ordering equal timestamps by event ID. Recording is deliberately fail-open: a
sink failure never rolls back a completed authentication or administrative
write, while an explicit audit-list request reports sink errors. User deletion
anonymizes actor and subject references. `AuditMetadata` recursively rejects
password-, cookie-, token-, OTP-, secret-, challenge-, API-key-, and
credential-bearing field names, including authorization and bearer fields; the
same validation runs during deserialization.

Audit action vocabulary version `2` contains `operator_security.owner_recovered`,
`user.created`, `user.role.changed`, `user.banned`, `user.unbanned`,
`user.removed`, `password.changed`, `password.reset_by_owner`,
`session.revoked`, `session.user_revoked`, `session.others_revoked`,
`session.all_revoked`, `impersonation.started`, `impersonation.stopped`,
`passkey.enrolled`, `passkey.renamed`, `passkey.deleted`,
`step_up.recovery_codes.generated`, `step_up.recovery_code.used`,
`guest_grant.issued`, `guest_grant.redeemed`, and `guest_grant.revoked`. This
native vocabulary is not Better Auth Infrastructure Dashboard audit-log
compatibility.

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

Role-driven passkey assurance, step-up enforcement, and the associated recovery
codes are provided only by the optional `StepUpPolicyPlugin`; they are not
Better Auth passkey behavior. Core password sign-in always returns a normal
Better Auth session, and core session JSON contains neither `assurance` nor
`stepUpRequired`.

```rust
let auth_store = Arc::new(MemoryStore::default());
let step_up_store = Arc::new(MemoryStepUpStore::default());
config.add_plugin(StepUpPolicyPlugin::new(
    auth_store.clone(),
    step_up_store,
    StepUpPolicyConfig {
        required_roles: vec!["admin".into()],
        ..StepUpPolicyConfig::default()
    },
))?;
let auth = AuthService::new(auth_store, config);
```

The plugin protects only the configured roles; its neutral default protects no
roles. `OwnerPolicyPlugin::step_up_config()` supplies the fixed-policy `owner`
preset. Step-Up freshness defaults to one day after a passkey, two-factor, or
recovery-code verification. It owns its state and recovery-code
storage, contributes its PostgreSQL migration, composes independently with
`PasskeyPlugin` and `TwoFactorPlugin`, and exposes recovery operations through
`AuthService::step_up_policy`. Its typed `session_projection` is the native host
view of assurance, freshness, and whether step-up is required. Enabling the
plugin invalidates pre-existing sessions for required roles because those
sessions have no authenticated plugin state. The plugin intentionally adds no
Better Auth routes or response fields; applications that want browser-visible
prompts must provide their own extension client.

Sole-owner recovery and custom owner policy are separate optional project
extensions documented in [#73](https://github.com/lucid-softworks/auth/issues/73)
and [#75](https://github.com/lucid-softworks/auth/issues/75). Better Auth passkey
endpoints do not impose those policies.

Two-Factor Authentication is an independent optional plugin. Memory-backed
applications provide a separate factor store and an OTP delivery callback:

```rust
#[async_trait]
impl TwoFactorOtpSender for MyOtpSender {
    async fn send(&self, message: TwoFactorOtp) -> Result<(), AuthError> {
        deliver_code(&message.user, &message.code).await
    }
}

let factors = Arc::new(MemoryTwoFactorStore::default());
let mut two_factor = TwoFactorConfig::default();
two_factor.issuer = Some("Example".into());
two_factor.otp = Some(OtpConfig::new(Arc::new(MyOtpSender)));
config.add_plugin(TwoFactorPlugin::new(factors, two_factor))?;
```

PostgreSQL applications pass the same `Arc<PostgresStore>` used for core auth
and apply the service's plugin migrations. The plugin owns
`lucid_auth_two_factors`; core migration does not create it. The official
`twoFactorClient` enable/disable, TOTP, OTP, and backup-code methods then work
without a custom browser transport. `AuthService::generate_two_factor_totp` and
`AuthService::view_two_factor_backup_codes` are trusted server-only equivalents
of Better Auth's server APIs and must never be exposed without application-level
authorization.

TOTP secrets and backup-code lists use authenticated encryption at rest. OTPs
are persisted only as one-way hashes, TOTP counters and backup-code replacements
are atomic, sign-in challenges have a five-attempt budget, consecutive factor
failures lock the account by default, and trusted-device records rotate on use
and expire after 30 days. Configure those durations and budgets through
`TwoFactorConfig`; disabling the plugin removes all two-factor routes and its
`twoFactorEnabled` user field.

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

Email OTP is also optional. Implement `EmailOtpSender` and register the plugin;
the official Better Auth 1.7.1 `emailOTPClient` then supports verification,
passwordless sign-in/signup, password reset, and configured email changes:

```rust
let mut email_otp = EmailOtpConfig::new(Arc::new(MyEmailOtpSender));
email_otp.storage = EmailOtpStorage::Hashed;
email_otp.change_email.enabled = true;
config.add_plugin(EmailOtpPlugin::new(email_otp))?;
```

Defaults match Better Auth: six numeric digits, a 300-second expiry, three
attempts, rotating resends, plain storage, disabled signup-triggered delivery,
and disabled email change. Select `Hashed`, `Encrypted`, or a custom storage
adapter when persisted OTP secrecy is required. Successful redemption is
atomic; unknown-user verification and reset sends remain enumeration-safe.
`send_verification_on_sign_up` and `override_default_email_verification` mirror
the Better Auth plugin options. Native code can also call `create_email_otp` and
`get_email_otp`, corresponding to Better Auth's server-only APIs.

Phone Number is an optional native plugin. Supply the same memory or PostgreSQL
store used by `AuthService`, an OTP sender, and—when OTP verification may create
users—a temporary-email resolver:

```rust
let phone_number = PhoneNumberConfig {
    send_otp: Some(Arc::new(MyPhoneOtpSender)),
    send_password_reset_otp: Some(Arc::new(MyPhoneResetOtpSender)),
    sign_up_on_verification: Some(PhoneNumberSignUpConfig {
        temporary_email: Arc::new(MyTemporaryPhoneEmail),
        temporary_name: None,
    }),
    ..PhoneNumberConfig::default()
};
config.add_plugin(PhoneNumberPlugin::new(store.clone(), phone_number))?;
```

The official Better Auth 1.7.1 `phoneNumberClient` supports opaque phone strings
by default; format validation is opt-in through `PhoneNumberValidator`. Its
defaults are six numeric digits, a 300-second expiry, three attempts, optional
signup after verification, and password-based `signIn.phoneNumber`. OTP
verification is the passwordless session/signup flow. The plugin also implements
password-reset SMS delivery, authenticated phone replacement, atomic uniqueness,
custom schema field names, and the native server-only `consume_phone_number_otp`
API. `updateUser` may clear
`phoneNumber` with `null`, which also clears verification, but cannot set or
replace it directly. PostgreSQL deployments must apply the service's plugin
migrations so the unique phone-number index is present.

Google One Tap is an optional native plugin. Give `OneTapConfig` a Google web
client ID, or omit it to reuse the client ID from a registered Google social
provider:

```rust
let mut google = BuiltinProvider::new(
    BuiltinProviderKind::Google,
    std::env::var("GOOGLE_CLIENT_ID")?,
    std::env::var("GOOGLE_CLIENT_SECRET")?,
);
google.config_mut().hosted_domain = Some("example.com".into());
config.add_social_provider(google)?;

// When omitted, the registered Google provider's client ID is used.
let one_tap = OneTapConfig::default();
config.add_plugin(OneTapPlugin::new(one_tap))?;
```

Register Better Auth 1.7.1's client plugin with the same Google web client ID:

```ts
import { createAuthClient } from "better-auth/client";
import { oneTapClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
  plugins: [oneTapClient({ clientId: googleClientId })],
});

await authClient.oneTap({ callbackURL: "/dashboard" });
```

The plugin ID is `one-tap`, the client factory/action are
`oneTapClient`/`oneTap`, and the only server route is
`POST /one-tap/callback` under the configured auth base path.
The official client loads Google Identity Services, renders or prompts in the
browser, and enables FedCM by default; One Tap is therefore browser-only and an
SSR invocation intentionally does nothing. `promptOptions.fedCM: false` selects
the non-FedCM prompt behavior supported by the official client. Prompt mode
retries with a one-second base delay for up to five attempts by default, while
button mode renders Google's button instead. The official client also prevents
silent Google access after sign-out. An action-level `nonce` is forwarded to
Google Identity Services only; Better Auth 1.7.1 does not send it to or validate
it at the callback route.

`callbackURL` is validated by the server's trusted-origin policy, but the
callback response is `{ token, user }` and the server never redirects. After a
successful callback, the official browser client performs the navigation.
`hosted_domain` enforces Google's `hd` claim for both Google OAuth and One Tap;
use `"*"` to require any non-empty hosted-domain claim. One Tap otherwise uses
the normal Google account linking, signup, session, anonymous-upgrade, and
email-verification policies. The plugin adds no schema, migration, cookie, or
plugin-specific rate-limit declaration.

Sign In With Ethereum is an optional native plugin. Supply the shared memory or
PostgreSQL store, a nonce generator, and the application-specific Ethereum
signature verifier:

```rust
let mut siwe = SiweConfig::new(
    "example.com",
    Arc::new(MySiweNonceGenerator),
    Arc::new(MySiweMessageVerifier),
);
siwe.email_domain_name = Some("example.com".into());
siwe.ens_lookup = Some(Arc::new(MyEnsLookup));
config.add_plugin(SiwePlugin::new(store.clone(), siwe))?;
```

`SiweNonceGenerator` must return 8–250 ASCII alphanumeric characters.
`SiweMessageVerifier` receives the original message and signature, EIP-55
checksummed address, numeric chain ID, and Better Auth's CAIP-122 projection.
The nonce is stored for 15 minutes and is consumed as soon as a syntactically
valid nonce is parsed, before domain, address, chain, time, or signature checks.
This ordering and the deliberately narrow message parser match Better Auth
1.7.1 exactly.

Use the official client without a Lucid-specific adapter:

```ts
import { createAuthClient } from "better-auth/client";
import { siweClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
  plugins: [siweClient()],
});

const { data: nonce } = await authClient.siwe.nonce();
const result = await authClient.siwe.verify({ message, signature });
```

The plugin exposes `POST /siwe/nonce`, its `POST /siwe/get-nonce` alias, and
`POST /siwe/verify`. Verification returns exactly
`{ token, success: true, user: { id, walletAddress, chainId } }` and creates a
normal session. Anonymous mode is enabled by default
and generates the same wallet-derived email shape as Better Auth; disabling it
requires a valid `email`. A wallet seen on another chain reuses its existing
user and adds a non-primary wallet/account identity. PostgreSQL deployments
must apply the plugin migration for the configured wallet-address model (the
default table is `lucid_auth_wallet_addresses`).

Organization is an optional native plugin. Its store is independent from the
core authentication store and can use either memory or PostgreSQL:

```rust
let organizations = Arc::new(MemoryOrganizationStore::default());
let organization = OrganizationPluginConfig {
    teams: OrganizationTeamsConfig {
        enabled: true,
        ..OrganizationTeamsConfig::default()
    },
    dynamic_access_control: OrganizationDynamicAccessControlConfig {
        enabled: true,
        ..OrganizationDynamicAccessControlConfig::default()
    },
    ..OrganizationPluginConfig::default()
};
config.add_plugin(OrganizationPlugin::with_config(organizations, organization))?;
```

The plugin implements every Better Auth 1.7.1 `organizationClient` method for
organizations, active state, members, invitations, teams, permissions, and
dynamic roles. Limits and last-owner rules are enforced atomically. Invitation
delivery, creation policy, and all documented organization/member/invitation/team
lifecycle hooks have native async traits. PostgreSQL users pass the shared
`PostgresStore` and apply the plugin migration described below.

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
permissions, refills, and per-key rate limits are supported. Set a named
configuration's `reference` to `ApiKeyReference::Organization` to require the
Organization plugin and enforce its `apiKey` create/read/update/delete
permissions. Advanced request callbacks and secondary/custom-storage profiles are tracked in
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
let report = store.migrate_all(&service.plugin_migrations()).await?;
assert!(report.compatible);
```

Plugin migrations are keyed by `(plugin_id, migration_id)`, share the core
advisory migration lock, and are transactional and idempotent. See the
[native plugin example](examples/native_plugin.rs) for a route, middleware,
migration, cookie/rate-limit declarations, and official-client metadata.

`PostgresStore::migration_plan` discovers the deterministic ordered core/plugin
migrations and derives their final tables, columns/types, and explicit indexes
directly from the checked-in SQL. `diagnose_schema` is a read-only in-process
catalog check for pending or unknown migrations, changed descriptions or
SHA-256 fingerprints, and missing/mistyped physical objects. Reports contain
only migration/object identifiers and never receive or serialize a database
URL. Existing installations gain fingerprints through migration `0018`; a
nonempty checksum mismatch is rejected instead of silently accepting edited
migration history.

The Better Auth Admin surface is absent unless `AdminPlugin` is registered:

```rust
config.add_plugin(AdminPlugin::default())?;
```

It uses `AdminConfig` and defaults to the official `admin` and `user` roles.
`AdminRole::allow` defines custom resource/action
statements, `admin_user_ids` grants access independently of role, and
`default_role`, ban defaults/message, and impersonation duration mirror the
documented plugin options. Administrator impersonation remains disabled unless
`allow_impersonating_admins` is enabled or a custom role grants
`user:impersonate-admins`. Role arrays are stored as Better Auth's comma-joined
role value. The official client can create passwordless users, preserve
additional fields, query and update users, check permissions, manage bans and
sessions, and enter or stop bounded impersonation sessions.

Without `AdminPlugin`, Admin routes are not mounted and Admin's `role`, `banned`,
`banReason`, and `banExpires` user fields are omitted. Core logic does not
interpret those fields. To opt into lucid-auth's fixed owner/member/viewer
product policy, compose the separate host-policy plugin with its exact Admin
configuration:

```rust
config.add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))?;
config.add_plugin(OwnerPolicyPlugin)?;
```

`OwnerPolicyPlugin` alone is rejected, as is pairing it with a different Admin
role configuration. It owns the fixed role vocabulary, owner-only gates,
last-owner invariant, owner-promotion session revocation, and owner-oriented
defaults used by Guest Capability, Audit, and Operator Security. Generic Admin
does not retain any of those rules as compatibility aliases.

For an existing PostgreSQL installation, make an explicit migration choice
before serving traffic:

- To retain existing `owner`, `member`, and `viewer` values, register the exact
  pair above and apply all plugin migrations.
- To adopt Better Auth Admin directly, register `AdminPlugin` with roles that
  match the values you intentionally keep, or rewrite persisted role values to
  the configured Better Auth roles in an application migration.
- To run core-only, register neither plugin. The bundled store leaves legacy
  Admin columns dormant, while HTTP schemas and principals omit their values.

The bundled stores physically colocate Better Auth Admin values with their user
records for atomic reads; `AdminPlugin` is their sole behavioral owner. The
owner-policy plugin adds no duplicate role or ban storage.

Managed temporary passwords and local sole-owner recovery are optional lucid
operator policy, not Better Auth Admin behavior. Default and Admin-only user
responses contain no `mustChangePassword` field, and creating or resetting a
user password does not silently restrict that account.

Register `OperatorSecurityPlugin` to opt into administrator-issued temporary
credentials and native recovery:

```rust
let store = Arc::new(MemoryStore::default());
config.add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))?;
config.add_plugin(OwnerPolicyPlugin)?;
config.add_plugin(OperatorSecurityPlugin::new(
    store.clone(),
    OperatorSecurityConfig::default(),
))?;
let auth = AuthService::new(store, config);
```

The plugin exposes temporary-credential status separately from Better Auth user
JSON. `AuthService::principal` and sensitive plugin hooks reject access until
the official change-password flow clears the plugin state. Provisioned bootstrap
passwords can opt into the same policy through `OperatorSecurityConfig`.

`AuthService::operator_security().local_recover_sole_owner` is an explicitly
out-of-band native primitive for a host CLI. It atomically refuses multi-owner
installations, replaces the sole owner's password, clears bans, sessions,
passkeys, API keys, and enabled factor-plugin state, marks the replacement
temporary, and records an actorless audit event when `AuditPlugin` is enabled.
The operator plugin contributes no HTTP endpoint. Its PostgreSQL migration owns
the temporary-password table and consumes the legacy core column without keeping
a compatibility alias.

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
IP-address options. Better Auth's separate `trustedProxyHeaders` URL behavior is
disabled by default; set `config.trusted_proxy_headers = true` only when a
trusted edge overwrites both `x-forwarded-host` and `x-forwarded-proto`.

Routes mount at `/api/auth` by default. `AuthConfig::set_base_url` and
`set_base_path` configure HTTPS production origins and custom mounts; an HTTPS
base URL also selects Better Auth's `__Secure-` cookie names. `CookieConfig`
supports the Better Auth prefix, per-cookie names and attributes, and optional
cross-subdomain scope. Call `AuthConfig::enable_cors` to answer credentialed
preflights for trusted origins; untrusted origins remain blocked by the same
CSRF policy.

Session storage and cookie caching follow Better Auth's separate primary-token
and `session_data` design. The default remains database-backed with cookie cache
disabled. To enable the default compact cache:

```rust
config.session.cookie_cache.enabled = true;
```

Set `CookieCacheStrategy::Jwt` for HS256 or `CookieCacheStrategy::Jwe` for
Better Auth's HKDF-derived A256CBC-HS512 encrypted profile. `max_age`,
`refresh_cache`, and `version` correspond to Better Auth's `cookieCache`
settings; changing `version` invalidates existing caches. Large cache values are
split into Better Auth-compatible numbered cookies.

Database and secondary-backed sessions slide at Better Auth's one-day
`updateAge` by default. Set `config.session.update_age`, or set
`disable_session_refresh` to suppress automatic writes. With
`defer_session_refresh`, `GET /get-session` is write-free and returns the exact
camelCase `needsRefresh` flag; Better Auth's client then uses
`POST /get-session` to perform the refresh. POST is rejected with 405 unless
that mode is enabled. `disableRefresh=true` suppresses one request, and
`rememberMe: false` uses Better Auth's signed `dont_remember` cookie so the
one-day session never slides and renewed cookies remain non-persistent.

Set `config.secondary_storage` to an `Arc<dyn SecondaryStorage>` to make it the
authoritative live-session and verification-value store. Verification records
use `verification:<processed identifier>` keys, remaining-expiry TTLs, and
atomic `getAndDelete` consumption. `verification.store_in_database` adds a
durable mirror; it defaults to `false`, matching Better Auth. Identifier storage
defaults to `Plain`; select `VerificationIdentifierStorage::Hashed` for Better
Auth's SHA-256 base64url profile, provide a `Custom` async hasher, and use ordered
`verification.store_identifier.overrides` for purpose-prefix rules. Atomic
verification reservation fails closed when secondary-only storage is selected.

`store_session_in_database` mirrors sessions to the primary store and
`preserve_session_in_database` expires instead of deleting that audit row on
revocation. The default rate-limit storage mode also selects configured
secondary storage. Use `SessionStorageMode::Stateless` only with cookie cache
enabled; pure stateless sessions cannot be individually revoked, so use short
cache lifetimes and version invalidation for incidents. Custom `AuthStore`
implementations must make session refresh and verification consume/reserve
operations atomic update/delete/insert-only operations; missing or concurrently
deleted records must never be inserted again.

Migration `0019_better_auth_session_tokens.sql` intentionally invalidates old
hashed session rows and stores Better Auth's opaque token so `listSessions` and
`revokeSession` use the same value. Existing sessions must sign in again after
that upgrade.

## Conformance tests

The black-box suite installs the exact official Better Auth client versions in
`conformance/package-lock.json` and runs them against an ephemeral native Rust
server:

```sh
npm ci --prefix conformance --ignore-scripts
npm test --prefix conformance
```

It currently exercises session, the full username and anonymous lifecycles,
admin, all official passkey, user-owned API-key, magic-link, and two-factor
client methods. Passkey registration and authentication use complete signatures
through an in-process virtual authenticator. The fixture and Node dependencies
are excluded from the published crate.

This project is not affiliated with Better Auth.
