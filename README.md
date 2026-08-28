# lucid-auth

`lucid-auth` is a native Rust authentication backend for applications using
the official Better Auth JavaScript client. It implements a deliberately
tested Better Auth-compatible HTTP and session surface without executing or
embedding a JavaScript authentication server.

The compatibility target is Better Auth `1.7.1`. See the
[compatibility matrix](COMPATIBILITY.md) for method-level coverage, known
limitations, upgrade audit, and links to every tracked gap.

## Start here

- [Install and run the memory, SQLite, or PostgreSQL server](docs/installation.md)
- [Connect React, Vue, Svelte, Solid, vanilla, SSR, and extension clients](docs/frameworks.md)
- [Connect the pinned Electron main, preload, renderer, and browser-proxy clients](docs/frameworks.md#electron)
- [Review the production proxy, TLS, cookie, CORS, secret, and migration checklist](docs/production.md)
- [Choose a database ID strategy and migrate older UUID schemas](#database-id-strategies)
- [Choose only supported core methods and plugins](COMPATIBILITY.md)
- [Enable Agent Auth and review its exact server/client boundary](COMPATIBILITY.md#agent-auth)

The crate targets Rust 1.90 and Axum 0.8. The official client must be pinned to
Better Auth 1.7.1. From a checkout, this starts the CI-compiled memory example:

```sh
export BETTER_AUTH_SECRET="$(openssl rand -base64 32)"
export BETTER_AUTH_URL="http://localhost:3000"
export FRONTEND_ORIGIN="http://localhost:5173"
cargo run --example http_memory --features axum
```

For durable local storage without a separate database server, enable `sqlite`
and run the native SQLx example. The store consumes the same resolved Better
Auth schema as the service and performs additive Better Auth 1.7.1 migrations:

```sh
export DATABASE_URL="sqlite://lucid-auth.db"
cargo run --example http_sqlite --features axum,sqlite
```

`SqliteStore` accepts an existing `SqlitePool`, a URL, or caller-built SQLx
connection options. It does not set foreign keys, WAL, synchronous mode, busy
timeouts, shared cache, retries, or checkpoint policy. A plain
`sqlite::memory:` database must use one pool connection; use a file database or
an explicitly configured shared-memory URI for multiple connections. See the
[SQLite storage matrix](COMPATIBILITY.md#storage-and-deployment) for the exact
native versus D1 boundary.

The currently supported surface covers:

- `getSession` and `useSession`
- core email/password signup, signin, and current-password verification
- stateless HS256 email verification with a native async delivery callback
- enumeration-resistant password-reset email and single-use reset redemption
- the complete official `emailOTPClient` surface as an optional native plugin
- the complete official `phoneNumberClient` surface as an optional native plugin
- the official Google `oneTapClient` callback surface as an optional native plugin
- the complete official `multiSessionClient` surface as an optional native plugin
- the complete official `lastLoginMethodClient` surface as an optional native plugin
- the official `jwtClient` token/JWKS surface as an optional native plugin
- the complete official `oneTimeTokenClient` surface as an optional native plugin
- the official `@better-auth/electron` main-process, preload, renderer, and
  browser-proxy flow as an optional native plugin
- standalone and OAuth Provider device authorization through the official
  `deviceAuthorizationClient` and `oauthDeviceAuthorizationClient`
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
- preview/development OAuth through the production callback deployment with the
  optional OAuth Proxy server plugin and ordinary `signIn.social` client
- Expo native cookie/deep-link transport through the pinned
  `@better-auth/expo@1.7.1` client and optional `ExpoPlugin`, while Expo web
  remains ordinary browser behavior
- the complete official `oauthProviderClient` management surface plus the
  native OAuth 2.0/OIDC authorization-server protocol as an optional plugin
- the `@better-auth/mcp` authorization preset, protected-resource discovery,
  and Bearer/DPoP request verification for application-owned MCP routes
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
- the Better Auth Open API schema endpoint and Scalar reference page as an
  optional server-only native plugin
- Dub signup lead attribution as an optional native plugin matching
  `@dub/better-auth@0.0.6`
- the standalone managed email client from `@better-auth/infra@0.4.3`
- the standalone managed SMS client from `@better-auth/infra@0.4.3`
- the 26 core `@better-auth/infra@0.4.3` Dash routes plus their shared
  connection, hosted-JWT, and request-identification substrate

The library keeps authentication protocol details separate from host-product
authorization. Core principals contain actor, subject, session, and credential
provenance only. An explicitly enabled host-policy plugin may project a role;
core-only principals leave it unset.

### Database ID strategies

`AuthConfig::database_id_generation` is the exact native equivalent of Better
Auth 1.7.1's `advanced.database.generateId`. The default is not UUID: it creates
32-character `a-zA-Z0-9` IDs in the application.

```rust
use lucid_auth::DatabaseIdGeneration;

// Better Auth's omitted/default advanced.database.generateId.
config.database_id_generation = DatabaseIdGeneration::Default;

// Better Auth generateId: false. Every inserted table needs a database default.
config.database_id_generation = DatabaseIdGeneration::Database;

// Better Auth generateId: "serial". PostgreSQL uses integer identity columns.
config.database_id_generation = DatabaseIdGeneration::Serial;

// Better Auth generateId: "uuid". PostgreSQL uses native UUID columns/defaults.
config.database_id_generation = DatabaseIdGeneration::Uuid;
```

A callback receives Better Auth's logical model name and the presence-sensitive
size requested by the calling path:

```rust
use lucid_auth::{
    DatabaseIdGeneration, DatabaseIdGenerationRequest,
    DatabaseIdGenerationResult, DatabaseIdGenerator,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Debug)]
struct ModelIds(AtomicU64);

impl DatabaseIdGenerator for ModelIds {
    fn generate(
        &self,
        request: DatabaseIdGenerationRequest<'_>,
    ) -> DatabaseIdGenerationResult {
        let sequence = self.0.fetch_add(1, Ordering::Relaxed);
        DatabaseIdGenerationResult::Id(format!("app_{}_{sequence}", request.model))
    }
}

config.database_id_generation =
    DatabaseIdGeneration::Callback(Arc::new(ModelIds(AtomicU64::new(1))));
```

All public record IDs and references remain strings, including serial database
values. `DatabaseIdGeneration::Database` is intentionally invalid with the
official memory-store behavior because no database supplies the omitted IDs;
use `Default`, `Serial`, `Uuid`, or a callback for memory-backed services.
Adapter capabilities such as native UUID support and `disableIdGeneration` are
adapter declarations, not additional application strategy names. There are no
legacy aliases for `AuthIdGenerator`, `AuthConfig::id_generator`, or implicit
UUID fallback.

The [database ID compatibility table](COMPATIBILITY.md#database-id-generation)
documents callback precedence, `forceAllowId`, Test Utils fallback behavior,
and the complete memory/PostgreSQL boundary. Existing installations that used
the former UUID default must follow the
[breaking database ID migration guide](docs/database-id-migration.md) before
running migrations.

### Expo and React Native

Register the exact native server counterpart and explicitly trust the
application's production scheme:

```rust
use lucid_auth::ExpoPlugin;

config.set_base_url("https://auth.example.com")?;
config.trust_origin("myapp://")?;
config.add_plugin(ExpoPlugin::default())?;
```

Install the pinned official client in the Expo application:

```sh
npm install --save-exact better-auth@1.7.1 @better-auth/expo@1.7.1
npx expo install expo-constants expo-linking expo-network expo-secure-store expo-web-browser
```

Use `expoClient()` from `@better-auth/expo/client` with SecureStore. On native,
the client sends `expo-origin`, stored cookies, and `x-skip-oauth-proxy`; the
server preserves a real `Origin`, substitutes only the exact `expo-origin`
header when `Origin` is absent, and applies the normal trusted-origin/CSRF
policy. Relative `callbackURL`, `newUserCallbackURL`, and `errorCallbackURL`
values are deep-linked by the official client. Incorrect casing such as
`callbackUrl` is unsupported.

The plugin contributes only `exp://` when `NODE_ENV=development`. It never
trusts `myapp://`, CIDR patterns, or production wildcards automatically. Its
hidden `GET /expo-authorization-proxy` accepts external HTTPS authorization
targets and uses core OAuth state cookies; callback, magic-link, and
email-verification redirects hand cookies only to trusted non-HTTP(S) schemes.
Do not log authorization URLs, redirect query strings, or cookie material.

Expo web is pass-through browser behavior and does not use SecureStore headers,
deep-link rewriting, or native session-cache hydration. SecureStore chunking,
cookie filtering, focus/network managers, session caching, and
`lastLoginMethodClient` remain client-side features of the pinned npm package;
the Rust plugin owns no schema, migration, device state, or retry layer. See the
 [framework guide](docs/frameworks.md#expo-and-react-native) for the complete
boundary.

### Electron

Install the exact client package and enable its native server counterpart:

```sh
npm install --save-exact better-auth@1.7.1 @better-auth/electron@1.7.1
```

```rust
use lucid_auth::ElectronPlugin;

config.add_plugin(ElectronPlugin::default())?;
```

Use `electronClient()` only in Electron's main process, `setupRenderer()` in a
context-isolated preload, and `electronProxyClient()` in the web page that
hands the authenticated browser session back to the application. Keep the
session/cookie store in the main process. The complete setup, package entry
points, deep-link flow, and the pinned package's raw-versus-encoded token
boundary are documented in the [framework guide](docs/frameworks.md#electron).

### Stripe billing

Stripe support is opt-in and uses a narrow native HTTP client; no Node process,
JavaScript sidecar, Stripe CLI, or general-purpose billing model is required.
Keep both the Stripe API key and webhook secret in server-only environment
variables:

```rust
use lucid_auth::{
    MemoryStripeStore, StaticPlans, StripeHttpClient, StripeOptions, StripePlan,
    StripePlugin, SubscriptionConfiguration, SubscriptionOptions,
};
use std::sync::Arc;

let stripe = Arc::new(StripeHttpClient::new(std::env::var("STRIPE_SECRET_KEY")?));
let mut stripe_options = StripeOptions::new(
    stripe,
    std::env::var("STRIPE_WEBHOOK_SECRET")?,
);
stripe_options.subscription = SubscriptionConfiguration::Enabled(
    SubscriptionOptions::new(Arc::new(StaticPlans(vec![StripePlan {
        name: "pro".into(),
        price_id: Some("price_monthly".into()),
        lookup_key: None,
        annual_discount_price_id: None,
        annual_discount_lookup_key: None,
        limits: None,
        group: None,
        seat_price_id: None,
        proration_behavior: Default::default(),
        line_items: vec![],
        free_trial: None,
    }]))),
);
config.add_plugin(StripePlugin::new(
    stripe_options,
    Arc::new(MemoryStripeStore::new()),
))?;
```

Use `PostgresStripeStore` in a PostgreSQL deployment, bind it through the
service, and apply the store's resolved schema. The browser client must use the same
pinned package and enable subscription inference explicitly:

```ts
import { createAuthClient } from "better-auth/client";
import { stripeClient } from "@better-auth/stripe/client";

export const authClient = createAuthClient({
  plugins: [stripeClient({ subscription: true })],
});
```

The webhook is `POST /api/auth/stripe/webhook` with the default auth base path.
Configure Stripe to send the untouched raw request body and `stripe-signature`
header there. Callback inputs use Better Auth's exact casing—most notably
`callbackURL`; aliases such as `callbackUrl` are deliberately unsupported. See
the [Stripe compatibility row](COMPATIBILITY.md#payments-analytics-and-better-auth-infrastructure)
for the audited boundary and issue link.

### Polar billing

Polar support is opt-in and pins Better Auth `1.7.1`,
`@polar-sh/better-auth@1.8.4`, and `@polar-sh/sdk@0.47.1`. Configure only the
feature factories used by the application; an empty feature list is valid, and
repeating one feature uses the last configuration, matching the adapter:

```rust
use lucid_auth::{
    CheckoutOptions, PolarFeature, PolarHttpClient, PolarOptions, PolarPlugin,
    PolarProduct, PolarProducts, PolarTheme, PortalOptions, UsageOptions,
    WebhooksOptions,
};
use std::sync::Arc;

let checkout = CheckoutOptions {
    products: Some(PolarProducts::static_products(vec![PolarProduct::new(
        "polar_product_id",
        "pro",
    )])),
    success_url: Some("/billing/success?checkout_id={CHECKOUT_ID}".into()),
    authenticated_users_only: true,
    ..CheckoutOptions::default()
};
let portal = PortalOptions::new(
    Some("https://app.example.com/account"),
    Some(PolarTheme::Dark),
)?;
let webhooks = WebhooksOptions::new(std::env::var("POLAR_WEBHOOK_SECRET")?);

let mut polar_options = PolarOptions::new(
    Arc::new(PolarHttpClient::new(std::env::var("POLAR_ACCESS_TOKEN")?)),
    vec![
        PolarFeature::Checkout(checkout),
        PolarFeature::Portal(portal),
        PolarFeature::Usage(UsageOptions::default()),
        PolarFeature::Webhooks(webhooks),
    ],
);
polar_options.create_customer_on_sign_up = true;
config.add_plugin(PolarPlugin::new(polar_options))?;
```

The portal-level return URL must be absolute because the upstream adapter
constructs it with `new URL(returnUrl)` when the feature is installed. Checkout
success and return URLs may be relative paths beginning with `/` or absolute
URLs. Configure Polar's webhook endpoint as
`POST /api/auth/polar/webhooks`, then enable its official browser client:

```ts
import { createAuthClient } from "better-auth/client";
import { polarClient } from "@polar-sh/better-auth/client";

export const authClient = createAuthClient({
  plugins: [polarClient()],
});
```

Polar is authoritative for customers, products, checkouts, subscriptions,
orders, benefits, meters, and events. `PolarPlugin` deliberately creates no
local billing or customer-mapping tables and contributes no migrations; it also
adds no retry or idempotency layer to Polar provider calls. See the
[Polar compatibility row](COMPATIBILITY.md#payments-analytics-and-better-auth-infrastructure)
for the exact endpoint, webhook, lifecycle, and recovery boundary.

### Autumn billing

Autumn support is opt-in and pins Better Auth `1.7.1`, `autumn-js@1.2.53`,
and its generated SDK metadata version `0.10.18`. By default, customers are
resolved from the authenticated user and the provider key is read from
`AUTUMN_SECRET_KEY`:

```rust
use lucid_auth::{AutumnCustomerScope, AutumnOptions, AutumnPlugin};

let mut autumn = AutumnOptions::default();
autumn.secret_key = Some(std::env::var("AUTUMN_SECRET_KEY")?);
autumn.base_url = Some("https://autumn-proxy.example.com/provider-prefix".into());
autumn.customer_scope = AutumnCustomerScope::UserAndOrganization;
config.add_plugin(AutumnPlugin::new(autumn))?;
```

Omit `secret_key` to read `AUTUMN_SECRET_KEY` automatically. Use `base_url` for
an alternate Autumn API URL, or `autumn_url` for the adapter's higher-precedence
spelling. `AutumnCustomerScope::User` always uses the session user;
`Organization` requires an active organization;
`UserAndOrganization` prefers it and falls back to the user. For application-
specific identity rules, set `identify` to an `AutumnIdentityProvider`; its
trusted `AutumnIdentity` replaces the built-in scope resolver.

The official React provider selects Better Auth's path and credential defaults
only when `useBetterAuth` is enabled:

```tsx
import { AutumnProvider } from "autumn-js/react";

export function Providers({ children }) {
  return <AutumnProvider useBetterAuth={true}>{children}</AutumnProvider>;
}
```

Direct client construction must supply those settings explicitly:

```ts
import { createAutumnClient } from "autumn-js/react";

export const autumn = createAutumnClient({
  backendUrl: "https://auth.example.com",
  pathPrefix: "/api/auth/autumn",
  includeCredentials: true,
});
```

The plugin exposes exactly Autumn's 15 camelCase POST endpoints. It owns no
local billing models or migrations, accepts no client-selected customer, and
adds no retries or idempotency behavior. Provider-produced errors intentionally
retain Autumn's Better Auth 1.7.1 outer-HTTP-200 envelope; public request-schema
errors remain HTTP 400. See the
[Autumn compatibility row](COMPATIBILITY.md#payments-analytics-and-better-auth-infrastructure)
for the complete transport, identity, fail-open, and exclusion boundary.

### Creem billing

Creem support is opt-in and pins Better Auth `1.7.1`,
`@creem_io/better-auth@1.1.4`, `creem@1.6.0`,
`@creem_io/webhook-types@1.0.0`, and the conformance oracle's `zod@4.4.3`.
Keep the API key and webhook secret in server-only environment variables. The
same core memory store must back both authentication and the Creem plugin:

```rust
use lucid_auth::{CreemOptions, CreemPlugin, MemoryStore};
use std::sync::Arc;

let store = Arc::new(MemoryStore::default());
let mut creem = CreemOptions::new(std::env::var("CREEM_API_KEY")?);
creem.webhook_secret = Some(std::env::var("CREEM_WEBHOOK_SECRET")?);
creem.default_success_url = Some("https://app.example.com/billing/success".into());
config.add_plugin(CreemPlugin::in_memory(creem, store.clone()))?;
```

For PostgreSQL, construct the plugin store from the same `PostgresStore` and
the exact options used by the plugin. Add the plugin before evolving the schema
so its remapped user fields and `creem_subscription` model are included:

```rust
use lucid_auth::{AuthService, CreemOptions, CreemPlugin, PostgresCreemStore, PostgresStore};
use std::sync::Arc;

let store = PostgresStore::new(pool, Default::default());
let mut creem = CreemOptions::new(std::env::var("CREEM_API_KEY")?);
creem.webhook_secret = Some(std::env::var("CREEM_WEBHOOK_SECRET")?);
let creem_store = Arc::new(PostgresCreemStore::new(
    store.clone(),
    &creem.schema,
    creem.persist_subscriptions,
)?);
config.add_plugin(CreemPlugin::new(creem, creem_store))?;
let service = AuthService::try_new(Arc::new(store.clone()), config)?;
store.migrate_all(&service.plugin_migrations()).await?;
```

Set `test_mode = true` for Creem's test API. Setting
`persist_subscriptions = false` removes the plugin table, user fields, and
their resolved schema contributions; access checks then report that database
persistence is disabled.
The official browser client works unchanged:

```ts
import { createAuthClient } from "better-auth/client";
import { creemClient } from "@creem_io/better-auth/client";

export const authClient = createAuthClient({
  plugins: [creemClient()],
});
```

With the default auth base path, configure Creem to send webhooks to
`POST /api/auth/creem/webhook`. The route exists only when a non-empty webhook
secret is configured. Delivery is deliberately sequential, best-effort, and
non-transactional, matching the adapter: a customer link or trial flag can
remain written if a later subscription operation fails. There is no event
ledger, replay rejection, reordering, or retry queue, so every callback must be
idempotent and deployments need their own reconciliation process.

Applications that do not need HTTP routes can use `CreemServerConfig` with the
native direct helpers. Provider operations are `create_creem_checkout`,
`create_creem_portal`, `cancel_creem_subscription`,
`retrieve_creem_subscription`, and `search_creem_transactions`, with
`create_creem_client` exposing the narrow transport. The other helper
equivalents are `is_active_creem_subscription`, `format_creem_date`,
`get_creem_days_until_renewal`, `validate_creem_server_webhook_signature`,
`check_creem_subscription_access`, and `get_active_creem_subscriptions`. Only
the five provider operations require the API key.

See the
[Creem compatibility row](COMPATIBILITY.md#payments-analytics-and-better-auth-infrastructure)
for the exact endpoint, provider, persistence, webhook, callback, and helper
boundary, including the intentional per-plugin schema-isolation improvement.

### Dodo Payments billing

Dodo Payments support is opt-in and pins Better Auth `1.7.1`,
`@dodopayments/better-auth@1.6.5`, `@dodopayments/core@0.3.14`, and
`dodopayments@2.47.0`. It requires a Dodo Payments account and a server-only
live or test API key; enable only the endpoint groups the application uses:

```rust
use lucid_auth::{
    DodoCheckoutOptions, DodoPaymentsFeature, DodoPaymentsHttpClient,
    DodoPaymentsOptions, DodoPaymentsPlugin, DodoPaymentsProviderConfig,
    DodoProduct, DodoProducts, DodoWebhooksOptions,
};
use std::sync::Arc;

let client = Arc::new(DodoPaymentsHttpClient::new(
    DodoPaymentsProviderConfig::live(std::env::var("DODO_PAYMENTS_API_KEY")?),
));
let checkout = DodoCheckoutOptions {
    products: Some(DodoProducts::static_products(vec![DodoProduct::new(
        "pdt_pro",
        "pro",
    )])),
    success_url: Some("https://app.example.com/billing/success".into()),
    authenticated_users_only: true,
};
let webhooks = DodoWebhooksOptions::new(
    std::env::var("DODO_PAYMENTS_WEBHOOK_KEY")?,
);
let mut options = DodoPaymentsOptions::new(
    client,
    vec![
        DodoPaymentsFeature::Checkout(checkout),
        DodoPaymentsFeature::Portal,
        DodoPaymentsFeature::Usage,
        DodoPaymentsFeature::Webhooks(webhooks),
    ],
);
options.create_customer_on_sign_up = true;
config.add_plugin(DodoPaymentsPlugin::new(options, store.clone()))?;
```

Use `DodoPaymentsProviderConfig::test` with a Dodo test-mode key. The native
`create_customer_on_sign_up` and `get_customer_params` options correspond to
upstream `createCustomerOnSignUp` and `getCustomerParams`; implement
`DodoCustomerParamsProvider` and assign it to `options.get_customer_params` to
add string metadata or an optional phone number during customer creation and
updates. The plugin stores only the optional, non-input `dodoCustomerId` user
field. Dodo remains authoritative for billing, and lucid-auth adds no payment,
subscription, usage, or webhook-delivery ledger.

Configure Dodo to deliver signed webhooks to
`POST /api/auth/dodopayments/webhooks`, and install the official browser client:

```ts
import { createAuthClient } from "better-auth/client";
import { dodopaymentsClient } from "@dodopayments/better-auth/client";

export const authClient = createAuthClient({
  plugins: [dodopaymentsClient()],
});

await authClient.dodopayments.checkoutSession({
  product_cart: [{ product_id: "pdt_pro", quantity: 1 }],
});
await authClient.dodopayments.customer.portal();
await authClient.dodopayments.customer.subscriptions.list();
await authClient.dodopayments.customer.payments.list();
await authClient.dodopayments.usage.ingest({
  event_id: "request_123",
  event_name: "api_request",
});
await authClient.dodopayments.usage.meters.list();
```

`dodopayments.checkoutSession` is the preferred checkout API. The pinned
adapter also exposes the upstream-deprecated `dodopayments.checkout` method and
`POST /dodopayments/checkout`; they remain supported with their exact legacy
behavior because they are part of version 1.6.5, not as lucid-auth aliases. See
the [Dodo Payments compatibility row](COMPATIBILITY.md#payments-analytics-and-better-auth-infrastructure)
for the exact checkout, lifecycle, provider, webhook, and exclusion boundary.

### Commet billing

Commet support is opt-in and pins Better Auth `1.7.1`,
`@commet/better-auth@8.1.0`, and `@commet/node@9.1.0`. It requires a server-only
Commet API key beginning with `ck_` and exposes only the endpoint groups
selected by the application. `CommetProviderConfig::new` validates that key and
returns a `Result`:

```rust
use lucid_auth::{
    CommetFeature, CommetHttpClient, CommetOptions, CommetPlugin,
    CommetPortalOptions, CommetProviderConfig, CommetSubscriptionsOptions,
    CommetWebhooksOptions,
};
use std::sync::Arc;

let provider = CommetProviderConfig::new(std::env::var("COMMET_API_KEY")?)?;
let client = Arc::new(CommetHttpClient::new(provider));
let mut options = CommetOptions::new(
    client,
    vec![
        CommetFeature::Portal(CommetPortalOptions {
            return_url: Some("https://app.example.com/billing".into()),
        }),
        CommetFeature::Subscriptions(CommetSubscriptionsOptions::default()),
        CommetFeature::Features,
        CommetFeature::Usage,
        CommetFeature::Seats,
        CommetFeature::Webhooks(CommetWebhooksOptions::new(
            std::env::var("COMMET_WEBHOOK_SECRET")?,
        )),
    ],
);
options.create_customer_on_sign_up = true;
config.add_plugin(CommetPlugin::new(options))?;
```

Set `options.get_customer_create_params` to a `CommetCustomerParamsProvider`
when signup should add a full name or arbitrary JSON metadata. The upstream
`domain` callback field is exposed but intentionally not forwarded by adapter
8.1.0. Commet owns all customer and billing state; the plugin adds no database
field, table, migration, organization mapping, or webhook-delivery ledger.

Install the official client and use its exact namespaces:

```ts
import { createAuthClient } from "better-auth/client";
import { commetClient } from "@commet/better-auth/client";

export const authClient = createAuthClient({ plugins: [commetClient()] });

await authClient.customer.portal();
await authClient.subscription.get();
await authClient.features.list();
await authClient.features.check("api-requests");
await authClient.usage.track({ feature: "api-requests", value: 1 });
await authClient.seats.list();
```

Configure signed deliveries at `POST /api/auth/commet/webhooks`. See the
[Commet compatibility row](COMPATIBILITY.md#payments-analytics-and-better-auth-infrastructure)
for the exact 13 client actions, lifecycle, provider, retry, signature,
callback, and exclusion boundary.

### Chargebee billing

Chargebee support is opt-in and pins Better Auth `1.7.1`, the
Chargebee-maintained `@chargebee/better-auth@1.2.0`, and its
`chargebee@3.23.1` runtime. The plugin is fully native: inject an application
implementation of `ChargebeeClient` that performs the required Chargebee API
operations and parses/authenticates webhooks. No Node process or JavaScript
sidecar is used.

```rust
use lucid_auth::{
    ChargebeeClient, ChargebeeFreeTrial, ChargebeeOptions, ChargebeePlan,
    ChargebeePlanType, ChargebeePlugin, ChargebeeSubscriptionOptions,
    MemoryChargebeeStore, StaticChargebeePlans,
};
use std::sync::Arc;

// Application-owned native gateway; keep the site and API key server-side.
let provider: Arc<dyn ChargebeeClient> = Arc::new(MyChargebeeGateway::new(
    std::env::var("CHARGEBEE_SITE")?,
    std::env::var("CHARGEBEE_API_KEY")?,
));
let plans = Arc::new(StaticChargebeePlans(vec![ChargebeePlan {
    name: "pro".into(),
    item_price_id: "price_pro".into(),
    item_id: None,
    item_family_id: None,
    plan_type: ChargebeePlanType::Plan,
    billing_cycles: None,
    free_trial: Some(ChargebeeFreeTrial { days: 7.0 }),
    limits: Some(serde_json::json!({ "projects": 20 })),
}]));

let mut options = ChargebeeOptions::new(provider);
options.subscription = Some(ChargebeeSubscriptionOptions::new(true, plans));
options.create_customer_on_sign_up = true;
options.webhook_username = Some(std::env::var("CHARGEBEE_WEBHOOK_USERNAME")?.into());
options.webhook_password = Some(std::env::var("CHARGEBEE_WEBHOOK_PASSWORD")?.into());

let chargebee_store = Arc::new(MemoryChargebeeStore::new(store.clone()));
config.add_plugin(ChargebeePlugin::new(options, chargebee_store))?;
```

`MyChargebeeGateway` above is application code implementing the narrow
`ChargebeeClient` trait; it is not a lucid-auth type. Use
`PostgresChargebeeStore`, bind it through `AuthService`, and evolve its resolved
schema for PostgreSQL.
For organization-owned subscriptions, also install the native Organization
plugin and enable `ChargebeeOrganizationOptions`; Chargebee organization mode
does not install Organization support implicitly.

Configure Chargebee to deliver webhooks to
`POST /api/auth/chargebee/webhook`. Basic authentication is enforced only when
both webhook credentials are configured. Then install the official browser
client with subscription inference enabled:

```ts
import { createAuthClient } from "better-auth/client";
import { chargebeeClient } from "@chargebee/better-auth/client";

export const authClient = createAuthClient({
  plugins: [chargebeeClient({ subscription: true })],
});

await authClient.subscription.create({
  itemPriceId: "price_pro",
  successUrl: "/billing/success",
  cancelUrl: "/billing",
});
```

The provider remains authoritative while lucid-auth stores the adapter's local
customer linkage, subscription, and subscription-item projection. Create and
update accept upstream's declared `returnUrl` field but do not use it; callback
queries use exact `callbackURL` casing. Webhook handling intentionally awaits
authentication, native processing, custom listeners, and event-bus persistence
before acknowledging a delivery, fixing the published adapter's unsafe early
acknowledgement race. See the
[Chargebee compatibility details](COMPATIBILITY.md#chargebee-120) for the exact
route, lifecycle, schema, webhook, and conformance boundary.

### Dub lead attribution

Dub support is opt-in and pins Better Auth `1.7.1`,
`@dub/better-auth@0.0.6`, and `dub@0.66.5`. Inject only the application-owned
native lead transport that the adapter needs; lucid-auth does not start Node,
embed JavaScript, or expose Dub credentials to requests:

```rust
use lucid_auth::{DubLead, DubLeadError, DubOptions, DubPlugin, FnDubLeadTracker};
use std::sync::Arc;

let tracker = Arc::new(FnDubLeadTracker::new(|lead: DubLead| async move {
    // Application code: send `lead` with a server-side Dub SDK or HTTP client.
    send_lead_to_dub(lead)
        .await
        .map_err(|error| DubLeadError::new(error.to_string()))
}));
let mut dub = DubOptions::new(tracker);
dub.lead_event_name = Some("Signed Up".into());
config.add_plugin(DubPlugin::new(dub))?;
```

Place `dub_id` yourself after obtaining the user's consent. The plugin reads
that exact case-sensitive cookie after any user creation, percent-decodes its
first value, and sends `clickId`, `eventName`, and the new user's id, name,
email, and optional image. It does not create or validate the attribution
cookie. On a default provider result—success or rejection—it emits the
upstream adapter's exact pathless deletion header. Because the header has no
`Path`, it may not remove a source cookie that was scoped to `/`; applications
remain responsible for cookie placement, consent, and cleanup.

Set `disable_lead_tracking = true` to leave both tracking and the cookie
untouched. An empty `lead_event_name` falls back to `Sign Up`. Set
`custom_lead_track` to an `Arc<dyn DubCustomLeadTrack>` or use
`FnDubCustomLeadTrack` when the application must replace the Dub call entirely.
The callback receives the persisted user and request context. Its failure is
deliberately visible as an empty HTTP 500 after the user, credential account,
and session have committed, and all response cookies are discarded, matching
the pinned adapter.

Do not install a Dub browser client for this target. Although upstream docs
show `@dub/better-auth/client`, version 0.0.6 does not export that subpath.
Its only server route, `POST /api/auth/dub/link`, also cannot complete OAuth
under Better Auth 1.7.1: without OAuth configuration it returns 404, and with
configuration it reaches an upstream missing-endpoint error and returns an
empty 500. Lucid-auth reproduces those observable outcomes and does not invent
a callback route or repaired client contract. See the
[Dub compatibility details](COMPATIBILITY.md#dub-006).

### Better Auth Infrastructure Dash

`DashPlugin` installs the 26 core `/dash/*` routes published by
`@better-auth/infra@0.4.3`, including configuration/validation, user CRUD and
NDJSON export, account/password/session management, impersonation, moderation,
analytics, email actions, and the five-action raw adapter endpoint. Managed
JWT authorization is mandatory; `/dash/validate` alone skips the JTI lookup,
matching the pinned plugin.

```rust
use lucid_auth::{
    AuthConfig, DashActivityTracking, DashOptions, DashPlugin,
    InfraConnectionOptions,
};
use std::time::Duration;

let mut auth = AuthConfig::new([42_u8; 32])?;
auth.add_plugin(DashPlugin::new(DashOptions {
    connection: InfraConnectionOptions {
        api_key: Some(std::env::var("BETTER_AUTH_API_KEY")?),
        ..InfraConnectionOptions::default()
    },
    activity_tracking: DashActivityTracking {
        enabled: true,
        update_interval: Duration::from_secs(300),
    },
}))?;
```

Activity tracking is opt-in and adds the optional `lastActiveAt` user field.
The verification and reset-email routes reuse the application's configured
Better Auth email callbacks; they do not silently install a second provider.
The shared `DashJwtVerifier` and `IdentificationService` remain available for
applications that need the lower-level hosted-JWT and identification substrate.

The API client sends the configured credential to `BETTER_AUTH_API_URL` or
`https://dash.better-auth.com`; the KV lookup client uses
`BETTER_AUTH_KV_URL` or `https://kv.better-auth.com`. Hosted authorization also
sends JWT/JTI data and fetches JWKS. Identification lookups send request IDs and
can return visitor, IP, location, browser, confidence, incognito, and bot data.
Keep credentials server-side and configure only origins trusted with that data.
See the [exact Dash core and substrate compatibility boundary](COMPATIBILITY.md#dash-core-routes-043).

### Better Auth Infrastructure managed email

Managed email support pins `@better-auth/infra@0.4.3` and is a standalone
outbound client, not a Better Auth plugin. Create an `EmailSender` once and call
its `send`, `send_bulk`, or `get_templates` method from the application-owned
callback that already handles verification, password reset, Email OTP,
organization invitations, or another email-producing lifecycle. The one-shot
`send_email` and `send_bulk_emails` functions are available when reusing a
sender is unnecessary. Nothing is registered with `AuthConfig`, and installing
this crate does not automatically redirect existing delivery callbacks to the
managed service.

```rust
use lucid_auth::{
    EmailConfig, EmailSender, ResetPasswordVariables, SendEmailOptions,
};

let sender = EmailSender::new(Some(EmailConfig {
    api_key: Some(std::env::var("BETTER_AUTH_API_KEY")?),
    ..EmailConfig::default()
}));
let result = sender
    .send(SendEmailOptions::new(
        "person@example.com",
        ResetPasswordVariables::new(
            "https://app.example.com/reset?token=...",
            "person@example.com",
        ),
    ))
    .await;
if !result.success {
    // Apply the application's delivery-failure policy here.
}
```

For core password resets, wrap the call above in the application's
`PasswordResetEmailSender` implementation and assign it to
`config.email_and_password.send_reset_password`; verification and the optional
plugins have their own typed sender callbacks. That adapter performs the field
mapping explicitly, so installing managed email never changes an existing
delivery path.

The exact template IDs are `verify-email`, `reset-password`, `change-email`,
`sign-in-otp`, `verify-email-otp`, `reset-password-otp`, `magic-link`,
`two-factor`, `invitation`, `application-invite`, `delete-account`,
`stale-account-user`, and `stale-account-admin`. Each has a typed native
variable structure matching the published required and optional string fields.
The client exposes no arbitrary body, attachment, locale, request ID, provider,
callback URL, or idempotency option.

By default, configuration reads `BETTER_AUTH_API_KEY`, uses
`BETTER_AUTH_API_URL` or `https://dash.better-auth.com/api`, and applies the
package's three-second timeout.
An explicit API URL receives both the bearer credential and the complete
message payload. Recipient addresses, subjects, links, OTPs, invitation data,
IP addresses, and other template variables therefore cross that remote trust
boundary; keep the key server-side and configure only an origin you trust.

Each call performs exactly one managed-service request. Bulk send remains one
remote bulk operation, and the managed backend—not this client—combines shared
variables with per-recipient overrides. There is no automatic retry, backoff,
queue, delivery ledger, local provider fallback, or reconciliation. See the
[managed email compatibility details](COMPATIBILITY.md#managed-email-043) for
the precise request, configuration, result, and failure contract.

### Better Auth Infrastructure managed SMS

Managed SMS support also pins `@better-auth/infra@0.4.3`. It is a standalone
outbound client, not an auth plugin: creating an `SmsSender` does not install a
route, schema, migration, browser client, or automatic `dash`/`sentinel`
delivery hook. Call it explicitly from an application-owned phone-number or
two-factor OTP sender. The one-shot `send_sms` function is available when a
reusable sender is unnecessary.

```rust
use lucid_auth::{SendSmsOptions, SmsConfig, SmsSender, SmsTemplateId};

let sender = SmsSender::new(Some(SmsConfig {
    api_key: Some(std::env::var("BETTER_AUTH_API_KEY")?),
    ..SmsConfig::default()
}));
let result = sender
    .send(
        SendSmsOptions::new("+1234567890", "123456")
            .with_template(SmsTemplateId::PhoneVerification)
            .with_client_ip("203.0.113.8"),
    )
    .await;
if !result.success {
    // Apply the application's delivery-failure policy here.
}
```

For `PhoneNumberPlugin`, adapt the sender through `PhoneNumberOtpSender` and
assign it to `PhoneNumberConfig::send_otp`; use `TwoFactorOtpSender` with
`OtpConfig` for delivered two-factor codes. That explicit adapter selects
`phone-verification`, `two-factor`, `sign-in-otp`, or no template. The managed
callable surface has no template-variables input even though the upstream
TypeScript declarations publish a variable type for template metadata.

Configuration and transport use the same API-key, API-origin, `/api` suffix,
three-second timeout, bearer header, and infrastructure user agent as the
published package. A truthy `client_ip` adds `x-better-auth-client-ip`. Every
call sends the phone number, OTP, selected template, and optional end-user IP
to the configured origin exactly once. There is no local E.164 validation,
retry, batching, idempotency key, queue, status polling, webhook, locale,
provider selection, or password-reset template. See the
[managed SMS compatibility details](COMPATIBILITY.md#managed-sms-043).

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
remain unencrypted. The bound PostgreSQL schema uses issuer-qualified identity
exclusively; incompatible provider-qualified layouts are not migrated or read.

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

Captcha protection is an optional native server plugin. Choose one of the four
closed Better Auth 1.7.1 provider variants and register it normally:

```rust
use lucid_auth::{CaptchaConfig, CaptchaPlugin, CloudflareTurnstileOptions};

config.add_plugin(CaptchaPlugin::new(CaptchaConfig::CloudflareTurnstile(
    CloudflareTurnstileOptions::new(std::env::var("TURNSTILE_SECRET_KEY")?),
)))?;
```

This protects `/sign-up/email`, `/sign-in/email`, and
`/request-password-reset` by default. Set a non-empty `endpoints` list to
replace those paths; `*` matches one path segment and `**` matches nested
segments. An empty list restores the defaults. Provider verification always
times out after ten seconds and fails closed. Client code needs no Captcha
client plugin—pass the provider token through the ordinary request options:

```ts
await authClient.signIn.email({
  email,
  password,
  fetchOptions: {
    headers: { "x-captcha-response": captchaToken },
  },
});
```

Google reCAPTCHA supports `min_score`, `expected_action`, and
`allowed_hostnames`; Turnstile supports the latter two; hCaptcha and CaptchaFox
support `site_key`. All providers support replacement endpoints and a non-empty
`site_verify_url_override`. Client IPs come only from the shared
`config.ip_address` headers and trusted-proxy rules; the legacy
`x-captcha-user-remote-ip` header is ignored. See the
[compatibility matrix](COMPATIBILITY.md#security-utility-and-developer-plugins)
for the exact supported boundary and pinned upstream evidence.

i18n error messages are an optional native plugin matching
`@better-auth/i18n@1.7.1`. Select any built-in catalogs (or supply exact custom
locale/error-code maps), configure the ordered detection strategies, and
register it normally:

```rust
use lucid_auth::{
    I18nConfig, I18nLocaleDetection, I18nLocales, I18nPlugin,
};

let translations = I18nLocales::selected(["en", "fr"]);
let mut i18n = I18nConfig::new(translations)?;
i18n.detection = vec![
    I18nLocaleDetection::Cookie,
    I18nLocaleDetection::Header,
];
i18n.locale_cookie = "locale".into();
config.add_plugin(I18nPlugin::new(i18n)?)?;
```

The bundled `I18nLocales` contains the exact 22 published 1.7.1 catalogs. The
plugin translates only marked Better Auth API errors, preserving their status
and code while adding `originalMessage`; it does not translate arbitrary JSON,
successful responses, or OAuth protocol errors. Locale keys are matched
exactly, strategies run in order, and a selected locale missing an error-code
entry does not retry the default catalog. The official `i18nClient()` is
type-inference-only and needs no locale endpoint. See the
[compatibility matrix](COMPATIBILITY.md#security-utility-and-developer-plugins)
for the exact no-storage/no-locale-management boundary.

### Have I Been Pwned

Register the server-only plugin to screen password hashes on Better Auth's seven
official password-setting paths through the HIBP k-anonymity API:

```rust
use lucid_auth::{HaveIBeenPwnedOptions, HaveIBeenPwnedPlugin};

config.add_plugin(HaveIBeenPwnedPlugin::new(HaveIBeenPwnedOptions {
    enabled: None,
    paths: None,
    custom_password_compromised_message: None,
}))?;
```

Those are the complete Better Auth 1.7.1 options. `Some(false)` disables checks;
an explicitly supplied `paths` list replaces the defaults exactly, so an empty
list screens no paths; and an empty custom message falls back to Better Auth's
official message. Matching is exact and request-path scoped. Direct native hash
operations with no auth request path bypass the plugin, and sign-in/password
verification is never screened. The plugin adds no route, client, cookie,
schema, migration, middleware, or rate-limit rule. See the
[compatibility matrix](COMPATIBILITY.md#security-utility-and-developer-plugins)
for the exact request, parser, error, and route-side-effect contract.

### Open API reference

Enable the crate's `axum` feature and register the server-only Open API plugin:

```rust
use lucid_auth::{AuthConfig, OpenApiPlugin};

let mut config = AuthConfig::new(std::env::var("BETTER_AUTH_SECRET")?.into_bytes())?;
config.set_base_url("https://auth.example.com")?;
config.add_plugin(OpenApiPlugin::default())?;
```

The Scalar UI is then available at `/api/auth/reference`, and its JSON document
at `/api/auth/open-api/generate-schema`. Native tooling can retrieve the same
typed document without HTTP:

```rust
use lucid_auth::{AuthService, generate_open_api_schema};

let document = generate_open_api_schema(&service);
let json = serde_json::to_string_pretty(&document)?;
```

The reference path, Scalar theme, CSP nonce, and UI availability use only the
Better Auth 1.7.1 options:

```rust
use lucid_auth::{OpenApiConfig, OpenApiPlugin, OpenApiTheme};

config.add_plugin(OpenApiPlugin::new(OpenApiConfig {
    path: "/docs".into(),
    disable_default_reference: false,
    theme: OpenApiTheme::Moon,
    nonce: Some("request-csp-nonce".into()),
}))?;
```

Set `disable_default_reference` to `true` to return Better Auth's empty JSON
404 from the UI route while keeping `/open-api/generate-schema` enabled. The
schema route is fixed, both plugin routes are hidden from their own document,
and Better Auth 1.7.1 provides no `openAPIClient` browser plugin. See the
[compatibility matrix](COMPATIBILITY.md#security-utility-and-developer-plugins)
for the exact generation boundary.

### Test-only helpers

Create a separate auth service for integration tests and install the privileged
server-only Test Utils plugin there. Do not add it to the production service:

```rust
use lucid_auth::{AuthConfig, AuthService, MemoryStore, TestUtilsPlugin};
use std::sync::Arc;

let store = Arc::new(MemoryStore::default());
let mut test_config = AuthConfig::new([7_u8; 32])?;
test_config.add_plugin(TestUtilsPlugin::default())?;
let test_auth = AuthService::new(store, test_config);
```

The helper factory does not write until `save_user`, and login creates an
ordinary persistent session with a Better Auth-compatible signed cookie:

```rust
use lucid_auth::TestUserOverrides;

let test = test_auth.test().expect("Test Utils is installed");
let user = test.create_user(TestUserOverrides {
    email: Some("integration@example.com".into()),
    ..TestUserOverrides::default()
});
let user = test.save_user(user).await?;
let login = test.login(user.id).await?;

// Pass login.headers["cookie"] to an ordinary auth request.
assert_eq!(login.cookies[0].domain, "localhost");
```

Register `TestUtilsPlugin::new(TestUtilsOptions { capture_otp: true })` to expose
the optional passive OTP view. Register the Organization plugin on the same
test service to expose the optional raw Organization fixture view. Test Utils
adds no route or remotely callable bypass by itself. It is the native equivalent
of `testUtils()` only; Better Auth's separate `better-auth/test` Node/Vitest
harness is outside the Rust server compatibility boundary. See the
[compatibility matrix](COMPATIBILITY.md#security-utility-and-developer-plugins)
for the exact surface.

Test Utils factories call the configured context ID generator first. A literal
defer/`false` result uses Better Auth's 24-character `a-zA-Z0-9` factory
fallback; the ordinary default strategy returns its normal 32-character ID,
and `Uuid` returns a UUID. An empty callback string remains empty because it is
not literal `false`.

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

OAuth Popup is optional and reuses the configured social and Generic OAuth
providers:

```rust
config.add_plugin(OAuthPopupPlugin)?;
```

Use Better Auth's official 1.7.1 browser plugin:

```ts
import { createAuthClient } from "better-auth/client";
import { oauthPopupClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
  plugins: [oauthPopupClient()],
});

await authClient.signIn.popup({
  provider: "google",
  callbackURL: "/dashboard",
});
```

`GET /oauth-popup/start` validates the opener and callback URLs, creates the
ordinary OAuth state plus a signed `oauth_popup` marker, and redirects to the
provider. The callback retains its redirect and cookies but returns Better
Auth's pinned CSP-protected completion document, which posts the signed session
cookie value to the opener. Top-level use needs no other plugin. A client inside
a cross-origin iframe stores that value and sends it as a bearer session
credential, so embedded use additionally requires Bearer support ([#34]).

The marker intentionally is not bound into OAuth state, is not revalidated on
the callback, and uses one fixed cookie. Concurrent popup starts can therefore
overwrite each other's opener marker. Database OAuth state remains one-time;
encrypted cookie state keeps Better Auth's normal ten-minute replay window.
These are the Better Auth 1.7.1 protocol boundaries rather than extra Lucid
behavior. Per-cookie naming and attributes can be set with
`config.cookies.plugin["oauth_popup"]`; `max_age` and `partitioned` follow
Better Call's merge and serialization rules. Generated official-client popup
failures currently return their error code as the `message`, while the exported
error-code metadata still contains the descriptive text.

OAuth Proxy is an independent optional server plugin for preview and
development deployments whose OAuth provider is configured to call only the
production deployment:

```rust
use chrono::Duration;
use lucid_auth::{OAuthProxyConfig, OAuthProxyPlugin, OAuthProxySecret};
use url::Url;

config.add_plugin(OAuthProxyPlugin::new(OAuthProxyConfig {
    current_url: Some(Url::parse("https://preview.example.com")?),
    production_url: Some(Url::parse("https://auth.example.com")?),
    max_age: Duration::seconds(60),
    secret: Some(OAuthProxySecret::Plain(
        std::env::var("OAUTH_PROXY_SECRET")?.into_bytes(),
    )),
}))?;
```

Register the same proxy secret in every participating deployment. It can be
separate from the global Better Auth secret; versioned proxy secrets are also
supported for rotation. The production deployment may use its production URL
as `current_url`, in which case the plugin detects matching origins and leaves
the ordinary flow unchanged. A non-empty `x-skip-oauth-proxy` request header
also opts one social sign-in out of proxying.

There is no `oauthProxyClient`. Applications keep using the ordinary official
client:

```ts
await authClient.signIn.social({
  provider: "github",
  callbackURL: "https://app.example.com/signed-in",
});
```

On preview sign-in, the plugin keeps the original callback and OAuth state,
uses the production `/callback/:provider` URI for the provider, and replaces
the provider's state parameter with a shared-secret encrypted proxy package.
Production exchanges the authorization code and relays an encrypted user,
account, token, and callback profile to the preview deployment's
`GET /oauth-proxy-callback`. Preview validates the trusted callback, rejects a
payload older than `max_age` or over ten seconds in the future, consumes the
original OAuth state, creates the ordinary account/session, and redirects to
the state-bound callback or new-user URL.

Database-backed OAuth state is atomically consumed. Better Auth 1.7.1's cookie
state strategy only expires its response cookie and does not add a separate
server-side replay record. Request-derived preview origins are accepted only
when trusted; explicit `current_url`, supported hosting-platform URLs, and the
configured base URL provide the remaining upstream resolution order.

Matching Better Auth 1.7.1, OAuth Proxy forwards neither an OIDC nonce,
callback `iss`, OAuth `device_id`, nor a provider `error_description` across
the proxy hop. It adds no dedicated client factory, plugin-owned cookie,
schema, migration, rate limit, or error-code table; its only route is
`GET /oauth-proxy-callback`.

OAuth Provider is the independent authorization-server plugin matching
`@better-auth/oauth-provider@1.7.1`. The JWT plugin owns provider signing keys;
the OAuth Provider plugin owns its seven models, routes, rate limits, and schema:

```rust
use lucid_auth::{
    AuthService, JwtPlugin, OAuthProviderPlugin, OAuthProviderPluginConfig,
};
use lucid_auth::postgres::PostgresStore;
use std::sync::Arc;

config.add_plugin(JwtPlugin::default())?;
config.add_plugin(OAuthProviderPlugin::in_memory(
    OAuthProviderPluginConfig::new("/sign-in", "/oauth/consent"),
))?;
```

Use the schema-aware PostgreSQL constructor in production, passing the same
cloneable store used by `AuthService`, and migrate the bound resolved schema
before serving:

```rust
let postgres_store = PostgresStore::new(pool, Default::default());
let provider_config = OAuthProviderPluginConfig::new(
    "/sign-in",
    "/oauth/consent",
);
config.add_plugin(OAuthProviderPlugin::postgres(
    provider_config,
    postgres_store.clone(),
)?)?;
let service = AuthService::try_new(Arc::new(postgres_store.clone()), config)?;
postgres_store
    .migrate_all(&service.plugin_migrations())
    .await?;
```

The required pages receive Better Auth's signed `oauth_query` and must return
it through the provider's continue or consent methods.

```ts
import { createAuthClient } from "better-auth/client";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";

export const authClient = createAuthClient({
  baseURL: "https://issuer.example.com",
  plugins: [oauthProviderClient()],
});
```

Authorization code, client credentials, refresh tokens, OIDC, DPoP, resource
indicators, discovery, registration, client/consent management, introspection,
revocation, UserInfo, and logout follow the pinned plugin contract. Better
Auth's server-only admin/resource actions intentionally remain unavailable over
HTTP, and device authorization is a separate plugin. See the
[compatibility matrix](COMPATIBILITY.md) for the precise boundary.

MCP support matches the authorization boundary of `@better-auth/mcp@1.7.1`.
It is an OAuth Provider preset and RFC 9728 protected-resource server, not an
MCP transport: it binds issued tokens to one configured MCP resource, links
newly registered clients to that resource, serves both root-mounted protected
resource metadata aliases, and verifies Bearer or DPoP credentials before an
application-owned MCP handler runs. It reuses OAuth Provider's seven models,
six rate limits, token/resource policy, and refresh rotation; the MCP preset
defaults the refresh-token retry overlap to 30 seconds, with explicit zero
restoring strict replay handling.

Install the preset instead of a separate `OAuthProviderPlugin`; its descriptor
remains `oauth-provider`, so it cannot be combined with another provider:

```rust
use lucid_auth::{
    JwtPlugin, McpPlugin, McpPluginConfig, OAuthProviderPluginConfig,
};

config.add_plugin(JwtPlugin::default())?;
let provider = OAuthProviderPluginConfig::new("/sign-in", "/oauth/consent");
config.add_plugin(McpPlugin::in_memory(McpPluginConfig::new(
    "https://api.example.com/mcp",
    provider,
))?)?;
```

Use `McpPlugin::postgres` with the same `PostgresStore` as `AuthService` in
production. It contributes the ordinary OAuth Provider schema and no
MCP-specific model.

There is no `@better-auth/mcp/client` export or MCP-specific Better Auth client
action. Use `oauthProviderClient()` for the inherited client-management
surface and version 2 of the official `@modelcontextprotocol/client` package
for MCP discovery, authorization, and protocol requests. The host application
owns its MCP HTTP `POST` route and transport. Lucid Auth does not add an MCP
session/SSE bridge, protocol-session store, database model, cookie, client
factory, or route-specific rate limit.

The configured resource must be one absolute URL without credentials, query,
or fragment. HTTPS is required except for localhost and numeric loopback
development URLs. Protected-resource metadata is publicly cacheable for 15
seconds and advertises the externally resolved OAuth issuer, resource scopes,
and Provider DPoP algorithms. Request challenges use the exact JSON-RPC error
shape and RFC 6750/RFC 9728 `WWW-Authenticate` parameters expected by the
official MCP client.

The convenience request verifier defaults issuer, JWKS, and audience from the
auth base URL. That default audience deliberately does not infer the MCP
preset's configured resource; pass the resource explicitly when they differ.
The convenience path uses durable core verification reservations for DPoP
replay protection. The lower-level verifier accepts explicit issuer/audience,
local JWKS or remote introspection, scope policy, and a custom replay store.

Create one verifier with the service, then call it before dispatching each
application-owned MCP request:

```rust
use lucid_auth::{
    McpProtectedRequest, McpProtectedRequestOutcome, RequireMcpAuthOptions,
    require_mcp_auth,
};

let verifier = require_mcp_auth(
    service.clone(),
    RequireMcpAuthOptions {
        resource: Some("https://api.example.com/mcp".into()),
        required_scopes: Some(vec!["mcp.read".into()]),
        ..Default::default()
    },
)?;

match verifier.verify(&McpProtectedRequest {
    authorization_header,
    dpop_proof_jwt,
    method: "POST".into(),
    url: "https://api.example.com/mcp".into(),
}).await? {
    McpProtectedRequestOutcome::Authorized(claims) => {
        // Dispatch the JSON-RPC request with the verified claims.
    }
    McpProtectedRequestOutcome::Challenge(challenge) => {
        // Return challenge.status_code, challenge.www_authenticate,
        // challenge.content_type(), and challenge.json_rpc_body().
    }
}
```

Device Authorization is a separate plugin matching Better Auth 1.7.1. For a
standalone first-party device flow, install it without OAuth Provider:

```rust
use lucid_auth::{DeviceAuthorizationConfig, DeviceAuthorizationPlugin};

config.add_plugin(DeviceAuthorizationPlugin::in_memory(
    DeviceAuthorizationConfig::default(),
))?;
```

Use the matching official client plugin. The standalone `/device/token`
exchange creates a first-party session and returns its bearer token without
setting a browser session cookie:

```ts
import { createAuthClient } from "better-auth/client";
import { deviceAuthorizationClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
  plugins: [deviceAuthorizationClient()],
});
```

For RFC 8628 token issuance by OAuth Provider, install the companion after the
provider and keep `JwtPlugin` for provider signing keys:

```rust
use lucid_auth::{
    DeviceAuthorizationConfig, JwtPlugin, OAuthDeviceAuthorizationPlugin,
    OAuthProviderPlugin, OAuthProviderPluginConfig,
};

config.add_plugin(JwtPlugin::default())?;
config.add_plugin(OAuthProviderPlugin::in_memory(
    OAuthProviderPluginConfig::new("/sign-in", "/oauth/consent"),
))?;
config.add_plugin(OAuthDeviceAuthorizationPlugin::in_memory(
    DeviceAuthorizationConfig::default(),
))?;
```

```ts
import { createAuthClient } from "better-auth/client";
import {
  oauthDeviceAuthorizationClient,
  oauthProviderClient,
} from "@better-auth/oauth-provider/client";

export const authClient = createAuthClient({
  baseURL: "https://issuer.example.com",
  plugins: [oauthProviderClient(), oauthDeviceAuthorizationClient()],
});
```

OAuth-owned device codes are exchanged at `/oauth2/token`; `/device/token` is
reserved for standalone codes and deliberately returns `invalid_grant` for
OAuth-owned codes. Both variants own a dedicated `deviceCode` model with atomic
claim and one-time redemption. In production, use `DeviceAuthorizationPlugin::postgres`
or `OAuthDeviceAuthorizationPlugin::postgres` with the same cloneable
`PostgresStore` passed to `AuthService`, then migrate the bound schema as in the
OAuth Provider example above.

Bearer session authentication is a separate, optional server plugin:

```rust
config.add_plugin(BearerPlugin::default())?;
```

Better Auth 1.7.1 has no `bearerClient()` factory. Use the ordinary client fetch
configuration with the complete signed value returned in `set-auth-token`:

```ts
export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
  fetchOptions: {
    auth: { type: "Bearer", token: storedSessionToken },
  },
});
```

By default the plugin accepts either an opaque database session token or the
signed Better Call cookie value. Set
`BearerPlugin::new(BearerConfig { require_signature: true })` to accept only the
signed form. An accepted bearer credential takes precedence over a session
cookie even if its session no longer exists; an invalid signed credential is a
no-op and leaves cookie authentication available, matching upstream. Normal
session existence, expiry, revocation, cache binding, bans, and enabled plugin
policy still apply. Matching upstream hook ordering, a syntactically accepted
Bearer credential bypasses browser `Origin` and cross-site-navigation checks;
an invalid signed credential does not bypass those checks for a coexisting
cookie. The plugin never reads query/body tokens and does not add bearer-specific
JSON errors, `WWW-Authenticate`, routes, schema, migrations, or client metadata.
Responses that set a live primary session cookie expose its complete decoded
signed value through `set-auth-token` and
`Access-Control-Expose-Headers`; sign-out/expiry cookies do not.

JWT-plugin tokens are service tokens for external resource servers to verify
against JWKS. Bearer does not accept those JWTs; it transports Better Auth
session credentials. OAuth Popup uses this plugin only for a cross-origin
embedded client that cannot rely on its partitioned browser cookie.

JWT is an independent optional plugin. Its default is Better Auth 1.7.1 EdDSA
with an Ed25519 key, a 15-minute token lifetime, `GET /jwks`, and authenticated
`GET /token`:

```rust
use lucid_auth::{JwkAlgorithm, JwtConfig, JwtPlugin};

let mut jwt = JwtConfig::default();
jwt.jwks.key_pair_config = Some(JwkAlgorithm::EdDsa);
config.add_plugin(JwtPlugin::new(jwt))?;
```

Register `jwtClient()` from `better-auth/client/plugins` in the official
JavaScript client. Its `token()` method calls `/token`; `jwks()` calls the path
configured on the client plugin, which must match `jwt.jwks.jwks_path` on the
Rust server. Native server code uses `service.jwt()` for server-only signing,
verification, key creation, and exact key selection. The supported algorithms
are EdDSA/Ed25519, ES256, ES512, PS256, and RS256.

The plugin lazily creates signing keys and contributes its JWKS schema.
Private JWKs are encrypted by default with Better Auth's randomized
XChaCha20-Poly1305 format. `AuthConfig::set_versioned_secrets` enables `$ba$`
versioned envelopes and optional legacy bare-hex decryption during secret
rotation. Bind `AuthService` and run `PostgresStore::migrate` before serving;
memory storage needs no setup. Custom table/field names and independent
read/create adapter callbacks are available through `JwtConfig`.

Set `jwt.session_cookie_cache = true` together with
`config.session.cookie_cache.strategy = CookieCacheStrategy::Jwt` to replace
the ordinary HS256 cache token with Better Auth's asymmetric, JWKS-verifiable
session-cache profile. Remote `jwt.sign` cannot be combined with this mode.
`jwks.remote_url` makes the local JWKS route return 404 and requires an explicit
primary algorithm for discovery metadata. JWT responses are `no-store`, and
only public JWK fields are returned over HTTP.

One-Time Token is an independent optional plugin for transferring an existing
session to another browser, device, or domain:

```rust
config.add_plugin(OneTimeTokenPlugin::default())?;
```

```ts
import { createAuthClient } from "better-auth/client";
import { oneTimeTokenClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
  plugins: [oneTimeTokenClient()],
});

const { data: generated } = await authClient.oneTimeToken.generate();
await authClient.oneTimeToken.verify({ token: generated.token });
```

Generation requires an ordinary session. Tokens default to 32 random
characters, expire after three minutes, and are consumed atomically before the
referenced session is checked. Storage is plaintext by Better Auth default;
select `OneTimeTokenStorage::Hashed` or provide a custom async hasher when the
adapter must not contain the raw transfer token. A custom async generator,
server-only HTTP generation, verification without setting a session cookie,
and automatic `set-ott` headers on responses that bind a session are available
through `OneTimeTokenConfig`.

The token is a portable bearer credential, not a purpose- or user-bound proof.
Redemption returns and optionally binds the originating session even when the
browser already has a different session. It has no payload, origin, IP, or
freshness policy. Matching Better Auth 1.7.1 exactly, redemption burns the token
before session lookup; missing and expired sessions therefore cannot be retried.
The pinned implementation also queues the referenced session cookie before its
expired-session rejection and can issue a successor `set-ott` header when that
hook is enabled. Applications should use short expiries, hashed storage, secure
transport, and avoid enabling the response header unless that exchange flow is
required.

Lucid deliberately does not reproduce five pinned 1.7.1 bugs: an expired/null
session cannot receive `set-auth-jwt`; schema remapping is instance-local;
token responses and errors are never cacheable; private JWKs are redacted from
ordinary diagnostics even when storage encryption is disabled; and service
token signing fails unless issuer/audience can be resolved safely. These are
security/correctness fixes, not legacy modes or compatibility aliases.

Additional fields for Better Auth's user, session, account, and verification
models are explicit and typed. Plugin schema descriptors are merged in the order
plugins are supplied; each core model then applies its core fields, those merged
plugin fields, and finally the host's additional fields. The result is available
through `AuthService::database_schema_fields`.
Client input validation runs before hooks. The adapter phase then applies
defaults and input transforms once to the final shallow-patched data; updates
also apply `on_update_with`. Responses apply returned/output policy.
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

PostgreSQL creates each configured additional field as its own resolved physical
column, including model/field remaps, references, and indexes. There is no
catch-all JSONB persistence column or legacy fallback.

Set `AuthConfig::database_hooks` for host hooks or implement
`AuthPlugin::database_hooks` for plugin hooks. Before hooks run in plugin
dependency order and then host order; they can continue, shallow-merge a
partial top-level patch, or cancel. Explicit null and undefined values overwrite
earlier values, while nested objects replace instead of recursively merging.
There is no whole-record replacement alias. A cancellation or error prevents
the authoritative write. After hooks run in the same order only after
persistence has committed, so an after-hook error is reported but does not roll
the write back.

`DatabaseHookContext::transaction` exposes the active canonical-logical adapter
view for reentrant reads and writes. User/account creation inserts the user,
passes its adapter-returned string ID to the account hook, inserts the account,
and commits both before either after hook runs. Memory stages an isolated copy;
PostgreSQL reuses the current SQL transaction and connection, including with a
one-connection pool. Neither adapter retries after hook execution begins.
Custom `AuthStore` implementations provide this boundary through
`AuthStore::transaction`, `DatabaseTransaction`, and
`DatabaseTransactionOperation`; `run_database_transaction` is the typed helper.
HTTP calls include method, path, query, and headers in `DatabaseHookContext`;
native calls have no request. `run_in_background` schedules non-authoritative
follow-up work outside the authoritative transaction. Update hooks may not
change protected identity, ownership, or creation fields.

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
stateless signed tokens, callback URLs, and session-cookie refresh are enforced
in every mode. The two current phases use the exact
`change-email-confirmation` and `change-email-verification` claims; the Better
Auth 1.7.1 legacy token branch remains distinct.

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

For PostgreSQL, pass `AuthService::plugin_migrations()` to
`PostgresStore::migrate_all`. The bound Better Auth schema does not include
guest-capability tables unless this Lucid extension is registered.

Product security auditing is another optional lucid-auth extension. Core stores
have no audit methods, the bound Better Auth schema creates no audit table, and
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
and migrate the schema after binding `AuthService`. The configured factor model
is absent when the plugin is disabled. The official
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
`VerificationEmail` containing the user, verification URL, and signed token.
Configure `AuthConfig::set_base_url` as well so delivered links use the public
authentication origin and base path.
`send_on_sign_up`, `send_on_sign_in`, `auto_sign_in_after_verification`, and
`expires_in` mirror Better Auth's verification lifecycle. Core email links are
stateless HS256 JWTs signed with the current configured secret. Newly issued
tokens contain lowercase email, numeric `iat`/`exp`, and only the
`{"alg":"HS256"}` protected header; they create no verification record.
Expiry has no clock leeway, while the shipped 1.7.1 verifier accepts a validly
signed token with absent temporal claims and validates them when present.

Password reset delivery is supplied by implementing `PasswordResetEmailSender`
and assigning it to `config.email_and_password.send_reset_password`. The sender
receives the user, reset URL, and one-time token. The default expiry is one hour;
`reset_password_token_expires_in`, `revoke_sessions_on_password_reset`, and the
native async `on_password_reset` callback mirror Better Auth's lifecycle options.
Reset requests use a 24-character `a-zA-Z0-9` token and accept Better Auth's
exact `redirectTo` field, while the emailed
callback endpoint accepts exact `callbackURL`; incorrectly cased aliases are not
supported. The complete `reset-password:<token>` identifier is processed once
through the configured plain/hashed/custom verification storage. Password
replacement and single-use token consumption are atomic; `on_password_reset`
runs before optional session revocation.

Current-user deletion is disabled by default. Enable it with
`config.user.delete_user.enabled = true`. Better Auth's password and fresh-session
flows then work immediately; configure a native
`DeleteAccountVerificationSender` to require a purpose-bound, single-use email
token instead. `before_delete` and `after_delete` callbacks compose with plugin
user-deletion hooks, and successful deletion clears the session cookie and all
adapter-owned account data. Deletion links and requests accept only the exact
`callbackURL` spelling.

Core session credentials are always 32 characters from `a-zA-Z0-9`, independent
of session database IDs. Deletion verification uses 32 lowercase-alphanumeric
characters and the complete `delete-account-<token>` identifier, consuming the
record before checking its user binding. Upgrading from the earlier native token
formats intentionally invalidates existing sessions, reset links, persisted
email links, and deletion links; no legacy lookup aliases are retained.

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

Phone Number is an optional native plugin. Supply the same memory, SQLite, or PostgreSQL
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
replace it directly. PostgreSQL deployments migrate the bound service schema so
the unique phone-number index is present.

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
migrate the bound service schema, including the configured wallet-address
model.

Organization is an optional native plugin. Its store is independent from the
core authentication store and can use memory, SQLite, or PostgreSQL:

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
lifecycle hooks have native async traits. SQLite and PostgreSQL users pass the
shared database store and migrate the resolved schema after binding the service.

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
the Better Auth 1.7.1 paths and schemas. Server-only verification and expired-key
cleanup remain native `AuthService` methods and are not mounted as HTTP routes.
Secrets use Better Auth's 64-character
letter-only default generator, optional prefixes, and SHA-256 base64url hashing;
only creation returns the plaintext key. Stored hashes never appear in get,
list, update, or verify responses. Ownership and `configId` are enforced for
management operations. Quota and rate-limit claims are atomic in database and
database-fallback modes in both the memory and PostgreSQL stores. Better Auth's
secondary-storage-only mode deliberately uses a non-atomic read/merge/write
snapshot, so concurrent processes can oversubscribe a quota or rate window.

Set `enable_session_for_api_keys` to accept the configured headers (default
`x-api-key`) as Better Auth sessions. Header arrays, synchronous custom getters,
async validators, callback order/count, multiple named configurations, custom
key generation, starting-character display, expiry bounds/defaults, metadata,
permissions, refills, and per-key rate limits match `@better-auth/api-key@1.7.1`.
Set `storage` to `ApiKeyStorage::SecondaryStorage` for the exact secondary-only
record keys and serialization; set `fallback_to_database` for Better Auth's
database-authoritative read-through cache. `custom_storage` takes precedence
over the service-wide secondary store, and `defer_updates` makes secondary-only
usage writes and invalid-key deletion eventually consistent.

`disable_key_hashing` stores bearer secrets in plaintext and materially worsens
the impact of a database or cache breach. API-key-backed sessions impersonate
the owning user and are not recommended as a general production session
mechanism. Deferred updates can expose stale state, and the secondary-only
reference-list lock is process-local rather than distributed. Set a named
configuration's `reference` to `ApiKeyReference::Organization` to require the
Organization plugin and enforce its `apiKey` create/read/update/delete
permissions. The pinned oracle and native storage/request contracts are tracked
by [#76](https://github.com/lucid-softworks/auth/issues/76).

Native plugins implement `AuthPlugin` and are registered with
`AuthConfig::add_plugin`. Construct plugin-enabled services with
`AuthService::try_new` so invalid IDs, missing or cyclic dependencies,
conflicts, duplicate/core route ownership, cookie collisions, migration IDs,
rate limits, middleware declarations, and false or incomplete provenance claims
fail before the router starts. Every `PluginDescriptor` is explicitly either a
`PinnedBetterAuthPort`, with exact upstream server artifact identity, or a
`LucidExtension`, which makes no Better Auth compatibility claim. Official
upstream client metadata is separate from server identity; application-authored
client metadata cannot be reported as upstream evidence. Plugin routes remain
inside the normal origin/CORS security boundary, while plugin middleware is
scoped to the routes that plugin owns. Session lifecycle hooks run in validated
dependency order.

This is an in-process native Rust composition boundary, not a JavaScript plugin
runtime, community SDK, registry, certification program, or marketplace.
Arbitrary Better Auth npm/JavaScript plugins do not execute in Rust.

PostgreSQL hosts first bind the complete Better Auth schema through
`AuthService`, then migrate that resolved schema plus any Lucid extension
operations:

```rust
let report = store.migrate_all(&service.plugin_migrations()).await?;
assert!(report.compatible);
```

Lucid extension operations are keyed by `(plugin_id, migration_id)`, share the
schema advisory lock, and are transactional and idempotent. Official Better
Auth plugins contribute schema instead of replayable SQL. See the
[native plugin example](examples/native_plugin.rs) for a route, middleware,
migration, cookie/rate-limit declarations, and application-owned client
metadata. The example is a project extension and is not an official Better Auth
plugin or client.

`PostgresStore::migration_plan` derives deterministic tables, columns/types,
and explicit indexes directly from the schema already bound by `AuthService`.
Only Lucid extension operations appear in its migration descriptors.
`diagnose_schema` is a read-only in-process catalog check for pending or changed
extension operations and missing/mistyped physical objects. Reports contain
only operation/object identifiers and never receive or serialize a database
URL.

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
  pair above and apply the full bound schema plus enabled Lucid extension operations.
- To adopt Better Auth Admin directly, register `AdminPlugin` with roles that
  match the values you intentionally keep, or rewrite persisted role values to
  the configured Better Auth roles in an application migration.
- To run core-only, register neither plugin. The bound schema, HTTP responses,
  and principals omit Admin-only fields; lucid-auth does not read compatibility
  aliases for a previous shape.

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
The operator plugin contributes no HTTP endpoint. Its PostgreSQL extension
operation owns the temporary-password table; no compatibility column or alias is
part of the Better Auth schema.

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

PostgreSQL stores Better Auth's opaque session token directly so `listSessions`
and `revokeSession` use the same value. Historical hashed-session layouts are
not a supported compatibility mode.

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
