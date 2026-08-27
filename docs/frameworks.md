# Better Auth client and framework guide

lucid-auth targets the official Better Auth `1.7.1` HTTP clients. Install that
version exactly and select the client entry point for the UI framework:

```sh
npm install --save-exact better-auth@1.7.1
```

| UI | Import |
| --- | --- |
| Vanilla JavaScript/TypeScript | `better-auth/client` |
| React | `better-auth/react` |
| Vue | `better-auth/vue` |
| Svelte | `better-auth/svelte` |
| Solid | `better-auth/solid` |

The configuration is otherwise the same:

```ts
import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
});
```

Replace only the import for Vue, Svelte, Solid, or vanilla. Omit `baseURL` when
the application and auth routes share an origin. If the Rust server uses a
custom base path, include that full path, for example
`https://auth.example.com/custom/auth`.

Use the framework's reactive `useSession` API in browser components. Normal
methods such as `signUp.email`, `signIn.email`, `getSession`, and `signOut` use
the same tested HTTP contract in every entry point. Add a client plugin only
when its server counterpart is marked Supported in the
[compatibility matrix](../COMPATIBILITY.md).

## Separate frontend and auth origins

Configure both sides; setting client `baseURL` alone is not sufficient:

```rust
config.set_base_url("https://auth.example.com")?;
config.trust_origin("https://app.example.com")?;
config.enable_cors();
```

Credentialed CORS responses are emitted only for trusted origins. Never use a
blanket `Access-Control-Allow-Origin: *` layer around the auth router. Browser
requests still need their real `Origin`; callback and redirect URLs must be a
safe relative path or match a configured trusted origin.

## Next.js, Nuxt, SvelteKit, Astro, and other SSR frameworks

These frameworks can use the normal framework client, but their Better Auth
server adapters are replaced by the Rust service:

- Do not create the documented TypeScript catch-all `auth.handler` route.
- Prefer routing `/api/auth/*` through the framework/reverse proxy to lucid-auth
  on the same public origin. The client can then omit `baseURL`.
- If auth has a separate origin, configure trusted-origin CORS and the explicit
  client `baseURL` as above.
- For server-rendered session data, make an HTTP request to
  `/api/auth/get-session` and forward the incoming `cookie` header. Do not call
  `auth.api.getSession`; there is no in-process TypeScript auth object.
- Forward every `Set-Cookie` header unchanged. Preserve `Origin`, `Host`, and
  the transport peer address, and use the trusted-proxy rules from the
  [production guide](production.md).

Next.js route handlers, Nuxt/Nitro server routes, SvelteKit hooks, Astro API
routes, Hono, Express, and Cloudflare Workers examples on the Better Auth site
are server-mount instructions for a JavaScript runtime. They are not additional
wire protocols and should not be mounted alongside lucid-auth.

## Browser extensions

The normal browser client works from an extension when the manifest can reach
the auth origin and the exact extension origin is trusted:

```rust
config.set_base_url("https://auth.example.com")?;
config.trust_origin("chrome-extension://abcdefghijklmnop")?;
config.enable_cors();
```

```json
{
  "host_permissions": ["https://auth.example.com/*"]
}
```

Use the framework client appropriate to the extension UI and set
`baseURL: "https://auth.example.com"`. Pin the extension ID in production; do
not use a wildcard custom scheme. Cookie availability depends on the extension
browser and manifest policy. If cookies are partitioned or unavailable, the
standard browser client does not silently become a bearer-token client.

## Expo and React Native

Pin the official packages and let Expo select SDK-compatible peer versions:

```sh
npm install --save-exact better-auth@1.7.1 @better-auth/expo@1.7.1
npx expo install expo-constants expo-linking expo-network expo-secure-store expo-web-browser
```

Enable only the matching server plugin and list every production scheme
explicitly:

```rust
use lucid_auth::{ExpoOptions, ExpoPlugin};

config.set_base_url("https://auth.example.com")?;
config.trust_origin("myapp://")?;
config.add_plugin(ExpoPlugin::new(ExpoOptions {
    disable_origin_override: false,
}))?;
```

```ts
import { createAuthClient } from "better-auth/react";
import { expoClient } from "@better-auth/expo/client";
import * as SecureStore from "expo-secure-store";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
  plugins: [
    expoClient({
      scheme: "myapp",
      storagePrefix: "myapp",
      storage: SecureStore,
    }),
  ],
});
```

On iOS and Android, `expoClient()` uses `credentials: "omit"`, sends its stored
cookie through the `cookie` header, sends `expo-origin` for non-ID-token
requests, and always sends `x-skip-oauth-proxy: true`. The Rust plugin copies
only `expo-origin` into a missing standard `Origin`; it never replaces an
existing `Origin`, and core trusted-origin and CSRF checks still run. Set
`disable_origin_override` only to reproduce upstream's
`disableOriginOverride: true` option.

Relative values of the exact `callbackURL`, `newUserCallbackURL`, and
`errorCallbackURL` fields become Expo deep links. `callbackUrl` and other casing
aliases are deliberately unsupported. Social and link redirects pass through
the hidden `GET /expo-authorization-proxy`; the server accepts only external
HTTPS URLs without fragments and uses the core 600-second `oauth_state` or
300-second signed `state` cookie. Only callback, magic-link verification, and
email-verification responses can append a complete `Set-Cookie` header to a
trusted custom-scheme redirect. Never log those URLs or cookies.

The plugin itself adds only `exp://` when `NODE_ENV=development`. Add `myapp://`
and any broader development patterns with `AuthConfig::trust_origin`;
production wildcards and local-network CIDRs are never inferred. Expo web
remains the ordinary browser client: there is no header substitution,
SecureStore cookie transport, deep-link rewrite, or native cache behavior.

Cookie filtering, `__Secure-` handling, expiration/deletion, colon-normalized
SecureStore keys, 1,800-character chunk commits, session-cache hydration,
focus/network managers, and the `/plugins` `lastLoginMethodClient` export are
provided by `@better-auth/expo` on the device. They are pinned by the executable
oracle but are not reimplemented or persisted by the Rust server. The server
plugin owns no schema, migration, rate limit, error dictionary, provider,
device store, or retry behavior; see [#77](https://github.com/lucid-softworks/auth/issues/77).

## Electron

The official `@better-auth/electron` system-browser integration is **not yet
compatible**. It requires server-side transfer/code-exchange and proxy routes
that are not part of the core HTTP client. This is tracked in
[#78](https://github.com/lucid-softworks/auth/issues/78).

A hand-written Electron main-process client may use supported HTTP endpoints,
but it must keep cookie/token material out of the renderer and implement its own
safe system-browser callback flow. The documented `electronClient()` and
`electronProxyClient()` must not be advertised until the native plugin passes
their exact conformance contract.

## Client plugins and types

Client plugins are transport helpers for corresponding server behavior. Use
only those listed as Supported. TypeScript `inferAdditionalFields<typeof auth>`
cannot import a Rust server type; for separate client/server projects, declare
additional user and session fields explicitly with Better Auth's client-side
`inferAdditionalFields` form.

The official docs used for this boundary are Better Auth's
[installation](https://better-auth.com/docs/installation),
[client](https://better-auth.com/docs/concepts/client),
[Expo](https://better-auth.com/docs/integrations/expo), and
[Electron](https://better-auth.com/docs/beta/integrations/electron) guides.
