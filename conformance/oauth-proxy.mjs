import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { oAuthProxy } from "better-auth/plugins";

const previewOrigin = "https://preview.example.test";
const productionOrigin = "https://auth.example.test";
const appOrigin = "https://app.example.test";
const previewBaseURL = `${previewOrigin}/api/auth`;
const productionBaseURL = `${productionOrigin}/api/auth`;
const proxySecret = "P".repeat(32);

function success(result, method) {
  assert.equal(result.error, null, `${method}: ${JSON.stringify(result.error)}`);
  assert.notEqual(result.data, null, `${method}: missing data`);
  return result.data;
}

class HandlerTransport {
  constructor(auth) {
    this.auth = auth;
    this.cookies = new Map();
    this.requests = [];
  }

  async fetch(input, init = {}) {
    const incoming = new Request(input, init);
    const headers = new Headers(incoming.headers);
    if (this.cookies.size > 0) headers.set("cookie", this.cookieHeader());
    if (incoming.method !== "GET" && incoming.method !== "HEAD") {
      headers.set("origin", appOrigin);
    }
    const outgoing = new Request(incoming, { headers });
    const response = await this.auth.handler(outgoing);
    this.requests.push({
      body: typeof init.body === "string" ? JSON.parse(init.body) : null,
      method: outgoing.method,
      pathname: new URL(outgoing.url).pathname,
      responseHeaders: new Headers(response.headers),
    });
    for (const cookie of response.headers.getSetCookie()) {
      const [pair, ...attributes] = cookie.split(";");
      const separator = pair.indexOf("=");
      const name = pair.slice(0, separator);
      const value = pair.slice(separator + 1);
      const removed =
        value.length === 0 ||
        attributes.some((attribute) => /^\s*max-age=0\s*$/i.test(attribute));
      if (removed) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return response;
  }

  cookieHeader() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }
}

function authFixture({
  origin,
  globalSecret,
  options,
  getUserInfo = async () => ({
    user: {
      name: "OAuth Proxy User",
      email: "oauth-proxy@example.com",
      emailVerified: true,
      image: "https://provider.example.test/avatar.png",
    },
    data: { id: "oauth-proxy-subject", login: "proxy-user" },
  }),
}) {
  return betterAuth({
    baseURL: `${origin}/api/auth`,
    secret: globalSecret,
    trustedOrigins: [appOrigin, previewOrigin, productionOrigin],
    logger: { disabled: true },
    socialProviders: {
      github: {
        clientId: "oauth-proxy-client",
        clientSecret: "oauth-proxy-client-secret",
        getUserInfo,
      },
    },
    plugins: [oAuthProxy(options)],
  });
}

function request(auth, url, init = {}) {
  return auth.handler(new Request(url, { redirect: "manual", ...init }));
}

function assertRedirectError(response, baseURL, code) {
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), `${baseURL}?error=${code}`);
}

async function metadataConformance() {
  const plugin = oAuthProxy();
  assert.equal(plugin.id, "oauth-proxy");
  assert.equal(plugin.version, "1.7.2");
  assert.equal(plugin.options, undefined);
  assert.deepEqual(Object.keys(plugin.endpoints), ["oAuthProxy"]);
  assert.equal(plugin.endpoints.oAuthProxy.path, "/oauth-proxy-callback");
  assert.equal(plugin.endpoints.oAuthProxy.options.method, "GET");
  assert.equal(plugin.endpoints.oAuthProxy.options.operationId, "oauthProxyCallback");
  assert.deepEqual(
    plugin.endpoints.oAuthProxy.options.metadata.openapi.parameters.map(
      ({ name, required }) => [name, required],
    ),
    [
      ["callbackURL", true],
      ["profile", false],
    ],
  );
  assert.equal(plugin.hooks.before.length, 2);
  assert.equal(plugin.hooks.after.length, 2);
  assert.deepEqual(
    plugin.hooks.before.map((hook) => [
      hook.matcher({ path: "/sign-in/social" }),
      hook.matcher({ path: "/callback/:id" }),
    ]),
    [
      [true, false],
      [false, true],
    ],
  );
  assert.deepEqual(
    plugin.hooks.after.map((hook) => [
      hook.matcher({ path: "/sign-in/social" }),
      hook.matcher({ path: "/callback/:id" }),
    ]),
    [
      [true, false],
      [false, true],
    ],
  );
  for (const unsupported of [
    "client",
    "cookies",
    "schema",
    "migrations",
    "rateLimit",
    "$ERROR_CODES",
  ]) {
    assert.equal(unsupported in plugin, false);
  }

  const configuredOptions = {
    currentURL: previewOrigin,
    productionURL: productionOrigin,
    maxAge: 45,
    secret: proxySecret,
  };
  assert.equal(oAuthProxy(configuredOptions).options, configuredOptions);
}

async function endpointErrorConformance() {
  const auth = authFixture({
    origin: previewOrigin,
    globalSecret: "V".repeat(32),
    options: {
      currentURL: previewOrigin,
      productionURL: productionOrigin,
      secret: proxySecret,
    },
  });
  const endpoint = `${previewBaseURL}/oauth-proxy-callback`;

  const missingCallback = await request(auth, endpoint);
  assert.equal(missingCallback.status, 400);
  assert.deepEqual(await missingCallback.json(), {
    code: "VALIDATION_ERROR",
    message: "[query.callbackURL] Invalid input: expected string, received undefined",
  });

  const untrustedCallback = await request(
    auth,
    `${endpoint}?callbackURL=${encodeURIComponent("https://evil.example.test/done")}`,
  );
  assert.equal(untrustedCallback.status, 403);
  assert.deepEqual(await untrustedCallback.json(), {
    code: "INVALID_CALLBACK_URL",
    message: "Invalid callbackURL",
  });

  const callbackURL = `${appOrigin}/done`;
  const errorURL = `${previewBaseURL}/error`;
  const missingProfile = await request(
    auth,
    `${endpoint}?callbackURL=${encodeURIComponent(callbackURL)}`,
  );
  assertRedirectError(missingProfile, errorURL, "missing_profile");

  const invalidProfile = await request(
    auth,
    `${endpoint}?callbackURL=${encodeURIComponent(callbackURL)}&profile=not-encrypted`,
  );
  assertRedirectError(invalidProfile, errorURL, "invalid_profile");

  const invalidPayload = await symmetricEncrypt({
    key: proxySecret,
    data: "{}",
  });
  const malformed = await request(
    auth,
    `${endpoint}?callbackURL=${encodeURIComponent(callbackURL)}&profile=${encodeURIComponent(invalidPayload)}`,
  );
  assertRedirectError(malformed, errorURL, "invalid_payload");

  const invalidJSON = await symmetricEncrypt({
    key: proxySecret,
    data: "not JSON",
  });
  const unparsable = await request(
    auth,
    `${endpoint}?callbackURL=${encodeURIComponent(callbackURL)}&profile=${encodeURIComponent(invalidJSON)}`,
  );
  assertRedirectError(unparsable, errorURL, "invalid_payload");

  const payloadErrorURL = `${appOrigin}/oauth-error`;
  const expiredPayload = await symmetricEncrypt({
    key: proxySecret,
    data: JSON.stringify({
      timestamp: Date.now() - 61_000,
      userInfo: {},
      account: {},
      state: "expired-state",
      callbackURL,
      errorURL: payloadErrorURL,
    }),
  });
  const expired = await request(
    auth,
    `${endpoint}?callbackURL=${encodeURIComponent(callbackURL)}&profile=${encodeURIComponent(expiredPayload)}`,
  );
  assertRedirectError(expired, payloadErrorURL, "payload_expired");

  const futurePayload = await symmetricEncrypt({
    key: proxySecret,
    data: JSON.stringify({
      timestamp: Date.now() + 11_000,
      userInfo: {},
      account: {},
      state: "future-state",
      callbackURL,
      errorURL: payloadErrorURL,
    }),
  });
  const fromFuture = await request(
    auth,
    `${endpoint}?callbackURL=${encodeURIComponent(callbackURL)}&profile=${encodeURIComponent(futurePayload)}`,
  );
  assertRedirectError(fromFuture, payloadErrorURL, "payload_expired");

  const missingStateCookie = await symmetricEncrypt({
    key: proxySecret,
    data: JSON.stringify({
      timestamp: Date.now(),
      userInfo: { id: "missing-state", email: "missing@example.com", name: "Missing" },
      account: { providerId: "github", accountId: "missing-state" },
      state: "missing-state",
      callbackURL,
      errorURL: payloadErrorURL,
    }),
  });
  const stateMismatch = await request(
    auth,
    `${endpoint}?callbackURL=${encodeURIComponent(callbackURL)}&profile=${encodeURIComponent(missingStateCookie)}`,
  );
  assertRedirectError(stateMismatch, payloadErrorURL, "state_mismatch");
}

async function skippedProxyConformance() {
  const auth = authFixture({
    origin: previewOrigin,
    globalSecret: "S".repeat(32),
    options: {
      currentURL: previewOrigin,
      productionURL: productionOrigin,
      secret: proxySecret,
    },
  });
  const response = await request(auth, `${previewBaseURL}/sign-in/social`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: appOrigin,
      "x-skip-oauth-proxy": "1",
    },
    body: JSON.stringify({
      provider: "github",
      callbackURL: `${appOrigin}/skip-complete`,
      disableRedirect: true,
    }),
  });
  assert.equal(response.status, 200);
  const result = await response.json();
  const providerURL = new URL(result.url);
  assert.equal(
    providerURL.searchParams.get("redirect_uri"),
    `${previewBaseURL}/callback/github`,
  );
  assert.equal(providerURL.searchParams.get("state").length, 32);
}

async function fullProxyConformance() {
  const previewAuth = authFixture({
    origin: previewOrigin,
    globalSecret: "V".repeat(32),
    options: {
      currentURL: previewOrigin,
      productionURL: productionOrigin,
      maxAge: 60,
      secret: proxySecret,
    },
  });
  let userInfoTokens;
  const productionAuth = authFixture({
    origin: productionOrigin,
    globalSecret: "D".repeat(32),
    options: {
      currentURL: productionOrigin,
      productionURL: productionOrigin,
      maxAge: 60,
      secret: proxySecret,
    },
    getUserInfo: async (tokens) => {
      userInfoTokens = tokens;
      return {
        user: {
          name: "OAuth Proxy User",
          email: "oauth-proxy@example.com",
          emailVerified: true,
          image: "https://provider.example.test/avatar.png",
        },
        data: { id: "oauth-proxy-subject", login: "proxy-user" },
      };
    },
  });
  const previewTransport = new HandlerTransport(previewAuth);
  const client = createAuthClient({
    baseURL: previewOrigin,
    fetchOptions: { customFetchImpl: previewTransport.fetch.bind(previewTransport) },
  });
  const callbackURL = `${appOrigin}/oauth-complete`;
  const errorCallbackURL = `${appOrigin}/oauth-error`;
  const newUserCallbackURL = `${appOrigin}/oauth-welcome`;
  const social = success(
    await client.signIn.social({
      provider: "github",
      callbackURL,
      errorCallbackURL,
      newUserCallbackURL,
      disableRedirect: true,
    }),
    "OAuth Proxy signIn.social",
  );
  assert.equal(social.redirect, false);
  const signInRequest = previewTransport.requests.at(-1);
  assert.equal(signInRequest.pathname, "/api/auth/sign-in/social");
  assert.equal(signInRequest.method, "POST");
  assert.deepEqual(signInRequest.body, {
    provider: "github",
    callbackURL,
    errorCallbackURL,
    newUserCallbackURL,
    disableRedirect: true,
  });
  const stateCookie = signInRequest.responseHeaders
    .getSetCookie()
    .find((cookie) => cookie.startsWith("__Secure-better-auth.oauth_state="));
  assert.ok(stateCookie, "preview sign-in did not set the OAuth state cookie");
  assert.match(
    stateCookie,
    /; Max-Age=600; Path=\/; HttpOnly; Secure; SameSite=Lax$/,
  );

  const providerURL = new URL(social.url);
  assert.equal(providerURL.origin, "https://github.com");
  assert.equal(providerURL.pathname, "/login/oauth/authorize");
  assert.equal(
    providerURL.searchParams.get("redirect_uri"),
    `${productionBaseURL}/callback/github`,
  );
  const encryptedStatePackage = providerURL.searchParams.get("state");
  const statePackage = JSON.parse(
    await symmetricDecrypt({ key: proxySecret, data: encryptedStatePackage }),
  );
  assert.deepEqual(Object.keys(statePackage), ["state", "stateCookie", "isOAuthProxy"]);
  assert.equal(statePackage.state.length, 32);
  assert.equal(statePackage.isOAuthProxy, true);
  const stateData = JSON.parse(
    await symmetricDecrypt({ key: proxySecret, data: statePackage.stateCookie }),
  );
  assert.equal(
    stateData.callbackURL,
    `${previewBaseURL}/oauth-proxy-callback?callbackURL=${encodeURIComponent(callbackURL)}`,
  );
  assert.equal(stateData.errorURL, errorCallbackURL);
  assert.equal(stateData.newUserURL, newUserCallbackURL);
  assert.equal(stateData.oauthState, statePackage.state);

  const previousFetch = globalThis.fetch;
  let productionCallback;
  try {
    const denied = await request(
      productionAuth,
      `${productionBaseURL}/callback/github?error=access_denied&state=${encodeURIComponent(encryptedStatePackage)}`,
    );
    assertRedirectError(denied, errorCallbackURL, "access_denied");

    const noCode = await request(
      productionAuth,
      `${productionBaseURL}/callback/github?state=${encodeURIComponent(encryptedStatePackage)}`,
    );
    assertRedirectError(noCode, errorCallbackURL, "no_code");

    const missingProvider = await request(
      productionAuth,
      `${productionBaseURL}/callback/missing?code=ignored&state=${encodeURIComponent(encryptedStatePackage)}`,
    );
    assertRedirectError(
      missingProvider,
      errorCallbackURL,
      "oauth_provider_not_found",
    );

    const mismatchedPackage = await symmetricEncrypt({
      key: proxySecret,
      data: JSON.stringify({ ...statePackage, state: "mismatched-state" }),
    });
    const stateMismatch = await request(
      productionAuth,
      `${productionBaseURL}/callback/github?code=ignored&state=${encodeURIComponent(mismatchedPackage)}`,
    );
    assertRedirectError(stateMismatch, errorCallbackURL, "state_mismatch");

    globalThis.fetch = async () => {
      throw new Error("mock provider rejected the authorization code");
    };
    const invalidCode = await request(
      productionAuth,
      `${productionBaseURL}/callback/github?code=invalid&state=${encodeURIComponent(encryptedStatePackage)}`,
    );
    assertRedirectError(invalidCode, errorCallbackURL, "invalid_code");

    globalThis.fetch = async (input, init = {}) => {
      assert.equal(String(input), "https://github.com/login/oauth/access_token");
      assert.equal(init.method, "POST");
      assert.equal(init.body.get("code"), "proxy-authorization-code");
      assert.equal(
        init.body.get("redirect_uri"),
        `${productionBaseURL}/callback/github`,
      );
      return Response.json({
        access_token: "proxy-access-token",
        refresh_token: "proxy-refresh-token",
        token_type: "bearer",
        scope: "read:user,user:email",
      });
    };
    productionCallback = await request(
      productionAuth,
      `${productionBaseURL}/callback/github?code=proxy-authorization-code&state=${encodeURIComponent(encryptedStatePackage)}`,
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
  assert.equal(productionCallback.status, 302);
  const profileCallbackURL = new URL(productionCallback.headers.get("location"));
  assert.equal(profileCallbackURL.origin, previewOrigin);
  assert.equal(profileCallbackURL.pathname, "/api/auth/oauth-proxy-callback");
  assert.equal(profileCallbackURL.searchParams.get("callbackURL"), callbackURL);
  assert.ok(profileCallbackURL.searchParams.get("profile"));
  assert.equal(userInfoTokens.accessToken, "proxy-access-token");
  assert.equal(userInfoTokens.refreshToken, "proxy-refresh-token");

  const profileCallback = await previewTransport.fetch(profileCallbackURL, {
    redirect: "manual",
  });
  assert.equal(profileCallback.status, 302);
  assert.equal(profileCallback.headers.get("location"), newUserCallbackURL);
  assert.ok(
    profileCallback.headers
      .getSetCookie()
      .some((cookie) => cookie.startsWith("__Secure-better-auth.session_token=")),
    "proxy callback did not bind a preview session",
  );
  const session = success(await client.getSession(), "OAuth Proxy getSession");
  assert.equal(session.user.email, "oauth-proxy@example.com");
  assert.equal(session.user.name, "OAuth Proxy User");
  assert.equal(session.user.image, "https://provider.example.test/avatar.png");
}

export async function oauthProxyConformance() {
  await metadataConformance();
  await endpointErrorConformance();
  await skippedProxyConformance();
  await fullProxyConformance();
  console.log("ok - OAuth Proxy official server and ordinary social client contract");
}
