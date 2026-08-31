import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import {
  DEFAULT_OAUTH_SCOPES,
  oauthProvider,
} from "@better-auth/oauth-provider";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { oauthProviderResourceClient } from "@better-auth/oauth-provider/resource-client";

const origin = "https://issuer.example.test";
const baseURL = `${origin}/api/auth`;
const clientOrigin = "https://client.example.test";
const secret = "R".repeat(32);

function endpointContract(plugin) {
  return Object.entries(plugin.endpoints).map(([key, endpoint]) => [
    key,
    endpoint.path,
    endpoint.options.method,
  ]);
}

function pluginOptions(overrides = {}) {
  return {
    loginPage: "/login",
    consentPage: "/consent",
    disableJwtPlugin: true,
    ...overrides,
  };
}

function fixture(overrides = {}) {
  return betterAuth({
    baseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [oauthProvider(pluginOptions(overrides))],
  });
}

function request(auth, path, init = {}) {
  const url = path.startsWith("http") ? path : `${baseURL}${path}`;
  return auth.handler(new Request(url, { redirect: "manual", ...init }));
}

async function json(response) {
  return response.json();
}

function formRequest(values, headers = {}) {
  return {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(values),
  };
}

function basic(clientId, clientSecret) {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

async function formOnlyEndpointConformance(auth) {
  const expected = {
    message:
      'Content-Type "application/json" is not allowed. Allowed types: application/x-www-form-urlencoded',
    code: "UNSUPPORTED_MEDIA_TYPE",
  };

  for (const path of [
    "/oauth2/token",
    "/oauth2/introspect",
    "/oauth2/revoke",
    "/oauth2/userinfo",
  ]) {
    const response = await request(auth, path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(response.status, 415, `${path} must reject JSON bodies`);
    assert.deepEqual(await json(response), expected);
  }
}

async function metadataConformance() {
  const plugin = oauthProvider(pluginOptions());
  assert.equal(plugin.id, "oauth-provider");
  assert.equal(plugin.version, "1.7.2");
  assert.equal(typeof plugin.onRequest, "function");
  assert.equal(typeof plugin.init, "function");
  assert.equal(plugin.hooks.before.length, 1);
  assert.equal(plugin.hooks.after.length, 1);
  assert.deepEqual(DEFAULT_OAUTH_SCOPES, [
    "openid",
    "profile",
    "email",
    "offline_access",
  ]);
  assert.deepEqual(endpointContract(plugin), [
    ["getOAuthServerConfig", "/.well-known/oauth-authorization-server", "GET"],
    ["getOpenIdConfig", "/.well-known/openid-configuration", "GET"],
    ["oauth2Authorize", "/oauth2/authorize", ["GET", "POST"]],
    ["oauth2Consent", "/oauth2/consent", "POST"],
    ["oauth2Continue", "/oauth2/continue", "POST"],
    ["oauth2Token", "/oauth2/token", "POST"],
    ["oauth2Introspect", "/oauth2/introspect", "POST"],
    ["oauth2Revoke", "/oauth2/revoke", "POST"],
    ["oauth2UserInfo", "/oauth2/userinfo", ["GET", "POST"]],
    ["oauth2EndSession", "/oauth2/end-session", ["GET", "POST"]],
    ["oauth2EndSessionConfirmation", "/oauth2/end-session/confirm", "POST"],
    ["registerOAuthClient", "/oauth2/register", "POST"],
    ["adminCreateOAuthClient", "/admin/oauth2/create-client", "POST"],
    ["createOAuthClient", "/oauth2/create-client", "POST"],
    ["getOAuthClient", "/oauth2/get-client", "GET"],
    ["getOAuthClientPublic", "/oauth2/public-client", "GET"],
    ["getOAuthClientPublicPrelogin", "/oauth2/public-client-prelogin", "POST"],
    ["getOAuthClients", "/oauth2/get-clients", "GET"],
    ["adminUpdateOAuthClient", "/admin/oauth2/update-client", "PATCH"],
    ["updateOAuthClient", "/oauth2/update-client", "POST"],
    ["rotateClientSecret", "/oauth2/client/rotate-secret", "POST"],
    ["deleteOAuthClient", "/oauth2/delete-client", "POST"],
    ["getOAuthConsent", "/oauth2/get-consent", "GET"],
    ["getOAuthConsents", "/oauth2/get-consents", "GET"],
    ["updateOAuthConsent", "/oauth2/update-consent", "POST"],
    ["deleteOAuthConsent", "/oauth2/delete-consent", "POST"],
    ["adminCreateOAuthResource", "/admin/oauth2/resources", "POST"],
    ["adminListOAuthResources", "/admin/oauth2/resources", "GET"],
    ["adminGetOAuthResource", "/admin/oauth2/resources/:identifier", "GET"],
    ["adminUpdateOAuthResource", "/admin/oauth2/resources/:identifier", "PATCH"],
    ["adminDeleteOAuthResource", "/admin/oauth2/resources/:identifier", "DELETE"],
    [
      "adminLinkClientResource",
      "/admin/oauth2/resources/:identifier/clients/:client_id",
      "POST",
    ],
    [
      "adminUnlinkClientResource",
      "/admin/oauth2/resources/:identifier/clients/:client_id",
      "DELETE",
    ],
  ]);
  assert.deepEqual(Object.keys(plugin.schema), [
    "oauthClient",
    "oauthResource",
    "oauthClientResource",
    "oauthRefreshToken",
    "oauthAccessToken",
    "oauthConsent",
    "oauthClientAssertion",
  ]);
  assert.deepEqual(
    plugin.rateLimit.map(({ window, max }) => [window, max]),
    [
      [60, 20],
      [60, 30],
      [60, 100],
      [60, 30],
      [60, 5],
      [60, 60],
    ],
  );
  assert.deepEqual(
    plugin.rateLimit.map((rule) =>
      [
        "/oauth2/token",
        "/oauth2/authorize",
        "/oauth2/introspect",
        "/oauth2/revoke",
        "/oauth2/register",
        "/oauth2/userinfo",
      ].find((path) => rule.pathMatcher(path)),
    ),
    [
      "/oauth2/token",
      "/oauth2/authorize",
      "/oauth2/introspect",
      "/oauth2/revoke",
      "/oauth2/register",
      "/oauth2/userinfo",
    ],
  );
  assert.deepEqual(plugin.options, {
    codeExpiresIn: 600,
    accessTokenExpiresIn: 3600,
    m2mAccessTokenExpiresIn: 3600,
    refreshTokenExpiresIn: 2_592_000,
    refreshTokenReuseInterval: 0,
    allowUnauthenticatedClientRegistration: false,
    allowDynamicClientRegistration: false,
    disableJwtPlugin: true,
    storeClientSecret: "encrypted",
    storeTokens: "hashed",
    grantTypes: ["authorization_code", "client_credentials", "refresh_token"],
    loginPage: "/login",
    consentPage: "/consent",
    scopes: DEFAULT_OAUTH_SCOPES,
    claims: [
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "sid",
      "scope",
      "azp",
      "name",
      "picture",
      "given_name",
      "family_name",
      "email",
      "email_verified",
    ],
    clientRegistrationAllowedScopes: undefined,
  });
}

function configurationConformance() {
  assert.throws(
    () =>
      oauthProvider(
        pluginOptions({
          scopes: ["openid"],
          clientRegistrationAllowedScopes: ["missing"],
        }),
      ),
    /clientRegistrationAllowedScope missing not found in scopes/,
  );
  assert.throws(
    () => oauthProvider(pluginOptions({ pairwiseSecret: "too-short" })),
    /pairwiseSecret must be at least 32 characters long/,
  );
  assert.throws(
    () => oauthProvider(pluginOptions({ grantTypes: ["refresh_token"] })),
    /refresh_token grant requires authorization_code grant/,
  );
  assert.throws(
    () => oauthProvider(pluginOptions({ storeClientSecret: "hashed" })),
    /unable to store hashed secrets because id tokens will be signed with secret/,
  );
  assert.throws(
    () =>
      oauthProvider({
        loginPage: "/login",
        consentPage: "/consent",
        storeClientSecret: "encrypted",
      }),
    /encryption method not recommended, please use 'hashed' or the 'hash' function/,
  );
}

async function clientConformance() {
  const plugin = oauthProviderClient();
  assert.equal(plugin.id, "oauth-provider-client");
  assert.equal(plugin.version, "1.7.2");
  assert.equal(plugin.fetchPlugins.length, 1);
  assert.equal(plugin.fetchPlugins[0].id, "oauth-provider-signin");
  assert.deepEqual(plugin.$InferServerPlugin, {});

  const previousWindow = globalThis.window;
  globalThis.window = {
    location: {
      search:
        "?client_id=untrusted&state=unsigned&scope=ignored&sig=signed-value" +
        "&ba_param=client_id&ba_param=sig&ba_param=ba_param",
    },
  };
  try {
    const context = {
      method: "POST",
      headers: new Headers({ "content-type": "application/json" }),
      body: JSON.stringify({ email: "user@example.com" }),
    };
    await plugin.fetchPlugins[0].hooks.onRequest(context);
    const body = JSON.parse(context.body);
    assert.equal(body.email, "user@example.com");
    const oauthQuery = new URLSearchParams(body.oauth_query);
    assert.equal(oauthQuery.get("client_id"), "untrusted");
    assert.equal(oauthQuery.get("sig"), "signed-value");
    assert.equal(oauthQuery.get("state"), null);
    assert.equal(oauthQuery.get("scope"), null);

    const prepopulated = {
      method: "POST",
      headers: new Headers({ "content-type": "application/json" }),
      body: JSON.stringify({ oauth_query: "preserved=1" }),
    };
    await plugin.fetchPlugins[0].hooks.onRequest(prepopulated);
    assert.deepEqual(JSON.parse(prepopulated.body), { oauth_query: "preserved=1" });
  } finally {
    if (previousWindow === undefined) delete globalThis.window;
    else globalThis.window = previousWindow;
  }

  const resourcePlugin = oauthProviderResourceClient();
  assert.equal(resourcePlugin.id, "oauth-provider-resource-client");
  assert.equal(resourcePlugin.version, "1.7.2");
  const actions = resourcePlugin.getActions();
  assert.deepEqual(Object.keys(actions), [
    "verifyBearerToken",
    "verifyAccessTokenRequest",
    "getProtectedResourceMetadata",
  ]);
  const protectedResource = await actions.getProtectedResourceMetadata(
    {
      resource: "https://resource.example.test",
      authorization_servers: [baseURL],
      scopes_supported: ["read"],
    },
    { externalScopes: ["read"] },
  );
  assert.equal(protectedResource.resource, "https://resource.example.test");
  assert.deepEqual(protectedResource.authorization_servers, [baseURL]);
  assert.deepEqual(protectedResource.scopes_supported, ["read"]);
  assert.ok(protectedResource.dpop_signing_alg_values_supported.includes("ES256"));
  await assert.rejects(
    actions.verifyBearerToken("", {
      verifyOptions: { audience: "https://resource.example.test", issuer: baseURL },
    }),
    (error) => error.status === "UNAUTHORIZED",
  );
}

async function serverConformance() {
  const storedTokens = [];
  const auth = fixture({
    scopes: [...DEFAULT_OAUTH_SCOPES, "read"],
    allowDynamicClientRegistration: true,
    allowUnauthenticatedClientRegistration: true,
    scopeExpirations: { read: "90s" },
    prefix: { opaqueAccessToken: "oracle_at_" },
    generateOpaqueAccessToken: () => "generatedOpaqueToken",
    storeTokens: {
      hash: (token, type) => {
        storedTokens.push({ token, type });
        return `stored:${type}:${token}`;
      },
    },
    customAccessTokenClaims: () => ({
      oracle_access_claim: true,
      iss: "https://untrusted.example.test",
    }),
    customTokenResponseFields: ({ grantType, scopes, verificationValue }) => ({
      oracle_grant: grantType,
      oracle_scopes: scopes,
      oracle_has_verification: verificationValue !== undefined,
      access_token: "must-not-override",
      expires_in: -1,
    }),
    validateInitialAccessToken: ({ initialAccessToken }) =>
      initialAccessToken === "initial-registration-token" ? {} : false,
    clientPrivileges: () => true,
  });

  const discovery = await request(auth, "/.well-known/openid-configuration");
  assert.equal(discovery.status, 200);
  const metadata = await json(discovery);
  assert.equal(metadata.issuer, baseURL);
  assert.equal(metadata.authorization_endpoint, `${baseURL}/oauth2/authorize`);
  assert.equal(metadata.token_endpoint, `${baseURL}/oauth2/token`);
  assert.equal(metadata.introspection_endpoint, `${baseURL}/oauth2/introspect`);
  assert.equal(metadata.revocation_endpoint, `${baseURL}/oauth2/revoke`);
  assert.equal(metadata.userinfo_endpoint, `${baseURL}/oauth2/userinfo`);
  assert.equal(metadata.registration_endpoint, `${baseURL}/oauth2/register`);
  assert.deepEqual(metadata.response_types_supported, ["code"]);
  assert.ok(metadata.code_challenge_methods_supported.includes("S256"));
  assert.ok(metadata.scopes_supported.includes("openid"));
  assert.ok(metadata.scopes_supported.includes("read"));
  assert.ok(metadata.grant_types_supported.includes("client_credentials"));

  await formOnlyEndpointConformance(auth);

  const head = await request(auth, "/.well-known/openid-configuration", {
    method: "HEAD",
  });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");
  const invalidDiscoveryMethod = await request(
    auth,
    "/.well-known/openid-configuration",
    { method: "POST" },
  );
  assert.equal(invalidDiscoveryMethod.status, 405);
  assert.equal(invalidDiscoveryMethod.headers.get("allow"), "GET, HEAD");

  const registrationBody = {
    client_name: "Conformance Client",
    redirect_uris: [`${clientOrigin}/callback`],
    token_endpoint_auth_method: "client_secret_basic",
    grant_types: ["client_credentials"],
    scope: "read",
  };
  const unauthenticatedMachineClient = await request(auth, "/oauth2/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(registrationBody),
  });
  assert.equal(unauthenticatedMachineClient.status, 400);
  assert.deepEqual(await json(unauthenticatedMachineClient), {
    error: "invalid_client_metadata",
    error_description: "client_credentials grant requires authenticated registration",
  });

  const registration = await request(auth, "/oauth2/register", {
    method: "POST",
    headers: {
      authorization: "Bearer initial-registration-token",
      "content-type": "application/json",
    },
    body: JSON.stringify(registrationBody),
  });
  assert.equal(registration.status, 201, await registration.clone().text());
  const dynamicallyRegistered = await json(registration);
  assert.match(dynamicallyRegistered.client_id, /^[A-Za-z]{32}$/);
  assert.match(dynamicallyRegistered.client_secret, /^[A-Za-z]{32}$/);
  assert.equal(dynamicallyRegistered.client_name, "Conformance Client");
  assert.deepEqual(dynamicallyRegistered.redirect_uris, [`${clientOrigin}/callback`]);
  assert.equal(
    dynamicallyRegistered.token_endpoint_auth_method,
    "client_secret_basic",
  );
  assert.deepEqual(dynamicallyRegistered.grant_types, ["client_credentials"]);
  assert.equal(
    dynamicallyRegistered.scope,
    "openid profile email offline_access read",
  );

  const signUp = await request(auth, "/sign-up/email", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin,
    },
    body: JSON.stringify({
      name: "OAuth Operator",
      email: "oauth-operator@example.com",
      password: "correct horse battery staple",
    }),
  });
  assert.equal(signUp.status, 200, await signUp.clone().text());
  const sessionCookie = signUp.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith("__Secure-better-auth.session_token="))
    .split(";", 1)[0];
  const serverOnlyRegistration = await request(auth, "/admin/oauth2/create-client", {
    method: "POST",
    headers: {
      cookie: sessionCookie,
      "content-type": "application/json",
      origin,
    },
    body: JSON.stringify({
      ...registrationBody,
      client_name: "Managed Machine Client",
      client_credentials_scopes: ["read"],
    }),
  });
  assert.equal(serverOnlyRegistration.status, 404);

  const registered = await auth.api.adminCreateOAuthClient({
    headers: new Headers({ cookie: sessionCookie, origin }),
    body: {
      ...registrationBody,
      client_name: "Managed Machine Client",
      client_credentials_scopes: ["read"],
    },
  });
  assert.match(registered.client_id, /^[A-Za-z]{32}$/);
  assert.match(registered.client_secret, /^[A-Za-z]{32}$/);
  assert.equal(registered.client_name, "Managed Machine Client");
  assert.deepEqual(registered.client_credentials_scopes, ["read"]);

  const invalidClient = await request(
    auth,
    "/oauth2/token",
    formRequest(
      { grant_type: "client_credentials", scope: "read" },
      { authorization: basic(registered.client_id, "wrong-secret") },
    ),
  );
  assert.equal(invalidClient.status, 401);
  assert.equal(invalidClient.headers.get("www-authenticate"), "Basic");
  assert.deepEqual(await json(invalidClient), {
    error: "invalid_client",
    error_description: "invalid client_secret",
  });

  const tokenResponse = await request(
    auth,
    "/oauth2/token",
    formRequest(
      { grant_type: "client_credentials", scope: "read" },
      { authorization: basic(registered.client_id, registered.client_secret) },
    ),
  );
  assert.equal(tokenResponse.status, 200, await tokenResponse.clone().text());
  assert.equal(tokenResponse.headers.get("cache-control"), "no-store");
  assert.equal(tokenResponse.headers.get("pragma"), "no-cache");
  const issued = await json(tokenResponse);
  assert.equal(issued.token_type, "Bearer");
  assert.equal(issued.expires_in, 90);
  assert.ok(Math.abs(issued.expires_at - Math.floor(Date.now() / 1000) - 90) <= 1);
  assert.equal(issued.scope, "read");
  assert.equal(issued.access_token, "oracle_at_generatedOpaqueToken");
  assert.equal(issued.oracle_grant, "client_credentials");
  assert.deepEqual(issued.oracle_scopes, ["read"]);
  assert.equal(issued.oracle_has_verification, false);
  assert.equal("refresh_token" in issued, false);
  assert.equal("id_token" in issued, false);
  assert.deepEqual(storedTokens[0], {
    token: "generatedOpaqueToken",
    type: "access_token",
  });

  const literalScopeSplit = await request(
    auth,
    "/oauth2/token",
    formRequest(
      { grant_type: "client_credentials", scope: "read  read" },
      { authorization: basic(registered.client_id, registered.client_secret) },
    ),
  );
  assert.equal(literalScopeSplit.status, 400);
  assert.deepEqual(await json(literalScopeSplit), {
    error: "invalid_scope",
    error_description: "The following scopes are invalid: ",
  });

  const introspected = await request(
    auth,
    "/oauth2/introspect",
    formRequest(
      { token: issued.access_token },
      { authorization: basic(registered.client_id, registered.client_secret) },
    ),
  );
  assert.equal(introspected.status, 200);
  assert.equal(introspected.headers.get("cache-control"), "no-store");
  const active = await json(introspected);
  assert.equal(active.active, true);
  assert.equal(active.client_id, registered.client_id);
  assert.equal(active.scope, "read");
  assert.equal(active.token_type, "Bearer");
  assert.equal(active.oracle_access_claim, true);
  assert.equal(active.iss, baseURL);
  assert.ok(
    storedTokens.some(
      ({ token, type }) =>
        token === "generatedOpaqueToken" && type === "access_token",
    ),
  );

  const userInfo = await request(auth, "/oauth2/userinfo", {
    headers: { authorization: `Bearer ${issued.access_token}` },
  });
  assert.equal(userInfo.status, 400);
  assert.equal(userInfo.headers.get("cache-control"), "no-store");
  assert.equal(userInfo.headers.get("www-authenticate"), null);
  assert.deepEqual(await json(userInfo), {
    error: "invalid_scope",
    error_description: "Missing required scope",
  });

  const revoked = await request(
    auth,
    "/oauth2/revoke",
    formRequest(
      { token: issued.access_token },
      { authorization: basic(registered.client_id, registered.client_secret) },
    ),
  );
  assert.equal(revoked.status, 200);
  assert.equal(await revoked.text(), "");

  const afterRevocation = await request(
    auth,
    "/oauth2/introspect",
    formRequest(
      { token: issued.access_token },
      { authorization: basic(registered.client_id, registered.client_secret) },
    ),
  );
  assert.equal(afterRevocation.status, 200);
  assert.deepEqual(await json(afterRevocation), { active: false });
}

export async function oauthProviderConformance() {
  await metadataConformance();
  configurationConformance();
  await clientConformance();
  await serverConformance();
  console.log("ok - OAuth Provider official server and client contract");
}

function nativeSuccess(result, operation) {
  assert.equal(
    result.error,
    null,
    `${operation}: ${JSON.stringify(result.error)}`,
  );
  return result.data;
}

export async function oauthProviderNativeConformance(baseURL, customFetchImpl) {
  const client = createAuthClient({
    baseURL,
    fetchOptions: { customFetchImpl },
    plugins: [oauthProviderClient()],
  });
  nativeSuccess(
    await client.signIn.email({
      email: "luna@example.com",
      password: "correct horse battery staple",
    }),
    "oauthProvider.signIn",
  );
  const created = nativeSuccess(
    await client.oauth2.createClient({
      redirect_uris: ["https://official-client.example/callback"],
      client_name: "Official OAuth Provider client",
    }),
    "oauthProvider.createClient",
  );
  assert.equal(created.client_name, "Official OAuth Provider client");
  assert.equal(typeof created.client_id, "string");
  assert.equal(typeof created.client_secret, "string");

  const fetched = nativeSuccess(
    await client.oauth2.getClient({ query: { client_id: created.client_id } }),
    "oauthProvider.getClient",
  );
  assert.equal(fetched.client_id, created.client_id);
  const listed = nativeSuccess(
    await client.oauth2.getClients(),
    "oauthProvider.getClients",
  );
  assert.ok(listed.some((candidate) => candidate.client_id === created.client_id));

  const updated = nativeSuccess(
    await client.oauth2.updateClient({
      client_id: created.client_id,
      update: { client_name: "Updated official client" },
    }),
    "oauthProvider.updateClient",
  );
  assert.equal(updated.client_name, "Updated official client");
  const rotated = nativeSuccess(
    await client.oauth2.client.rotateSecret({ client_id: created.client_id }),
    "oauthProvider.rotateClientSecret",
  );
  assert.equal(typeof rotated.client_secret, "string");
  assert.notEqual(rotated.client_secret, created.client_secret);

  nativeSuccess(
    await client.oauth2.deleteClient({ client_id: created.client_id }),
    "oauthProvider.deleteClient",
  );
  console.log("ok - OAuth Provider official client against native server");
}
