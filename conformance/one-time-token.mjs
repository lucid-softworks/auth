import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { oneTimeTokenClient } from "better-auth/client/plugins";
import { oneTimeToken } from "better-auth/plugins";

const authOrigin = "https://one-time-token.example.test";
const authBaseURL = `${authOrigin}/api/auth`;
const secret = "R".repeat(32);

function success(result, method) {
  assert.equal(result.error, null, `${method}: ${JSON.stringify(result.error)}`);
  assert.notEqual(result.data, null, `${method}: missing data`);
  return result.data;
}

function error(result, method, message) {
  assert.equal(result.data, null, `${method}: unexpectedly returned data`);
  assert.equal(result.error?.status, 400, `${method}: ${JSON.stringify(result.error)}`);
  assert.equal(result.error?.message, message);
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
      headers.set("origin", authOrigin);
    }
    const outgoing = new Request(incoming, { headers });
    const response = await this.auth.handler(outgoing);
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
    this.requests.push({
      body: typeof init.body === "string" ? JSON.parse(init.body) : null,
      method: outgoing.method,
      pathname: new URL(outgoing.url).pathname,
      responseHeaders: new Headers(response.headers),
    });
    return response;
  }

  cookieHeader() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }
}

function fixture(pluginOptions, authOptions = {}, capturedVerifications = []) {
  const auth = betterAuth({
    baseURL: authBaseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    ...authOptions,
    databaseHooks: {
      ...authOptions.databaseHooks,
      verification: {
        ...authOptions.databaseHooks?.verification,
        create: {
          ...authOptions.databaseHooks?.verification?.create,
          after: async (verification, context) => {
            capturedVerifications.push({ verification, context });
            await authOptions.databaseHooks?.verification?.create?.after?.(
              verification,
              context,
            );
          },
        },
      },
    },
    plugins: [oneTimeToken(pluginOptions)],
  });
  const transport = new HandlerTransport(auth);
  const client = createAuthClient({
    baseURL: authOrigin,
    fetchOptions: { customFetchImpl: transport.fetch.bind(transport) },
    plugins: [oneTimeTokenClient()],
  });
  return { auth, client, transport };
}

async function signUp(client, identity) {
  return success(
    await client.signUp.email({
      name: `OTT ${identity}`,
      email: `${identity}@example.com`,
      password: "correct horse battery staple",
    }),
    `${identity} signUp.email`,
  );
}

async function directVerify(auth, token, extra = {}) {
  return auth.handler(
    new Request(`${authBaseURL}/one-time-token/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: authOrigin,
      },
      body: JSON.stringify({ token, ...extra }),
    }),
  );
}

function metadataConformance() {
  const server = oneTimeToken();
  assert.equal(server.id, "one-time-token");
  assert.equal(server.version, "1.7.2");
  assert.equal(server.options, undefined);
  assert.deepEqual(Object.keys(server.endpoints), [
    "generateOneTimeToken",
    "verifyOneTimeToken",
  ]);
  assert.equal(server.endpoints.generateOneTimeToken.path, "/one-time-token/generate");
  assert.equal(server.endpoints.generateOneTimeToken.options.method, "GET");
  assert.equal(server.endpoints.verifyOneTimeToken.path, "/one-time-token/verify");
  assert.equal(server.endpoints.verifyOneTimeToken.options.method, "POST");
  assert.equal(server.hooks.after.length, 1);
  for (const unsupported of ["schema", "cookies", "migrations", "$ERROR_CODES"]) {
    assert.equal(unsupported in server, false);
  }

  const configuredOptions = { expiresIn: 7, storeToken: "hashed" };
  assert.equal(oneTimeToken(configuredOptions).options, configuredOptions);

  const client = oneTimeTokenClient();
  assert.deepEqual(client, {
    id: "one-time-token",
    version: "1.7.2",
    $InferServerPlugin: {},
  });
}

async function defaultAndClientConformance() {
  const captured = [];
  const { auth, client, transport } = fixture(undefined, {}, captured);
  const unauthorized = await transport.fetch(
    `${authBaseURL}/one-time-token/generate`,
  );
  assert.equal(unauthorized.status, 401);
  assert.deepEqual(await unauthorized.json(), {
    code: "UNAUTHORIZED",
    message: "Unauthorized",
  });

  const first = await signUp(client, "ott-first");
  assert.equal(transport.requests.at(-1).responseHeaders.get("set-ott"), null);
  const generated = success(
    await client.oneTimeToken.generate(),
    "oneTimeToken.generate",
  );
  assert.match(generated.token, /^[A-Za-z0-9_-]{32}$/);
  assert.equal(transport.requests.at(-1).pathname, "/api/auth/one-time-token/generate");
  assert.equal(transport.requests.at(-1).method, "GET");
  assert.equal(captured.length, 1);
  assert.equal(captured[0].verification.identifier, `one-time-token:${generated.token}`);
  assert.equal(captured[0].verification.value, first.token);
  const lifetime =
    new Date(captured[0].verification.expiresAt).getTime() -
    new Date(captured[0].verification.createdAt).getTime();
  assert.ok(lifetime >= 179_000 && lifetime <= 180_000);

  const secondTransport = new HandlerTransport(auth);
  const secondClient = createAuthClient({
    baseURL: authOrigin,
    fetchOptions: { customFetchImpl: secondTransport.fetch.bind(secondTransport) },
    plugins: [oneTimeTokenClient()],
  });
  const second = await signUp(secondClient, "ott-second");
  const verified = success(
    await secondClient.oneTimeToken.verify({ token: generated.token }),
    "oneTimeToken.verify portable handoff",
  );
  assert.equal(verified.user.id, first.user.id);
  assert.equal(verified.session.token, first.token);
  assert.equal("token" in verified, false);
  assert.equal(secondTransport.requests.at(-1).pathname, "/api/auth/one-time-token/verify");
  assert.equal(secondTransport.requests.at(-1).method, "POST");
  assert.deepEqual(secondTransport.requests.at(-1).body, { token: generated.token });
  assert.notEqual(verified.user.id, second.user.id);
  assert.equal(
    success(await secondClient.getSession(), "session after OTT handoff").user.id,
    first.user.id,
  );

  error(
    await secondClient.oneTimeToken.verify({ token: generated.token }),
    "oneTimeToken replay",
    "Invalid token",
  );
  error(
    await secondClient.oneTimeToken.verify({ token: "not-a-token" }),
    "oneTimeToken invalid",
    "Invalid token",
  );

  const purposeAgnostic = success(
    await client.oneTimeToken.generate(),
    "purpose-agnostic generate",
  );
  const purposeResponse = await directVerify(auth, purposeAgnostic.token, {
    payload: { ignored: true },
    purpose: "ignored-purpose",
  });
  assert.equal(purposeResponse.status, 200);
  assert.equal((await purposeResponse.json()).user.id, first.user.id);

  const concurrent = success(
    await client.oneTimeToken.generate(),
    "concurrent generate",
  );
  const concurrentResponses = await Promise.all([
    directVerify(auth, concurrent.token),
    directVerify(auth, concurrent.token),
  ]);
  assert.deepEqual(
    concurrentResponses.map((response) => response.status).sort(),
    [200, 400],
  );
  assert.deepEqual(
    await concurrentResponses.find((response) => response.status === 400).json(),
    { message: "Invalid token" },
  );
}

async function storageConformance() {
  const hashedRows = [];
  const hashedFixture = fixture({ storeToken: "hashed" }, {}, hashedRows);
  await signUp(hashedFixture.client, "ott-hashed");
  const hashed = success(
    await hashedFixture.client.oneTimeToken.generate(),
    "hashed generate",
  );
  const expectedHash = createHash("sha256").update(hashed.token).digest("base64url");
  assert.equal(
    hashedRows[0].verification.identifier,
    `one-time-token:${expectedHash}`,
  );
  assert.equal(hashedRows[0].verification.identifier.includes(hashed.token), false);
  assert.equal(
    success(
      await hashedFixture.client.oneTimeToken.verify({ token: hashed.token }),
      "hashed verify",
    ).user.email,
    "ott-hashed@example.com",
  );

  const hashCalls = [];
  const customRows = [];
  const customFixture = fixture(
    {
      generateToken: async () => "Visible-Custom-Token",
      storeToken: {
        type: "custom-hasher",
        hash: async (token) => {
          hashCalls.push(token);
          return `custom:${token.toLowerCase()}`;
        },
      },
    },
    {},
    customRows,
  );
  await signUp(customFixture.client, "ott-custom-hash");
  const custom = success(
    await customFixture.client.oneTimeToken.generate(),
    "custom hash generate",
  );
  assert.equal(custom.token, "Visible-Custom-Token");
  assert.equal(
    customRows[0].verification.identifier,
    "one-time-token:custom:visible-custom-token",
  );
  success(
    await customFixture.client.oneTimeToken.verify({ token: custom.token }),
    "custom hash verify",
  );
  assert.deepEqual(hashCalls, [custom.token, custom.token]);
}

async function failureAndExpirationConformance() {
  const expiredTokenFixture = fixture({ expiresIn: -1 });
  await signUp(expiredTokenFixture.client, "ott-expired-token");
  const expiredToken = success(
    await expiredTokenFixture.client.oneTimeToken.generate(),
    "expired token generate",
  );
  error(
    await expiredTokenFixture.client.oneTimeToken.verify({
      token: expiredToken.token,
    }),
    "expired token verify",
    "Invalid token",
  );

  const missingSessionFixture = fixture();
  await signUp(missingSessionFixture.client, "ott-missing-session");
  const missingSessionToken = success(
    await missingSessionFixture.client.oneTimeToken.generate(),
    "missing session generate",
  );
  success(await missingSessionFixture.client.signOut(), "missing session signOut");
  error(
    await missingSessionFixture.client.oneTimeToken.verify({
      token: missingSessionToken.token,
    }),
    "missing session verify",
    "Session not found",
  );
  error(
    await missingSessionFixture.client.oneTimeToken.verify({
      token: missingSessionToken.token,
    }),
    "missing session replay",
    "Invalid token",
  );

  const expiredSessionFixture = fixture(undefined, {
    session: { expiresIn: 1 },
  });
  await signUp(expiredSessionFixture.client, "ott-expired-session");
  const expiredSessionToken = success(
    await expiredSessionFixture.client.oneTimeToken.generate(),
    "expired session generate",
  );
  await new Promise((resolve) => setTimeout(resolve, 1_100));
  const expiredSessionResponse = await directVerify(
    expiredSessionFixture.auth,
    expiredSessionToken.token,
  );
  assert.equal(expiredSessionResponse.status, 400);
  assert.deepEqual(await expiredSessionResponse.clone().json(), {
    message: "Session expired",
  });
  assert.ok(
    expiredSessionResponse.headers
      .getSetCookie()
      .some((cookie) => cookie.startsWith("__Secure-better-auth.session_token=")),
    "pinned verification queues a session cookie before rejecting expiry",
  );
  const expiredReplay = await directVerify(
    expiredSessionFixture.auth,
    expiredSessionToken.token,
  );
  assert.equal(expiredReplay.status, 400);
  assert.deepEqual(await expiredReplay.json(), {
    message: "Invalid token",
  });
}

async function configurationConformance() {
  let generateContext;
  const serverOnlyFixture = fixture({
    disableClientRequest: true,
    generateToken: async (session, context) => {
      generateContext = { session, hasRequest: Boolean(context.request) };
      return "server-only-token";
    },
  });
  const serverUser = await signUp(serverOnlyFixture.client, "ott-server-only");
  error(
    await serverOnlyFixture.client.oneTimeToken.generate(),
    "disabled client generate",
    "Client requests are disabled",
  );
  assert.equal(generateContext, undefined);
  const serverGenerated = await serverOnlyFixture.auth.api.generateOneTimeToken({
    headers: new Headers({ cookie: serverOnlyFixture.transport.cookieHeader() }),
  });
  assert.deepEqual(serverGenerated, { token: "server-only-token" });
  assert.equal(generateContext.session.user.id, serverUser.user.id);
  assert.equal(generateContext.session.session.token, serverUser.token);
  assert.equal(generateContext.hasRequest, false);

  const noCookieFixture = fixture({ disableSetSessionCookie: true });
  const noCookieUser = await signUp(noCookieFixture.client, "ott-no-cookie");
  const noCookieToken = success(
    await noCookieFixture.client.oneTimeToken.generate(),
    "no-cookie generate",
  );
  const verifier = new HandlerTransport(noCookieFixture.auth);
  const verifierClient = createAuthClient({
    baseURL: authOrigin,
    fetchOptions: { customFetchImpl: verifier.fetch.bind(verifier) },
    plugins: [oneTimeTokenClient()],
  });
  const noCookieVerified = success(
    await verifierClient.oneTimeToken.verify({ token: noCookieToken.token }),
    "no-cookie verify",
  );
  assert.equal(noCookieVerified.user.id, noCookieUser.user.id);
  assert.equal(verifier.cookies.size, 0);
  assert.equal((await verifierClient.getSession()).data, null);

  const headerFixture = fixture({
    generateToken: async () => "header-issued-token",
    setOttHeaderOnNewSession: true,
  });
  const headerUser = await signUp(headerFixture.client, "ott-header");
  const signupRequest = headerFixture.transport.requests.at(-1);
  assert.equal(signupRequest.responseHeaders.get("set-ott"), "header-issued-token");
  assert.equal(
    signupRequest.responseHeaders.get("access-control-expose-headers"),
    "set-ott",
  );
  const headerVerifier = new HandlerTransport(headerFixture.auth);
  const headerClient = createAuthClient({
    baseURL: authOrigin,
    fetchOptions: { customFetchImpl: headerVerifier.fetch.bind(headerVerifier) },
    plugins: [oneTimeTokenClient()],
  });
  assert.equal(
    success(
      await headerClient.oneTimeToken.verify({ token: "header-issued-token" }),
      "header token verify",
    ).user.id,
    headerUser.user.id,
  );
}

export async function oneTimeTokenConformance() {
  metadataConformance();
  await defaultAndClientConformance();
  await storageConformance();
  await failureAndExpirationConformance();
  await configurationConformance();
  console.log("ok - one-time-token official server and client contract");
}
