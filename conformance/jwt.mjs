import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { jwtClient } from "better-auth/client/plugins";
import { jwt, toExpJWT } from "better-auth/plugins";
import {
  SignJWT,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
} from "jose";

const authOrigin = "https://jwt.example.test";
const authBaseURL = `${authOrigin}/api/auth`;
const secret = "R".repeat(32);

function success(result, method) {
  assert.equal(result.error, null, `${method}: ${JSON.stringify(result.error)}`);
  assert.notEqual(result.data, null, `${method}: missing data`);
  return result.data;
}

function cookiePair(response, suffix = ".session_token") {
  const cookie = response.headers
    .getSetCookie()
    .find((candidate) => candidate.slice(0, candidate.indexOf("=")).endsWith(suffix));
  assert.ok(cookie, `response did not set a ${suffix} cookie`);
  return cookie.split(";", 1)[0];
}

async function request(auth, path, init = {}, baseURL = authBaseURL) {
  return auth.handler(new Request(`${baseURL}${path}`, init));
}

async function signUp(auth, identity, baseURL = authBaseURL) {
  const origin = new URL(baseURL).origin;
  const response = await request(
    auth,
    "/sign-up/email",
    {
      method: "POST",
      headers: { "content-type": "application/json", origin },
      body: JSON.stringify({
        name: `JWT ${identity}`,
        email: `${identity}@example.com`,
        password: "correct horse battery staple",
      }),
    },
    baseURL,
  );
  assert.equal(response.status, 200);
  return {
    body: await response.clone().json(),
    cookie: cookiePair(response),
  };
}

async function tokenResponse(auth, cookie, baseURL = authBaseURL) {
  return request(auth, "/token", { headers: { cookie } }, baseURL);
}

async function jwksResponse(auth, path = "/jwks", baseURL = authBaseURL) {
  return request(auth, path, {}, baseURL);
}

class HandlerTransport {
  constructor(auth, origin) {
    this.auth = auth;
    this.origin = origin;
    this.cookies = new Map();
    this.requests = [];
  }

  async fetch(input, init = {}) {
    const incoming = new Request(input, init);
    const headers = new Headers(incoming.headers);
    if (this.cookies.size > 0) {
      headers.set(
        "cookie",
        [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; "),
      );
    }
    if (incoming.method !== "GET" && incoming.method !== "HEAD") {
      headers.set("origin", this.origin);
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
      method: outgoing.method,
      pathname: new URL(outgoing.url).pathname,
      responseHeaders: new Headers(response.headers),
    });
    return response;
  }
}

function metadataConformance() {
  const server = jwt();
  assert.equal(server.id, "jwt");
  assert.equal(server.version, "1.7.1");
  assert.equal(server.options, undefined);
  assert.deepEqual(Object.keys(server.endpoints), [
    "getJwks",
    "getToken",
    "signJWT",
    "verifyJWT",
  ]);
  assert.equal(server.endpoints.getJwks.path, "/jwks");
  assert.equal(server.endpoints.getJwks.options.method, "GET");
  assert.equal(
    server.endpoints.getJwks.options.metadata.openapi.operationId,
    "getJSONWebKeySet",
  );
  assert.equal(server.endpoints.getToken.path, "/token");
  assert.equal(server.endpoints.getToken.options.method, "GET");
  assert.equal(
    server.endpoints.getToken.options.metadata.openapi.operationId,
    "getJSONWebToken",
  );
  assert.equal(server.endpoints.signJWT.path, undefined);
  assert.equal(server.endpoints.signJWT.options.metadata.SERVER_ONLY, true);
  assert.equal(server.endpoints.verifyJWT.path, undefined);
  assert.equal(server.endpoints.verifyJWT.options.metadata.SERVER_ONLY, true);
  assert.deepEqual(Object.keys(server.schema.jwks.fields), [
    "publicKey",
    "privateKey",
    "createdAt",
    "expiresAt",
    "alg",
    "crv",
  ]);
  assert.equal("cookies" in server, false);
  assert.equal(server.hooks.after.length, 1);

  const client = jwtClient();
  assert.equal(client.id, "better-auth-client");
  assert.equal(client.version, "1.7.1");
  assert.deepEqual(client.$InferServerPlugin, {});
  assert.deepEqual(client.pathMethods, { "/jwks": "GET" });
  assert.equal(typeof client.getActions, "function");
  assert.deepEqual(
    jwtClient({ jwks: { jwksPath: "/.well-known/jwks.json" } }).pathMethods,
    { "/.well-known/jwks.json": "GET" },
  );
}

async function defaultServerConformance() {
  const auth = betterAuth({
    baseURL: authBaseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [jwt()],
  });

  const unauthorized = await request(auth, "/token");
  assert.equal(unauthorized.status, 401);
  assert.deepEqual(await unauthorized.json(), {
    message: "Unauthorized",
    code: "UNAUTHORIZED",
  });

  const fixture = await signUp(auth, "jwt-default");
  const before = Math.floor(Date.now() / 1_000);
  const issued = await tokenResponse(auth, fixture.cookie);
  const after = Math.floor(Date.now() / 1_000);
  assert.equal(issued.status, 200);
  const { token } = await issued.json();
  const header = decodeProtectedHeader(token);
  const payload = decodeJwt(token);
  assert.deepEqual(Object.keys(header), ["alg", "kid"]);
  assert.equal(header.alg, "EdDSA");
  assert.equal(typeof header.kid, "string");
  assert.ok(header.kid.length > 0);
  assert.ok(payload.iat >= before && payload.iat <= after);
  assert.equal(payload.exp, payload.iat + 900);
  assert.equal(payload.iss, authOrigin);
  assert.equal(payload.aud, authOrigin);
  assert.equal(payload.sub, fixture.body.user.id);
  assert.equal(payload.id, fixture.body.user.id);
  assert.equal(payload.email, fixture.body.user.email);
  assert.equal(payload.name, fixture.body.user.name);
  assert.equal(payload.emailVerified, false);

  const publicResponse = await jwksResponse(auth);
  assert.equal(publicResponse.status, 200);
  const publicSet = await publicResponse.json();
  assert.equal(publicSet.keys.length, 1);
  const publicKey = publicSet.keys[0];
  assert.deepEqual(Object.keys(publicKey).sort(), ["alg", "crv", "kid", "kty", "x"]);
  assert.equal(publicKey.alg, "EdDSA");
  assert.equal(publicKey.crv, "Ed25519");
  assert.equal(publicKey.kid, header.kid);
  assert.equal(publicKey.kty, "OKP");
  assert.equal("use" in publicKey, false);
  assert.equal("privateKey" in publicKey, false);
  assert.equal("d" in publicKey, false);
  const imported = await importJWK(publicKey, "EdDSA");
  const verified = await jwtVerify(token, imported, {
    issuer: authOrigin,
    audience: authOrigin,
  });
  assert.equal(verified.payload.sub, fixture.body.user.id);

  const sessionResponse = await request(auth, "/get-session", {
    headers: { cookie: fixture.cookie },
  });
  assert.equal(sessionResponse.status, 200);
  const sessionToken = sessionResponse.headers.get("set-auth-jwt");
  assert.ok(sessionToken);
  assert.equal(decodeProtectedHeader(sessionToken).kid, header.kid);
  assert.equal(decodeJwt(sessionToken).sub, fixture.body.user.id);
  assert.equal(
    sessionResponse.headers.get("access-control-expose-headers"),
    "set-auth-jwt",
  );

  const noHeaderAuth = betterAuth({
    baseURL: authBaseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [jwt({ disableSettingJwtHeader: true })],
  });
  const noHeaderFixture = await signUp(noHeaderAuth, "jwt-no-header");
  const noHeaderSession = await request(noHeaderAuth, "/get-session", {
    headers: { cookie: noHeaderFixture.cookie },
  });
  assert.equal(noHeaderSession.status, 200);
  assert.equal(noHeaderSession.headers.get("set-auth-jwt"), null);
  assert.equal((await tokenResponse(noHeaderAuth, noHeaderFixture.cookie)).status, 200);
}

async function clientConformance() {
  const auth = betterAuth({
    baseURL: authBaseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [jwt()],
  });
  const transport = new HandlerTransport(auth, authOrigin);
  const client = createAuthClient({
    baseURL: authOrigin,
    fetchOptions: { customFetchImpl: transport.fetch.bind(transport) },
    plugins: [jwtClient()],
  });
  const signedUp = success(
    await client.signUp.email({
      name: "JWT Client",
      email: "jwt-client@example.com",
      password: "correct horse battery staple",
    }),
    "jwt client signUp.email",
  );
  const issued = success(await client.token(), "jwt client token");
  assert.equal(decodeJwt(issued.token).sub, signedUp.user.id);
  assert.equal(transport.requests.at(-1).pathname, "/api/auth/token");
  assert.equal(transport.requests.at(-1).method, "GET");
  const keySet = success(await client.jwks(), "jwt client jwks");
  assert.equal(keySet.keys[0].kid, decodeProtectedHeader(issued.token).kid);
  assert.equal(transport.requests.at(-1).pathname, "/api/auth/jwks");
  assert.equal(transport.requests.at(-1).method, "GET");
  success(await client.getSession(), "jwt client getSession");
  const sessionToken = transport.requests.at(-1).responseHeaders.get("set-auth-jwt");
  assert.ok(sessionToken);
  assert.equal(
    decodeProtectedHeader(sessionToken).kid,
    decodeProtectedHeader(issued.token).kid,
  );
  assert.equal(decodeJwt(sessionToken).sub, signedUp.user.id);

  const customPath = "/.well-known/jwks.json";
  const customAuth = betterAuth({
    baseURL: authBaseURL,
    secret,
    logger: { disabled: true },
    plugins: [jwt({ jwks: { jwksPath: customPath } })],
  });
  const customTransport = new HandlerTransport(customAuth, authOrigin);
  const customClient = createAuthClient({
    baseURL: authOrigin,
    fetchOptions: { customFetchImpl: customTransport.fetch.bind(customTransport) },
    plugins: [jwtClient({ jwks: { jwksPath: customPath } })],
  });
  assert.equal(success(await customClient.jwks(), "custom jwt client jwks").keys.length, 1);
  assert.equal(customTransport.requests.at(-1).pathname, `/api/auth${customPath}`);
  assert.equal((await jwksResponse(customAuth)).status, 404);
}

async function algorithmConformance() {
  const configurations = [
    { alg: "EdDSA", crv: "Ed25519" },
    { alg: "ES256" },
    { alg: "ES512" },
    { alg: "PS256", modulusLength: 2048 },
    { alg: "RS256", modulusLength: 2048 },
  ];
  for (const configuration of configurations) {
    const label = configuration.alg.toLowerCase();
    const origin = `https://jwt-${label}.example.test`;
    const baseURL = `${origin}/api/auth`;
    const auth = betterAuth({
      baseURL,
      secret,
      emailAndPassword: { enabled: true },
      logger: { disabled: true },
      plugins: [jwt({ jwks: { keyPairConfig: configuration } })],
    });
    const fixture = await signUp(auth, `jwt-${label}`, baseURL);
    const issued = await tokenResponse(auth, fixture.cookie, baseURL);
    assert.equal(issued.status, 200);
    const token = (await issued.json()).token;
    const header = decodeProtectedHeader(token);
    assert.equal(header.alg, configuration.alg);
    const set = await (await jwksResponse(auth, "/jwks", baseURL)).json();
    assert.equal(set.keys.length, 1);
    assert.equal(set.keys[0].alg, configuration.alg);
    assert.equal(set.keys[0].kid, header.kid);
    const key = await importJWK(set.keys[0], configuration.alg);
    const verified = await jwtVerify(token, key, {
      issuer: origin,
      audience: origin,
    });
    assert.equal(verified.payload.sub, fixture.body.user.id);
  }
}

async function payloadAndRemoteConformance() {
  const payloadIat = Math.floor(Date.now() / 1_000) - 5;
  let callbackSession;
  const customAuth = betterAuth({
    baseURL: authBaseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [
      jwt({
        jwt: {
          audience: "configured-audience",
          expirationTime: "2h",
          getSubject: async (session) => {
            callbackSession = session;
            return `subject:${session.user.id}`;
          },
          issuer: "configured-issuer",
          definePayload: async ({ user }) => ({
            aud: ["payload-audience", "payload-secondary"],
            iat: payloadIat,
            iss: "payload-issuer",
            marker: user.email,
            sub: "ignored-payload-subject",
          }),
        },
      }),
    ],
  });
  const fixture = await signUp(customAuth, "jwt-payload");
  const token = (await (await tokenResponse(customAuth, fixture.cookie)).json()).token;
  const payload = decodeJwt(token);
  assert.equal(payload.iat, payloadIat);
  assert.equal(payload.exp, payloadIat + 7_200);
  assert.equal(payload.iss, "payload-issuer");
  assert.deepEqual(payload.aud, ["payload-audience", "payload-secondary"]);
  assert.equal(payload.sub, `subject:${fixture.body.user.id}`);
  assert.equal(payload.marker, fixture.body.user.email);
  assert.equal(callbackSession.user.id, fixture.body.user.id);
  assert.equal(typeof callbackSession.session.token, "string");

  let remoteCall;
  const remoteAuth = betterAuth({
    baseURL: authBaseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [
      jwt({
        jwks: {
          keyPairConfig: { alg: "RS256" },
          remoteUrl: "not even a URL",
        },
        jwt: {
          audience: ["remote-audience"],
          issuer: "remote-issuer",
          sign: async (resolvedPayload, header, signingConfig) => {
            remoteCall = { resolvedPayload, header, signingConfig };
            return "remote.header.signature";
          },
        },
      }),
    ],
  });
  const remoteFixture = await signUp(remoteAuth, "jwt-remote");
  const remoteToken = await tokenResponse(remoteAuth, remoteFixture.cookie);
  assert.equal(remoteToken.status, 200);
  assert.deepEqual(await remoteToken.json(), { token: "remote.header.signature" });
  assert.equal(remoteCall.header, undefined);
  assert.deepEqual(remoteCall.signingConfig, {
    signingKeyId: undefined,
    signingAlgorithm: undefined,
  });
  assert.equal(remoteCall.resolvedPayload.sub, remoteFixture.body.user.id);
  assert.equal(remoteCall.resolvedPayload.iss, "remote-issuer");
  assert.deepEqual(remoteCall.resolvedPayload.aud, ["remote-audience"]);
  assert.equal(typeof remoteCall.resolvedPayload.iat, "number");
  assert.equal(remoteCall.resolvedPayload.exp, remoteCall.resolvedPayload.iat + 900);
  const remoteJwks = await jwksResponse(remoteAuth);
  assert.equal(remoteJwks.status, 404);
  assert.equal(await remoteJwks.text(), "");
}

async function serverOnlyAndRetiredKeyConformance() {
  const rows = [];
  let callbackOrderVerified = false;
  const options = {
    adapter: {
      async getJwks(context) {
        assert.equal(typeof context, "object");
        return rows;
      },
      async createJwk(data, context) {
        assert.equal(typeof data.publicKey, "string");
        assert.equal(typeof context, "object");
        callbackOrderVerified = true;
        const row = { ...data, id: "custom-key-id" };
        rows.push(row);
        return row;
      },
    },
    jwks: { disablePrivateKeyEncryption: true },
  };
  const auth = betterAuth({
    baseURL: authBaseURL,
    secret,
    logger: { disabled: true },
    plugins: [jwt(options)],
  });
  const signed = await auth.api.signJWT({
    body: {
      payload: {
        aud: authOrigin,
        marker: "server-only",
        sub: "server-only-subject",
      },
    },
  });
  assert.equal(callbackOrderVerified, true);
  assert.equal(rows.length, 1);
  assert.equal(JSON.parse(rows[0].privateKey).d.length > 0, true);
  assert.equal("d" in JSON.parse(rows[0].publicKey), false);
  assert.equal(decodeProtectedHeader(signed.token).kid, "custom-key-id");
  assert.equal((await auth.api.verifyJWT({ body: { token: signed.token } })).payload.marker, "server-only");
  assert.deepEqual(await auth.api.verifyJWT({ body: { token: `${signed.token}x` } }), {
    payload: null,
  });

  for (const path of ["/sign-jwt", "/verify-jwt"]) {
    const response = await request(auth, path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(response.status, 404);
    assert.equal(await response.text(), "");
  }

  const privateKey = await importJWK(JSON.parse(rows[0].privateKey), rows[0].alg);
  const tokenWithoutExpiration = await new SignJWT({
    aud: authOrigin,
    marker: "no-expiration",
    sub: "no-expiration-subject",
  })
    .setProtectedHeader({ alg: rows[0].alg, kid: rows[0].id })
    .setIssuer(authOrigin)
    .sign(privateKey);
  assert.equal(
    (await auth.api.verifyJWT({ body: { token: tokenWithoutExpiration } })).payload.marker,
    "no-expiration",
  );

  rows[0].expiresAt = new Date(0);
  const retiredPublicSet = await (await jwksResponse(auth)).json();
  assert.deepEqual(retiredPublicSet, { keys: [] });
  assert.equal(
    (await auth.api.verifyJWT({ body: { token: tokenWithoutExpiration } })).payload.marker,
    "no-expiration",
  );
}

async function optionConformance() {
  for (const invalidPath of ["", "jwks", "/safe/../bad", 123]) {
    assert.throws(
      () => jwt({ jwks: { jwksPath: invalidPath } }),
      {
        name: "BetterAuthError",
        message:
          "options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'",
      },
    );
  }
  assert.throws(
    () => jwt({ jwt: { sign: () => "token" } }),
    {
      name: "BetterAuthError",
      message: "options.jwks.remoteUrl must be set when using options.jwt.sign",
    },
  );
  assert.throws(
    () => jwt({ jwks: { remoteUrl: "not a URL" } }),
    {
      name: "BetterAuthError",
      message:
        "options.jwks.keyPairConfig.alg must be specified when options.jwks.remoteUrl is used for OpenID metadata",
    },
  );

  assert.equal(toExpJWT(1_234, 9_999), 1_234);
  assert.equal(toExpJWT(new Date(1_234_999), 9_999), 1_234);
  assert.equal(toExpJWT("15m", 1_000), 1_900);
  assert.equal(toExpJWT("-5 minutes", 1_000), 700);
  assert.equal(toExpJWT("5 minutes ago", 1_000), 700);
  assert.equal(toExpJWT("5 minutes from now", 1_000), 1_300);
  assert.throws(
    () => toExpJWT("invalid", 1_000),
    /Invalid time string format: "invalid"/,
  );

  for (const session of [undefined, { cookieCache: { strategy: "compact" } }]) {
    const auth = betterAuth({
      baseURL: authBaseURL,
      secret,
      logger: { disabled: true },
      ...(session ? { session } : {}),
      plugins: [jwt({ sessionCookieCache: true })],
    });
    await assert.rejects(
      () => auth.api.getSession({ headers: new Headers() }),
      {
        name: "BetterAuthError",
        message:
          '`jwt({ sessionCookieCache: true })` requires `session.cookieCache.strategy = "jwt"`.',
      },
    );
  }
  const cacheAuth = betterAuth({
    baseURL: authBaseURL,
    secret,
    logger: { disabled: true },
    session: { cookieCache: { strategy: "jwt" } },
    plugins: [jwt({ sessionCookieCache: true })],
  });
  assert.equal(await cacheAuth.api.getSession({ headers: new Headers() }), null);

  const remoteCacheAuth = betterAuth({
    baseURL: authBaseURL,
    secret,
    logger: { disabled: true },
    session: { cookieCache: { strategy: "jwt" } },
    plugins: [
      jwt({
        sessionCookieCache: true,
        jwks: { keyPairConfig: { alg: "EdDSA" }, remoteUrl: "remote" },
        jwt: { sign: () => "remote" },
      }),
    ],
  });
  await assert.rejects(
    () => remoteCacheAuth.api.getSession({ headers: new Headers() }),
    {
      name: "BetterAuthError",
      message:
        "`jwt({ sessionCookieCache: true })` requires locally managed JWT plugin keys and does not support `jwt.sign`.",
    },
  );
}

export async function jwtConformance() {
  metadataConformance();
  await defaultServerConformance();
  await clientConformance();
  await algorithmConformance();
  await payloadAndRemoteConformance();
  await serverOnlyAndRetiredKeyConformance();
  await optionConformance();
  console.log("ok - JWT official server, client, and JOSE contract");
}
