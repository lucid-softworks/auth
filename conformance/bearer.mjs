import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import * as clientPlugins from "better-auth/client/plugins";
import { bearer } from "better-auth/plugins";

const authOrigin = "https://bearer.example.test";
const authBaseURL = `${authOrigin}/api/auth`;
const secret = "R".repeat(32);

function cookiePair(response, suffix = ".session_token") {
  const cookie = response.headers
    .getSetCookie()
    .find((candidate) => candidate.slice(0, candidate.indexOf("=")).endsWith(suffix));
  assert.ok(cookie, `response did not set a ${suffix} cookie`);
  return cookie.split(";", 1)[0];
}

function success(result, method) {
  assert.equal(result.error, null, `${method}: ${JSON.stringify(result.error)}`);
  assert.notEqual(result.data, null, `${method}: missing data`);
  return result.data;
}

async function request(auth, path, init = {}) {
  return auth.handler(new Request(`${authBaseURL}${path}`, init));
}

async function signUp(auth, identity) {
  const response = await request(auth, "/sign-up/email", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: authOrigin,
    },
    body: JSON.stringify({
      name: `Bearer ${identity}`,
      email: `${identity}@example.com`,
      password: "correct horse battery staple",
    }),
  });
  assert.equal(response.status, 200);
  const body = await response.clone().json();
  const signedToken = response.headers.get("set-auth-token");
  assert.ok(signedToken, "bearer plugin did not expose the issued session token");
  assert.equal(signedToken.split(".", 1)[0], body.token);
  assert.equal(
    signedToken,
    decodeURIComponent(cookiePair(response).slice(cookiePair(response).indexOf("=") + 1)),
  );
  assert.equal(response.headers.get("access-control-expose-headers"), "set-auth-token");
  return {
    cookie: cookiePair(response),
    email: body.user.email,
    opaqueToken: body.token,
    response,
    signedToken,
  };
}

async function session(auth, { authorization, cookie } = {}) {
  const headers = new Headers();
  if (authorization !== undefined) headers.set("authorization", authorization);
  if (cookie !== undefined) headers.set("cookie", cookie);
  const response = await request(auth, "/get-session", { headers });
  assert.equal(response.status, 200);
  return response.json();
}

function pluginMetadataConformance() {
  const plugin = bearer();
  assert.equal(plugin.id, "bearer");
  assert.equal(plugin.version, "1.7.1");
  assert.equal(plugin.options, undefined);
  assert.deepEqual(Object.keys(plugin.hooks), ["before", "after"]);
  assert.equal(plugin.hooks.before.length, 1);
  assert.equal(plugin.hooks.after.length, 1);
  for (const unsupported of [
    "endpoints",
    "schema",
    "migrations",
    "rateLimit",
    "$ERROR_CODES",
  ]) {
    assert.equal(unsupported in plugin, false, `${unsupported} must not be advertised`);
  }

  const signedOnly = bearer({ requireSignature: true });
  assert.deepEqual(signedOnly.options, { requireSignature: true });
  assert.equal("bearerClient" in clientPlugins, false);
}

async function serverConformance() {
  const auth = betterAuth({
    baseURL: authBaseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [bearer()],
  });
  const first = await signUp(auth, "bearer-first");
  const second = await signUp(auth, "bearer-second");

  assert.equal(
    (await session(auth, { authorization: `Bearer ${first.opaqueToken}` })).user.email,
    first.email,
  );
  assert.equal(
    (await session(auth, { authorization: `bEaReR ${first.signedToken}` })).user.email,
    first.email,
  );
  assert.equal(
    (
      await session(auth, {
        authorization: `Bearer ${encodeURIComponent(first.signedToken)}`,
      })
    ).user.email,
    first.email,
  );

  const invalidSignedFallsBack = await session(auth, {
    authorization: `Bearer ${first.opaqueToken}.invalid-signature`,
    cookie: second.cookie,
  });
  assert.equal(invalidSignedFallsBack.user.email, second.email);

  const acceptedBearerWins = await session(auth, {
    authorization: `Bearer ${first.signedToken}`,
    cookie: second.cookie,
  });
  assert.equal(acceptedBearerWins.user.email, first.email);

  const acceptedMissingOpaqueWins = await session(auth, {
    authorization: "Bearer missing-opaque-session",
    cookie: second.cookie,
  });
  assert.equal(acceptedMissingOpaqueWins, null);

  const signedOnlyAuth = betterAuth({
    baseURL: authBaseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [bearer({ requireSignature: true })],
  });
  const signedOnlySession = await signUp(signedOnlyAuth, "bearer-signed-only");
  assert.equal(
    (
      await session(signedOnlyAuth, {
        authorization: `Bearer ${signedOnlySession.signedToken}`,
      })
    ).user.email,
    signedOnlySession.email,
  );
  assert.equal(
    await session(signedOnlyAuth, {
      authorization: `Bearer ${signedOnlySession.opaqueToken}`,
    }),
    null,
  );

  for (const [identity, requestHeaders] of [
    ["bearer-sign-out-no-origin", {}],
    [
      "bearer-sign-out-hostile-origin",
      { origin: "https://evil.example.test" },
    ],
    [
      "bearer-sign-out-cross-site-navigation",
      {
        origin: "https://evil.example.test",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "cross-site",
      },
    ],
  ]) {
    const bearerOnlySession = await signUp(auth, identity);
    const headers = new Headers({
      authorization: `Bearer ${bearerOnlySession.signedToken}`,
      ...requestHeaders,
    });
    const bearerOnlySignOut = await request(auth, "/sign-out", {
      method: "POST",
      headers,
    });
    assert.equal(bearerOnlySignOut.status, 200);
    assert.deepEqual(await bearerOnlySignOut.json(), { success: true });
    assert.deepEqual(bearerOnlySignOut.headers.getSetCookie(), [
      "__Secure-better-auth.session_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
      "__Secure-better-auth.session_data=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
      "__Secure-better-auth.account_data=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
      "__Secure-better-auth.oauth_state=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
      "__Secure-better-auth.dont_remember=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
    ]);
    assert.equal(bearerOnlySignOut.headers.get("set-auth-token"), null);
    assert.equal(
      await session(auth, {
        authorization: `Bearer ${bearerOnlySession.signedToken}`,
      }),
      null,
    );
  }

  const signedOut = await request(auth, "/sign-out", {
    method: "POST",
    headers: { cookie: first.cookie, origin: authOrigin },
  });
  assert.equal(signedOut.status, 200);
  assert.equal(signedOut.headers.get("set-auth-token"), null);
}

async function clientConformance() {
  const auth = betterAuth({
    baseURL: authBaseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [bearer()],
  });
  const fixture = await signUp(auth, "bearer-client");
  const requests = [];
  const customFetchImpl = async (input, init = {}) => {
    const outgoing = new Request(input, init);
    requests.push(outgoing.clone());
    return auth.handler(outgoing);
  };
  const client = createAuthClient({
    baseURL: authOrigin,
    fetchOptions: {
      auth: { type: "Bearer", token: () => fixture.signedToken },
      customFetchImpl,
    },
  });

  const authenticated = success(await client.getSession(), "getSession bearer auth");
  assert.equal(authenticated.user.email, fixture.email);
  assert.equal(requests.at(-1).headers.get("authorization"), `Bearer ${fixture.signedToken}`);

  const perRequest = success(
    await client.$fetch("/get-session", {
      auth: undefined,
      headers: { authorization: `Bearer ${fixture.opaqueToken}` },
    }),
    "$fetch per-request bearer auth",
  );
  assert.equal(perRequest.user.email, fixture.email);
  assert.equal(
    requests.at(-1).headers.get("authorization"),
    `Bearer ${fixture.opaqueToken}`,
  );
}

export async function bearerConformance() {
  pluginMetadataConformance();
  await serverConformance();
  await clientConformance();
  console.log("ok - Bearer official server and generic client contract");
}
