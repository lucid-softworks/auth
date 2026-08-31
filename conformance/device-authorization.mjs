import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import {
  deviceAuthorization,
  deviceAuthorizationOptionsSchema,
} from "better-auth/plugins/device-authorization";
import { deviceAuthorizationClient } from "better-auth/client/plugins";
import {
  DEVICE_CODE_GRANT_TYPE,
  oauthDeviceAuthorization,
} from "@better-auth/oauth-provider";
import {
  oauthDeviceAuthorizationClient,
  oauthProviderClient,
} from "@better-auth/oauth-provider/client";

const origin = "https://device.example.test";
const baseURL = `${origin}/api/auth`;
const secret = "D".repeat(32);

function endpointContract(plugin) {
  return Object.entries(plugin.endpoints).map(([key, endpoint]) => [
    key,
    endpoint.path,
    endpoint.options.method,
  ]);
}

function request(auth, path, init = {}) {
  return auth.handler(
    new Request(`${baseURL}${path}`, { redirect: "manual", ...init }),
  );
}

async function body(response) {
  return response.json();
}

function jsonRequest(value, headers = {}) {
  return {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(value),
  };
}

function sessionCookie(response) {
  const cookie = response.headers
    .getSetCookie()
    .find((candidate) =>
      candidate.slice(0, candidate.indexOf("=")).endsWith(".session_token"),
    );
  assert.ok(cookie, "device oracle sign-up did not set a session cookie");
  return cookie.split(";", 1)[0];
}

function pluginConformance() {
  const plugin = deviceAuthorization();
  assert.equal(plugin.id, "device-authorization");
  assert.equal(plugin.version, "1.7.2");
  assert.deepEqual(endpointContract(plugin), [
    ["deviceCode", "/device/code", "POST"],
    ["deviceToken", "/device/token", "POST"],
    ["deviceVerify", "/device", "GET"],
    ["deviceApprove", "/device/approve", "POST"],
    ["deviceDeny", "/device/deny", "POST"],
  ]);
  assert.deepEqual(Object.keys(plugin.schema), ["deviceCode"]);
  assert.deepEqual(Object.keys(plugin.schema.deviceCode.fields), [
    "deviceCode",
    "userCode",
    "userId",
    "expiresAt",
    "status",
    "lastPolledAt",
    "pollingInterval",
    "clientId",
    "scope",
  ]);
  assert.deepEqual(
    [
      plugin.options.expiresIn,
      plugin.options.interval,
      plugin.options.deviceCodeLength,
      plugin.options.userCodeLength,
    ],
    ["30m", "5s", 40, 8],
  );
  assert.equal(plugin.rateLimit.length, 1);
  assert.equal(plugin.rateLimit[0].pathMatcher("/device"), true);
  assert.equal(plugin.rateLimit[0].window, 1800);
  assert.equal(plugin.rateLimit[0].max, 5);

  assert.equal(
    deviceAuthorizationOptionsSchema.parse({ expiresIn: "-1.5s", interval: "0s" })
      .expiresIn,
    "-1.5s",
  );
  assert.throws(
    () => deviceAuthorizationOptionsSchema.parse({ deviceCodeLength: 0 }),
    /Too small|greater than 0/i,
  );
  assert.throws(
    () => deviceAuthorizationOptionsSchema.parse({ userCodeLength: 192 }),
    /Too big|less than or equal to 191/i,
  );

  const client = deviceAuthorizationClient();
  assert.equal(client.id, "device-authorization");
  assert.equal(client.version, "1.7.2");
  assert.deepEqual(client.pathMethods, {
    "/device/code": "POST",
    "/device/token": "POST",
    "/device": "GET",
    "/device/approve": "POST",
    "/device/deny": "POST",
  });
  const oauthClient = oauthDeviceAuthorizationClient();
  assert.equal(oauthClient.id, "device-authorization");
  assert.deepEqual(oauthClient.pathMethods, client.pathMethods);
  assert.equal(DEVICE_CODE_GRANT_TYPE, "urn:ietf:params:oauth:grant-type:device_code");

  const oauthPlugin = oauthDeviceAuthorization();
  assert.deepEqual(Object.keys(oauthPlugin.schema.deviceCode.fields).slice(-2), [
    "resources",
    "oauthClientId",
  ]);
}

async function standaloneServerConformance() {
  let sequence = 0;
  const observed = [];
  const auth = betterAuth({
    baseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [
      deviceAuthorization({
        interval: "0s",
        generateDeviceCode: () => `custom-device-${++sequence}`,
        generateUserCode: () => `CUSTOM-${sequence}`,
        validateClient: (clientId) => clientId === "standalone-client",
        onDeviceAuthRequest: (clientId, scope) =>
          observed.push({ clientId, scope }),
      }),
    ],
  });

  const media = await request(auth, "/device/code", {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: "standalone-client",
  });
  assert.equal(media.status, 415);
  assert.deepEqual(await body(media), {
    message:
      'Content-Type "text/plain" is not allowed. Allowed types: application/json, application/x-www-form-urlencoded',
    code: "UNSUPPORTED_MEDIA_TYPE",
  });

  const createdResponse = await request(
    auth,
    "/device/code",
    jsonRequest({
      client_id: "standalone-client",
      scope: "openid profile",
      ignored: true,
    }),
  );
  assert.equal(createdResponse.status, 200);
  assert.equal(createdResponse.headers.get("cache-control"), "no-store");
  assert.equal(createdResponse.headers.get("pragma"), "no-cache");
  const created = await body(createdResponse);
  assert.equal(created.device_code, "custom-device-1");
  assert.equal(created.user_code, "CUSTOM-1");
  assert.equal(created.verification_uri, `${origin}/device`);
  assert.equal(
    created.verification_uri_complete,
    `${origin}/device?user_code=CUSTOM-1`,
  );
  assert.equal(created.expires_in, 1800);
  assert.equal(created.interval, 0);
  assert.deepEqual(observed, [
    { clientId: "standalone-client", scope: "openid profile" },
  ]);

  const anonymous = await request(auth, "/device?user_code=CUSTOM-1");
  assert.equal(anonymous.status, 200);
  assert.deepEqual(await body(anonymous), {
    user_code: "CUSTOM-1",
    status: "pending",
  });

  const pending = await request(
    auth,
    "/device/token",
    jsonRequest({
      grant_type: DEVICE_CODE_GRANT_TYPE,
      device_code: created.device_code,
      client_id: "standalone-client",
    }),
  );
  assert.equal(pending.status, 400);
  assert.equal((await body(pending)).error, "authorization_pending");

  const signUp = await request(
    auth,
    "/sign-up/email",
    jsonRequest(
      {
        name: "Device User",
        email: "device-user@example.test",
        password: "correct horse battery staple",
      },
      { origin },
    ),
  );
  assert.equal(signUp.status, 200);
  const cookie = sessionCookie(signUp);
  const owned = await request(auth, "/device?user_code=CUSTOM-1", {
    headers: { cookie },
  });
  assert.deepEqual(await body(owned), {
    user_code: "CUSTOM-1",
    status: "pending",
    client_id: "standalone-client",
    scope: "openid profile",
  });
  const approved = await request(
    auth,
    "/device/approve",
    jsonRequest({ userCode: "CUSTOM-1" }, { cookie, origin }),
  );
  assert.equal(approved.status, 200);
  assert.deepEqual(await body(approved), { success: true });

  const exchanged = await request(
    auth,
    "/device/token",
    jsonRequest({
      grant_type: DEVICE_CODE_GRANT_TYPE,
      device_code: created.device_code,
      client_id: "standalone-client",
    }),
  );
  assert.equal(exchanged.status, 200);
  assert.equal(exchanged.headers.get("cache-control"), "no-store");
  assert.equal(exchanged.headers.get("set-cookie"), null);
  const token = await body(exchanged);
  assert.equal(token.token_type, "Bearer");
  assert.equal(token.scope, "openid profile");
  assert.equal(typeof token.access_token, "string");
  assert.equal(Number.isInteger(token.expires_in), true);

  const replay = await request(
    auth,
    "/device/token",
    jsonRequest({
      grant_type: DEVICE_CODE_GRANT_TYPE,
      device_code: created.device_code,
      client_id: "standalone-client",
    }),
  );
  assert.equal(replay.status, 400);
  assert.equal((await body(replay)).error, "invalid_grant");
}

export async function deviceAuthorizationConformance() {
  pluginConformance();
  await standaloneServerConformance();
  console.log("ok - Device Authorization official server and client contract");
}

function success(result, operation) {
  assert.equal(result.error, null, `${operation}: ${JSON.stringify(result.error)}`);
  return result.data;
}

async function signIn(client) {
  success(
    await client.signIn.email({
      email: "luna@example.com",
      password: "correct horse battery staple",
    }),
    "device.signIn",
  );
}

export async function deviceAuthorizationNativeStandaloneConformance(
  baseURL,
  customFetchImpl,
) {
  const client = createAuthClient({
    baseURL,
    fetchOptions: { customFetchImpl },
    plugins: [deviceAuthorizationClient()],
  });
  await signIn(client);
  const created = success(
    await client.device.code({
      client_id: "official-standalone-device",
      scope: "profile email",
    }),
    "device.code",
  );
  const verification = success(
    await client.device({ query: { user_code: created.user_code } }),
    "device.verify",
  );
  assert.equal(verification.client_id, "official-standalone-device");
  success(
    await client.device.approve({ userCode: created.user_code }),
    "device.approve",
  );
  const token = success(
    await client.device.token({
      grant_type: DEVICE_CODE_GRANT_TYPE,
      device_code: created.device_code,
      client_id: "official-standalone-device",
    }),
    "device.token",
  );
  assert.equal(token.token_type, "Bearer");
  assert.equal(token.scope, "profile email");

  const denied = success(
    await client.device.code({
      client_id: "official-standalone-device",
      scope: "email",
    }),
    "device.code denied request",
  );
  success(
    await client.device({ query: { user_code: denied.user_code } }),
    "device.verify denied request",
  );
  success(
    await client.device.deny({ userCode: denied.user_code }),
    "device.deny",
  );
  const deniedToken = await client.device.token({
    grant_type: DEVICE_CODE_GRANT_TYPE,
    device_code: denied.device_code,
    client_id: "official-standalone-device",
  });
  assert.equal(deniedToken.data, null);
  assert.equal(deniedToken.error.status, 400);
  assert.equal(deniedToken.error.error, "access_denied");
  console.log("ok - Device Authorization official client against native server");
}

export async function deviceAuthorizationNativeOAuthConformance(
  baseURL,
  customFetchImpl,
) {
  const client = createAuthClient({
    baseURL,
    fetchOptions: { customFetchImpl },
    plugins: [oauthProviderClient(), oauthDeviceAuthorizationClient()],
  });
  await signIn(client);
  const registered = success(
    await client.oauth2.createClient({
      client_name: "Official OAuth device",
      redirect_uris: ["https://device-client.example/callback"],
      token_endpoint_auth_method: "none",
      grant_types: [DEVICE_CODE_GRANT_TYPE],
      scope: "profile email",
    }),
    "oauthDevice.createClient",
  );
  const created = success(
    await client.device.code({
      client_id: registered.client_id,
      scope: "profile email",
    }),
    "oauthDevice.code",
  );
  const verification = success(
    await client.device({ query: { user_code: created.user_code } }),
    "oauthDevice.verify",
  );
  assert.equal(verification.client_id, registered.client_id);
  success(
    await client.device.approve({ userCode: created.user_code }),
    "oauthDevice.approve",
  );
  const wrongEndpoint = await client.device.token({
    grant_type: DEVICE_CODE_GRANT_TYPE,
    device_code: created.device_code,
    client_id: registered.client_id,
  });
  assert.equal(wrongEndpoint.data, null);
  assert.equal(wrongEndpoint.error.status, 400);
  assert.equal(wrongEndpoint.error.error, "invalid_grant");

  const response = await customFetchImpl(`${baseURL}/api/auth/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: DEVICE_CODE_GRANT_TYPE,
      device_code: created.device_code,
      client_id: registered.client_id,
    }),
  });
  assert.equal(response.status, 200, await response.clone().text());
  const token = await response.json();
  assert.equal(token.token_type, "Bearer");
  assert.equal(token.scope, "profile email");
  assert.equal(typeof token.access_token, "string");

  const denied = success(
    await client.device.code({
      client_id: registered.client_id,
      scope: "email",
    }),
    "oauthDevice.code denied request",
  );
  success(
    await client.device({ query: { user_code: denied.user_code } }),
    "oauthDevice.verify denied request",
  );
  success(
    await client.device.deny({ userCode: denied.user_code }),
    "oauthDevice.deny",
  );
  console.log("ok - OAuth Device Authorization official client against native server");
}
