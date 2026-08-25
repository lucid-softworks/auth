import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createAuthClient } from "better-auth/client";
import { getCookieCache } from "better-auth/cookies";
import { symmetricDecodeJWT } from "better-auth/crypto";
import {
  adminClient,
  anonymousClient,
  emailOTPClient,
  magicLinkClient,
  jwtClient,
  lastLoginMethodClient,
  multiSessionClient,
  oneTimeTokenClient,
  oneTapClient,
  phoneNumberClient,
  siweClient,
  twoFactorClient,
  usernameClient,
  organizationClient,
} from "better-auth/client/plugins";
import { passkeyClient } from "@better-auth/passkey/client";
import { apiKeyClient } from "@better-auth/api-key/client";
import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { installVirtualAuthenticator } from "./virtual-authenticator.mjs";
import { bearerConformance } from "./bearer.mjs";
import { jwtConformance } from "./jwt.mjs";
import { oneTimeTokenConformance } from "./one-time-token.mjs";
import { oauthPopupConformance } from "./oauth-popup.mjs";
import { oauthProxyConformance } from "./oauth-proxy.mjs";
import {
  oauthProviderConformance,
  oauthProviderNativeConformance,
} from "./oauth-provider.mjs";

const repository = fileURLToPath(new URL("..", import.meta.url));
const betterAuthPackage = JSON.parse(
  await readFile(new URL("node_modules/better-auth/package.json", import.meta.url)),
);
const passkeyPackage = JSON.parse(
  await readFile(
    new URL("node_modules/@better-auth/passkey/package.json", import.meta.url),
  ),
);
const apiKeyPackage = JSON.parse(
  await readFile(
    new URL("node_modules/@better-auth/api-key/package.json", import.meta.url),
  ),
);
const nativePluginClient = {
  id: "lucid-native-conformance",
  version: "1.0.0",
  $InferServerPlugin: {},
  pathMethods: {
    "/native-plugin/ping": "GET",
    "/native-plugin/rate-limit": "GET",
  },
};

class BrowserTransport {
  constructor(origin) {
    this.origin = origin;
    this.cookies = new Map();
    this.requests = [];
  }

  async fetch(input, init = {}) {
    const rawUrl =
      input instanceof URL
        ? input.href
        : input instanceof Request
          ? input.url
          : String(input);
    const url = new URL(rawUrl);
    const headers = new Headers(init.headers);
    if (this.cookies.size > 0) {
      headers.set(
        "cookie",
        [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; "),
      );
    }
    headers.set("origin", this.origin);
    const method = (init.method ?? "GET").toUpperCase();
    const body = typeof init.body === "string" ? JSON.parse(init.body) : null;
    const recordedRequest = {
      method,
      pathname: url.pathname,
      search: url.search,
      body,
      headers: new Headers(headers),
    };
    this.requests.push(recordedRequest);

    const response = await fetch(input, { ...init, headers });
    recordedRequest.responseHeaders = new Headers(response.headers);
    for (const cookie of response.headers.getSetCookie()) {
      const [pair, ...attributes] = cookie.split(";");
      const separator = pair.indexOf("=");
      const name = pair.slice(0, separator);
      const value = pair.slice(separator + 1);
      const removed = attributes.some((attribute) =>
        /^\s*max-age=0\s*$/i.test(attribute),
      );
      if (removed || value.length === 0) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return response;
  }

  async useFixtureSession(authenticationMethod) {
    const response = await this.fetch(
      `${this.origin}/__conformance__/session/${authenticationMethod}`,
      { method: "POST" },
    );
    assert.equal(response.status, 200);
  }

  clearCookies() {
    this.cookies.clear();
  }

  assertRequest(pathname, method, body = undefined) {
    const request = this.requests.findLast(
      (candidate) => candidate.pathname === pathname && candidate.method === method,
    );
    assert.ok(request, `${method} ${pathname} was not sent`);
    if (body !== undefined) assert.deepEqual(request.body, body);
    return request;
  }
}

function success(result, method) {
  assert.equal(result.error, null, `${method}: ${JSON.stringify(result.error)}`);
  assert.notEqual(result.data, null, `${method}: missing data`);
  return result.data;
}

function chunkedCookie(cookies, name) {
  const direct = cookies.get(name);
  if (direct) return direct;
  return [...cookies]
    .flatMap(([cookieName, value]) => {
      const match = cookieName.match(
        new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.(\\d+)$`),
      );
      return match ? [[Number(match[1]), value]] : [];
    })
    .sort(([left], [right]) => left - right)
    .map(([, value]) => value)
    .join("");
}

function responseCookiePair(response, suffix = ".session_token") {
  const cookie = response.headers
    .getSetCookie()
    .find((candidate) => candidate.slice(0, candidate.indexOf("=")).endsWith(suffix));
  assert.ok(cookie, `response did not set a ${suffix} cookie`);
  return cookie.split(";", 1)[0];
}

async function decodedAccountCookie(transport) {
  const value = chunkedCookie(transport.cookies, "better-auth.account_data");
  assert.ok(value, "better-auth.account_data cookie is missing");
  return symmetricDecodeJWT(
    value,
    "R".repeat(32),
    "better-auth-account",
  );
}

async function capturedEmailOtp(origin, kind, email) {
  const response = await fetch(
    `${origin}/__conformance__/email-otp/${kind}/${encodeURIComponent(email)}`,
  );
  assert.equal(response.status, 200, `missing ${kind} OTP for ${email}`);
  return (await response.json()).otp;
}

async function capturedPhoneNumberOtp(origin, kind, phoneNumber) {
  const response = await fetch(
    `${origin}/__conformance__/phone-number-otp/${kind}/${encodeURIComponent(phoneNumber)}`,
  );
  assert.equal(response.status, 200, `missing ${kind} OTP for ${phoneNumber}`);
  return (await response.json()).code;
}

async function runCase(name, callback) {
  try {
    await callback();
    console.log(`ok - ${name}`);
  } catch (error) {
    error.message = `${name}: ${error.message}`;
    throw error;
  }
}

async function siweClientConformance() {
  const requests = [];
  const plugin = siweClient();
  assert.equal(plugin.id, "siwe");
  assert.equal(plugin.version, betterAuthPackage.version);
  assert.deepEqual(plugin.pathMethods, {
    "/siwe/nonce": "POST",
    "/siwe/get-nonce": "POST",
  });

  const client = createAuthClient({
    baseURL: "https://siwe.example.test",
    fetchOptions: {
      customFetchImpl: async (input, init = {}) => {
        const url = new URL(String(input));
        requests.push({
          method: init.method,
          pathname: url.pathname,
          body: typeof init.body === "string" ? JSON.parse(init.body) : null,
        });
        if (url.pathname.endsWith("/verify")) {
          return Response.json({
            token: "siwe-session-token",
            success: true,
            user: {
              id: "siwe-user",
              walletAddress: "0x0000000000000000000000000000000000000000",
              chainId: 1,
            },
          });
        }
        return Response.json({ nonce: "12345678" });
      },
    },
    plugins: [plugin],
  });

  assert.deepEqual(success(await client.siwe.nonce(), "siwe.nonce"), {
    nonce: "12345678",
  });
  assert.deepEqual(success(await client.siwe.getNonce(), "siwe.getNonce"), {
    nonce: "12345678",
  });
  const message = "siwe.example.test wants you to sign in with your Ethereum account";
  const signature = "0xsigned-message";
  const verified = success(
    await client.siwe.verify({
      message,
      signature,
      email: "Wallet@Example.com",
    }),
    "siwe.verify",
  );
  assert.equal(verified.success, true);
  assert.deepEqual(requests, [
    {
      method: "POST",
      pathname: "/api/auth/siwe/nonce",
      body: {},
    },
    {
      method: "POST",
      pathname: "/api/auth/siwe/get-nonce",
      body: {},
    },
    {
      method: "POST",
      pathname: "/api/auth/siwe/verify",
      body: {
        message,
        signature,
        email: "Wallet@Example.com",
      },
    },
  ]);
  console.log("ok - SIWE official client contract");
}

async function lastLoginMethodClientConformance() {
  const previousDocument = globalThis.document;
  try {
    delete globalThis.document;
    const serverSide = lastLoginMethodClient().getActions();
    assert.equal(serverSide.getLastUsedLoginMethod(), null);
    assert.equal(serverSide.isLastUsedLoginMethod("email"), false);
    serverSide.clearLastUsedLoginMethod();

    let assigned;
    let documentCookie =
      "better-auth.last_used_login_method=oidc%2Fgoogle%20%2Bfoo; " +
      "better-auth.last_used_login_method=email; malformed=%E0%A4%A";
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: {
        get cookie() {
          return documentCookie;
        },
        set cookie(value) {
          assigned = value;
          documentCookie = value;
        },
      },
    });
    const actions = lastLoginMethodClient().getActions();
    assert.equal(actions.getLastUsedLoginMethod(), "email");
    assert.equal(actions.isLastUsedLoginMethod("email"), true);
    assert.equal(actions.isLastUsedLoginMethod("EMAIL"), false);
    actions.clearLastUsedLoginMethod();
    assert.equal(
      assigned,
      "better-auth.last_used_login_method=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;",
    );

    const custom = lastLoginMethodClient({
      cookieName: "custom.last-login",
      domain: ".example.com",
    }).getActions();
    globalThis.document.cookie = "custom.last-login=%E0%A4%A";
    assert.equal(custom.getLastUsedLoginMethod(), "%E0%A4%A");
    globalThis.document.cookie = 'custom.last-login="magic-link"';
    assert.equal(custom.getLastUsedLoginMethod(), "magic-link");
    custom.clearLastUsedLoginMethod();
    assert.equal(
      assigned,
      "custom.last-login=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=.example.com;",
    );
  } finally {
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
  }
  console.log("ok - last-login-method official client contract");
}

async function conformance(origin) {
  installVirtualAuthenticator(origin);
  const transport = new BrowserTransport(origin);
  const client = createAuthClient({
    baseURL: origin,
    fetchOptions: { customFetchImpl: transport.fetch.bind(transport) },
    plugins: [
      usernameClient(),
      anonymousClient(),
      emailOTPClient(),
      adminClient(),
      twoFactorClient(),
      passkeyClient(),
      apiKeyClient(),
      magicLinkClient(),
      lastLoginMethodClient(),
      multiSessionClient(),
      oneTimeTokenClient(),
      phoneNumberClient(),
      oneTapClient({ clientId: "conformance-google-client" }),
      siweClient(),
      organizationClient({
        teams: { enabled: true },
        dynamicAccessControl: { enabled: true },
      }),
      nativePluginClient,
    ],
  });

  await runCase("Better Auth 1.7.1 baseline", async () => {
    assert.equal(betterAuthPackage.version, "1.7.1");
    assert.equal(passkeyPackage.version, betterAuthPackage.version);
    assert.equal(apiKeyPackage.version, betterAuthPackage.version);
    const response = await transport.fetch(`${origin}/__conformance__/version`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { betterAuth: betterAuthPackage.version });
    const plugins = await transport.fetch(`${origin}/__conformance__/plugins`);
    assert.equal(plugins.status, 200);
    const metadata = await plugins.json();
    const nativePlugin = metadata.find((plugin) => plugin.id === "conformance");
    const magicLink = metadata.find((plugin) => plugin.id === "magic-link");
    const emailOtp = metadata.find((plugin) => plugin.id === "email-otp");
    const apiKey = metadata.find((plugin) => plugin.id === "api-key");
    const anonymous = metadata.find((plugin) => plugin.id === "anonymous");
    const username = metadata.find((plugin) => plugin.id === "username");
    const phoneNumber = metadata.find((plugin) => plugin.id === "phone-number");
    const oneTap = metadata.find((plugin) => plugin.id === "one-tap");
    const siwe = metadata.find((plugin) => plugin.id === "siwe");
    const multiSession = metadata.find((plugin) => plugin.id === "multi-session");
    const lastLoginMethod = metadata.find(
      (plugin) => plugin.id === "last-login-method",
    );
    const oneTimeToken = metadata.find((plugin) => plugin.id === "one-time-token");
    const bearer = metadata.find((plugin) => plugin.id === "bearer");
    const jwt = metadata.find((plugin) => plugin.id === "jwt");
    assert.equal(nativePlugin.client.betterAuthVersion, betterAuthPackage.version);
    assert.equal(nativePlugin.endpoints[0].clientMethod, "nativePlugin.ping");
    assert.equal(magicLink.client.factory, "magicLinkClient");
    assert.equal(emailOtp.client.factory, "emailOTPClient");
    assert.equal(apiKey.client.factory, "apiKeyClient");
    assert.equal(anonymous.client.factory, "anonymousClient");
    assert.equal(username.client.factory, "usernameClient");
    assert.equal(phoneNumber.client.factory, "phoneNumberClient");
    assert.equal(oneTap.client.factory, "oneTapClient");
    assert.equal(siwe.client.factory, "siweClient");
    assert.equal(multiSession.client.factory, "multiSessionClient");
    assert.equal(lastLoginMethod.client.factory, "lastLoginMethodClient");
    assert.deepEqual(lastLoginMethod.endpoints, []);
    assert.ok(oneTimeToken, "one-time-token plugin metadata is missing");
    assert.equal(oneTimeToken.client.factory, "oneTimeTokenClient");
    assert.deepEqual(
      oneTimeToken.endpoints.map((endpoint) => [
        endpoint.method,
        endpoint.path,
        endpoint.clientMethod,
      ]),
      [
        ["GET", "/one-time-token/generate", "oneTimeToken.generate"],
        ["POST", "/one-time-token/verify", "oneTimeToken.verify"],
      ],
    );
    assert.deepEqual(oneTimeToken.cookies, []);
    assert.deepEqual(oneTimeToken.rateLimits, []);
    assert.ok(bearer, "bearer plugin metadata is missing");
    assert.equal(bearer.client, null);
    assert.deepEqual(bearer.endpoints, []);
    assert.deepEqual(bearer.cookies, []);
    assert.deepEqual(bearer.rateLimits, []);
    assert.ok(jwt, "JWT plugin metadata is missing");
    assert.equal(jwt.client.factory, "jwtClient");
    assert.deepEqual(
      jwt.endpoints.map((endpoint) => [endpoint.path, endpoint.clientMethod]),
      [
        ["/jwks", "jwks"],
        ["/token", "token"],
      ],
    );
    assert.deepEqual(jwt.cookies, []);
    assert.deepEqual(jwt.rateLimits, []);
    assert.deepEqual(
      multiSession.endpoints.map((endpoint) => [endpoint.path, endpoint.clientMethod]),
      [
        ["/multi-session/list-device-sessions", "multiSession.listDeviceSessions"],
        ["/multi-session/set-active", "multiSession.setActive"],
        ["/multi-session/revoke", "multiSession.revoke"],
      ],
    );
    assert.deepEqual(
      oneTap.endpoints.map((endpoint) => [endpoint.path, endpoint.clientMethod]),
      [["/one-tap/callback", "oneTap"]],
    );
    assert.deepEqual(
      phoneNumber.endpoints.map((endpoint) => [endpoint.path, endpoint.clientMethod]),
      [
        ["/sign-in/phone-number", "signIn.phoneNumber"],
        ["/phone-number/send-otp", "phoneNumber.sendOtp"],
        ["/phone-number/verify", "phoneNumber.verify"],
        [
          "/phone-number/request-password-reset",
          "phoneNumber.requestPasswordReset",
        ],
        ["/phone-number/reset-password", "phoneNumber.resetPassword"],
      ],
    );
    assert.deepEqual(
      siwe.endpoints.map((endpoint) => [endpoint.path, endpoint.clientMethod]),
      [
        ["/siwe/nonce", "siwe.nonce"],
        ["/siwe/get-nonce", "siwe.getNonce"],
        ["/siwe/verify", "siwe.verify"],
      ],
    );
  });

  await runCase("last-login-method official client against native server", async () => {
    transport.clearCookies();
    success(
      await client.signUp.email({
        name: "Last Login User",
        email: "last-login@example.com",
        password: "correct horse battery staple",
      }),
      "last-login signup",
    );
    assert.equal(
      transport.cookies.get("better-auth.last_used_login_method"),
      "email",
    );
    success(await client.signOut(), "last-login signout");
    assert.equal(
      transport.cookies.get("better-auth.last_used_login_method"),
      "email",
    );
  });

  await runCase("multi-session official client", async () => {
    transport.clearCookies();
    const first = success(
      await client.signUp.email({
        name: "Multi One",
        email: "multi-one@example.com",
        password: "correct horse battery staple",
      }),
      "multi-session first signup",
    );
    const firstSelector = [...transport.cookies.keys()].find((name) =>
      name.includes("_multi-"),
    );
    assert.ok(firstSelector);
    transport.cookies.delete("better-auth.session_token");
    for (const name of [...transport.cookies.keys()]) {
      if (name.startsWith("better-auth.session_data")) transport.cookies.delete(name);
    }

    const second = success(
      await client.signUp.email({
        name: "Multi Two",
        email: "multi-two@example.com",
        password: "correct horse battery staple",
      }),
      "multi-session second signup",
    );
    assert.equal(
      [...transport.cookies.keys()].filter((name) => name.includes("_multi-")).length,
      2,
    );
    const sessions = success(
      await client.multiSession.listDeviceSessions(),
      "multiSession.listDeviceSessions",
    );
    assert.deepEqual(
      new Set(sessions.map((entry) => entry.session.token)),
      new Set([first.token, second.token]),
    );
    success(
      await client.multiSession.setActive({ sessionToken: first.token }),
      "multiSession.setActive",
    );
    transport.assertRequest("/api/auth/multi-session/set-active", "POST", {
      sessionToken: first.token,
    });
    assert.equal(
      success(await client.getSession(), "multi-session active session").session.token,
      first.token,
    );
    assert.deepEqual(
      success(
        await client.multiSession.revoke({ sessionToken: first.token }),
        "multiSession.revoke",
      ),
      { status: true },
    );
    transport.assertRequest("/api/auth/multi-session/revoke", "POST", {
      sessionToken: first.token,
    });
    assert.equal(
      success(await client.getSession(), "multi-session replacement").session.token,
      second.token,
    );
    success(await client.signOut(), "multi-session cleanup signOut");
  });

  await runCase("SIWE official client against native server", async () => {
    const nonce = success(await client.siwe.nonce(), "siwe.nonce").nonce;
    assert.match(nonce, /^[A-Za-z0-9]{8,250}$/);
    const aliasNonce = success(
      await client.siwe.getNonce(),
      "siwe.getNonce",
    ).nonce;
    assert.match(aliasNonce, /^[A-Za-z0-9]{8,250}$/);
    const address = "0x52908400098527886E0F7030069857D2E4169EE7";
    const domain = new URL(origin).host;
    const message = `${domain} wants you to sign in with your Ethereum account:\n${address}\n\nURI: ${origin}\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: 2026-08-24T12:00:00Z`;
    const verified = success(
      await client.siwe.verify({ message, signature: "0xconformance" }),
      "siwe.verify",
    );
    assert.equal(verified.success, true);
    assert.equal(verified.user.walletAddress, address);
    assert.equal(verified.user.chainId, 1);
    assert.equal(typeof verified.token, "string");
    transport.assertRequest("/api/auth/siwe/nonce", "POST", {});
    transport.assertRequest("/api/auth/siwe/get-nonce", "POST", {});
    transport.assertRequest("/api/auth/siwe/verify", "POST", {
      message,
      signature: "0xconformance",
    });
  });

  await runCase("one-tap official client callback contract", async () => {
    let callback;
    const previousWindow = globalThis.window;
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {
        document: {},
        googleScriptInitialized: true,
        location: { href: origin },
        google: {
          accounts: {
            id: {
              initialize(options) {
                callback = options.callback;
                assert.equal(options.client_id, "conformance-google-client");
                assert.equal(options.use_fedcm_for_prompt, true);
                assert.equal(options.nonce, "forwarded-to-google-only");
              },
              prompt() {
                void callback({ credential: "not-a-google-jwt" });
              },
            },
          },
        },
      },
    });
    try {
      await client.oneTap({
        callbackURL: "/after-one-tap",
        nonce: "forwarded-to-google-only",
      });
    } finally {
      if (previousWindow === undefined) delete globalThis.window;
      else globalThis.window = previousWindow;
    }
    transport.assertRequest("/api/auth/one-tap/callback", "POST", {
      idToken: "not-a-google-jwt",
      callbackURL: "/after-one-tap",
    });
  });

  await runCase("get-session rejects POST without deferred refresh", async () => {
    const response = await client.$fetch("/get-session", { method: "POST" });
    assert.equal(response.data, null);
    assert.equal(response.error?.status, 405);
    assert.equal(response.error?.code, "METHOD_NOT_ALLOWED");
    assert.equal(
      response.error?.message,
      "POST method requires deferSessionRefresh to be enabled in session config",
    );
  });

  await runCase("native plugin client metadata and route", async () => {
    const data = success(await client.nativePlugin.ping(), "nativePlugin.ping");
    assert.deepEqual(data, {
      plugin: "conformance",
      betterAuth: betterAuthPackage.version,
    });
    transport.assertRequest("/api/auth/native-plugin/ping", "GET");
  });

  await runCase("Better Auth request rate limiting", async () => {
    assert.deepEqual(
      success(await client.nativePlugin.rateLimit(), "nativePlugin.rateLimit first"),
      { allowed: true },
    );
    assert.deepEqual(
      success(await client.nativePlugin.rateLimit(), "nativePlugin.rateLimit second"),
      { allowed: true },
    );
    const limited = await client.nativePlugin.rateLimit();
    assert.equal(limited.data, null);
    assert.equal(limited.error?.status, 429);
    assert.equal(limited.error?.message, "Too many requests. Please try again later.");
  });

  await runCase("core email and password clients", async () => {
    const signedUp = success(
      await client.signUp.email({
        name: "Email User",
        email: "Email.User@Example.com",
        password: "correct horse battery staple",
        image: "https://example.com/email-user.png",
        callbackURL: "/verify-email",
      }),
      "signUp.email",
    );
    assert.equal(signedUp.user.email, "email.user@example.com");
    assert.equal(signedUp.user.image, "https://example.com/email-user.png");
    assert.equal(typeof signedUp.token, "string");
    transport.assertRequest("/api/auth/sign-up/email", "POST", {
      name: "Email User",
      email: "Email.User@Example.com",
      password: "correct horse battery staple",
      image: "https://example.com/email-user.png",
      callbackURL: "/verify-email",
    });

    const verified = success(
      await client.$fetch("/verify-password", {
        method: "POST",
        body: { password: "correct horse battery staple" },
      }),
      "verifyPassword",
    );
    assert.equal(verified.status, true);
    transport.assertRequest("/api/auth/verify-password", "POST", {
      password: "correct horse battery staple",
    });

    success(await client.signOut(), "signOut after email signup");
    const signedIn = success(
      await client.signIn.email({
        email: "EMAIL.USER@example.com",
        password: "correct horse battery staple",
        callbackURL: "/dashboard",
        rememberMe: false,
      }),
      "signIn.email",
    );
    assert.equal(signedIn.user.email, "email.user@example.com");
    assert.equal(signedIn.redirect, true);
    assert.equal(signedIn.url, "/dashboard");
    assert.equal(signedIn.twoFactorRedirect, undefined);
    assert.equal(signedIn.twoFactorMethods, undefined);
    assert.equal(signedIn.mfaSetupRequired, undefined);
    transport.assertRequest("/api/auth/sign-in/email", "POST", {
      email: "EMAIL.USER@example.com",
      password: "correct horse battery staple",
      callbackURL: "/dashboard",
      rememberMe: false,
    });

    const rejected = await client.signIn.email({
      email: "missing@example.com",
      password: "wrong password",
    });
    assert.equal(rejected.data, null);
    assert.equal(rejected.error?.status, 401);
    assert.equal(rejected.error?.code, "INVALID_EMAIL_OR_PASSWORD");
    success(await client.signOut(), "signOut after email signin");
  });

  await runCase("email verification clients", async () => {
    const sent = success(
      await client.sendVerificationEmail({
        email: "email.user@example.com",
        callbackURL: "/verified",
      }),
      "sendVerificationEmail",
    );
    assert.equal(sent.status, true);
    transport.assertRequest("/api/auth/send-verification-email", "POST", {
      email: "email.user@example.com",
      callbackURL: "/verified",
    });
    const captured = await transport.fetch(
      `${origin}/__conformance__/verification-token/email.user%40example.com`,
    );
    assert.equal(captured.status, 200);
    const { token } = await captured.json();
    const verified = success(
      await client.verifyEmail({ query: { token } }),
      "verifyEmail",
    );
    assert.equal(verified.status, true);
    assert.equal(verified.user, null);
    const session = success(await client.getSession(), "verified getSession");
    assert.equal(session.user.emailVerified, true);

    const replay = await client.verifyEmail({ query: { token } });
    assert.equal(replay.data, null);
    assert.equal(replay.error?.status, 401);
    assert.equal(replay.error?.code, "INVALID_TOKEN");
    success(await client.signOut(), "signOut after email verification");

    success(
      await client.signUp.email({
        name: "Changed Email",
        email: "change-source@example.com",
        password: "correct horse battery staple",
      }),
      "signUp.email for changeEmail",
    );
    const changed = success(
      await client.changeEmail({
        newEmail: "change-target@example.com",
        callbackURL: "/changed",
      }),
      "changeEmail",
    );
    assert.equal(changed.status, true);
    transport.assertRequest("/api/auth/change-email", "POST", {
      newEmail: "change-target@example.com",
      callbackURL: "/changed",
    });
    const changeCaptured = await transport.fetch(
      `${origin}/__conformance__/verification-token/change-target%40example.com`,
    );
    assert.equal(changeCaptured.status, 200);
    const changeToken = (await changeCaptured.json()).token;
    const changedVerification = success(
      await client.verifyEmail({ query: { token: changeToken } }),
      "verifyEmail after changeEmail",
    );
    assert.equal(changedVerification.user.email, "change-target@example.com");
    assert.equal(changedVerification.user.emailVerified, true);
    success(await client.signOut(), "signOut after changeEmail");
  });

  await runCase("password reset clients", async () => {
    const requested = success(
      await client.requestPasswordReset({
        email: "email.user@example.com",
        redirectTo: "/choose-password",
      }),
      "requestPasswordReset",
    );
    assert.equal(requested.status, true);
    transport.assertRequest("/api/auth/request-password-reset", "POST", {
      email: "email.user@example.com",
      redirectTo: "/choose-password",
    });
    const captured = await transport.fetch(
      `${origin}/__conformance__/password-reset-token/email.user%40example.com`,
    );
    assert.equal(captured.status, 200);
    const { token } = await captured.json();
    const reset = success(
      await client.resetPassword({
        newPassword: "replacement horse battery staple",
        token,
      }),
      "resetPassword",
    );
    assert.equal(reset.status, true);
    transport.assertRequest("/api/auth/reset-password", "POST", {
      newPassword: "replacement horse battery staple",
      token,
    });
    const replay = await client.resetPassword({
      newPassword: "another replacement password",
      token,
    });
    assert.equal(replay.data, null);
    assert.equal(replay.error?.status, 400);
    assert.equal(replay.error?.code, "INVALID_TOKEN");

    const signedIn = success(
      await client.signIn.email({
        email: "email.user@example.com",
        password: "replacement horse battery staple",
      }),
      "signIn.email after password reset",
    );
    assert.equal(signedIn.user.email, "email.user@example.com");
    success(await client.signOut(), "signOut after password reset");
  });

  await runCase("email OTP official client", async () => {
    const sentVerification = success(
      await client.emailOtp.sendVerificationOtp({
        email: "LUNA@example.com",
        type: "email-verification",
      }),
      "emailOtp.sendVerificationOtp",
    );
    assert.equal(sentVerification.success, true);
    const verificationOtp = await capturedEmailOtp(
      origin,
      "email-verification",
      "luna@example.com",
    );
    const wrongOtp = await client.emailOtp.checkVerificationOtp({
      email: "luna@example.com",
      type: "email-verification",
      otp: "not-the-otp",
    });
    assert.equal(wrongOtp.data, null);
    assert.equal(wrongOtp.error?.status, 400);
    assert.equal(wrongOtp.error?.code, "INVALID_OTP");
    const checked = success(
      await client.emailOtp.checkVerificationOtp({
        email: "luna@example.com",
        type: "email-verification",
        otp: verificationOtp,
      }),
      "emailOtp.checkVerificationOtp",
    );
    assert.equal(checked.success, true);
    const verified = success(
      await client.emailOtp.verifyEmail({
        email: "luna@example.com",
        otp: verificationOtp,
      }),
      "emailOtp.verifyEmail",
    );
    assert.equal(verified.status, true);
    assert.equal(verified.user.emailVerified, true);
    assert.equal(typeof verified.token, "string");
    const replay = await client.emailOtp.verifyEmail({
      email: "luna@example.com",
      otp: verificationOtp,
    });
    assert.equal(replay.data, null);
    assert.equal(replay.error?.code, "INVALID_OTP");
    success(await client.signOut(), "email OTP verification signOut");

    const email = "otp-user@example.com";
    success(
      await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" }),
      "emailOtp.sendVerificationOtp sign-in",
    );
    const signInOtp = await capturedEmailOtp(origin, "sign-in", email);
    const signedIn = success(
      await client.signIn.emailOtp({
        email,
        otp: signInOtp,
        name: "OTP User",
        image: "https://example.com/otp-user.png",
        department: "authentication",
      }),
      "signIn.emailOtp",
    );
    assert.equal(signedIn.user.email, email);
    assert.equal(signedIn.user.emailVerified, true);
    assert.equal(signedIn.user.department, "authentication");
    success(await client.signOut(), "email OTP sign-in signOut");

    success(
      await client.emailOtp.requestPasswordReset({ email }),
      "emailOtp.requestPasswordReset",
    );
    const resetOtp = await capturedEmailOtp(origin, "forget-password", email);
    const reset = success(
      await client.emailOtp.resetPassword({
        email,
        otp: resetOtp,
        password: "OTP replacement horse battery staple",
      }),
      "emailOtp.resetPassword",
    );
    assert.equal(reset.success, true);
    success(
      await client.signIn.email({
        email,
        password: "OTP replacement horse battery staple",
      }),
      "email sign-in after OTP reset",
    );

    const newEmail = "otp-user-changed@example.com";
    success(
      await client.emailOtp.requestEmailChange({ newEmail }),
      "emailOtp.requestEmailChange",
    );
    const changeOtp = await capturedEmailOtp(origin, "change-email", newEmail);
    const changed = success(
      await client.emailOtp.changeEmail({ newEmail, otp: changeOtp }),
      "emailOtp.changeEmail",
    );
    assert.equal(changed.success, true);
    const changedSession = success(
      await client.getSession(),
      "getSession after email OTP change",
    );
    assert.equal(changedSession.user.email, newEmail);
    assert.equal(changedSession.user.emailVerified, true);
    success(await client.signOut(), "email OTP change signOut");
  });

  await runCase("phone-number official client", async () => {
    const phoneNumber = "desk-extension-204";
    const sent = success(
      await client.phoneNumber.sendOtp({ phoneNumber }),
      "phoneNumber.sendOtp",
    );
    assert.deepEqual(sent, { message: "code sent" });
    transport.assertRequest("/api/auth/phone-number/send-otp", "POST", {
      phoneNumber,
    });

    const code = await capturedPhoneNumberOtp(
      origin,
      "verification",
      phoneNumber,
    );
    assert.match(code, /^\d{6}$/);
    const verified = success(
      await client.phoneNumber.verify({ phoneNumber, code }),
      "phoneNumber.verify",
    );
    assert.equal(verified.status, true);
    assert.equal(typeof verified.token, "string");
    assert.equal(verified.user.phoneNumber, phoneNumber);
    assert.equal(verified.user.phoneNumberVerified, true);
    assert.equal(verified.user.email, `phone-${phoneNumber}@example.com`);
    assert.equal(verified.user.name, `Phone ${phoneNumber}`);
    transport.assertRequest("/api/auth/phone-number/verify", "POST", {
      phoneNumber,
      code,
    });

    const replay = await client.phoneNumber.verify({ phoneNumber, code });
    assert.equal(replay.data, null);
    assert.equal(replay.error?.status, 400);
    assert.equal(replay.error?.code, "OTP_NOT_FOUND");

    const requested = success(
      await client.phoneNumber.requestPasswordReset({ phoneNumber }),
      "phoneNumber.requestPasswordReset",
    );
    assert.deepEqual(requested, { status: true });
    transport.assertRequest(
      "/api/auth/phone-number/request-password-reset",
      "POST",
      { phoneNumber },
    );
    const resetOtp = await capturedPhoneNumberOtp(
      origin,
      "password-reset",
      phoneNumber,
    );
    assert.match(resetOtp, /^\d{6}$/);
    const newPassword = "phone replacement horse battery staple";
    const reset = success(
      await client.phoneNumber.resetPassword({
        otp: resetOtp,
        phoneNumber,
        newPassword,
      }),
      "phoneNumber.resetPassword",
    );
    assert.deepEqual(reset, { status: true });
    transport.assertRequest("/api/auth/phone-number/reset-password", "POST", {
      otp: resetOtp,
      phoneNumber,
      newPassword,
    });

    const signedIn = success(
      await client.signIn.phoneNumber({
        phoneNumber,
        password: newPassword,
        rememberMe: false,
      }),
      "signIn.phoneNumber",
    );
    assert.equal(typeof signedIn.token, "string");
    assert.equal(signedIn.user.phoneNumber, phoneNumber);
    assert.equal(signedIn.user.phoneNumberVerified, true);
    transport.assertRequest("/api/auth/sign-in/phone-number", "POST", {
      phoneNumber,
      password: newPassword,
      rememberMe: false,
    });

    const rejectedUpdate = await client.updateUser({
      phoneNumber: "another-opaque-phone",
    });
    assert.equal(rejectedUpdate.data, null);
    assert.equal(rejectedUpdate.error?.status, 400);
    assert.equal(rejectedUpdate.error?.code, "PHONE_NUMBER_CANNOT_BE_UPDATED");
    const cleared = success(
      await client.updateUser({ phoneNumber: null }),
      "updateUser clear phone number",
    );
    assert.deepEqual(cleared, { status: true });
    transport.assertRequest("/api/auth/update-user", "POST", {
      phoneNumber: null,
    });
    const clearedSession = success(
      await client.getSession(),
      "getSession after phone-number clear",
    );
    assert.equal(clearedSession.user.phoneNumber ?? null, null);
    assert.equal(clearedSession.user.phoneNumberVerified ?? false, false);
    success(await client.signOut(), "phone-number signOut");
  });

  await runCase("username and session clients", async () => {
    const available = success(
      await client.isUsernameAvailable({ username: "available_user" }),
      "isUsernameAvailable",
    );
    assert.equal(available.available, true);
    transport.assertRequest("/api/auth/is-username-available", "POST", {
      username: "available_user",
    });

    const signedUp = success(
      await client.signUp.email({
        name: "Username User",
        email: "username-user@example.com",
        password: "correct horse battery staple",
        username: "Mixed_User",
        displayUsername: "Mixed User",
      }),
      "signUp.email with username",
    );
    assert.equal(signedUp.user.username, "mixed_user");
    assert.equal(signedUp.user.displayUsername, "Mixed User");
    transport.assertRequest("/api/auth/sign-up/email", "POST", {
      name: "Username User",
      email: "username-user@example.com",
      password: "correct horse battery staple",
      username: "Mixed_User",
      displayUsername: "Mixed User",
    });

    const updated = success(
      await client.updateUser({
        name: "Renamed Profile",
        image: null,
        username: "Renamed_User",
        displayUsername: "Renamed User",
        timezone: "Europe/London",
      }),
      "updateUser username",
    );
    assert.equal(updated.status, true);
    transport.assertRequest("/api/auth/update-user", "POST", {
      name: "Renamed Profile",
      image: null,
      username: "Renamed_User",
      displayUsername: "Renamed User",
      timezone: "Europe/London",
    });
    const sessionUpdate = success(
      await client.updateSession({ theme: "dark" }),
      "updateSession additional field",
    );
    assert.equal(sessionUpdate.session.theme, "dark");
    transport.assertRequest("/api/auth/update-session", "POST", { theme: "dark" });
    const updatedSession = success(
      await client.getSession(),
      "getSession after username update",
    );
    assert.equal(updatedSession.user.username, "renamed_user");
    assert.equal(updatedSession.user.displayUsername, "Renamed User");
    assert.equal(updatedSession.user.name, "Renamed Profile");
    assert.equal(updatedSession.user.image, null);
    assert.equal(updatedSession.user.timezone, "Europe/London");
    assert.equal(updatedSession.session.theme, "dark");
    success(await client.signOut(), "signOut after username update");

    const normalizedSignIn = success(
      await client.signIn.username({
        username: "RENAMED_USER",
        password: "correct horse battery staple",
      }),
      "signIn.username normalized",
    );
    assert.equal(normalizedSignIn.user.username, "renamed_user");
    success(await client.signOut(), "signOut after normalized username signin");

    const signedIn = success(
      await client.signIn.username({
        username: "luna",
        password: "correct horse battery staple",
        callbackURL: "/dashboard",
      }),
      "signIn.username",
    );
    assert.equal(signedIn.user.username, "luna");
    assert.equal(signedIn.redirect, true);
    assert.equal(signedIn.url, "/dashboard");
    transport.assertRequest("/api/auth/sign-in/username", "POST", {
      username: "luna",
      password: "correct horse battery staple",
      callbackURL: "/dashboard",
    });

    const session = success(await client.getSession(), "getSession");
    assert.equal(session.user.username, "luna");
    assert.equal(session.session.assurance, undefined);
    assert.equal(session.session.stepUpRequired, undefined);
    transport.assertRequest("/api/auth/get-session", "GET");

    const rejected = await client.signIn.username({
      username: "luna",
      password: "wrong password",
    });
    assert.equal(rejected.data, null);
    assert.equal(rejected.error?.status, 401);
    assert.equal(rejected.error?.code, "INVALID_USERNAME_OR_PASSWORD");
  });

  await runCase("admin client", async () => {
    const administrator = success(await client.getSession(), "admin getSession");
    const created = success(
      await client.admin.createUser({
        email: "casey@example.com",
        password: "temporary password",
        name: "Casey",
        role: "member",
        data: { username: "casey", department: "support" },
      }),
      "admin.createUser",
    );
    assert.equal(created.user.username, "casey");
    assert.equal(created.user.department, "support");
    assert.equal(created.user.mustChangePassword, undefined);
    transport.assertRequest("/api/auth/admin/create-user", "POST", {
      email: "casey@example.com",
      password: "temporary password",
      name: "Casey",
      role: "member",
      data: { username: "casey", department: "support" },
    });

    const passwordless = success(
      await client.admin.createUser({
        email: "taylor@example.com",
        name: "Taylor",
        data: { username: "taylor" },
      }),
      "admin.createUser passwordless",
    );
    assert.equal(passwordless.user.role, "user");
    const dataRole = success(
      await client.admin.createUser({
        email: "river@example.com",
        name: "River",
        data: { username: "river", role: ["member", "viewer"] },
      }),
      "admin.createUser data role",
    );
    assert.equal(dataRole.user.role, "member,viewer");

    const fetched = success(
      await client.admin.getUser({ query: { id: created.user.id } }),
      "admin.getUser",
    );
    assert.equal(fetched.id, created.user.id);

    const updated = success(
      await client.admin.updateUser({
        userId: created.user.id,
        data: {
          name: "Casey Updated",
          emailVerified: true,
          department: "operations",
        },
      }),
      "admin.updateUser",
    );
    assert.equal(updated.name, "Casey Updated");
    assert.equal(updated.emailVerified, true);
    assert.equal(updated.department, "operations");

    const permission = success(
      await client.admin.hasPermission({ permissions: { user: ["list", "get"] } }),
      "admin.hasPermission",
    );
    assert.equal(permission.success, true);

    const listed = success(
      await client.admin.listUsers({
        query: {
          searchValue: "casey@",
          searchField: "email",
          searchOperator: "starts_with",
          limit: 20,
          offset: 0,
          sortBy: "name",
          sortDirection: "desc",
        },
      }),
      "admin.listUsers",
    );
    assert.equal(listed.total, 1);
    assert.ok(listed.users.some((user) => user.id === created.user.id));
    const listRequest = transport.assertRequest("/api/auth/admin/list-users", "GET");
    assert.match(listRequest.search, /limit=20/);
    const customFiltered = success(
      await client.admin.listUsers({
        query: {
          filterField: "department",
          filterValue: ["operations"],
          filterOperator: "in",
          sortBy: "department",
          sortDirection: "asc",
        },
      }),
      "admin.listUsers custom filter",
    );
    assert.deepEqual(
      customFiltered.users.map((user) => user.id),
      [created.user.id],
    );

    const role = success(
      await client.admin.setRole({
        userId: created.user.id,
        role: ["member", "viewer"],
      }),
      "admin.setRole",
    );
    assert.equal(role.user.role, "member,viewer");

    success(
      await client.admin.setUserPassword({
        userId: created.user.id,
        newPassword: "replacement password",
      }),
      "admin.setUserPassword",
    );
    const banned = success(
      await client.admin.banUser({
        userId: created.user.id,
        banReason: "conformance",
        banExpiresIn: 60,
      }),
      "admin.banUser",
    );
    assert.equal(banned.user.banned, true);
    const unbanned = success(
      await client.admin.unbanUser({ userId: created.user.id }),
      "admin.unbanUser",
    );
    assert.equal(unbanned.user.banned, false);

    const impersonated = success(
      await client.admin.impersonateUser({ userId: created.user.id }),
      "admin.impersonateUser",
    );
    assert.equal(impersonated.user.id, created.user.id);
    assert.equal(impersonated.session.impersonatedBy, administrator.user.id);
    const restored = success(
      await client.admin.stopImpersonating(),
      "admin.stopImpersonating",
    );
    assert.equal(restored.user.id, administrator.user.id);
    const restoredSession = success(
      await client.getSession(),
      "admin restored original session",
    );
    assert.equal(restoredSession.session.id, administrator.session.id);

    await transport.useFixtureSession("password");
    await transport.useFixtureSession("password");
    const current = success(await client.getSession(), "admin restored fixture session");
    const sessions = success(
      await client.admin.listUserSessions({ userId: administrator.user.id }),
      "admin.listUserSessions",
    );
    const revocable = sessions.sessions.find(
      (session) => session.id !== current.session.id,
    );
    assert.ok(revocable);
    success(
      await client.admin.revokeUserSession({ sessionToken: revocable.token }),
      "admin.revokeUserSession",
    );
    success(
      await client.admin.revokeUserSessions({ userId: created.user.id }),
      "admin.revokeUserSessions",
    );
    success(
      await client.admin.removeUser({ userId: passwordless.user.id }),
      "admin.removeUser",
    );
    success(
      await client.admin.removeUser({ userId: dataRole.user.id }),
      "admin.removeUser data role",
    );
  });

  await runCase("passkey client", async () => {
    const emptyPasskeys = success(
      await client.passkey.listUserPasskeys(),
      "passkey.listUserPasskeys",
    );
    assert.deepEqual(emptyPasskeys, []);
    transport.assertRequest("/api/auth/passkey/list-user-passkeys", "GET");

    const registration = success(
      await client.passkey.addPasskey({
        name: "Conformance key",
        authenticatorAttachment: "platform",
        context: "official-client",
        createSession: true,
      }),
      "passkey.addPasskey",
    );
    assert.equal(registration.name, "Conformance key");
    assert.equal(registration.deviceType, "singleDevice");
    assert.equal(registration.backedUp, false);
    assert.equal(registration.transports, "internal");
    assert.equal(registration.user.id, registration.userId);
    assert.equal(typeof registration.session.token, "string");
    const options = transport.assertRequest(
      "/api/auth/passkey/generate-register-options",
      "GET",
    );
    assert.match(options.search, /name=Conformance/);
    assert.match(options.search, /authenticatorAttachment=platform/);
    assert.match(options.search, /context=official-client/);
    transport.assertRequest("/api/auth/passkey/verify-registration", "POST");

    const passkeys = success(
      await client.passkey.listUserPasskeys(),
      "passkey.listUserPasskeys registered",
    );
    assert.equal(passkeys.length, 1);
    assert.equal(passkeys[0].credentialID, registration.credentialID);

    const updated = success(
      await client.passkey.updatePasskey({ id: passkeys[0].id, name: "Updated key" }),
      "passkey.updatePasskey",
    );
    assert.equal(updated.passkey.name, "Updated key");
    transport.assertRequest("/api/auth/passkey/update-passkey", "POST", {
      id: passkeys[0].id,
      name: "Updated key",
    });

    transport.clearCookies();
    const authentication = success(
      await client.signIn.passkey(),
      "signIn.passkey",
    );
    assert.equal(authentication.user.id, registration.userId);
    transport.assertRequest(
      "/api/auth/passkey/generate-authenticate-options",
      "GET",
    );
    transport.assertRequest("/api/auth/passkey/verify-authentication", "POST");

    const deleted = success(
      await client.passkey.deletePasskey({ id: passkeys[0].id }),
      "passkey.deletePasskey",
    );
    assert.equal(deleted.status, true);
    transport.assertRequest("/api/auth/passkey/delete-passkey", "POST", {
      id: passkeys[0].id,
    });
  });

  await runCase("complete two-factor client", async () => {
    await transport.useFixtureSession("password");
    const enabled = success(
      await client.twoFactor.enable({
        password: "correct horse battery staple",
        method: "totp",
        issuer: "lucid-auth conformance",
      }),
      "twoFactor.enable totp",
    );
    assert.equal(enabled.method, "totp");
    assert.equal(typeof enabled.totpURI, "string");
    assert.equal(enabled.backupCodes.length, 10);
    transport.assertRequest("/api/auth/two-factor/enable", "POST", {
      password: "correct horse battery staple",
      method: "totp",
      issuer: "lucid-auth conformance",
    });

    const uri = success(
      await client.twoFactor.getTotpUri({
        password: "correct horse battery staple",
      }),
      "twoFactor.getTotpUri",
    );
    assert.equal(typeof uri.totpURI, "string");
    const encodedSecret = new URL(enabled.totpURI).searchParams.get("secret");
    const secret = new TextDecoder().decode(base32.decode(encodedSecret));
    const setupCode = await createOTP(secret, { digits: 6, period: 1 }).totp();
    const setup = success(
      await client.twoFactor.verifyTotp({ code: setupCode, trustDevice: false }),
      "twoFactor.verifyTotp setup",
    );
    assert.equal(setup.user.twoFactorEnabled, true);

    const generated = success(
      await client.twoFactor.generateBackupCodes({
        password: "correct horse battery staple",
      }),
      "twoFactor.generateBackupCodes",
    );
    assert.equal(generated.status, true);
    assert.equal(generated.backupCodes.length, 10);
    transport.assertRequest("/api/auth/two-factor/generate-backup-codes", "POST", {
      password: "correct horse battery staple",
    });

    await new Promise((resolve) => setTimeout(resolve, 1100));
    transport.clearCookies();
    const totpChallenge = success(
      await client.signIn.username({
        username: "luna",
        password: "correct horse battery staple",
      }),
      "signIn.username TOTP challenge",
    );
    assert.equal(totpChallenge.twoFactorRedirect, true);
    assert.deepEqual(totpChallenge.twoFactorMethods, ["totp", "otp"]);
    const signInCode = await createOTP(secret, { digits: 6, period: 1 }).totp();
    const totpVerified = success(
      await client.twoFactor.verifyTotp({ code: signInCode, trustDevice: false }),
      "twoFactor.verifyTotp sign-in",
    );
    assert.equal(totpVerified.user.twoFactorEnabled, true);

    transport.clearCookies();
    success(
      await client.signIn.username({
        username: "luna",
        password: "correct horse battery staple",
      }),
      "signIn.username OTP challenge",
    );
    const sent = success(
      await client.twoFactor.sendOtp({ trustDevice: true }),
      "twoFactor.sendOtp",
    );
    assert.equal(sent.status, true);
    const otpResponse = await transport.fetch(
      `${origin}/__conformance__/two-factor-otp/luna@example.com`,
    );
    assert.equal(otpResponse.status, 200);
    const { code: deliveredCode } = await otpResponse.json();
    const otpVerified = success(
      await client.twoFactor.verifyOtp({
        code: deliveredCode,
        trustDevice: true,
      }),
      "twoFactor.verifyOtp",
    );
    assert.equal(otpVerified.user.twoFactorEnabled, true);
    assert.equal(
      transport.cookies.has("better-auth.trust_device"),
      true,
      `verifyOtp did not set the trust-device cookie: ${JSON.stringify([...transport.cookies.keys()])}`,
    );

    transport.cookies.delete("better-auth.session_token");
    const trusted = success(
      await client.signIn.username({
        username: "luna",
        password: "correct horse battery staple",
      }),
      "signIn.username trusted device",
    );
    assert.equal(trusted.twoFactorRedirect, undefined);
    assert.equal(trusted.user.twoFactorEnabled, true);

    transport.clearCookies();
    success(
      await client.signIn.username({
        username: "luna",
        password: "correct horse battery staple",
      }),
      "signIn.username backup-code challenge",
    );
    const backupVerified = success(
      await client.twoFactor.verifyBackupCode({
        code: generated.backupCodes[0],
        disableSession: false,
        trustDevice: false,
      }),
      "twoFactor.verifyBackupCode",
    );
    assert.equal(typeof backupVerified.token, "string");

    const disabled = success(
      await client.twoFactor.disable({ password: "correct horse battery staple" }),
      "twoFactor.disable",
    );
    assert.equal(disabled.status, true);

    const otpEnabled = success(
      await client.twoFactor.enable({
        password: "correct horse battery staple",
        method: "otp",
      }),
      "twoFactor.enable otp",
    );
    assert.deepEqual(otpEnabled, { method: "otp" });
    success(
      await client.twoFactor.disable({ password: "correct horse battery staple" }),
      "twoFactor.disable otp",
    );
  });

  await runCase("magic-link client", async () => {
    const email = "magic-client@example.com";
    const sent = success(
      await client.signIn.magicLink({
        email,
        name: "Magic Client",
        metadata: { source: "official-client" },
      }),
      "signIn.magicLink",
    );
    assert.deepEqual(sent, { status: true });
    transport.assertRequest("/api/auth/sign-in/magic-link", "POST", {
      email,
      name: "Magic Client",
      metadata: { source: "official-client" },
    });

    const tokenResponse = await transport.fetch(
      `${origin}/__conformance__/magic-link-token/${email}`,
    );
    assert.equal(tokenResponse.status, 200);
    const { token } = await tokenResponse.json();
    const verified = success(
      await client.magicLink.verify({ query: { token } }),
      "magicLink.verify",
    );
    assert.equal(verified.user.email, email);
    assert.equal(verified.user.emailVerified, true);
    assert.equal(typeof verified.token, "string");
    const request = transport.assertRequest("/api/auth/magic-link/verify", "GET");
    assert.equal(new URLSearchParams(request.search).get("token"), token);
    success(await client.signOut(), "signOut after magic link");
  });

  await runCase("API-key client", async () => {
    await transport.useFixtureSession("strong");
    const created = success(
      await client.apiKey.create({
        name: "Official client key",
        prefix: "official_",
        expiresIn: 86_400,
        metadata: { source: "official-client" },
      }),
      "apiKey.create",
    );
    assert.match(created.key, /^official_/);
    assert.equal(created.configId, "default");
    assert.equal(created.metadata.source, "official-client");
    assert.equal(created.permissions.documents[0], "read");
    assert.equal("keyHash" in created, false);
    transport.assertRequest("/api/auth/api-key/create", "POST", {
      name: "Official client key",
      prefix: "official_",
      expiresIn: 86_400,
      metadata: { source: "official-client" },
    });

    const fetched = success(
      await client.apiKey.get({ query: { id: created.id } }),
      "apiKey.get",
    );
    assert.equal(fetched.id, created.id);
    assert.equal("key" in fetched, false);

    const listed = success(
      await client.apiKey.list({
        query: {
          limit: 1,
          offset: 0,
          sortBy: "createdAt",
          sortDirection: "desc",
        },
      }),
      "apiKey.list",
    );
    assert.equal(listed.total, 1);
    assert.equal(listed.apiKeys[0].id, created.id);
    assert.equal("key" in listed.apiKeys[0], false);

    const updated = success(
      await client.apiKey.update({ keyId: created.id, name: "Updated client key" }),
      "apiKey.update",
    );
    assert.equal(updated.name, "Updated client key");

    const verifiedResponse = await transport.fetch(
      `${origin}/api/auth/api-key/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          key: created.key,
          permissions: { documents: ["read"] },
        }),
      },
    );
    assert.equal(verifiedResponse.status, 200);
    const verified = await verifiedResponse.json();
    assert.equal(verified.valid, true);
    assert.equal(verified.error, null);
    assert.equal("key" in verified.key, false);

    transport.clearCookies();
    const sessionResponse = await transport.fetch(`${origin}/api/auth/get-session`, {
      headers: { "x-api-key": created.key },
    });
    assert.equal(sessionResponse.status, 200);
    const session = await sessionResponse.json();
    assert.equal(session.session.id, created.id);
    assert.equal(session.user.email, "luna@example.com");

    await transport.useFixtureSession("strong");
    const deleted = success(
      await client.apiKey.delete({ keyId: created.id }),
      "apiKey.delete",
    );
    assert.equal(deleted.success, true);
  });

  await runCase("complete organization client", async () => {
    await transport.useFixtureSession("strong");
    const created = success(
      await client.organization.create({
        name: "Conformance Organization",
        slug: "conformance-organization",
        metadata: { fixture: true },
      }),
      "organization.create",
    );
    assert.equal(created.slug, "conformance-organization");
    assert.equal(created.members.length, 1);

    const checked = success(
      await client.organization.checkSlug({ slug: "available-organization" }),
      "organization.checkSlug",
    );
    assert.equal(checked.status, true);
    const organizations = success(
      await client.organization.list(),
      "organization.list",
    );
    assert.ok(organizations.some((organization) => organization.id === created.id));
    const fullOrganization = success(
      await client.organization.getFullOrganization(),
      "organization.getFullOrganization",
    );
    assert.equal(fullOrganization.id, created.id);
    assert.deepEqual(fullOrganization.invitations, []);
    assert.equal(fullOrganization.teams.length, 1);
    assert.equal(
      success(await client.organization.getActiveMember(), "organization.getActiveMember").role,
      "owner",
    );
    assert.equal(
      success(await client.organization.getActiveMemberRole(), "organization.getActiveMemberRole").role,
      "owner",
    );
    assert.equal(
      success(
        await client.organization.hasPermission({ permissions: { organization: ["update"] } }),
        "organization.hasPermission",
      ).success,
      true,
    );
    const updated = success(
      await client.organization.update({
        organizationId: created.id,
        data: { name: "Updated Organization" },
      }),
      "organization.update",
    );
    assert.equal(updated.name, "Updated Organization");
    assert.equal(
      success(
        await client.organization.getOrganization({ query: { organizationId: created.id } }),
        "organization.getOrganization",
      ).id,
      created.id,
    );

    const initialTeams = success(
      await client.organization.listTeams({ query: { organizationId: created.id } }),
      "organization.listTeams",
    );
    assert.equal(initialTeams.length, 1);
    const team = success(
      await client.organization.createTeam({ name: "Platform", organizationId: created.id }),
      "organization.createTeam",
    );
    const renamedTeam = success(
      await client.organization.updateTeam({ teamId: team.id, data: { name: "Core Platform" } }),
      "organization.updateTeam",
    );
    assert.equal(renamedTeam.name, "Core Platform");
    success(await client.organization.setActiveTeam({ teamId: initialTeams[0].id }), "organization.setActiveTeam");
    assert.ok(
      success(await client.organization.listUserTeams(), "organization.listUserTeams")
        .some((candidate) => candidate.id === initialTeams[0].id),
    );
    assert.equal(
      success(
        await client.organization.listTeamMembers({ query: { teamId: initialTeams[0].id } }),
        "organization.listTeamMembers",
      ).length,
      1,
    );

    const role = success(
      await client.organization.createRole({
        organizationId: created.id,
        role: "editor",
        permission: { ac: ["read"], member: [] },
      }),
      "organization.createRole",
    ).roleData;
    assert.equal(role.role, "editor");
    assert.ok(
      success(await client.organization.listRoles({ query: { organizationId: created.id } }), "organization.listRoles")
        .some((candidate) => candidate.id === role.id),
    );
    assert.equal(
      success(
        await client.organization.getRole({ query: { organizationId: created.id, roleId: role.id } }),
        "organization.getRole",
      ).id,
      role.id,
    );
    const changedRole = success(
      await client.organization.updateRole({
        organizationId: created.id,
        roleId: role.id,
        data: { roleName: "publisher", permission: { ac: ["read"] } },
      }),
      "organization.updateRole",
    ).roleData;
    assert.equal(changedRole.role, "publisher");
    assert.equal(
      success(
        await client.organization.deleteRole({ organizationId: created.id, roleId: role.id }),
        "organization.deleteRole",
      ).success,
      true,
    );

    const invitation = success(
      await client.organization.inviteMember({
        email: "organization-member@example.com",
        role: "member",
        organizationId: created.id,
        teamId: initialTeams[0].id,
      }),
      "organization.inviteMember",
    );
    assert.ok(
      success(
        await client.organization.listInvitations({ query: { organizationId: created.id } }),
        "organization.listInvitations",
      ).some((candidate) => candidate.id === invitation.id),
    );
    const canceledInvitation = success(
      await client.organization.inviteMember({
        email: "cancel-invitation@example.com",
        role: "member",
        organizationId: created.id,
      }),
      "organization.inviteMember for cancellation",
    );
    assert.equal(
      success(
        await client.organization.cancelInvitation({ invitationId: canceledInvitation.id }),
        "organization.cancelInvitation",
      ).status,
      "canceled",
    );

    const organizationKey = success(
      await client.apiKey.create({
        configId: "organization",
        organizationId: created.id,
        name: "Organization key",
      }),
      "organization-owned apiKey.create",
    );
    assert.equal(organizationKey.referenceId, created.id);
    assert.ok(
      success(
        await client.apiKey.list({ query: { organizationId: created.id, configId: "organization" } }),
        "organization-owned apiKey.list",
      ).apiKeys.some((key) => key.id === organizationKey.id),
    );
    const verifiedOrganizationKey = await transport.fetch(
      `${origin}/api/auth/api-key/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ key: organizationKey.key, configId: "organization" }),
      },
    );
    assert.equal(verifiedOrganizationKey.status, 200);
    assert.equal((await verifiedOrganizationKey.json()).valid, true);
    success(await client.apiKey.delete({ keyId: organizationKey.id, configId: "organization" }), "organization-owned apiKey.delete");

    success(await client.signOut(), "signOut before invitation acceptance");
    const invitee = success(
      await client.signUp.email({
        name: "Organization Member",
        email: "organization-member@example.com",
        password: "correct horse battery staple",
      }),
      "signUp.email organization member",
    );
    assert.ok(invitee.user.id);
    success(
      await client.sendVerificationEmail({ email: "organization-member@example.com" }),
      "organization member sendVerificationEmail",
    );
    const memberVerification = await transport.fetch(
      `${origin}/__conformance__/verification-token/organization-member%40example.com`,
    );
    assert.equal(memberVerification.status, 200);
    success(
      await client.verifyEmail({ query: { token: (await memberVerification.json()).token } }),
      "organization member verifyEmail",
    );
    const userInvitations = success(
      await client.organization.listUserInvitations(),
      "organization.listUserInvitations",
    );
    assert.equal(
      userInvitations.find((candidate) => candidate.id === invitation.id).organizationName,
      "Updated Organization",
    );
    assert.equal(
      success(
        await client.organization.getInvitation({ query: { id: invitation.id } }),
        "organization.getInvitation",
      ).id,
      invitation.id,
    );
    const accepted = success(
      await client.organization.acceptInvitation({ invitationId: invitation.id }),
      "organization.acceptInvitation",
    );
    assert.equal(accepted.member.userId, invitee.user.id);
    success(await client.organization.setActive({ organizationId: created.id }), "organization.setActive invitee");
    assert.ok(
      success(await client.organization.listUserTeams(), "organization.listUserTeams invitee")
        .some((candidate) => candidate.id === initialTeams[0].id),
    );

    await transport.useFixtureSession("strong");
    success(await client.organization.setActive({ organizationId: created.id }), "organization.setActive owner");
    let members = success(
      await client.organization.listMembers({ query: { organizationId: created.id } }),
      "organization.listMembers",
    );
    assert.equal(members.total, 2);
    const filteredMembersResult = await client.organization.listMembers({
        query: {
          organizationId: created.id,
          filterField: "role",
          filterOperator: "eq",
          filterValue: "member",
          sortBy: "createdAt",
          sortDirection: "desc",
          limit: 1,
          offset: 0,
        },
      });
    const filteredMembers = success(
      filteredMembersResult,
      "organization.listMembers filtering",
    );
    assert.equal(filteredMembers.total, 1);
    assert.equal(filteredMembers.members[0].userId, invitee.user.id);
    const inviteeMember = members.members.find((member) => member.userId === invitee.user.id);
    assert.ok(inviteeMember);
    assert.equal(
      success(
        await client.organization.updateMemberRole({
          memberId: inviteeMember.id,
          organizationId: created.id,
          role: "admin",
        }),
        "organization.updateMemberRole",
      ).role,
      "admin",
    );
    assert.equal(
      success(
        await client.organization.removeTeamMember({
          teamId: initialTeams[0].id,
          userId: invitee.user.id,
          organizationId: created.id,
        }),
        "organization.removeTeamMember",
      ).message,
      "Team member removed successfully.",
    );
    assert.equal(
      success(
        await client.organization.addTeamMember({
          teamId: initialTeams[0].id,
          userId: invitee.user.id,
          organizationId: created.id,
        }),
        "organization.addTeamMember",
      ).userId,
      invitee.user.id,
    );
    assert.equal(
      success(
        await client.organization.removeMember({
          memberIdOrEmail: inviteeMember.id,
          organizationId: created.id,
        }),
        "organization.removeMember",
      ).member.userId,
      invitee.user.id,
    );
    const leaveInvitation = success(
      await client.organization.inviteMember({
        email: "organization-member@example.com",
        role: "member",
        organizationId: created.id,
      }),
      "organization.inviteMember before leave",
    );
    success(await client.signOut(), "signOut owner before member leave");
    success(
      await client.signIn.email({
        email: "organization-member@example.com",
        password: "correct horse battery staple",
      }),
      "signIn organization member",
    );
    success(
      await client.organization.acceptInvitation({ invitationId: leaveInvitation.id }),
      "organization.acceptInvitation before leave",
    );
    success(await client.organization.leave({ organizationId: created.id }), "organization.leave");

    await transport.useFixtureSession("strong");
    const rejectedInvitation = success(
      await client.organization.inviteMember({
        email: "organization-reject@example.com",
        role: "member",
        organizationId: created.id,
      }),
      "organization.inviteMember before rejection",
    );
    success(await client.signOut(), "signOut owner before rejection");
    success(
      await client.signUp.email({
        name: "Organization Rejection",
        email: "organization-reject@example.com",
        password: "correct horse battery staple",
      }),
      "signUp.email organization rejection",
    );
    assert.equal(
      success(
        await client.organization.rejectInvitation({ invitationId: rejectedInvitation.id }),
        "organization.rejectInvitation",
      ).invitation.status,
      "rejected",
    );

    await transport.useFixtureSession("strong");
    success(await client.organization.setActive({ organizationId: created.id }), "organization.setActive owner final");
    members = success(
      await client.organization.listMembers({ query: { organizationId: created.id } }),
      "organization.listMembers after leave",
    );
    assert.equal(members.total, 1);
    const clearedTeam = await client.organization.setActiveTeam({ teamId: null });
    assert.equal(clearedTeam.error, null, `organization.clearActiveTeam: ${JSON.stringify(clearedTeam.error)}`);
    assert.equal(clearedTeam.data, null);
    assert.equal(
      success(
        await client.organization.removeTeam({ teamId: team.id, organizationId: created.id }),
        "organization.removeTeam",
      ).message,
      "Team removed successfully.",
    );
    const deleted = success(
      await client.organization.delete({ organizationId: created.id }),
      "organization.delete",
    );
    assert.equal(deleted.id, created.id);
  });

  await runCase("anonymous and sign-out clients", async () => {
    success(await client.signOut(), "signOut");
    const anonymous = success(await client.signIn.anonymous(), "signIn.anonymous");
    assert.equal(anonymous.user.isAnonymous, true);
    assert.equal(anonymous.user.role, "user");
    transport.assertRequest("/api/auth/sign-in/anonymous", "POST", {});
    const repeated = await client.signIn.anonymous();
    assert.equal(
      repeated.error?.code,
      "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
    );
    const deleted = success(
      await client.deleteAnonymousUser(),
      "deleteAnonymousUser",
    );
    assert.equal(deleted.success, true);
    transport.assertRequest("/api/auth/delete-anonymous-user", "POST", {});

    success(await client.signIn.anonymous(), "signIn.anonymous for email upgrade");
    const upgraded = success(
      await client.signUp.email({
        name: "Anonymous Upgrade",
        email: "anonymous-upgrade@example.com",
        password: "correct horse battery staple",
      }),
      "signUp.email anonymous upgrade",
    );
    assert.equal(upgraded.user.isAnonymous, false);
    const permanentDelete = await client.deleteAnonymousUser();
    assert.equal(permanentDelete.error?.code, "USER_IS_NOT_ANONYMOUS");
    success(await client.signOut(), "signOut after anonymous email upgrade");
  });

  await runCase("core social OAuth client and callback", async () => {
    transport.clearCookies();
    const anonymous = success(
      await client.signIn.anonymous(),
      "signIn.anonymous for social upgrade",
    );
    const social = success(
      await client.signIn.social({
        provider: "conformance-oauth",
        callbackURL: "/oauth/existing",
        newUserCallbackURL: "/oauth/new",
        errorCallbackURL: `${origin}/oauth/error`,
        disableRedirect: true,
        additionalParams: { prompt: "consent" },
      }),
      "signIn.social",
    );
    assert.equal(social.redirect, false);
    const authorize = new URL(social.url);
    assert.equal(authorize.origin, "https://provider.conformance.invalid");
    assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
    assert.ok(authorize.searchParams.get("nonce"));
    const state = authorize.searchParams.get("state");
    assert.ok(state);
    transport.assertRequest("/api/auth/sign-in/social", "POST", {
      provider: "conformance-oauth",
      callbackURL: "/oauth/existing",
      newUserCallbackURL: "/oauth/new",
      errorCallbackURL: `${origin}/oauth/error`,
      disableRedirect: true,
      additionalParams: { prompt: "consent" },
    });
    const callback = await transport.fetch(
      `${origin}/api/auth/callback/conformance-oauth?code=official-client-code&state=${encodeURIComponent(state)}&iss=${encodeURIComponent("https://issuer.conformance.invalid")}`,
      { redirect: "manual" },
    );
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get("location"), "/oauth/new");
    const session = success(await client.getSession(), "getSession after social OAuth");
    assert.equal(session.user.email, "official-social@example.com");
    assert.notEqual(session.user.id, anonymous.user.id);
    assert.equal(session.user.image, "https://provider.conformance.invalid/avatar.png");
    const selectedAccount = await decodedAccountCookie(transport);
    assert.equal(selectedAccount.userId, session.user.id);
    assert.equal(selectedAccount.providerId, "conformance-oauth");
    assert.equal(selectedAccount.accountId, "official-client-subject");
    success(await client.signOut(), "signOut after social OAuth");
    assert.equal(
      chunkedCookie(transport.cookies, "better-auth.account_data"),
      "",
    );
  });

  await runCase("generic OAuth uses the ordinary social client and callback", async () => {
    transport.clearCookies();
    const social = success(
      await client.signIn.social({
        provider: "generic-conformance",
        callbackURL: "/generic-oauth/complete",
        disableRedirect: true,
        scopes: ["email"],
        additionalParams: { audience: "official-client" },
      }),
      "signIn.social generic OAuth",
    );
    assert.equal(social.redirect, false);
    const authorize = new URL(social.url);
    assert.equal(authorize.origin, "https://generic.conformance.invalid");
    assert.equal(authorize.searchParams.get("scope"), "email profile");
    assert.equal(authorize.searchParams.get("audience"), "official-client");
    assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
    const state = authorize.searchParams.get("state");
    assert.ok(state);
    transport.assertRequest("/api/auth/sign-in/social", "POST", {
      provider: "generic-conformance",
      callbackURL: "/generic-oauth/complete",
      disableRedirect: true,
      scopes: ["email"],
      additionalParams: { audience: "official-client" },
    });
    const callback = await transport.fetch(
      origin +
        "/api/auth/callback/generic-conformance?code=generic-official-code&state=" +
        encodeURIComponent(state),
      { redirect: "manual" },
    );
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get("location"), "/generic-oauth/complete");
    const session = success(
      await client.getSession(),
      "getSession after generic OAuth",
    );
    assert.equal(session.user.email, "generic-official@example.com");
    assert.equal(session.user.name, "Generic Official User");
    const selectedAccount = await decodedAccountCookie(transport);
    assert.equal(selectedAccount.providerId, "generic-conformance");
    assert.equal(selectedAccount.accountId, "generic-official-subject");
    success(await client.signOut(), "signOut after generic OAuth");
  });

  await runCase("linked account and provider token clients", async () => {
    await transport.useFixtureSession("strong");
    const linked = success(
      await client.linkSocial({
        provider: "conformance-oauth",
        idToken: {
          token: "official-link-id-token",
          nonce: "official-link-nonce",
          accessToken: "official-link-access-token",
          refreshToken: "official-link-refresh-token",
        },
        disableRedirect: true,
      }),
      "linkSocial",
    );
    assert.deepEqual(linked, { url: "", status: true, redirect: false });
    transport.assertRequest("/api/auth/link-social", "POST", {
      provider: "conformance-oauth",
      idToken: {
        token: "official-link-id-token",
        nonce: "official-link-nonce",
        accessToken: "official-link-access-token",
        refreshToken: "official-link-refresh-token",
      },
      disableRedirect: true,
    });

    const accounts = success(await client.listAccounts(), "listAccounts");
    const account = accounts.find(
      (candidate) => candidate.providerId === "conformance-oauth",
    );
    assert.ok(account);
    assert.deepEqual(account.scopes, []);
    assert.equal(account.issuer, "https://issuer.conformance.invalid");
    assert.equal(account.accountId, "official-linked-subject");
    const linkedCookie = await decodedAccountCookie(transport);
    assert.equal(linkedCookie.id, account.id);
    assert.equal(linkedCookie.userId, account.userId);
    assert.equal(linkedCookie.providerId, account.providerId);
    assert.equal(linkedCookie.accessToken, "official-link-access-token");

    const validCookies = new Map(transport.cookies);
    const accountCookieName = [...transport.cookies.keys()].find((name) =>
      name.startsWith("better-auth.account_data"),
    );
    const accountCookieValue = transport.cookies.get(accountCookieName);
    transport.cookies.set(
      accountCookieName,
      `${accountCookieValue.slice(0, -1)}${accountCookieValue.endsWith("A") ? "B" : "A"}`,
    );
    const tampered = await client.getAccessToken({ useAccountCookie: true });
    assert.equal(tampered.data, null);
    assert.equal(tampered.error?.status, 400);
    assert.equal(chunkedCookie(transport.cookies, "better-auth.account_data"), "");
    transport.cookies = validCookies;

    const cookieAccess = success(
      await client.getAccessToken({ useAccountCookie: true }),
      "getAccessToken account cookie",
    );
    assert.equal(cookieAccess.accessToken, "official-link-access-token");

    const cookieInfo = success(
      await client.accountInfo({ query: { useAccountCookie: true } }),
      "accountInfo account cookie",
    );
    assert.equal(cookieInfo.account.id, account.id);
    assert.equal(cookieInfo.data.fixture, "linked-account");

    const cookieRefreshed = success(
      await client.refreshToken({ useAccountCookie: true }),
      "refreshToken account cookie",
    );
    assert.equal(cookieRefreshed.accessToken, "official-refreshed-access-token");
    assert.equal((await decodedAccountCookie(transport)).id, account.id);

    const access = success(
      await client.getAccessToken({ accountId: account.id }),
      "getAccessToken",
    );
    assert.equal(access.accessToken, "official-refreshed-access-token");
    assert.equal(access.idToken, "official-link-id-token");

    const refreshed = success(
      await client.refreshToken({ accountId: account.id }),
      "refreshToken",
    );
    assert.equal(refreshed.accessToken, "official-refreshed-access-token");
    assert.equal(refreshed.refreshToken, "official-refreshed-refresh-token");
    assert.equal(refreshed.providerId, "conformance-oauth");
    assert.equal(refreshed.accountId, account.id);

    const info = success(
      await client.accountInfo({ query: { accountId: account.id } }),
      "accountInfo",
    );
    assert.equal(info.account.id, account.id);
    assert.equal(info.account.accountId, "official-linked-subject");
    assert.equal(info.user.email, "luna@example.com");
    assert.equal(info.data.fixture, "linked-account");

    const accountOnlyCookies = [...transport.cookies]
      .filter(([name]) => name.startsWith("better-auth.account_data"))
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
    const accountOnly = await fetch(`${origin}/api/auth/get-access-token`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: accountOnlyCookies,
        origin,
      },
      body: JSON.stringify({ useAccountCookie: true }),
    });
    assert.equal(accountOnly.status, 401, "account cookie must not act as a bearer credential");

    const unlinked = success(
      await client.unlinkAccount({ accountId: account.id }),
      "unlinkAccount",
    );
    assert.equal(unlinked.status, true);
    const remaining = success(await client.listAccounts(), "listAccounts after unlink");
    assert.ok(
      remaining.every((candidate) => candidate.id !== account.id),
      "unlinked account must no longer be listed",
    );

    success(
      await client.signUp.email({
        name: "Account Cookie Binding",
        email: "account-cookie-binding@example.com",
        password: "correct horse battery staple",
      }),
      "signUp.email clears a different user's account cookie",
    );
    assert.equal(chunkedCookie(transport.cookies, "better-auth.account_data"), "");
  });

  await runCase("current-user deletion client", async () => {
    success(
      await client.signUp.email({
        name: "Delete User",
        email: "delete-user@example.com",
        password: "correct horse battery staple",
      }),
      "signUp.email for deleteUser",
    );
    const deleted = success(
      await client.deleteUser({
        password: "correct horse battery staple",
        callbackURL: "/goodbye",
      }),
      "deleteUser",
    );
    assert.deepEqual(deleted, { success: true, message: "User deleted" });
    transport.assertRequest("/api/auth/delete-user", "POST", {
      password: "correct horse battery staple",
      callbackURL: "/goodbye",
    });
    const session = await client.getSession();
    assert.equal(session.data, null);
  });
}

async function nativeBearerConformance(origin) {
  const signUp = async (identity) => {
    const response = await fetch(`${origin}/api/auth/sign-up/email`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin,
      },
      body: JSON.stringify({
        name: `Native Bearer ${identity}`,
        email: `native-bearer-${identity}@example.com`,
        password: "correct horse battery staple",
      }),
    });
    assert.equal(response.status, 200);
    const body = await response.clone().json();
    const signedToken = response.headers.get("set-auth-token");
    assert.ok(signedToken, "native bearer plugin did not expose a session token");
    const cookie = responseCookiePair(response);
    assert.equal(
      signedToken,
      decodeURIComponent(cookie.slice(cookie.indexOf("=") + 1)),
    );
    const exposedHeaders = response.headers
      .get("access-control-expose-headers")
      .split(",")
      .map((header) => header.trim().toLowerCase());
    assert.ok(exposedHeaders.includes("set-auth-token"));
    return {
      cookie,
      email: body.user.email,
      opaqueToken: body.token,
      signedToken,
    };
  };
  const getSession = async ({ authorization, cookie } = {}) => {
    const headers = new Headers();
    if (authorization !== undefined) headers.set("authorization", authorization);
    if (cookie !== undefined) headers.set("cookie", cookie);
    const response = await fetch(`${origin}/api/auth/get-session`, { headers });
    assert.equal(response.status, 200);
    return response.json();
  };

  const first = await signUp("first");
  const second = await signUp("second");
  assert.equal(
    (await getSession({ authorization: `Bearer ${first.opaqueToken}` })).user.email,
    first.email,
  );
  assert.equal(
    (await getSession({ authorization: `bEaReR ${first.signedToken}` })).user.email,
    first.email,
  );
  assert.equal(
    (
      await getSession({
        authorization: `Bearer ${encodeURIComponent(first.signedToken)}`,
      })
    ).user.email,
    first.email,
  );
  assert.equal(
    (
      await getSession({
        authorization: `Bearer ${first.opaqueToken}.invalid-signature`,
        cookie: second.cookie,
      })
    ).user.email,
    second.email,
  );
  assert.equal(
    (
      await getSession({
        authorization: `Bearer ${first.signedToken}`,
        cookie: second.cookie,
      })
    ).user.email,
    first.email,
  );

  const requests = [];
  let authToken = first.signedToken;
  const client = createAuthClient({
    baseURL: origin,
    fetchOptions: {
      auth: { type: "Bearer", token: () => authToken },
      customFetchImpl: async (input, init = {}) => {
        const request = new Request(input, init);
        requests.push(request.clone());
        return fetch(request);
      },
    },
  });
  assert.equal(
    success(await client.getSession(), "native signed bearer getSession").user.email,
    first.email,
  );
  assert.equal(
    requests.at(-1).headers.get("authorization"),
    `Bearer ${first.signedToken}`,
  );
  authToken = first.opaqueToken;
  assert.equal(
    success(await client.getSession(), "native opaque bearer getSession").user.email,
    first.email,
  );
  assert.equal(
    requests.at(-1).headers.get("authorization"),
    `Bearer ${first.opaqueToken}`,
  );

  const signedOut = await fetch(`${origin}/api/auth/sign-out`, {
    method: "POST",
    headers: { authorization: `Bearer ${first.signedToken}` },
  });
  assert.equal(signedOut.status, 200);
  assert.equal(signedOut.headers.get("set-auth-token"), null);
  assert.equal(
    await getSession({ authorization: `Bearer ${first.signedToken}` }),
    null,
  );
  console.log("ok - Bearer official client against native server");
}

async function nativeJwtConformance(origin) {
  const transport = new BrowserTransport(origin);
  const unauthorized = await transport.fetch(`${origin}/api/auth/token`);
  assert.equal(unauthorized.status, 401);
  assert.deepEqual(await unauthorized.json(), {
    code: "UNAUTHORIZED",
    message: "Unauthorized",
  });
  assert.equal(unauthorized.headers.get("cache-control"), "no-store");
  assert.equal(unauthorized.headers.get("pragma"), "no-cache");

  const client = createAuthClient({
    baseURL: origin,
    fetchOptions: { customFetchImpl: transport.fetch.bind(transport) },
    plugins: [jwtClient()],
  });
  const signedUp = success(
    await client.signUp.email({
      name: "Native JWT User",
      email: "native-jwt@example.com",
      password: "correct horse battery staple",
    }),
    "native JWT signUp.email",
  );
  const issued = success(await client.token(), "native jwtClient.token");
  const tokenRequest = transport.requests.at(-1);
  assert.equal(tokenRequest.pathname, "/api/auth/token");
  assert.equal(tokenRequest.method, "GET");
  assert.equal(tokenRequest.responseHeaders.get("cache-control"), "no-store");
  assert.equal(tokenRequest.responseHeaders.get("pragma"), "no-cache");

  const header = decodeProtectedHeader(issued.token);
  const payload = decodeJwt(issued.token);
  assert.deepEqual(Object.keys(header), ["alg", "kid"]);
  assert.equal(header.alg, "EdDSA");
  assert.equal(typeof header.kid, "string");
  assert.ok(header.kid.length > 0);
  assert.equal(payload.sub, signedUp.user.id);
  assert.equal(payload.id, signedUp.user.id);
  assert.equal(payload.email, signedUp.user.email);
  assert.equal(payload.iss, origin);
  assert.equal(payload.aud, origin);
  assert.equal(payload.exp, payload.iat + 900);

  const keySet = success(await client.jwks(), "native jwtClient.jwks");
  const jwksRequest = transport.requests.at(-1);
  assert.equal(jwksRequest.pathname, "/api/auth/jwks");
  assert.equal(jwksRequest.method, "GET");
  assert.equal(keySet.keys.length, 1);
  const publicKey = keySet.keys[0];
  assert.equal(publicKey.kid, header.kid);
  assert.equal(publicKey.alg, "EdDSA");
  assert.equal(publicKey.crv, "Ed25519");
  assert.equal(publicKey.kty, "OKP");
  assert.equal("privateKey" in publicKey, false);
  assert.equal("d" in publicKey, false);
  const imported = await importJWK(publicKey, "EdDSA");
  const verified = await jwtVerify(issued.token, imported, {
    issuer: origin,
    audience: origin,
  });
  assert.equal(verified.payload.sub, signedUp.user.id);

  success(await client.getSession(), "native JWT getSession");
  const sessionRequest = transport.requests.at(-1);
  assert.equal(sessionRequest.pathname, "/api/auth/get-session");
  const sessionToken = sessionRequest.responseHeaders.get("set-auth-jwt");
  assert.ok(sessionToken);
  assert.equal(decodeProtectedHeader(sessionToken).kid, header.kid);
  assert.equal(decodeJwt(sessionToken).sub, signedUp.user.id);
  assert.equal(
    sessionRequest.responseHeaders.get("access-control-expose-headers"),
    "set-auth-jwt",
  );

  for (const path of ["/sign-jwt", "/verify-jwt"]) {
    const response = await transport.fetch(`${origin}/api/auth${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(response.status, 404);
    assert.equal(await response.text(), "");
  }
  console.log("ok - JWT official client and JOSE against native server");
}

async function nativeOneTimeTokenConformance(origin) {
  const transport = new BrowserTransport(origin);
  const unauthorized = await transport.fetch(
    `${origin}/api/auth/one-time-token/generate`,
  );
  assert.equal(unauthorized.status, 401);
  assert.deepEqual(await unauthorized.json(), {
    code: "UNAUTHORIZED",
    message: "Unauthorized",
  });

  const client = createAuthClient({
    baseURL: origin,
    fetchOptions: { customFetchImpl: transport.fetch.bind(transport) },
    plugins: [oneTimeTokenClient()],
  });
  const signedUp = success(
    await client.signUp.email({
      name: "Native One-Time Token User",
      email: "native-one-time-token@example.com",
      password: "correct horse battery staple",
    }),
    "native oneTimeToken signUp.email",
  );
  const signupRequest = transport.requests.at(-1);
  const headerToken = signupRequest.responseHeaders.get("set-ott");
  assert.match(headerToken, /^[A-Za-z0-9_-]{32}$/);
  const exposedHeaders = signupRequest.responseHeaders
    .get("access-control-expose-headers")
    .split(",")
    .map((header) => header.trim().toLowerCase());
  assert.ok(exposedHeaders.includes("set-ott"));

  const generated = success(
    await client.oneTimeToken.generate(),
    "native oneTimeToken.generate",
  );
  assert.match(generated.token, /^[A-Za-z0-9_-]{32}$/);
  transport.assertRequest("/api/auth/one-time-token/generate", "GET");

  const handoffTransport = new BrowserTransport(origin);
  const handoffClient = createAuthClient({
    baseURL: origin,
    fetchOptions: {
      customFetchImpl: handoffTransport.fetch.bind(handoffTransport),
    },
    plugins: [oneTimeTokenClient()],
  });
  const verified = success(
    await handoffClient.oneTimeToken.verify({ token: generated.token }),
    "native oneTimeToken.verify",
  );
  assert.equal(verified.user.id, signedUp.user.id);
  assert.equal(verified.session.token, signedUp.token);
  const verifyRequest = handoffTransport.assertRequest(
    "/api/auth/one-time-token/verify",
    "POST",
    { token: generated.token },
  );
  assert.ok(
    verifyRequest.responseHeaders
      .getSetCookie()
      .some((cookie) => cookie.startsWith("better-auth.session_token=")),
    "one-time-token verification did not bind a session cookie",
  );
  assert.equal(
    success(await handoffClient.getSession(), "one-time-token handoff session").user.id,
    signedUp.user.id,
  );

  const replay = await handoffClient.oneTimeToken.verify({ token: generated.token });
  assert.equal(replay.data, null);
  assert.equal(replay.error?.status, 400);
  assert.equal(replay.error?.message, "Invalid token");

  const headerTransport = new BrowserTransport(origin);
  const headerClient = createAuthClient({
    baseURL: origin,
    fetchOptions: { customFetchImpl: headerTransport.fetch.bind(headerTransport) },
    plugins: [oneTimeTokenClient()],
  });
  const headerVerified = success(
    await headerClient.oneTimeToken.verify({ token: headerToken }),
    "native set-ott token verify",
  );
  assert.equal(headerVerified.user.id, signedUp.user.id);
  console.log("ok - one-time-token official client against native server");
}

async function cookieCacheConformance(origin, strategy) {
  const transport = new BrowserTransport(origin);
  const client = createAuthClient({
    baseURL: origin,
    fetchOptions: { customFetchImpl: transport.fetch.bind(transport) },
  });
  const email = `cookie-cache-${strategy}@example.com`;
  success(
    await client.signUp.email({
      name: "Cookie Cache User",
      email,
      password: "correct horse battery staple",
    }),
    `cookieCache.${strategy}.signUp`,
  );
  assert.equal(
    transport.cookies.has("better-auth.session_data"),
    true,
    `${strategy} session_data cookie was not set`,
  );
  const headers = new Headers({
    cookie: [...transport.cookies]
      .map(([name, value]) => `${name}=${value}`)
      .join("; "),
  });
  const decoded = await getCookieCache(headers, {
    strategy,
    secret: "R".repeat(32),
    isSecure: false,
  });
  assert.equal(decoded?.user.email, email);
  assert.equal(
    decoded?.session.token,
    transport.cookies.get("better-auth.session_token")?.split(".")[0],
  );
  console.log(`ok - Better Auth ${strategy} cookie-cache decoder`);
}

async function deferredSessionConformance(origin) {
  const transport = new BrowserTransport(origin);
  const client = createAuthClient({
    baseURL: origin,
    fetchOptions: { customFetchImpl: transport.fetch.bind(transport) },
  });
  success(
    await client.signUp.email({
      name: "Deferred Session User",
      email: "deferred-session@example.com",
      password: "correct horse battery staple",
    }),
    "deferredSession.signUp",
  );
  const pending = success(
    await client.$fetch("/get-session", { method: "GET" }),
    "deferredSession.get",
  );
  assert.equal(pending.needsRefresh, true);
  const refreshed = success(
    await client.$fetch("/get-session", { method: "POST" }),
    "deferredSession.post",
  );
  assert.equal("needsRefresh" in refreshed, false);
  assert.ok(new Date(refreshed.session.expiresAt) > new Date(pending.session.expiresAt));
  console.log("ok - Better Auth deferred session GET/POST contract");
}

async function startServer(strategy, deferred = false) {
  const child = spawn(
    "cargo",
    [
      "run",
      "--quiet",
      "--manifest-path",
      "conformance/server/Cargo.toml",
    ],
    {
      cwd: repository,
      env: {
        ...process.env,
        LUCID_AUTH_COOKIE_CACHE_STRATEGY: strategy,
        ...(deferred ? { LUCID_AUTH_DEFER_SESSION_REFRESH: "1" } : {}),
      },
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  child.stderr.on("data", (chunk) => {
    output += chunk;
  });
  const origin = await new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`server startup timed out\n${output}`)),
      120_000,
    );
    child.stdout.on("data", (chunk) => {
      output += chunk;
      const match = output.match(/LUCID_AUTH_CONFORMANCE_URL=(http:\/\/[^\s]+)/);
      if (match) {
        clearTimeout(timeout);
        resolve(match[1]);
      }
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`server exited with ${code}\n${output}`));
    });
  });
  return { child, origin };
}

function stopServer(child) {
  if (child.exitCode !== null) return;
  if (process.platform === "win32") child.kill("SIGTERM");
  else process.kill(-child.pid, "SIGTERM");
}

await siweClientConformance();
await lastLoginMethodClientConformance();
await bearerConformance();
await jwtConformance();
await oneTimeTokenConformance();
await oauthPopupConformance();
await oauthProxyConformance();
await oauthProviderConformance();

for (const strategy of ["compact", "jwt", "jwe"]) {
  const { child, origin } = await startServer(strategy);
  try {
    if (strategy === "compact") {
      await conformance(origin);
      await nativeBearerConformance(origin);
      await nativeJwtConformance(origin);
      await nativeOneTimeTokenConformance(origin);
      const oauthProviderTransport = new BrowserTransport(origin);
      await oauthProviderNativeConformance(
        origin,
        oauthProviderTransport.fetch.bind(oauthProviderTransport),
      );
    }
    await cookieCacheConformance(origin, strategy);
  } finally {
    stopServer(child);
  }
}


{
  const { child, origin } = await startServer("compact", true);
  try {
    await deferredSessionConformance(origin);
  } finally {
    stopServer(child);
  }
}
