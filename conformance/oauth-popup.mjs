import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { betterAuth } from "better-auth";
import {
  OAUTH_POPUP_COMPLETE_SCRIPT,
  OAUTH_POPUP_DATA_ELEMENT_ID,
  OAUTH_POPUP_ERROR_CODES,
  OAUTH_POPUP_MESSAGE_TYPE,
  OAUTH_POPUP_SCRIPT_CSP_HASH,
  POPUP_MARKER_COOKIE,
  oauthPopup,
} from "better-auth/plugins";
import {
  POPUP_TOKEN_STORAGE_KEY,
  createSignInPopup,
  oauthPopupClient,
  popupBearerFetchPlugin,
} from "better-auth/client/plugins";

const authOrigin = "https://auth.example.test";
const appOrigin = "https://app.example.test";
const authBaseURL = `${authOrigin}/api/auth`;
const secret = "R".repeat(32);

function popupPayload(html) {
  const escapedId = OAUTH_POPUP_DATA_ELEMENT_ID.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&",
  );
  const match = html.match(
    new RegExp(
      `<script type="application/json" id="${escapedId}">([^<]*)<\\/script>`,
    ),
  );
  assert.ok(match, "OAuth popup completion payload is missing");
  return JSON.parse(match[1]);
}

function cookieRequestHeader(response) {
  return response.headers
    .getSetCookie()
    .map((cookie) => cookie.split(";", 1)[0])
    .join("; ");
}

function cookieValue(setCookies, name) {
  const prefix = `${name}=`;
  const raw = setCookies.find((cookie) => cookie.startsWith(prefix));
  if (!raw) return undefined;
  return decodeURIComponent(raw.slice(prefix.length).split(";", 1)[0]);
}

function createStorage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem(key) {
      return values.get(key) ?? null;
    },
    removeItem(key) {
      values.delete(key);
    },
    setItem(key, value) {
      values.set(key, String(value));
    },
  };
}

function createWindowFixture({ embedded = false, localStorage, open }) {
  const listeners = new Map();
  const win = {
    addEventListener(type, listener) {
      const current = listeners.get(type) ?? new Set();
      current.add(listener);
      listeners.set(type, current);
    },
    localStorage: localStorage ?? createStorage(),
    location: { href: `${appOrigin}/login`, origin: appOrigin },
    open,
    outerHeight: 900,
    outerWidth: 1200,
    removeEventListener(type, listener) {
      listeners.get(type)?.delete(listener);
    },
    screenX: 100,
    screenY: 50,
  };
  win.self = win;
  if (embedded) {
    win.top = Object.defineProperty({}, "location", {
      configurable: true,
      get() {
        throw new Error("cross-origin frame");
      },
    });
  } else {
    win.top = win;
  }
  return {
    dispatchMessage(event) {
      for (const listener of listeners.get("message") ?? []) listener(event);
    },
    window: win,
  };
}

async function withWindow(fixture, callback) {
  const previousWindow = globalThis.window;
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: fixture.window,
  });
  try {
    return await callback();
  } finally {
    if (previousWindow === undefined) delete globalThis.window;
    else globalThis.window = previousWindow;
  }
}

async function serverConformance() {
  const auth = betterAuth({
    baseURL: authBaseURL,
    secret,
    trustedOrigins: [appOrigin],
    logger: { disabled: true },
    socialProviders: {
      github: {
        clientId: "popup-client",
        clientSecret: "popup-secret",
        getUserInfo: async () => ({
          user: {
            name: "Popup User",
            email: "popup@example.com",
            emailVerified: true,
          },
          data: { id: "popup-subject" },
        }),
      },
    },
    plugins: [oauthPopup()],
  });

  const request = (query) =>
    auth.handler(
      new Request(`${authBaseURL}/oauth-popup/start?${query}`, {
        redirect: "manual",
      }),
    );

  const missingProvider = await request(
    new URLSearchParams({ popupOrigin: appOrigin }),
  );
  assert.equal(missingProvider.status, 400);
  assert.deepEqual(await missingProvider.json(), {
    code: "VALIDATION_ERROR",
    message: "[query.provider] Invalid input: expected string, received undefined",
  });

  const invalidOrigin = await request(
    new URLSearchParams({
      provider: "github",
      popupOrigin: "https://evil.example.test",
    }),
  );
  assert.equal(invalidOrigin.status, 403);
  assert.deepEqual(await invalidOrigin.json(), {
    message: "Invalid origin",
    code: "INVALID_ORIGIN",
  });

  const invalidRedirect = await request(
    new URLSearchParams({
      provider: "github",
      popupOrigin: appOrigin,
      popupNonce: "redirect-nonce",
      callbackURL: "https://evil.example.test/callback",
      errorCallbackURL: "https://also-evil.example.test/error",
    }),
  );
  assert.equal(invalidRedirect.status, 200);
  assert.deepEqual(popupPayload(await invalidRedirect.text()), {
    type: OAUTH_POPUP_MESSAGE_TYPE,
    targetOrigin: appOrigin,
    nonce: "redirect-nonce",
    error: {
      code: "invalid_callback_url",
      description: "Untrusted URL: https://evil.example.test/callback",
    },
  });
  assert.equal(
    invalidRedirect.headers.get("content-security-policy"),
    `default-src 'none'; script-src '${OAUTH_POPUP_SCRIPT_CSP_HASH}'; base-uri 'none'`,
  );
  assert.equal(invalidRedirect.headers.get("cache-control"), "no-store");
  assert.equal(invalidRedirect.headers.get("pragma"), "no-cache");

  const providerNotFound = await request(
    new URLSearchParams({
      provider: "missing",
      popupOrigin: appOrigin,
      popupNonce: "provider-nonce",
    }),
  );
  assert.equal(providerNotFound.status, 200);
  assert.deepEqual(popupPayload(await providerNotFound.text()).error, {
    code: "provider_not_found",
    description: "Unknown provider: missing",
  });

  const nonce = "popup<\u2028nonce";
  const started = await request(
    new URLSearchParams({
      provider: "github",
      popupOrigin: appOrigin,
      popupNonce: nonce,
      callbackURL: "/popup-complete",
      scopes: "first,, third",
      requestSignUp: "true",
      additionalData: JSON.stringify({ provider: "forwarded-provider" }),
    }),
  );
  assert.equal(started.status, 302);
  const authorizationURL = new URL(started.headers.get("location"));
  assert.equal(authorizationURL.origin, "https://github.com");
  assert.equal(authorizationURL.pathname, "/login/oauth/authorize");
  assert.equal(authorizationURL.searchParams.get("client_id"), "popup-client");
  assert.equal(
    authorizationURL.searchParams.get("redirect_uri"),
    `${authBaseURL}/callback/github`,
  );
  assert.equal(
    authorizationURL.searchParams.get("scope"),
    "read:user user:email first   third",
  );
  const state = authorizationURL.searchParams.get("state");
  assert.equal(state.length, 32);

  const startCookies = started.headers.getSetCookie();
  assert.equal(startCookies.length, 2);
  assert.match(startCookies[0], /^__Secure-better-auth\.oauth_state=/);
  assert.match(startCookies[0], /; Max-Age=600; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
  assert.match(startCookies[1], /^__Secure-better-auth\.oauth_popup=/);
  assert.match(startCookies[1], /; Max-Age=600; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
  const signedMarker = cookieValue(
    startCookies,
    "__Secure-better-auth.oauth_popup",
  );
  assert.deepEqual(
    JSON.parse(signedMarker.slice(0, signedMarker.lastIndexOf("."))),
    { popupOrigin: appOrigin, popupNonce: nonce },
  );

  const previousFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    assert.equal(String(input), "https://github.com/login/oauth/access_token");
    assert.equal(init.method, "POST");
    assert.equal(init.body.get("code"), "popup-code");
    return Response.json({
      access_token: "popup-access-token",
      token_type: "bearer",
      scope: "read:user,user:email",
    });
  };
  let callback;
  try {
    callback = await auth.handler(
      new Request(
        `${authBaseURL}/callback/github?code=popup-code&state=${state}`,
        {
          headers: { cookie: cookieRequestHeader(started) },
          redirect: "manual",
        },
      ),
    );
  } finally {
    globalThis.fetch = previousFetch;
  }

  assert.equal(callback.status, 200);
  assert.equal(callback.headers.get("content-type"), "text/html; charset=utf-8");
  assert.equal(callback.headers.get("location"), "/popup-complete");
  const callbackCookies = callback.headers.getSetCookie();
  const sessionToken = cookieValue(
    callbackCookies,
    "__Secure-better-auth.session_token",
  );
  assert.ok(sessionToken);
  assert.match(
    callbackCookies.at(-1),
    /^__Secure-better-auth\.oauth_popup=; Max-Age=0;/,
  );
  const completionHTML = await callback.text();
  assert.match(completionHTML, /popup\\u003c\\u2028nonce/);
  assert.deepEqual(popupPayload(completionHTML), {
    type: OAUTH_POPUP_MESSAGE_TYPE,
    targetOrigin: appOrigin,
    nonce,
    token: sessionToken,
    redirectTo: "/popup-complete",
  });

  const deniedStart = await request(
    new URLSearchParams({
      provider: "github",
      popupOrigin: appOrigin,
      popupNonce: "denied-nonce",
      errorCallbackURL: "/popup-error",
    }),
  );
  const deniedState = new URL(deniedStart.headers.get("location")).searchParams.get(
    "state",
  );
  const denied = await auth.handler(
    new Request(
      `${authBaseURL}/callback/github?error=access_denied&error_description=Nope&state=${deniedState}`,
      {
        headers: { cookie: cookieRequestHeader(deniedStart) },
        redirect: "manual",
      },
    ),
  );
  assert.equal(denied.status, 200);
  assert.equal(denied.headers.get("location"), "/popup-error?error=access_denied&error_description=Nope");
  assert.deepEqual(popupPayload(await denied.text()), {
    type: OAUTH_POPUP_MESSAGE_TYPE,
    targetOrigin: appOrigin,
    nonce: "denied-nonce",
    error: { code: "access_denied", description: "Nope" },
  });
}

async function clientConformance() {
  const serverSide = createSignInPopup({
    $fetch: async () => assert.fail("SSR popup must not fetch"),
    options: { baseURL: authBaseURL },
    notifySessionSignal: () => assert.fail("SSR popup must not notify"),
  });
  assert.deepEqual(await serverSide({ provider: "github" }), {
    data: null,
    error: {
      code: "POPUP_SIGN_IN_FAILED",
      message: "POPUP_SIGN_IN_FAILED",
    },
  });

  let opened;
  let notified = 0;
  const storage = createStorage({ [POPUP_TOKEN_STORAGE_KEY]: "stale-token" });
  const popup = {
    closed: false,
    close() {
      this.closed = true;
    },
    focus() {
      this.focused = true;
    },
  };
  const fixture = createWindowFixture({
    localStorage: storage,
    open(url, name, features) {
      opened = { url: new URL(url), name, features };
      return popup;
    },
  });
  await withWindow(fixture, async () => {
    const signInPopup = createSignInPopup({
      $fetch: async (path) => {
        assert.equal(path, "/get-session");
        return { data: { session: { id: "popup-session" } }, error: null };
      },
      options: { baseURL: `${authBaseURL}/` },
      notifySessionSignal: () => {
        notified += 1;
      },
    });
    const pending = signInPopup({
      provider: "github",
      callbackURL: "/done",
      errorCallbackURL: "/error",
      newUserCallbackURL: "/welcome",
      scopes: ["openid", "profile"],
      requestSignUp: true,
      additionalData: { invitation: "invite-1" },
    });
    assert.equal(opened.name, "better-auth-oauth");
    assert.equal(
      opened.features,
      "width=500,height=600,left=450,top=200,menubar=no,toolbar=no",
    );
    assert.equal(opened.url.origin, authOrigin);
    assert.equal(opened.url.pathname, "/api/auth/oauth-popup/start");
    assert.equal(opened.url.searchParams.get("provider"), "github");
    assert.equal(opened.url.searchParams.get("popupOrigin"), appOrigin);
    assert.match(opened.url.searchParams.get("popupNonce"), /^[0-9a-f]{32}$/);
    assert.equal(opened.url.searchParams.get("callbackURL"), "/done");
    assert.equal(opened.url.searchParams.get("errorCallbackURL"), "/error");
    assert.equal(opened.url.searchParams.get("newUserCallbackURL"), "/welcome");
    assert.equal(opened.url.searchParams.get("scopes"), "openid,profile");
    assert.equal(opened.url.searchParams.get("requestSignUp"), "true");
    assert.equal(
      opened.url.searchParams.get("additionalData"),
      '{"invitation":"invite-1"}',
    );
    const nonce = opened.url.searchParams.get("popupNonce");
    fixture.dispatchMessage({
      origin: "https://evil.example.test",
      data: { type: OAUTH_POPUP_MESSAGE_TYPE, nonce, token: "wrong-origin" },
    });
    fixture.dispatchMessage({
      origin: authOrigin,
      data: { type: "wrong-type", nonce, token: "wrong-type" },
    });
    fixture.dispatchMessage({
      origin: authOrigin,
      data: { type: OAUTH_POPUP_MESSAGE_TYPE, nonce: "wrong", token: "wrong" },
    });
    fixture.dispatchMessage({
      origin: authOrigin,
      source: { deliberately: "not-the-popup" },
      data: { type: OAUTH_POPUP_MESSAGE_TYPE, nonce, token: "popup-token" },
    });
    assert.deepEqual(await pending, { data: { success: true }, error: null });
    assert.equal(storage.getItem(POPUP_TOKEN_STORAGE_KEY), null);
    assert.equal(popup.closed, true);
    assert.equal(notified, 1);
  });

  let blockedURL;
  const blockedStorage = createStorage({
    [POPUP_TOKEN_STORAGE_KEY]: "preserved-token",
  });
  const blockedFixture = createWindowFixture({
    localStorage: blockedStorage,
    open(url) {
      blockedURL = new URL(url);
      return null;
    },
  });
  await withWindow(blockedFixture, async () => {
    const blocked = createSignInPopup({
      $fetch: async () => assert.fail("blocked popup must not fetch"),
      options: { baseURL: authBaseURL },
      notifySessionSignal: () => assert.fail("blocked popup must not notify"),
    });
    assert.deepEqual(await blocked({ provider: "", providerId: "github" }), {
      data: null,
      error: {
        code: "POPUP_BLOCKED",
        message: "POPUP_BLOCKED",
      },
    });
    assert.equal(blockedURL.searchParams.get("provider"), "");
    assert.equal(
      blockedStorage.getItem(POPUP_TOKEN_STORAGE_KEY),
      "preserved-token",
    );
  });

  let activeURL;
  const activePopup = {
    closed: false,
    close() {
      this.closed = true;
    },
    focus() {
      this.focused = true;
    },
  };
  const activeFixture = createWindowFixture({
    open(url) {
      activeURL = new URL(url);
      return activePopup;
    },
  });
  await withWindow(activeFixture, async () => {
    const signInPopup = createSignInPopup({
      $fetch: async () => ({ data: { session: {} }, error: null }),
      options: { baseURL: authBaseURL },
      notifySessionSignal() {},
    });
    const first = signInPopup({ provider: "github" });
    assert.deepEqual(await signInPopup({ provider: "google" }), {
      data: null,
      error: {
        code: "POPUP_SIGN_IN_FAILED",
        message: "POPUP_SIGN_IN_FAILED",
      },
    });
    assert.equal(activePopup.focused, true);
    activeFixture.dispatchMessage({
      origin: authOrigin,
      data: {
        type: OAUTH_POPUP_MESSAGE_TYPE,
        nonce: activeURL.searchParams.get("popupNonce"),
        token: "active-token",
      },
    });
    assert.deepEqual(await first, { data: { success: true }, error: null });
  });

  let errorURL;
  const errorPopup = {
    closed: false,
    close() {
      this.closed = true;
    },
  };
  const errorFixture = createWindowFixture({
    open(url) {
      errorURL = new URL(url);
      return errorPopup;
    },
  });
  await withWindow(errorFixture, async () => {
    const signInPopup = createSignInPopup({
      $fetch: async () => assert.fail("relayed error must not fetch"),
      options: { baseURL: authBaseURL },
      notifySessionSignal: () => assert.fail("relayed error must not notify"),
    });
    const pending = signInPopup({ provider: "github" });
    errorFixture.dispatchMessage({
      origin: authOrigin,
      data: {
        type: OAUTH_POPUP_MESSAGE_TYPE,
        nonce: errorURL.searchParams.get("popupNonce"),
        error: { code: "access_denied", description: "User said no" },
      },
    });
    assert.deepEqual(await pending, {
      data: null,
      error: { code: "access_denied", message: "User said no" },
    });
  });

  const embeddedStorage = createStorage({
    [POPUP_TOKEN_STORAGE_KEY]: "previous-embedded-token",
  });
  let embeddedURL;
  const embeddedPopup = {
    closed: false,
    close() {
      this.closed = true;
    },
  };
  const embeddedFixture = createWindowFixture({
    embedded: true,
    localStorage: embeddedStorage,
    open(url) {
      embeddedURL = new URL(url);
      return embeddedPopup;
    },
  });
  await withWindow(embeddedFixture, async () => {
    const signInPopup = createSignInPopup({
      $fetch: async (path) => {
        assert.equal(path, "/get-session");
        return { data: null, error: { status: 401 } };
      },
      options: { baseURL: authBaseURL },
      notifySessionSignal: () => assert.fail("failed session must not notify"),
    });
    const pending = signInPopup({ provider: "github" });
    embeddedFixture.dispatchMessage({
      origin: authOrigin,
      data: {
        type: OAUTH_POPUP_MESSAGE_TYPE,
        nonce: embeddedURL.searchParams.get("popupNonce"),
        token: "embedded-token",
      },
    });
    assert.deepEqual(await pending, {
      data: null,
      error: {
        code: "POPUP_SIGN_IN_FAILED",
        message: "POPUP_SIGN_IN_FAILED",
        status: 401,
      },
    });
    assert.equal(
      embeddedStorage.getItem(POPUP_TOKEN_STORAGE_KEY),
      "embedded-token",
    );

    const context = {
      headers: new Headers(),
      request: { url: `${authBaseURL}/get-session` },
    };
    const authenticated = popupBearerFetchPlugin.hooks.onRequest(context);
    assert.equal(
      authenticated.headers.get("authorization"),
      "Bearer embedded-token",
    );

    const explicit = popupBearerFetchPlugin.hooks.onRequest({
      ...context,
      headers: new Headers({ authorization: "Basic explicit" }),
    });
    assert.equal(explicit.headers.get("authorization"), "Basic explicit");

    popupBearerFetchPlugin.hooks.onSuccess({
      request: { url: `${authBaseURL}/nested/sign-out` },
    });
    assert.equal(embeddedStorage.getItem(POPUP_TOKEN_STORAGE_KEY), null);
  });
}

export async function oauthPopupConformance() {
  const serverPlugin = oauthPopup();
  assert.equal(serverPlugin.id, "oauth-popup");
  assert.equal(serverPlugin.version, "1.7.1");
  assert.deepEqual(Object.keys(serverPlugin.endpoints), ["oauthPopupStart"]);
  assert.equal(serverPlugin.endpoints.oauthPopupStart.path, "/oauth-popup/start");
  assert.deepEqual(serverPlugin.$ERROR_CODES, OAUTH_POPUP_ERROR_CODES);

  const clientPlugin = oauthPopupClient();
  assert.equal(clientPlugin.id, "oauth-popup");
  assert.equal(clientPlugin.version, "1.7.1");
  assert.deepEqual(clientPlugin.$ERROR_CODES, OAUTH_POPUP_ERROR_CODES);
  assert.equal(clientPlugin.fetchPlugins[0].id, "better-auth-popup-bearer");
  assert.equal(clientPlugin.fetchPlugins[0].name, "Popup Bearer");

  assert.equal(OAUTH_POPUP_MESSAGE_TYPE, "better-auth:oauth-popup");
  assert.equal(OAUTH_POPUP_DATA_ELEMENT_ID, "better-auth-oauth-popup");
  assert.equal(POPUP_MARKER_COOKIE, "oauth_popup");
  assert.equal(POPUP_TOKEN_STORAGE_KEY, "better-auth.popup_token");
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(OAUTH_POPUP_ERROR_CODES).map(([name, value]) => [
        name,
        { code: value.code, message: value.message, string: String(value) },
      ]),
    ),
    {
      POPUP_SIGN_IN_FAILED: {
        code: "POPUP_SIGN_IN_FAILED",
        message: "Popup sign-in failed",
        string: "POPUP_SIGN_IN_FAILED",
      },
      POPUP_BLOCKED: {
        code: "POPUP_BLOCKED",
        message: "Sign-in popup was blocked by the browser",
        string: "POPUP_BLOCKED",
      },
      POPUP_CLOSED: {
        code: "POPUP_CLOSED",
        message: "Sign-in popup was closed before completing",
        string: "POPUP_CLOSED",
      },
      POPUP_TIMEOUT: {
        code: "POPUP_TIMEOUT",
        message: "Sign-in popup timed out",
        string: "POPUP_TIMEOUT",
      },
    },
  );
  assert.equal(
    `sha256-${createHash("sha256").update(OAUTH_POPUP_COMPLETE_SCRIPT).digest("base64")}`,
    OAUTH_POPUP_SCRIPT_CSP_HASH,
  );
  assert.equal(
    OAUTH_POPUP_SCRIPT_CSP_HASH,
    "sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ=",
  );

  await serverConformance();
  await clientConformance();
  console.log("ok - OAuth Popup official server and client contract");
}
