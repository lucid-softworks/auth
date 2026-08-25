import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import * as clientPlugins from "better-auth/client/plugins";
import { captcha } from "better-auth/plugins";

const authOrigin = "https://captcha.example.test";
const authBaseURL = `${authOrigin}/api/auth`;
const secret = "C".repeat(32);

const errors = {
  missing: {
    status: 400,
    body: '{"message":"Missing CAPTCHA response","code":"MISSING_RESPONSE"}',
  },
  rejected: {
    status: 403,
    body: '{"message":"Captcha verification failed","code":"VERIFICATION_FAILED"}',
  },
  unknown: {
    status: 500,
    body: '{"message":"Something went wrong","code":"UNKNOWN_ERROR"}',
  },
};

function context(options = {}) {
  const logs = [];
  return {
    ctx: {
      options: {
        basePath: "/api/auth",
        ...options,
      },
      logger: {
        error(...args) {
          logs.push(args);
        },
      },
    },
    logs,
  };
}

async function invoke(plugin, path, init = {}, contextOptions = {}) {
  const { ctx, logs } = context(contextOptions);
  const result = await plugin.onRequest(
    new Request(`${authOrigin}${path}`, init),
    ctx,
  );
  return { result, response: result?.response, logs };
}

async function assertMiddlewareResponse(response, expected) {
  assert.ok(response, "captcha middleware did not return a response");
  assert.equal(response.status, expected.status);
  assert.equal(response.headers.get("content-type"), "text/plain;charset=UTF-8");
  assert.equal(await response.text(), expected.body);
}

async function startVerifier() {
  const requests = [];
  const sockets = new Set();
  let reply = {
    body: JSON.stringify({ success: true }),
    headers: { "content-type": "application/json" },
    status: 200,
  };
  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      requests.push({
        body: Buffer.concat(chunks).toString("utf8"),
        headers: request.headers,
        method: request.method,
        url: request.url,
      });
      response.setHeader("connection", "close");
      response.writeHead(reply.status, reply.headers);
      response.end(reply.body);
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return {
    requests,
    setReply(next) {
      reply = {
        body: next.body ?? "",
        headers: next.headers ?? { "content-type": "application/json" },
        status: next.status ?? 200,
      };
    },
    url: `http://127.0.0.1:${address.port}/verify`,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      });
    },
  };
}

function pluginMetadataConformance() {
  const options = {
    provider: "google-recaptcha",
    secretKey: "metadata-secret",
  };
  const plugin = captcha(options);
  assert.equal(plugin.id, "captcha");
  assert.equal(plugin.version, "1.7.1");
  assert.equal(plugin.options, options);
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(plugin.$ERROR_CODES).map(([name, value]) => [
        name,
        { code: value.code, message: value.message },
      ]),
    ),
    {
    MISSING_RESPONSE: {
      code: "MISSING_RESPONSE",
      message: "Missing CAPTCHA response",
    },
    UNKNOWN_ERROR: {
      code: "UNKNOWN_ERROR",
      message: "Something went wrong",
    },
    VERIFICATION_FAILED: {
      code: "VERIFICATION_FAILED",
      message: "Captcha verification failed",
    },
    },
  );
  for (const value of Object.values(plugin.$ERROR_CODES)) {
    assert.equal(value.toString(), value.code);
  }
  assert.equal(typeof plugin.onRequest, "function");
  for (const unsupported of [
    "client",
    "cookies",
    "endpoints",
    "hooks",
    "migrations",
    "rateLimit",
    "schema",
  ]) {
    assert.equal(unsupported in plugin, false, `${unsupported} must not be advertised`);
  }
  assert.equal("captchaClient" in clientPlugins, false);
}

async function endpointMatchingConformance() {
  const defaults = captcha({
    provider: "google-recaptcha",
    secretKey: "endpoint-secret",
  });
  for (const path of [
    "/api/auth/sign-up/email",
    "/api/auth/sign-in/email",
    "/api/auth/request-password-reset",
    "/api/auth//sign-in///email//?ignored=yes",
  ]) {
    const { response } = await invoke(defaults, path);
    await assertMiddlewareResponse(response, errors.missing);
  }
  for (const path of [
    "/api/auth/sign-in/social",
    "/api/auth/sign-in/email/deeper",
    "/api/auth/SIGN-IN/email",
    "/outside/api/auth/sign-in/email",
  ]) {
    assert.equal((await invoke(defaults, path)).result, undefined);
  }

  const emptyEndpoints = captcha({
    provider: "google-recaptcha",
    secretKey: "endpoint-secret",
    endpoints: [],
  });
  await assertMiddlewareResponse(
    (await invoke(emptyEndpoints, "/api/auth/sign-in/email")).response,
    errors.missing,
  );

  const replacement = captcha({
    provider: "google-recaptcha",
    secretKey: "endpoint-secret",
    endpoints: ["/custom"],
  });
  assert.equal(
    (await invoke(replacement, "/api/auth/sign-in/email")).result,
    undefined,
  );
  await assertMiddlewareResponse(
    (await invoke(replacement, "/api/auth/custom/?query=ignored")).response,
    errors.missing,
  );

  const oneSegment = captcha({
    provider: "google-recaptcha",
    secretKey: "endpoint-secret",
    endpoints: ["/sign-in/*"],
  });
  await assertMiddlewareResponse(
    (await invoke(oneSegment, "/api/auth/sign-in/email")).response,
    errors.missing,
  );
  assert.equal(
    (await invoke(oneSegment, "/api/auth/sign-in/email/otp")).result,
    undefined,
  );
  assert.equal((await invoke(oneSegment, "/api/auth/sign-in")).result, undefined);

  const nested = captcha({
    provider: "google-recaptcha",
    secretKey: "endpoint-secret",
    endpoints: ["/sign-in/**"],
  });
  for (const path of [
    "/api/auth/sign-in",
    "/api/auth/sign-in/email",
    "/api/auth/sign-in/email/otp",
  ]) {
    await assertMiddlewareResponse(
      (await invoke(nested, path)).response,
      errors.missing,
    );
  }

  const literalQuestionMark = captcha({
    provider: "google-recaptcha",
    secretKey: "endpoint-secret",
    endpoints: ["/sign-?n/email"],
  });
  assert.equal(
    (await invoke(literalQuestionMark, "/api/auth/sign-in/email")).result,
    undefined,
  );

  const customBase = captcha({
    provider: "google-recaptcha",
    secretKey: "endpoint-secret",
  });
  await assertMiddlewareResponse(
    (
      await invoke(customBase, "/custom/auth/sign-in/email/", {}, {
        basePath: "/custom/auth",
      })
    ).response,
    errors.missing,
  );

  for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]) {
    const { response } = await invoke(defaults, "/api/auth/sign-in/email", {
      method,
    });
    await assertMiddlewareResponse(response, errors.missing);
  }
}

async function providerWireConformance() {
  const verifier = await startVerifier();
  try {
    const providerCases = [
      {
        provider: "cloudflare-turnstile",
        expectedContentType: "application/json",
        expectedBody: JSON.stringify({
          secret: "wire secret&",
          response: "wire+token",
          remoteip: "198.51.100.20",
        }),
      },
      {
        provider: "google-recaptcha",
        expectedContentType: "application/x-www-form-urlencoded",
        expectedBody:
          "secret=wire+secret%26&response=wire%2Btoken&remoteip=198.51.100.20",
      },
      {
        provider: "hcaptcha",
        siteKey: "site key&",
        expectedContentType: "application/x-www-form-urlencoded",
        expectedBody:
          "secret=wire+secret%26&response=wire%2Btoken&sitekey=site+key%26&remoteip=198.51.100.20",
      },
      {
        provider: "captchafox",
        siteKey: "site key&",
        expectedContentType: "application/x-www-form-urlencoded",
        expectedBody:
          "secret=wire+secret%26&response=wire%2Btoken&sitekey=site+key%26&remoteIp=198.51.100.20",
      },
    ];
    for (const testCase of providerCases) {
      const before = verifier.requests.length;
      const plugin = captcha({
        provider: testCase.provider,
        secretKey: "wire secret&",
        siteKey: testCase.siteKey,
        siteVerifyURLOverride: verifier.url,
      });
      const { result } = await invoke(
        plugin,
        "/api/auth/sign-in/email",
        {
          method: "POST",
          headers: {
            "x-captcha-response": "wire+token",
            "x-client-ip": "198.51.100.20",
          },
        },
        { advanced: { ipAddress: { ipAddressHeaders: ["x-client-ip"] } } },
      );
      assert.equal(result, undefined);
      assert.equal(verifier.requests.length, before + 1);
      const providerRequest = verifier.requests.at(-1);
      assert.equal(providerRequest.url, "/verify");
      assert.equal(providerRequest.method, "POST");
      assert.equal(
        providerRequest.headers["content-type"],
        testCase.expectedContentType,
      );
      assert.equal(providerRequest.body, testCase.expectedBody);
    }

    const requestsBeforeMissingResponse = verifier.requests.length;
    const missingResponse = await invoke(
      captcha({
        provider: "google-recaptcha",
        secretKey: "missing-response-secret",
        siteVerifyURLOverride: verifier.url,
      }),
      "/api/auth/sign-in/email",
    );
    await assertMiddlewareResponse(missingResponse.response, errors.missing);
    assert.equal(verifier.requests.length, requestsBeforeMissingResponse);

    const noOptionalFields = captcha({
      provider: "captchafox",
      secretKey: "no-optionals",
      siteKey: "",
      siteVerifyURLOverride: verifier.url,
    });
    assert.equal(
      (
        await invoke(
          noOptionalFields,
          "/api/auth/sign-in/email",
          {
            method: "POST",
            headers: {
              "x-captcha-response": "token",
              "x-captcha-user-remote-ip": "203.0.113.99",
              "x-forwarded-for": "203.0.113.40",
            },
          },
          { advanced: { ipAddress: { disableIpTracking: true } } },
        )
      ).result,
      undefined,
    );
    assert.equal(
      verifier.requests.at(-1).body,
      "secret=no-optionals&response=token",
    );

    const trustedChain = captcha({
      provider: "hcaptcha",
      secretKey: "trusted-chain",
      siteVerifyURLOverride: verifier.url,
    });
    await invoke(
      trustedChain,
      "/api/auth/sign-in/email",
      {
        headers: {
          "x-captcha-response": "token",
          "x-forwarded-for": "2001:DB8::1234, 10.1.2.3",
        },
      },
      {
        advanced: {
          ipAddress: {
            ipv6Subnet: 128,
            trustedProxies: ["10.0.0.0/8"],
          },
        },
      },
    );
    assert.equal(
      verifier.requests.at(-1).body,
      "secret=trusted-chain&response=token&remoteip=2001%3A0db8%3A0000%3A0000%3A0000%3A0000%3A0000%3A1234",
    );

    const mappedIpv4 = captcha({
      provider: "cloudflare-turnstile",
      secretKey: "mapped-ip",
      siteVerifyURLOverride: verifier.url,
    });
    await invoke(mappedIpv4, "/api/auth/sign-in/email", {
      headers: {
        "x-captcha-response": "token",
        "x-forwarded-for": "::ffff:192.0.2.42",
      },
    });
    assert.deepEqual(JSON.parse(verifier.requests.at(-1).body), {
      secret: "mapped-ip",
      response: "token",
      remoteip: "192.0.2.42",
    });
  } finally {
    await verifier.close();
  }
}

async function providerDecisionConformance() {
  const verifier = await startVerifier();
  try {
    async function verify(provider, reply, providerOptions = {}) {
      verifier.setReply(
        typeof reply === "string"
          ? { body: reply, headers: { "content-type": "text/plain" } }
          : {
              body: JSON.stringify(reply.body),
              status: reply.status,
            },
      );
      return invoke(
        captcha({
          provider,
          secretKey: "decision-secret",
          siteVerifyURLOverride: verifier.url,
          ...providerOptions,
        }),
        "/api/auth/sign-in/email",
        { headers: { "x-captcha-response": "decision-token" } },
        { advanced: { ipAddress: { disableIpTracking: true } } },
      );
    }

    for (const provider of [
      "cloudflare-turnstile",
      "google-recaptcha",
      "hcaptcha",
      "captchafox",
    ]) {
      assert.equal((await verify(provider, { body: { success: 1 } })).result, undefined);
      await assertMiddlewareResponse(
        (await verify(provider, { body: { success: false } })).response,
        errors.rejected,
      );
      await assertMiddlewareResponse(
        (await verify(provider, { body: null })).response,
        errors.unknown,
      );
      await assertMiddlewareResponse(
        (await verify(provider, { body: { success: false }, status: 503 })).response,
        errors.unknown,
      );
    }

    assert.equal(
      (
        await verify("google-recaptcha", {
          body: { success: true, score: 0.5 },
        })
      ).result,
      undefined,
    );
    await assertMiddlewareResponse(
      (
        await verify("google-recaptcha", {
          body: { success: true, score: 0.4999 },
        })
      ).response,
      errors.rejected,
    );
    assert.equal(
      (
        await verify("google-recaptcha", {
          body: { success: true, score: "0" },
        })
      ).result,
      undefined,
    );
    assert.equal(
      (
        await verify(
          "google-recaptcha",
          { body: { success: true, score: 0.7, action: "login", hostname: "A.test" } },
          { expectedAction: "login", allowedHostnames: ["A.test"] },
        )
      ).result,
      undefined,
    );
    for (const body of [
      { success: true, score: 0.7, action: "LOGIN", hostname: "A.test" },
      { success: true, score: 0.7, action: "login", hostname: "a.test" },
      { success: true, score: 0.7, action: "login" },
    ]) {
      await assertMiddlewareResponse(
        (
          await verify("google-recaptcha", { body }, {
            expectedAction: "login",
            allowedHostnames: ["A.test"],
          })
        ).response,
        errors.rejected,
      );
    }

    assert.equal(
      (
        await verify(
          "cloudflare-turnstile",
          { body: { success: true, action: "signup", hostname: "app.test" } },
          { expectedAction: "signup", allowedHostnames: ["app.test"] },
        )
      ).result,
      undefined,
    );
    await assertMiddlewareResponse(
      (
        await verify(
          "cloudflare-turnstile",
          { body: { success: true, action: "signup" } },
          { expectedAction: "signup", allowedHostnames: ["app.test"] },
        )
      ).response,
      errors.rejected,
    );
    assert.equal(
      (
        await verify(
          "cloudflare-turnstile",
          { body: { success: true } },
          { expectedAction: "", allowedHostnames: [] },
        )
      ).result,
      undefined,
    );

    await assertMiddlewareResponse(
      (await verify("hcaptcha", { body: {} })).response,
      errors.rejected,
    );
    await assertMiddlewareResponse(
      (await verify("hcaptcha", "not-json")).response,
      errors.rejected,
    );
    await assertMiddlewareResponse(
      (await verify("hcaptcha", "")).response,
      errors.unknown,
    );
  } finally {
    await verifier.close();
  }
}

async function defaultUrlsAndTimeoutConformance() {
  const expectedURLs = new Map([
    [
      "cloudflare-turnstile",
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    ],
    ["google-recaptcha", "https://www.google.com/recaptcha/api/siteverify"],
    ["hcaptcha", "https://api.hcaptcha.com/siteverify"],
    ["captchafox", "https://api.captchafox.com/siteverify"],
  ]);
  const nativeFetch = globalThis.fetch;
  const nativeSetTimeout = globalThis.setTimeout;
  const nativeClearTimeout = globalThis.clearTimeout;
  const calls = [];
  const timeouts = [];
  let timerId = 0;
  try {
    globalThis.setTimeout = (callback, milliseconds) => {
      const id = ++timerId;
      timeouts.push({ abort: () => callback(), milliseconds });
      return id;
    };
    globalThis.clearTimeout = () => {};
    globalThis.fetch = async (url, init) => {
      calls.push({ init, url: String(url) });
      return new Response('{"success":true}', {
        headers: { "content-type": "application/json" },
      });
    };
    for (const [provider, expectedURL] of expectedURLs) {
      const plugin = captcha({ provider, secretKey: "default-url-secret" });
      assert.equal(
        (
          await invoke(
            plugin,
            "/api/auth/sign-in/email",
            { headers: { "x-captcha-response": "token" } },
            { advanced: { ipAddress: { disableIpTracking: true } } },
          )
        ).result,
        undefined,
      );
      assert.equal(calls.at(-1).url, expectedURL);
      assert.equal(timeouts.at(-1).milliseconds, 10_000);
      assert.equal(calls.at(-1).init.signal.aborted, false);
    }

    const fallback = captcha({
      provider: "google-recaptcha",
      secretKey: "fallback-secret",
      siteVerifyURLOverride: "",
    });
    await invoke(
      fallback,
      "/api/auth/sign-in/email",
      { headers: { "x-captcha-response": "token" } },
      { advanced: { ipAddress: { disableIpTracking: true } } },
    );
    assert.equal(calls.at(-1).url, expectedURLs.get("google-recaptcha"));

    globalThis.fetch = async (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener(
          "abort",
          () => reject(new DOMException("The operation was aborted", "AbortError")),
          { once: true },
        );
      });
    for (const provider of expectedURLs.keys()) {
      const timeoutCount = timeouts.length;
      const pending = invoke(
        captcha({ provider, secretKey: "timeout-secret" }),
        "/api/auth/sign-in/email",
        { headers: { "x-captcha-response": "timeout-token" } },
        { advanced: { ipAddress: { disableIpTracking: true } } },
      );
      for (let attempt = 0; attempt < 20 && timeouts.length === timeoutCount; attempt++) {
        await Promise.resolve();
      }
      assert.equal(timeouts.length, timeoutCount + 1);
      assert.equal(timeouts.at(-1).milliseconds, 10_000);
      timeouts.at(-1).abort();
      await assertMiddlewareResponse((await pending).response, errors.unknown);
    }
  } finally {
    globalThis.fetch = nativeFetch;
    globalThis.setTimeout = nativeSetTimeout;
    globalThis.clearTimeout = nativeClearTimeout;
  }
}

async function errorConformance() {
  const missingSecret = captcha({
    provider: "google-recaptcha",
    secretKey: "",
  });
  const missingSecretResult = await invoke(
    missingSecret,
    "/api/auth/sign-in/email",
    { headers: { "x-captcha-response": "must-not-be-logged" } },
  );
  await assertMiddlewareResponse(missingSecretResult.response, errors.unknown);
  assert.equal(missingSecretResult.logs.length, 1);
  assert.equal(missingSecretResult.logs[0][0], "Missing secret key");
  assert.doesNotMatch(JSON.stringify(missingSecretResult.logs), /must-not-be-logged/);

  const plugin = captcha({
    provider: "google-recaptcha",
    secretKey: "must-not-be-logged-secret",
  });
  const missingHeader = await invoke(plugin, "/api/auth/sign-in/email", {
    headers: { "x-captcha-response": "" },
  });
  await assertMiddlewareResponse(missingHeader.response, errors.missing);
  assert.equal(missingHeader.logs.length, 0);

  const nativeFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      throw new Error("simulated provider outage");
    };
    const outage = await invoke(
      plugin,
      "/api/auth/sign-in/email",
      { headers: { "X-CaPtChA-ReSpOnSe": "must-not-be-logged-token" } },
      { advanced: { ipAddress: { disableIpTracking: true } } },
    );
    await assertMiddlewareResponse(outage.response, errors.unknown);
    assert.equal(outage.logs.length, 1);
    assert.equal(outage.logs[0][0], "simulated provider outage");
    assert.doesNotMatch(JSON.stringify(outage.logs), /must-not-be-logged/);
  } finally {
    globalThis.fetch = nativeFetch;
  }
}

async function hookOrderConformance() {
  const verifier = await startVerifier();
  try {
    const verifierPlugin = captcha({
      provider: "google-recaptcha",
      secretKey: "layer-order-secret",
      endpoints: ["/ok", "/sign-in/email"],
      siteVerifyURLOverride: verifier.url,
    });
    const rateEvents = [];
    const rateLimited = betterAuth({
      baseURL: authBaseURL,
      secret,
      logger: { disabled: true },
      rateLimit: {
        enabled: true,
        customStorage: {
          async consume() {
            rateEvents.push("rate-limit");
            return { allowed: false, retryAfter: 17 };
          },
        },
      },
      plugins: [
        {
          id: "before-captcha",
          onRequest() {
            rateEvents.push("plugin");
          },
        },
        verifierPlugin,
      ],
    });
    const requestsBeforeRateLimit = verifier.requests.length;
    const throttled = await rateLimited.handler(
      new Request(`${authBaseURL}/ok`, {
        headers: {
          "x-captcha-response": "valid-token",
          "x-forwarded-for": "198.51.100.80",
        },
      }),
    );
    assert.equal(throttled.status, 429);
    assert.equal(throttled.headers.get("x-retry-after"), "17");
    assert.deepEqual(rateEvents, ["rate-limit"]);
    assert.equal(verifier.requests.length, requestsBeforeRateLimit);

    const order = [];
    const orderedAuth = betterAuth({
      baseURL: authBaseURL,
      secret,
      logger: { disabled: true },
      rateLimit: { enabled: false },
      plugins: [
        {
          id: "captcha-header-injector",
          onRequest(request) {
            order.push("before");
            const headers = new Headers(request.headers);
            headers.set("x-captcha-response", "injected-token");
            return { request: new Request(request, { headers }) };
          },
        },
        verifierPlugin,
        {
          id: "after-captcha",
          onRequest() {
            order.push("after");
          },
        },
      ],
    });
    const ordered = await orderedAuth.handler(new Request(`${authBaseURL}/ok`));
    assert.equal(ordered.status, 200);
    assert.deepEqual(await ordered.json(), { ok: true });
    assert.deepEqual(order, ["before", "after"]);
    assert.equal(verifier.requests.at(-1).body.includes("injected-token"), true);

    const blockedOrder = [];
    const blockedAuth = betterAuth({
      baseURL: authBaseURL,
      secret,
      logger: { disabled: true },
      rateLimit: { enabled: false },
      plugins: [
        verifierPlugin,
        {
          id: "too-late-header-injector",
          onRequest() {
            blockedOrder.push("after");
          },
        },
      ],
    });
    const clientRequestsBefore = verifier.requests.length;
    const client = createAuthClient({
      baseURL: authOrigin,
      fetchOptions: {
        customFetchImpl(input, init) {
          return blockedAuth.handler(new Request(input, init));
        },
        headers: { "x-captcha-response": "client-token" },
      },
    });
    const clientResult = await client.$fetch("/ok");
    assert.equal(clientResult.error, null);
    assert.deepEqual(clientResult.data, { ok: true });
    assert.equal(verifier.requests.length, clientRequestsBefore + 1);
    assert.match(verifier.requests.at(-1).body, /response=client-token/);
    blockedOrder.length = 0;

    const blocked = await blockedAuth.handler(new Request(`${authBaseURL}/ok`));
    await assertMiddlewareResponse(blocked, errors.missing);
    assert.deepEqual(blockedOrder, []);

    const hostileOrigin = "https://hostile.example.test";
    const captchaBeforeOrigin = await blockedAuth.handler(
      new Request(`${authBaseURL}/sign-in/email`, {
        method: "POST",
        headers: {
          cookie: "better-auth.session_token=untrusted",
          "content-type": "application/json",
          origin: hostileOrigin,
        },
        body: "{}",
      }),
    );
    await assertMiddlewareResponse(captchaBeforeOrigin, errors.missing);

    const originAfterCaptcha = await blockedAuth.handler(
      new Request(`${authBaseURL}/sign-in/email`, {
        method: "POST",
        headers: {
          cookie: "better-auth.session_token=untrusted",
          "content-type": "application/json",
          origin: hostileOrigin,
          "x-captcha-response": "valid-token",
        },
        body: "{}",
      }),
    );
    assert.equal(
      originAfterCaptcha.status,
      403,
      await originAfterCaptcha.clone().text(),
    );
    assert.deepEqual(await originAfterCaptcha.json(), {
      code: "INVALID_ORIGIN",
      message: "Invalid origin",
    });

    const optionsBeforeRouting = await blockedAuth.handler(
      new Request(`${authBaseURL}/sign-in/email`, {
        method: "OPTIONS",
        headers: {
          origin: hostileOrigin,
          "access-control-request-headers": "content-type,x-captcha-response",
          "access-control-request-method": "POST",
        },
      }),
    );
    await assertMiddlewareResponse(optionsBeforeRouting, errors.missing);
    assert.equal(optionsBeforeRouting.headers.get("access-control-allow-origin"), null);
  } finally {
    await verifier.close();
  }
}

async function pinnedSourceConformance() {
  const packageMetadata = JSON.parse(
    await readFile(new URL("node_modules/better-auth/package.json", import.meta.url)),
  );
  assert.equal(packageMetadata.version, "1.7.1");

  const captchaSource = await readFile(
    new URL("node_modules/better-auth/dist/plugins/captcha/index.mjs", import.meta.url),
    "utf8",
  );
  assert.match(captchaSource, /const captcha = \(options\) => \(\{/);
  assert.match(captchaSource, /endpoint\.includes\("\*"\) \? wildcardMatch/);
  assert.match(captchaSource, /siteVerifyURLOverride \|\| siteVerifyMap/);

  const constantsSource = await readFile(
    new URL("node_modules/better-auth/dist/plugins/captcha/constants.mjs", import.meta.url),
    "utf8",
  );
  assert.match(constantsSource, /CAPTCHA_VERIFY_TIMEOUT_MS = 1e4/);
  for (const handler of [
    "captchafox",
    "cloudflare-turnstile",
    "google-recaptcha",
    "h-captcha",
  ]) {
    const source = await readFile(
      new URL(
        `node_modules/better-auth/dist/plugins/captcha/verify-handlers/${handler}.mjs`,
        import.meta.url,
      ),
      "utf8",
    );
    assert.match(source, /timeout: CAPTCHA_VERIFY_TIMEOUT_MS/);
  }
}

export async function captchaConformance() {
  pluginMetadataConformance();
  await endpointMatchingConformance();
  await providerWireConformance();
  await providerDecisionConformance();
  await defaultUrlsAndTimeoutConformance();
  await errorConformance();
  await hookOrderConformance();
  await pinnedSourceConformance();
  console.log("ok - Captcha official server and provider-wire contract");
}
