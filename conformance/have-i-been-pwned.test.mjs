import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { runWithEndpointContext } from "@better-auth/core/context";
import { isAPIError } from "better-auth/api";
import * as clientPlugins from "better-auth/client/plugins";
import * as aggregatePlugins from "better-auth/plugins";
import * as directExports from "better-auth/plugins/haveibeenpwned";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

const { haveIBeenPwned } = directExports;
const DEFAULT_PATHS = [
  "/sign-up/email",
  "/change-password",
  "/reset-password",
  "/email-otp/reset-password",
  "/phone-number/reset-password",
  "/admin/create-user",
  "/admin/set-user-password",
];
const DEFAULT_MESSAGE =
  "The password you entered has been compromised. Please choose a different password.";
let fetchMock;

function digest(password) {
  return createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
}

function install(options) {
  const calls = [];
  const originalPassword = {
    checkPassword: vi.fn(),
    config: { maxPasswordLength: 128, minPasswordLength: 8 },
    hash: vi.fn(async (password) => {
      calls.push(`hash:${password}`);
      return `hashed:${password}`;
    }),
    verify: vi.fn(),
  };
  const plugin = haveIBeenPwned(options);
  const wrappedPassword = plugin.init({ password: originalPassword }).context
    .password;
  return { calls, originalPassword, plugin, wrappedPassword };
}

async function hashAt(wrappedPassword, path, password) {
  return runWithEndpointContext({ path }, () => wrappedPassword.hash(password));
}

async function captureError(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected the password hash wrapper to reject");
}

function expectApiError(error, statusCode, body) {
  expect(isAPIError(error)).toBe(true);
  expect(error).toMatchObject({ body, statusCode });
}

beforeEach(() => {
  fetchMock = vi
    .spyOn(globalThis, "fetch")
    .mockRejectedValue(new Error("unexpected unmocked HIBP request"));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("better-auth@1.7.2 Have I Been Pwned oracle", () => {
  test("snapshots exports, descriptor, error code, and server-only surface", () => {
    const options = {
      customPasswordCompromisedMessage: "Choose another password",
      enabled: true,
      paths: ["/custom"],
    };
    const plugin = haveIBeenPwned(options);

    expect(Object.keys(directExports)).toEqual(["haveIBeenPwned"]);
    expect(aggregatePlugins.haveIBeenPwned).toBe(haveIBeenPwned);
    expect(clientPlugins).not.toHaveProperty("haveIBeenPwned");
    expect(plugin).toMatchObject({
      id: "have-i-been-pwned",
      options,
      version: "1.7.2",
    });
    expect(Object.keys(plugin)).toEqual([
      "id",
      "version",
      "init",
      "options",
      "$ERROR_CODES",
    ]);
    expect(plugin.$ERROR_CODES.PASSWORD_COMPROMISED).toMatchObject({
      code: "PASSWORD_COMPROMISED",
      message: DEFAULT_MESSAGE,
    });
    expect(plugin.$ERROR_CODES.PASSWORD_COMPROMISED.toString()).toBe(
      "PASSWORD_COMPROMISED",
    );
    for (const unsupported of [
      "client",
      "cookies",
      "endpoints",
      "hooks",
      "migrations",
      "onRequest",
      "rateLimit",
      "routes",
      "schema",
    ]) {
      expect(plugin).not.toHaveProperty(unsupported);
    }
    expect(haveIBeenPwned().options).toBeUndefined();
    expect(plugin.options).toBe(options);
  });

  test("pins the exact default path ordering in the shipped module", async () => {
    const source = await readFile(
      new URL(
        "node_modules/better-auth/dist/plugins/haveibeenpwned/index.mjs",
        import.meta.url,
      ),
      "utf8",
    );
    const defaultPathsSource = source.match(
      /const paths = options\?\.paths \|\| \[(.*?)\];/s,
    )?.[1];
    expect(defaultPathsSource).toBeDefined();
    expect(
      [...defaultPathsSource.matchAll(/"([^"]+)"/g)].map((match) => match[1]),
    ).toEqual(DEFAULT_PATHS);
  });

  test("wraps only hash and preserves the rest of the password context", () => {
    const { originalPassword, wrappedPassword } = install();

    expect(wrappedPassword.hash).not.toBe(originalPassword.hash);
    expect(wrappedPassword.verify).toBe(originalPassword.verify);
    expect(wrappedPassword.config).toBe(originalPassword.config);
    expect(wrappedPassword.checkPassword).toBe(originalPassword.checkPassword);
  });

  test("checks all seven default paths and bypasses every inexact path", async () => {
    const { originalPassword, wrappedPassword } = install();
    fetchMock.mockImplementation(async () =>
      new Response("not-a-match", {
        headers: { "content-type": "text/plain" },
      }),
    );

    for (const path of DEFAULT_PATHS) {
      await expect(hashAt(wrappedPassword, path, "selected")).resolves.toBe(
        "hashed:selected",
      );
    }
    expect(fetchMock).toHaveBeenCalledTimes(DEFAULT_PATHS.length);

    for (const path of [
      undefined,
      "",
      "/unrelated",
      "/SIGN-UP/EMAIL",
      "/sign-up/email/",
      "/sign-up/email?next=/",
      "/sign-up",
      "/sign-up/email/deeper",
    ]) {
      await expect(hashAt(wrappedPassword, path, "bypassed")).resolves.toBe(
        "hashed:bypassed",
      );
    }
    expect(fetchMock).toHaveBeenCalledTimes(DEFAULT_PATHS.length);
    expect(originalPassword.hash).toHaveBeenCalledTimes(
      DEFAULT_PATHS.length + 8,
    );
  });

  test("replaces default paths, retains an empty list, and honors enabled false", async () => {
    fetchMock.mockResolvedValue(
      new Response("not-a-match", {
        headers: { "content-type": "text/plain" },
      }),
    );

    const custom = install({ paths: ["/custom"] });
    await hashAt(custom.wrappedPassword, "/sign-up/email", "default-bypassed");
    await hashAt(custom.wrappedPassword, "/custom", "custom-checked");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const empty = install({ paths: [] });
    await hashAt(empty.wrappedPassword, "/sign-up/email", "empty-bypassed");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const disabled = install({ enabled: false });
    await expect(disabled.wrappedPassword.hash("disabled-no-context")).resolves.toBe(
      "hashed:disabled-no-context",
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  test("short-circuits an empty selected password before the request", async () => {
    const { originalPassword, wrappedPassword } = install();

    await expect(hashAt(wrappedPassword, "/change-password", "")).resolves.toBe(
      "hashed:",
    );
    expect(fetchMock).not.toHaveBeenCalled();
    expect(originalPassword.hash).toHaveBeenCalledOnce();
  });

  test("uses SHA-1 UTF-8 k-anonymity request fields without leaking secrets", async () => {
    const password = "pässword-🔐";
    const sha1 = digest(password);
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);
    const { calls, originalPassword, wrappedPassword } = install();
    fetchMock.mockImplementation(async (...args) => {
      calls.push("fetch");
      return new Response("unrelated:1", {
        headers: { "content-type": "text/plain" },
      });
    });

    await expect(
      hashAt(wrappedPassword, "/sign-up/email", password),
    ).resolves.toBe(`hashed:${password}`);

    expect(calls).toEqual(["fetch", `hash:${password}`]);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [input, init = {}] = fetchMock.mock.calls[0];
    const url = input instanceof Request ? input.url : String(input);
    const requestHeaders = new Headers(
      input instanceof Request ? input.headers : init.headers,
    );
    const method = input instanceof Request ? input.method : (init.method ?? "GET");
    const body = input instanceof Request ? input.body : init.body;
    expect(url).toBe(`https://api.pwnedpasswords.com/range/${prefix}`);
    expect(method).toBe("GET");
    expect(body).toBeNull();
    expect(Object.fromEntries(requestHeaders)).toEqual({
      "add-padding": "true",
      "user-agent": "BetterAuth Password Checker",
    });
    const serializedRequest = JSON.stringify({
      body,
      headers: Object.fromEntries(requestHeaders),
      method,
      url,
    });
    expect(serializedRequest).not.toContain(password);
    expect(serializedRequest).not.toContain(sha1);
    expect(serializedRequest).not.toContain(suffix);
    expect(originalPassword.hash).toHaveBeenCalledOnce();
  });

  test("matches only the case-insensitive field before the first colon", async () => {
    const password = "parser-contract";
    const sha1 = digest(password);
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);
    const matchingBodies = [
      `${suffix.toLowerCase()}:42\nUNRELATED:1`,
      `${suffix}:42\r\nUNRELATED:1`,
      suffix,
      `${suffix}:0:ignored`,
    ];
    const nonMatchingBodies = [
      "",
      "arbitrary malformed text",
      "<html>not a range response</html>",
      `${prefix}:1`,
      `${sha1}:1`,
      `${suffix.slice(1)}:1`,
      ` ${suffix}:1`,
      `${suffix} :1`,
      `${suffix}EXTRA:1`,
      `00000000000000000000000000000000000:0\n`,
    ];

    for (const body of matchingBodies) {
      const { originalPassword, wrappedPassword } = install();
      fetchMock.mockResolvedValueOnce(
        new Response(body, { headers: { "content-type": "text/plain" } }),
      );
      const error = await captureError(
        hashAt(wrappedPassword, "/reset-password", password),
      );
      expectApiError(error, 400, {
        code: "PASSWORD_COMPROMISED",
        message: DEFAULT_MESSAGE,
      });
      expect(originalPassword.hash).not.toHaveBeenCalled();
    }

    for (const body of nonMatchingBodies) {
      const { originalPassword, wrappedPassword } = install();
      fetchMock.mockResolvedValueOnce(
        new Response(body, { headers: { "content-type": "text/plain" } }),
      );
      await expect(
        hashAt(wrappedPassword, "/reset-password", password),
      ).resolves.toBe(`hashed:${password}`);
      expect(originalPassword.hash).toHaveBeenCalledOnce();
    }
  });

  test("uses the default for a missing or empty custom message and preserves whitespace", async () => {
    const password = "message-contract";
    const suffix = digest(password).slice(5);

    for (const [customPasswordCompromisedMessage, expectedMessage] of [
      [undefined, DEFAULT_MESSAGE],
      ["", DEFAULT_MESSAGE],
      ["   ", "   "],
      ["Exact custom message", "Exact custom message"],
    ]) {
      const options =
        customPasswordCompromisedMessage === undefined
          ? undefined
          : { customPasswordCompromisedMessage };
      const { originalPassword, wrappedPassword } = install(options);
      fetchMock.mockResolvedValueOnce(
        new Response(`${suffix}:999`, {
          headers: { "content-type": "text/plain" },
        }),
      );
      const error = await captureError(
        hashAt(wrappedPassword, "/admin/set-user-password", password),
      );
      expectApiError(error, 400, {
        code: "PASSWORD_COMPROMISED",
        message: expectedMessage,
      });
      expect(originalPassword.hash).not.toHaveBeenCalled();
    }
  });

  test("distinguishes status failures from transport and decoded-data failures", async () => {
    const password = "failure-contract";

    const brokenBody = new ReadableStream({
      start(controller) {
        controller.error(new Error("body read failed"));
      },
    });
    for (const [reply, expectedMessage] of [
      [
        new Response("outage", {
          headers: { "content-type": "text/plain" },
          status: 503,
        }),
        "Failed to check password. Status: 503",
      ],
      [new Error("transport failed"), "Failed to check password. Please try again later."],
      [
        new Response(JSON.stringify({ suffix: "not text" }), {
          headers: { "content-type": "application/json" },
        }),
        "Failed to check password. Please try again later.",
      ],
      [
        new Response(brokenBody, {
          headers: { "content-type": "text/plain" },
        }),
        "Failed to check password. Please try again later.",
      ],
    ]) {
      const { calls, originalPassword, wrappedPassword } = install();
      if (reply instanceof Error) {
        fetchMock.mockImplementationOnce(async () => {
          calls.push("fetch");
          throw reply;
        });
      } else {
        fetchMock.mockImplementationOnce(async () => {
          calls.push("fetch");
          return reply;
        });
      }
      const error = await captureError(
        hashAt(wrappedPassword, "/admin/create-user", password),
      );
      expectApiError(error, 500, { message: expectedMessage });
      expect(error.body).not.toHaveProperty("code");
      expect(calls).toEqual(["fetch"]);
      expect(originalPassword.hash).not.toHaveBeenCalled();
    }
  });

  test("calls the original hasher once after success and propagates its error", async () => {
    const { calls, originalPassword, wrappedPassword } = install();
    const originalError = new Error("original hash failed");
    fetchMock.mockImplementationOnce(async () => {
      calls.push("fetch");
      return new Response("not-a-match", {
        headers: { "content-type": "text/plain" },
      });
    });
    originalPassword.hash.mockImplementationOnce(async (password) => {
      calls.push(`hash:${password}`);
      throw originalError;
    });

    await expect(
      hashAt(wrappedPassword, "/phone-number/reset-password", "hash-error"),
    ).rejects.toBe(originalError);
    expect(calls).toEqual(["fetch", "hash:hash-error"]);
    expect(originalPassword.hash).toHaveBeenCalledOnce();
  });
});
