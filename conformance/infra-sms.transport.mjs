import { execFile as execFileCallback } from "node:child_process";
import { createServer } from "node:http";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import { logger } from "better-auth";
import { describe, expect, test, vi } from "vitest";
import {
  captureFetch,
  envApiBase,
  infraRoot,
  jsonResponse,
} from "./infra-sms.helpers.mjs";

const execFile = promisify(execFileCallback);

function config(overrides = {}) {
  return {
    apiKey: "sms-secret",
    apiUrl: "https://sms.example.test",
    ...overrides,
  };
}

function options(overrides = {}) {
  return { to: "+1234567890", code: "123456", ...overrides };
}

describe("@better-auth/infra@0.4.3 SMS transport oracle", () => {
  test("reusable sender sends every template and the generic body exactly once", async () => {
    const { fetch, requests } = captureFetch((_request, _init, index) =>
      jsonResponse({ messageId: index + 1, ignored: true }));
    const sender = infraRoot.createSMSSender(config());

    for (const template of ["phone-verification", "two-factor", "sign-in-otp"]) {
      await expect(sender.send(options({ template }))).resolves.toEqual({
        success: true,
        messageId: requests.length + 1,
      });
    }
    await expect(sender.send(options({ to: "not-e164", code: "", clientIp: "" })))
      .resolves.toEqual({ success: true, messageId: 4 });

    expect(fetch).toHaveBeenCalledTimes(4);
    expect(requests.map(({ body, method, url }) => ({ body, method, url }))).toEqual([
      ...["phone-verification", "two-factor", "sign-in-otp"].map((template) => ({
        body: { to: "+1234567890", code: "123456", template },
        method: "POST",
        url: "https://sms.example.test/api/v1/sms/send",
      })),
      {
        body: { to: "not-e164", code: "" },
        method: "POST",
        url: "https://sms.example.test/api/v1/sms/send",
      },
    ]);
    for (const request of requests) {
      expect(request.headers.authorization).toBe("Bearer sms-secret");
      expect(request.headers["user-agent"]).toBe("@better-auth/infra v0.4.3");
      expect(request.headers["content-type"]).toBe("application/json");
    }
    expect(requests[3].headers).not.toHaveProperty("x-better-auth-client-ip");
  });

  test("truthy clientIp overrides only the request headers and is forwarded verbatim", async () => {
    const { requests } = captureFetch(() => jsonResponse({ messageId: "ip" }));
    await infraRoot.createSMSSender(config()).send(options({ clientIp: "203.0.113.9" }));

    expect(requests[0].headers.authorization).toBe("Bearer sms-secret");
    expect(requests[0].headers["user-agent"]).toBe("@better-auth/infra v0.4.3");
    expect(requests[0].headers["x-better-auth-client-ip"]).toBe("203.0.113.9");
    expect(requests[0].body).toEqual({ to: "+1234567890", code: "123456" });
  });

  test("credential precedence and import-time URL capture preserve truthy suffix behavior", async () => {
    process.env.BETTER_AUTH_API_KEY = "environment-secret";
    const { requests } = captureFetch(() => jsonResponse({ messageId: "msg" }));

    await infraRoot.createSMSSender({
      apiKey: "configured-secret",
      apiUrl: "https://configured.example.test/api",
    }).send(options());
    await infraRoot.createSMSSender({
      apiKey: "",
      apiUrl: "https://configured.example.test/api/",
    }).send(options());
    await infraRoot.createSMSSender({ apiKey: "", apiUrl: "" }).send(options());

    expect(requests.map(({ headers, url }) => ({
      authorization: headers.authorization,
      url,
    }))).toEqual([
      {
        authorization: "Bearer configured-secret",
        url: "https://configured.example.test/api/v1/sms/send",
      },
      {
        authorization: "Bearer environment-secret",
        url: "https://configured.example.test/api//api/v1/sms/send",
      },
      {
        authorization: "Bearer environment-secret",
        url: `${envApiBase}/v1/sms/send`,
      },
    ]);
  });

  test("query and fragment API bases resolve operation paths from the origin root", async () => {
    const { requests } = captureFetch(() => jsonResponse({ messageId: "msg" }));

    for (const apiUrl of [
      "https://x.test/base?foo=1",
      "https://x.test/base#frag",
      "https://x.test/api?foo=1",
      "https://x.test/api#frag",
    ]) {
      await infraRoot.createSMSSender({ apiKey: "key", apiUrl }).send(options());
    }

    expect(requests.map(({ url }) => url)).toEqual(
      Array(4).fill("https://x.test/v1/sms/send"),
    );
  });

  test("default configuration targets the managed dashboard API", async () => {
    const {
      BETTER_AUTH_API_KEY: _apiKey,
      BETTER_AUTH_API_URL: _apiUrl,
      ...cleanEnv
    } = process.env;
    const script = `
      globalThis.fetch = async (input) => {
        console.log(String(input));
        return Response.json({ messageId: "default" });
      };
      const { sendSMS } = await import("@better-auth/infra");
      console.log(JSON.stringify(await sendSMS(
        { to: "+1234567890", code: "123456" },
        { apiKey: "secret" },
      )));
    `;
    const { stdout } = await execFile(process.execPath, ["--input-type=module", "-e", script], {
      cwd: new URL(".", import.meta.url),
      env: cleanEnv,
    });

    expect(stdout.trim().split("\n")).toEqual([
      "https://dash.better-auth.com/api/v1/sms/send",
      '{"success":true,"messageId":"default"}',
    ]);
  });

  test("missing API key short-circuits without a request", async () => {
    const { fetch } = captureFetch(() => {
      throw new Error("must not run");
    });
    const sender = infraRoot.createSMSSender({ apiKey: "", apiUrl: "https://sms.test" });

    await expect(sender.send(options())).resolves.toEqual({
      success: false,
      error: "API key not configured",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  test.each([
    ["empty object", {}, { success: true, messageId: undefined }],
    ["provider success ignored", { success: false, messageId: 7 }, { success: true, messageId: 7 }],
    ["null message ID", { messageId: null }, { success: true, messageId: null }],
    ["object message ID", { messageId: { nested: true } }, { success: true, messageId: { nested: true } }],
    ["array", [], { success: false, error: "Failed to parse JSON" }],
    ["string", "ok", { success: false, error: "Failed to parse JSON" }],
    ["number", 42, { success: false, error: "Failed to parse JSON" }],
    ["boolean", false, { success: false, error: "Failed to parse JSON" }],
    ["null", null, { success: false, error: "Failed to parse JSON" }],
  ])("normalizes %s success JSON exactly", async (_name, body, expected) => {
    const { fetch } = captureFetch(() => jsonResponse(body));
    await expect(infraRoot.createSMSSender(config()).send(options())).resolves.toEqual(expected);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  test("HTTP errors preserve truthy non-strings and fallback for falsey values", async () => {
    const messages = ["denied", 7, true, [], {}, "", 0, false, null];
    const { fetch } = captureFetch(() => new Response(
      JSON.stringify({ message: messages.shift() }),
      { headers: { "content-type": "application/json" }, status: 400 },
    ));
    const sender = infraRoot.createSMSSender(config());

    for (const expected of ["denied", 7, true, [], {}]) {
      await expect(sender.send(options())).resolves.toEqual({ success: false, error: expected });
    }
    for (let index = 0; index < 4; index += 1) {
      await expect(sender.send(options())).resolves.toEqual({
        success: false,
        error: "HTTP 400",
      });
    }
    expect(fetch).toHaveBeenCalledTimes(9);
  });

  test("native fetch decodes managed gzip JSON", async () => {
    const server = createServer((_request, response) => {
      response.writeHead(200, {
        "content-encoding": "gzip",
        "content-type": "application/json",
      });
      response.end(gzipSync(JSON.stringify({ messageId: "compressed" })));
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();
    try {
      await expect(infraRoot.sendSMS(options(), {
        apiKey: "key",
        apiUrl: `http://127.0.0.1:${port}`,
      })).resolves.toEqual({ success: true, messageId: "compressed" });
    } finally {
      await new Promise((resolve, reject) =>
        server.close((error) => error ? reject(error) : resolve()));
    }
  });

  test("warnings occur for missing keys and exceptions, but not HTTP/result failures", async () => {
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => {});
    const missing = infraRoot.createSMSSender({ apiKey: "", apiUrl: "https://sms.test" });
    await missing.send(options());
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenLastCalledWith(
      "[Dash] No API key provided for SMS sending. Set BETTER_AUTH_API_KEY environment variable or pass apiKey in config.",
    );

    const failures = [
      new Response(JSON.stringify({ message: "denied" }), {
        headers: { "content-type": "application/json" },
        status: 400,
      }),
      jsonResponse([]),
      new Error("offline"),
      "disconnected",
    ];
    const { fetch } = captureFetch(() => {
      const failure = failures.shift();
      if (failure instanceof Response) return failure;
      throw failure;
    });
    const sender = infraRoot.createSMSSender(config());

    await sender.send(options());
    await sender.send(options());
    expect(warn).toHaveBeenCalledTimes(1);
    await expect(sender.send(options())).resolves.toEqual({ success: false, error: "offline" });
    await expect(sender.send(options())).resolves.toEqual({
      success: false,
      error: "Failed to send SMS",
    });
    expect(warn).toHaveBeenCalledTimes(3);
    expect(warn.mock.calls.slice(1)).toEqual([
      ["[Dash] SMS send failed:", expect.objectContaining({ message: "offline" })],
      ["[Dash] SMS send failed:", "disconnected"],
    ]);
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  test("apiOptions timeout wins over apiTimeout and zero disables the timer", async () => {
    vi.useFakeTimers();
    let settle;
    const signals = [];
    const { fetch } = captureFetch((_request, init) => new Promise((resolve, reject) => {
      signals.push(init.signal);
      settle = resolve;
      init.signal.addEventListener("abort", () => reject(new Error("oracle aborted")), { once: true });
    }));

    const timed = infraRoot.createSMSSender(config({
      apiOptions: { timeout: 10 },
      apiTimeout: 500,
    })).send(options());
    await vi.advanceTimersByTimeAsync(11);
    await expect(timed).resolves.toEqual({ success: false, error: "oracle aborted" });
    expect(signals[0].aborted).toBe(true);

    const legacy = infraRoot.createSMSSender(config({ apiTimeout: 10 })).send(options());
    await vi.advanceTimersByTimeAsync(11);
    await expect(legacy).resolves.toEqual({ success: false, error: "oracle aborted" });
    expect(signals[1].aborted).toBe(true);

    const zero = infraRoot.createSMSSender(config({
      apiOptions: { timeout: 0 },
      apiTimeout: 10,
    })).send(options());
    await vi.advanceTimersByTimeAsync(3_001);
    expect(signals[2].aborted).toBe(false);
    settle(jsonResponse({ messageId: "zero" }));
    await expect(zero).resolves.toEqual({ success: true, messageId: "zero" });

    const defaults = infraRoot.createSMSSender(config()).send(options());
    await vi.advanceTimersByTimeAsync(2_999);
    expect(signals[3].aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(2);
    await expect(defaults).resolves.toEqual({ success: false, error: "oracle aborted" });
    expect(signals[3].aborted).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  test("one-shot wrapper creates one request with identical normalization", async () => {
    const { fetch, requests } = captureFetch(() => jsonResponse({ messageId: "wrapper" }));

    await expect(infraRoot.sendSMS(
      options({ template: "two-factor" }),
      config(),
    )).resolves.toEqual({ success: true, messageId: "wrapper" });

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(requests[0].url).toBe("https://sms.example.test/api/v1/sms/send");
  });
});
