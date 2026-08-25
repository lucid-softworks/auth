import { execFile as execFileCallback } from "node:child_process";
import { createServer } from "node:http";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import { describe, expect, test, vi } from "vitest";
import {
  captureFetch,
  envApiBase,
  infraEmail,
  jsonResponse,
} from "./infra-email.helpers.mjs";

const execFile = promisify(execFileCallback);

function config(overrides = {}) {
  return {
    apiKey: "email-secret",
    apiUrl: "https://mail.example.test",
    ...overrides,
  };
}

function failureMap(addresses, error) {
  return Object.fromEntries(addresses.map((to) => [to, [{ error }]]));
}

describe("@better-auth/infra@0.4.3 email transport oracle", () => {
  test("reusable sender performs the exact three operations and headers", async () => {
    const failures = { "two@example.test": [{ error: "rejected", messageId: "msg_2" }] };
    const templates = [{ id: "verify-email", name: "Verify email", description: "Verify" }];
    const { fetch, requests } = captureFetch((request) => {
      if (request.url.endsWith("/send-bulk")) {
        return jsonResponse({ success: false, failures });
      }
      if (request.url.endsWith("/templates")) return jsonResponse(templates);
      return jsonResponse({ messageId: "msg_1", ignored: true });
    });
    const sender = infraEmail.createEmailSender(config());

    await expect(sender.send({
      template: "verify-email",
      to: "one@example.test",
      variables: { verificationUrl: "https://app.test/verify", userEmail: "one@example.test" },
    })).resolves.toEqual({ success: true, messageId: "msg_1" });
    await expect(sender.sendBulk({
      template: "invitation",
      emails: [
        { to: "one@example.test" },
        { to: "two@example.test", variables: { role: "admin" } },
      ],
      subject: "Join us",
      variables: { appName: "Example" },
    })).resolves.toEqual({ success: false, failures });
    await expect(sender.getTemplates()).resolves.toEqual(templates);

    expect(fetch).toHaveBeenCalledTimes(3);
    expect(requests.map(({ body, method, url }) => ({ body, method, url }))).toEqual([
      {
        body: {
          template: "verify-email",
          to: "one@example.test",
          variables: {
            verificationUrl: "https://app.test/verify",
            userEmail: "one@example.test",
          },
        },
        method: "POST",
        url: "https://mail.example.test/api/v1/email/send",
      },
      {
        body: {
          template: "invitation",
          emails: [
            { to: "one@example.test", variables: {} },
            { to: "two@example.test", variables: { role: "admin" } },
          ],
          subject: "Join us",
          variables: { appName: "Example" },
        },
        method: "POST",
        url: "https://mail.example.test/api/v1/email/send-bulk",
      },
      {
        body: undefined,
        method: "GET",
        url: "https://mail.example.test/api/v1/email/templates",
      },
    ]);
    for (const request of requests) {
      expect(request.headers.authorization).toBe("Bearer email-secret");
      expect(request.headers["user-agent"]).toBe("@better-auth/infra v0.4.3");
    }
    expect(requests[0].headers["content-type"]).toBe("application/json");
    expect(requests[2].headers["content-type"]).toBeUndefined();
  });

  test("URL and credential precedence preserve exact truthy and suffix behavior", async () => {
    process.env.BETTER_AUTH_API_KEY = "environment-secret";
    const { requests } = captureFetch(() => jsonResponse({ messageId: "msg" }));
    const options = {
      template: "reset-password",
      to: "one@example.test",
      variables: { resetLink: "https://app.test/reset", userEmail: "one@example.test" },
    };

    await infraEmail.createEmailSender({
      apiKey: "configured-secret",
      apiUrl: "https://configured.example.test/api",
    }).send(options);
    await infraEmail.createEmailSender({
      apiKey: "",
      apiUrl: "https://configured.example.test/api/",
    }).send(options);
    await infraEmail.createEmailSender({ apiKey: "", apiUrl: "" }).send(options);

    expect(requests.map(({ headers, url }) => ({
      authorization: headers.authorization,
      url,
    }))).toEqual([
      {
        authorization: "Bearer configured-secret",
        url: "https://configured.example.test/api/v1/email/send",
      },
      {
        authorization: "Bearer environment-secret",
        url: "https://configured.example.test/api//api/v1/email/send",
      },
      {
        authorization: "Bearer environment-secret",
        url: `${envApiBase}/v1/email/send`,
      },
    ]);
  });

  test("query and fragment API bases resolve operation paths from the origin root", async () => {
    const { requests } = captureFetch(() => jsonResponse({ messageId: "msg" }));
    const options = {
      template: "reset-password",
      to: "one@example.test",
      variables: { resetLink: "secret", userEmail: "one@example.test" },
    };

    for (const apiUrl of [
      "https://x.test/base?foo=1",
      "https://x.test/base#frag",
      "https://x.test/api?foo=1",
      "https://x.test/api#frag",
    ]) {
      await infraEmail.createEmailSender({ apiKey: "key", apiUrl }).send(options);
    }

    expect(requests.map(({ url }) => url)).toEqual(
      Array(4).fill("https://x.test/v1/email/send"),
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
      const { sendEmail } = await import("@better-auth/infra/email");
      const result = await sendEmail({
        template: "magic-link",
        to: "one@example.test",
        variables: { magicLink: "secret", userEmail: "one@example.test" },
      }, { apiKey: "secret" });
      console.log(JSON.stringify(result));
    `;
    const { stdout } = await execFile(process.execPath, ["--input-type=module", "-e", script], {
      cwd: new URL(".", import.meta.url),
      env: cleanEnv,
    });

    expect(stdout.trim().split("\n")).toEqual([
      "https://dash.better-auth.com/api/v1/email/send",
      '{"success":true,"messageId":"default"}',
    ]);
  });

  test("missing API key short-circuits every operation without a request", async () => {
    const { fetch } = captureFetch(() => {
      throw new Error("must not run");
    });
    const sender = infraEmail.createEmailSender({ apiKey: "", apiUrl: "https://mail.test" });
    const emails = [
      { to: "duplicate@example.test" },
      { to: "other@example.test" },
      { to: "duplicate@example.test" },
    ];

    await expect(sender.send({
      template: "magic-link",
      to: "one@example.test",
      variables: { magicLink: "secret", userEmail: "one@example.test" },
    })).resolves.toEqual({ success: false, error: "API key not configured" });
    await expect(sender.sendBulk({ template: "sign-in-otp", emails })).resolves.toEqual({
      success: false,
      failures: failureMap(emails.map(({ to }) => to), "API key not configured"),
    });
    await expect(sender.getTemplates()).resolves.toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });

  test.each([
    ["empty object", {}, { success: true, messageId: undefined }],
    ["provider success is ignored", { success: false, messageId: "msg_false" }, { success: true, messageId: "msg_false" }],
    ["array", [], { success: false, error: "Failed to parse JSON" }],
    ["string", "ok", { success: false, error: "Failed to parse JSON" }],
    ["number", 42, { success: false, error: "Failed to parse JSON" }],
    ["boolean", false, { success: false, error: "Failed to parse JSON" }],
    ["null", null, { success: false, error: "Cannot read properties of null (reading 'messageId')" }],
  ])("single send normalizes %s success JSON exactly", async (_name, body, expected) => {
    const { fetch } = captureFetch(() => jsonResponse(body));
    const result = await infraEmail.createEmailSender(config()).send({
      template: "sign-in-otp",
      to: "one@example.test",
      variables: { otpCode: "123456", userEmail: "one@example.test" },
    });
    expect(result).toEqual(expected);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  test("single send preserves fetch errors and makes exactly one attempt", async () => {
    const responses = [
      new Response(JSON.stringify({ message: "rate limited" }), {
        headers: { "content-type": "application/json" },
        status: 429,
      }),
      new Response("", { status: 503 }),
      new Response("not json", { headers: { "content-type": "application/json" } }),
    ];
    const { fetch } = captureFetch(() => responses.shift());
    const sender = infraEmail.createEmailSender(config());
    const options = {
      template: "two-factor",
      to: "one@example.test",
      variables: { otpCode: "123456", userEmail: "one@example.test" },
    };

    await expect(sender.send(options)).resolves.toEqual({ success: false, error: "rate limited" });
    await expect(sender.send(options)).resolves.toEqual({ success: false, error: "HTTP 503" });
    await expect(sender.send(options)).resolves.toEqual({
      success: false,
      error: "Failed to parse JSON",
    });
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  test("HTTP error messages preserve truthy non-strings and fallback for falsey values", async () => {
    const messages = [7, true, [], {}, "", 0, false, null];
    const { fetch } = captureFetch(() => new Response(
      JSON.stringify({ message: messages.shift() }),
      { headers: { "content-type": "application/json" }, status: 400 },
    ));
    const sender = infraEmail.createEmailSender(config());
    const options = {
      template: "two-factor",
      to: "one@example.test",
      variables: { otpCode: "123456", userEmail: "one@example.test" },
    };

    for (const expected of [7, true, [], {}]) {
      await expect(sender.send(options)).resolves.toEqual({ success: false, error: expected });
    }
    for (let index = 0; index < 4; index += 1) {
      await expect(sender.send(options)).resolves.toEqual({
        success: false,
        error: "HTTP 400",
      });
    }
    expect(fetch).toHaveBeenCalledTimes(8);
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
      await expect(infraEmail.sendEmail({
        template: "reset-password",
        to: "one@example.test",
        variables: { resetLink: "secret", userEmail: "one@example.test" },
      }, {
        apiKey: "key",
        apiUrl: `http://127.0.0.1:${port}`,
      })).resolves.toEqual({ success: true, messageId: "compressed" });
    } finally {
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  test("single send converts Error and non-Error transport exceptions without retry", async () => {
    const failures = [new Error("offline"), "disconnected"];
    const { fetch } = captureFetch(() => {
      throw failures.shift();
    });
    const sender = infraEmail.createEmailSender(config());
    const options = {
      template: "delete-account",
      to: "one@example.test",
      variables: { deletionLink: "secret", userEmail: "one@example.test" },
    };

    await expect(sender.send(options)).resolves.toEqual({ success: false, error: "offline" });
    await expect(sender.send(options)).resolves.toEqual({
      success: false,
      error: "Failed to send email",
    });
    expect(fetch).toHaveBeenCalledTimes(2);
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
    const options = {
      template: "sign-in-otp",
      to: "one@example.test",
      variables: { otpCode: "123456", userEmail: "one@example.test" },
    };

    const timed = infraEmail.createEmailSender(config({
      apiOptions: { timeout: 10 },
      apiTimeout: 500,
    })).send(options);
    await vi.advanceTimersByTimeAsync(11);
    await expect(timed).resolves.toEqual({ success: false, error: "oracle aborted" });
    expect(signals[0].aborted).toBe(true);

    const legacy = infraEmail.createEmailSender(config({ apiTimeout: 10 })).send(options);
    await vi.advanceTimersByTimeAsync(11);
    await expect(legacy).resolves.toEqual({ success: false, error: "oracle aborted" });
    expect(signals[1].aborted).toBe(true);

    const zero = infraEmail.createEmailSender(config({
      apiOptions: { timeout: 0 },
      apiTimeout: 10,
    })).send(options);
    await vi.advanceTimersByTimeAsync(3_001);
    expect(signals[2].aborted).toBe(false);
    settle(jsonResponse({ messageId: "zero" }));
    await expect(zero).resolves.toEqual({ success: true, messageId: "zero" });

    const defaults = infraEmail.createEmailSender(config()).send(options);
    await vi.advanceTimersByTimeAsync(2_999);
    expect(signals[3].aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(2);
    await expect(defaults).resolves.toEqual({ success: false, error: "oracle aborted" });
    expect(signals[3].aborted).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  test("bulk passes through valid shape and rejects invalid shapes per recipient", async () => {
    const addresses = ["one@example.test", "two@example.test", "one@example.test"];
    const acceptedFailures = "not validated";
    const responses = [
      { success: false, failures: acceptedFailures, ignored: true },
      {},
      [],
      null,
    ];
    const { fetch } = captureFetch(() => jsonResponse(responses.shift()));
    const sender = infraEmail.createEmailSender(config());
    const options = {
      template: "application-invite",
      emails: addresses.map((to) => ({ to })),
    };

    await expect(sender.sendBulk(options)).resolves.toEqual({
      success: false,
      failures: acceptedFailures,
    });
    await expect(sender.sendBulk(options)).resolves.toEqual({
      success: false,
      failures: failureMap(addresses, "Failed to parse JSON"),
    });
    await expect(sender.sendBulk(options)).resolves.toEqual({
      success: false,
      failures: failureMap(addresses, "Failed to parse JSON"),
    });
    await expect(sender.sendBulk(options)).resolves.toEqual({
      success: false,
      failures: failureMap(addresses, "Cannot read properties of null (reading 'success')"),
    });
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  test("bulk fans HTTP and transport failures out once with duplicate collapse", async () => {
    const addresses = ["same@example.test", "other@example.test", "same@example.test"];
    const responses = [
      new Response(JSON.stringify({ message: "denied" }), {
        headers: { "content-type": "application/json" },
        status: 403,
      }),
      new Error("offline"),
      "disconnected",
    ];
    const { fetch } = captureFetch(() => {
      const response = responses.shift();
      if (response instanceof Response) return response;
      throw response;
    });
    const sender = infraEmail.createEmailSender(config());
    const options = {
      template: "stale-account-admin",
      emails: addresses.map((to) => ({ to })),
    };

    await expect(sender.sendBulk(options)).resolves.toEqual({
      success: false,
      failures: failureMap(addresses, "denied"),
    });
    await expect(sender.sendBulk(options)).resolves.toEqual({
      success: false,
      failures: failureMap(addresses, "offline"),
    });
    await expect(sender.sendBulk(options)).resolves.toEqual({
      success: false,
      failures: failureMap(addresses, "Failed to send bulk emails"),
    });
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  test("template listing returns only top-level arrays and swallows failures", async () => {
    const array = [null, "template", { arbitrary: true }];
    const responses = [
      jsonResponse(array),
      jsonResponse({ templates: [] }),
      new Response("not json", { headers: { "content-type": "application/json" } }),
      new Response("bad", { status: 500 }),
      new Error("offline"),
    ];
    const { fetch } = captureFetch(() => {
      const response = responses.shift();
      if (response instanceof Response) return response;
      throw response;
    });
    const sender = infraEmail.createEmailSender(config());

    await expect(sender.getTemplates()).resolves.toEqual(array);
    await expect(sender.getTemplates()).resolves.toEqual([]);
    await expect(sender.getTemplates()).resolves.toEqual([]);
    await expect(sender.getTemplates()).resolves.toEqual([]);
    await expect(sender.getTemplates()).resolves.toEqual([]);
    expect(fetch).toHaveBeenCalledTimes(5);
  });

  test("one-shot wrappers create requests with the same normalization", async () => {
    const { fetch, requests } = captureFetch((_request, _init, index) => index === 0
      ? jsonResponse({ messageId: "wrapper" })
      : jsonResponse({ success: true }));

    await expect(infraEmail.sendEmail({
      template: "verify-email-otp",
      to: "one@example.test",
      variables: { otpCode: "123456", userEmail: "one@example.test" },
    }, config())).resolves.toEqual({ success: true, messageId: "wrapper" });
    await expect(infraEmail.sendBulkEmails({
      template: "verify-email-otp",
      emails: [{ to: "one@example.test" }],
    }, config())).resolves.toEqual({ success: true, failures: undefined });

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(requests.map(({ url }) => url)).toEqual([
      "https://mail.example.test/api/v1/email/send",
      "https://mail.example.test/api/v1/email/send-bulk",
    ]);
  });
});
