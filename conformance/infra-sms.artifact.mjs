import { createRequire } from "node:module";
import { describe, expect, test } from "vitest";
import {
  infraRoot,
  infraText,
  packageJson,
  packageLock,
} from "./infra-sms.helpers.mjs";

const require = createRequire(import.meta.url);

describe("@better-auth/infra@0.4.3 SMS artifact oracle", () => {
  test("pins the artifact, registry metadata, and effective runtime", async () => {
    const pkg = await packageJson("@better-auth/infra");
    const lock = await packageLock();
    const locked = lock.packages["node_modules/@better-auth/infra"];

    expect(pkg.version).toBe("0.4.3");
    expect(pkg.dependencies["@better-fetch/fetch"]).toBe("1.3.1");
    expect(locked.resolved).toBe(
      "https://registry.npmjs.org/@better-auth/infra/-/infra-0.4.3.tgz",
    );
    expect(locked.integrity).toBe(
      "sha512-wQAdFoFxD/waZYHyF9hKIf8jAnWxVK0R2S28Q/4vCrXWCDKBn5ZVZb1Sy8UHcmbnr1p7xuscBZJTPoFfE6y89A==",
    );
    expect({
      integrity: locked.integrity,
      sha1: "f20fabec398194cae23ccc35c324eccf8796e4db",
    }).toEqual({
      integrity: "sha512-wQAdFoFxD/waZYHyF9hKIf8jAnWxVK0R2S28Q/4vCrXWCDKBn5ZVZb1Sy8UHcmbnr1p7xuscBZJTPoFfE6y89A==",
      sha1: "f20fabec398194cae23ccc35c324eccf8796e4db",
    });
    expect((await packageJson("better-auth")).version).toBe("1.7.1");
    expect((await packageJson("@better-auth/core")).version).toBe("1.7.1");
    expect((await packageJson("@better-fetch/fetch")).version).toBe("1.3.1");
  });

  test("SMS is exported only from the package root", () => {
    expect(Object.keys(infraRoot)).toEqual([
      "CHALLENGE_TTL", "DEFAULT_DIFFICULTY", "EMAIL_TEMPLATES", "SMS_TEMPLATES",
      "USER_EVENT_TYPES", "createEmailSender", "createSMSSender", "dash",
      "decodePoWChallenge", "encodePoWSolution", "normalizeEmail", "sendBulkEmails",
      "sendEmail", "sendSMS", "sentinel", "solvePoWChallenge", "verifyPoWSolution",
    ]);
    expect(Object.keys(infraRoot.createSMSSender({ apiKey: "key" }))).toEqual(["send"]);
    expect(() => require.resolve("@better-auth/infra/sms")).toThrow(
      expect.objectContaining({ code: "ERR_PACKAGE_PATH_NOT_EXPORTED" }),
    );
    expect(() => require.resolve("@better-auth/infra/sms/client")).toThrow(
      expect.objectContaining({ code: "ERR_PACKAGE_PATH_NOT_EXPORTED" }),
    );
  });

  test("publishes exactly three inert runtime template descriptors", () => {
    expect(Object.keys(infraRoot.SMS_TEMPLATES)).toEqual([
      "phone-verification", "two-factor", "sign-in-otp",
    ]);
    expect(infraRoot.SMS_TEMPLATES).toEqual({
      "phone-verification": { variables: {} },
      "two-factor": { variables: {} },
      "sign-in-otp": { variables: {} },
    });
    expect(infraRoot.SMS_TEMPLATES).not.toHaveProperty("password-reset");
  });

  test("declarations expose only the published config, options, results, and variables", async () => {
    const declarations = await infraText("dist/index.d.mts");
    const sms = declarations.slice(
      declarations.indexOf("//#region src/sms.d.ts"),
      declarations.indexOf("//#endregion", declarations.indexOf("//#region src/sms.d.ts")),
    );

    for (const declaration of [
      "type SMSTemplateId = keyof typeof SMS_TEMPLATES;",
      "type SMSTemplateVariables<T extends SMSTemplateId>",
      "interface SendSMSResult",
      "interface SMSConfig",
      "interface SendSMSOptions",
      "declare function createSMSSender(config?: SMSConfig)",
      "declare function sendSMS(options: SendSMSOptions, config?: SMSConfig)",
      "to: string;",
      "code: string;",
      "template?: SMSTemplateId;",
      "clientIp?: string;",
      "timeout?: number;",
      "@deprecated Use `apiOptions.timeout` instead.",
    ]) {
      expect(sms).toContain(declaration);
    }
    expect(sms.match(/readonly variables: \{[\s\S]*?\};/g)).toHaveLength(3);
    expect(sms).not.toMatch(/password-reset|locale|requestId|idempotency|variables\?:/i);
  });

  test("runtime has no plugin, automatic Dash/Sentinel wiring, or added delivery features", async () => {
    const runtime = await infraText("dist/index.mjs");
    const sms = runtime.slice(
      runtime.indexOf("//#region src/sms.ts"),
      runtime.indexOf("//#endregion", runtime.indexOf("//#region src/sms.ts")),
    );

    expect(sms).toContain('"/v1/sms/send"');
    expect(sms).not.toMatch(/createAuthEndpoint|BetterAuthPlugin|clientPlugin|schema|migration/i);
    expect(sms).not.toMatch(/retry|backoff|idempot|locale|requestId|provider|queue|webhook/i);
    expect(String(infraRoot.dash)).not.toMatch(/createSMSSender|sendSMS/);
    expect(String(infraRoot.sentinel)).not.toMatch(/createSMSSender|sendSMS/);
  });
});
