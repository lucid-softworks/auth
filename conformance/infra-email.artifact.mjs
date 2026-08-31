import { createRequire } from "node:module";
import { describe, expect, test } from "vitest";
import {
  infraEmail,
  infraRoot,
  infraText,
  packageJson,
  packageLock,
} from "./infra-email.helpers.mjs";

const require = createRequire(import.meta.url);

const templateVariables = {
  "verify-email": [
    "verificationCode?: string;", "verificationUrl: string;", "userEmail: string;",
    "userName?: string;", "appName?: string;", "expirationMinutes?: string;",
  ],
  "reset-password": [
    "resetLink: string;", "userEmail: string;", "userName?: string;",
    "appName?: string;", "expirationMinutes?: string;",
  ],
  "change-email": [
    "confirmationLink: string;", "newEmail: string;", "currentEmail: string;",
    "userName?: string;", "appName?: string;", "expirationMinutes?: string;",
  ],
  "sign-in-otp": [
    "otpCode: string;", "userEmail: string;", "appName?: string;",
    "expirationMinutes?: string;",
  ],
  "verify-email-otp": [
    "otpCode: string;", "userEmail: string;", "appName?: string;",
    "expirationMinutes?: string;",
  ],
  "reset-password-otp": [
    "otpCode: string;", "userEmail: string;", "appName?: string;",
    "expirationMinutes?: string;",
  ],
  "magic-link": [
    "magicLink: string;", "userEmail: string;", "appName?: string;",
    "expirationMinutes?: string;",
  ],
  "two-factor": [
    "otpCode: string;", "userEmail: string;", "userName?: string;",
    "appName?: string;", "expirationMinutes?: string;",
  ],
  invitation: [
    "inviteLink: string;", "inviterName: string;", "inviterEmail: string;",
    "organizationName: string;", "role: string;", "appName?: string;",
    "expirationDays?: string;",
  ],
  "application-invite": [
    "inviteLink: string;", "inviterName: string;", "inviterEmail: string;",
    "inviteeEmail: string;", "appName?: string;", "expirationDays?: string;",
  ],
  "delete-account": [
    "deletionLink: string;", "userEmail: string;", "userName?: string;",
    "appName?: string;", "expirationMinutes?: string;",
  ],
  "stale-account-user": [
    "userEmail: string;", "userName?: string;", "appName?: string;",
    "daysSinceLastActive: string;", "loginTime: string;", "loginLocation?: string;",
    "loginDevice?: string;", "loginIp?: string;",
  ],
  "stale-account-admin": [
    "userEmail: string;", "userName?: string;", "userId: string;",
    "appName?: string;", "daysSinceLastActive: string;", "loginTime: string;",
    "loginLocation?: string;", "loginDevice?: string;", "loginIp?: string;",
    "adminEmail: string;",
  ],
};

describe("@better-auth/infra@0.4.3 email artifact oracle", () => {
  test("pins the artifact, registry metadata, exports, and effective runtime", async () => {
    const pkg = await packageJson("@better-auth/infra");
    const lock = await packageLock();
    const locked = lock.packages["node_modules/@better-auth/infra"];

    expect(pkg.version).toBe("0.4.3");
    expect(pkg.exports).toEqual({
      ".": {
        types: "./dist/index.d.mts",
        import: "./dist/index.mjs",
        default: "./dist/index.mjs",
      },
      "./client": {
        types: "./dist/client.d.mts",
        import: "./dist/client.mjs",
        default: "./dist/client.mjs",
      },
      "./email": {
        types: "./dist/email.d.mts",
        import: "./dist/email.mjs",
        default: "./dist/email.mjs",
      },
      "./native": {
        types: "./dist/native.d.mts",
        import: "./dist/native.mjs",
        default: "./dist/native.mjs",
      },
    });
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
    expect((await packageJson("better-auth")).version).toBe("1.7.2");
    expect((await packageJson("@better-auth/core")).version).toBe("1.7.2");
    expect((await packageJson("@better-fetch/fetch")).version).toBe("1.3.1");
  });

  test("root and email subpath share the four email runtime exports", () => {
    expect(Object.keys(infraEmail)).toEqual([
      "EMAIL_TEMPLATES", "createEmailSender", "sendBulkEmails", "sendEmail",
    ]);
    for (const name of Object.keys(infraEmail)) {
      expect(infraRoot[name]).toBe(infraEmail[name]);
    }
    for (const absent of [
      "getTemplates", "email", "emailClient", "emailPlugin", "schema", "migrations",
    ]) {
      expect(infraEmail).not.toHaveProperty(absent);
    }
    expect(() => require.resolve("@better-auth/infra/email/client")).toThrow(
      expect.objectContaining({ code: "ERR_PACKAGE_PATH_NOT_EXPORTED" }),
    );
  });

  test("publishes exactly thirteen inert runtime template descriptors", () => {
    expect(Object.keys(infraEmail.EMAIL_TEMPLATES)).toEqual(Object.keys(templateVariables));
    expect(infraEmail.EMAIL_TEMPLATES).toEqual(Object.fromEntries(
      Object.keys(templateVariables).map((template) => [template, { variables: {} }]),
    ));
  });

  test("declarations pin required and optional variables without runtime validation", async () => {
    const declarations = await infraText("dist/email.d.mts");
    for (const [template, variables] of Object.entries(templateVariables)) {
      const quoted = template === "invitation" ? "invitation" : `\"${template}\"`;
      const match = declarations.match(new RegExp(
        `readonly ${quoted}: \\{\\s+readonly variables: \\{([^}]*)\\}`,
      ));
      expect(match, `missing declaration for ${template}`).not.toBeNull();
      expect(match[1].trim().split(/\n/).map((line) => line.trim())).toEqual(variables);
    }
    for (const declaration of [
      "type EmailTemplateId = keyof typeof EMAIL_TEMPLATES;",
      "type EmailTemplateVariables<T extends EmailTemplateId>",
      "interface SendEmailResult",
      "interface EmailConfig",
      "type SendEmailOptions<T extends EmailTemplateId = EmailTemplateId>",
      "type SendBulkEmailsOptions<T extends EmailTemplateId = EmailTemplateId>",
      "interface SendBulkEmailsResult",
    ]) {
      expect(declarations).toContain(declaration);
    }
    expect(declarations).toContain("timeout?: number;");
    expect(declarations).toContain("@deprecated Use `apiOptions.timeout` instead.");
  });

  test("runtime contains no plugin, route, retry, locale, or provider abstraction", async () => {
    const runtime = await infraText("dist/email.mjs");
    expect(runtime).not.toMatch(/createAuthEndpoint|BetterAuthPlugin|clientPlugin|schema|migration/i);
    expect(runtime).not.toMatch(/retry|backoff|idempot|locale|requestId|callbackURL/i);
    expect(runtime).not.toMatch(/attachment|provider|queue|ledger/i);
    expect(runtime).toContain('"/v1/email/send"');
    expect(runtime).toContain('"/v1/email/send-bulk"');
    expect(runtime).toContain('"/v1/email/templates"');
  });
});
