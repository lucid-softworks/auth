import { readFile } from "node:fs/promises";
import { describe, expect, test, vi } from "vitest";
import { decodeJwt, decodeProtectedHeader, jwtVerify } from "jose";
import { generateId } from "@better-auth/core/utils/id";
import { createEmailVerificationToken } from "better-auth/api";

const packageMetadata = JSON.parse(
  await readFile(new URL("node_modules/better-auth/package.json", import.meta.url), "utf8"),
);
const coreMetadata = JSON.parse(
  await readFile(new URL("node_modules/@better-auth/core/package.json", import.meta.url), "utf8"),
);
const internalAdapter = await readFile(
  new URL("node_modules/better-auth/dist/db/internal-adapter.mjs", import.meta.url),
  "utf8",
);
const passwordRoutes = await readFile(
  new URL("node_modules/better-auth/dist/api/routes/password.mjs", import.meta.url),
  "utf8",
);
const emailRoutes = await readFile(
  new URL("node_modules/better-auth/dist/api/routes/email-verification.mjs", import.meta.url),
  "utf8",
);
const updateRoutes = await readFile(
  new URL("node_modules/better-auth/dist/api/routes/update-user.mjs", import.meta.url),
  "utf8",
);

describe("Better Auth 1.7.1 core lifecycle token oracle", () => {
  test("pins the packages and base-62 ID generator", () => {
    expect(packageMetadata.version).toBe("1.7.1");
    expect(coreMetadata.version).toBe("1.7.1");
    for (const size of [24, 32]) {
      const values = Array.from({ length: 128 }, () => generateId(size));
      expect(values.every((value) => value.length === size)).toBe(true);
      expect(values.every((value) => /^[a-zA-Z0-9]+$/.test(value))).toBe(true);
      expect(new Set(values).size).toBeGreaterThan(1);
    }
    expect(internalAdapter).toContain("token: generateId(32)");
  });

  test("pins email JWT header, lowercasing, iat, exp, and signature", async () => {
    const secret = "lifecycle-token-oracle-secret-at-least-32-bytes";
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00.000Z"));
    try {
      const token = await createEmailVerificationToken(
        secret,
        "Current@Example.com",
        "New@Example.com",
        1_800,
        { requestType: "change-email-confirmation" },
      );
      expect(decodeProtectedHeader(token)).toEqual({ alg: "HS256" });
      expect(decodeJwt(token)).toEqual({
        email: "current@example.com",
        updateTo: "new@example.com",
        requestType: "change-email-confirmation",
        iat: 1_704_067_200,
        exp: 1_704_069_000,
      });
      await expect(
        jwtVerify(token, new TextEncoder().encode(secret), { algorithms: ["HS256"] }),
      ).resolves.toBeDefined();
    } finally {
      vi.useRealTimers();
    }
  });

  test("pins reset, change-email, and deletion artifact ordering and identifiers", () => {
    expect(passwordRoutes).toContain("generateId(24)");
    expect(passwordRoutes).toContain('findVerificationValue("dummy-verification-token")');
    expect(passwordRoutes).toContain('logger.warn("Reset Password: User not found")');
    expect(passwordRoutes).toContain("identifier: `reset-password:${verificationToken}`");
    expect(passwordRoutes.indexOf("onPasswordReset({ user }")).toBeLessThan(
      passwordRoutes.lastIndexOf("revokeSessionsOnPasswordReset"),
    );

    expect(emailRoutes).toContain('case "change-email-confirmation"');
    expect(emailRoutes).toContain('case "change-email-verification"');
    expect(emailRoutes).toContain("Legacy flow");
    expect(emailRoutes).toContain("emailVerified: false");

    expect(updateRoutes).toContain('generateRandomString(32, "0-9", "a-z")');
    expect(updateRoutes).toContain("identifier: `delete-account-${token}`");
    expect(updateRoutes.indexOf("consumeVerificationValue(`delete-account-")).toBeLessThan(
      updateRoutes.indexOf("token.value !== session.user.id"),
    );
  });
});
