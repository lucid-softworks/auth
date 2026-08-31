import { describe, expect, it } from "vitest";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import {
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import {
  ATTR_CONTEXT,
  ATTR_DB_COLLECTION_NAME,
  ATTR_DB_OPERATION_NAME,
  ATTR_HOOK_TYPE,
  ATTR_HTTP_RESPONSE_STATUS_CODE,
  ATTR_HTTP_ROUTE,
  ATTR_OPERATION_ID,
  withSpan,
} from "@better-auth/core/instrumentation";
import { withSpan as withPureSpan } from "./node_modules/@better-auth/core/dist/instrumentation/pure.index.mjs";
import {
  assertPinnedInstrumentationArtifact,
  instrumentationArtifact,
} from "./instrumentation.artifact.mjs";

describe("Better Auth 1.7.2 instrumentation authority", () => {
  it("exports exact constants and span completion semantics", async () => {
    assertPinnedInstrumentationArtifact(await instrumentationArtifact());
    expect({
      ATTR_CONTEXT,
      ATTR_HOOK_TYPE,
      ATTR_OPERATION_ID,
      ATTR_HTTP_ROUTE,
      ATTR_HTTP_RESPONSE_STATUS_CODE,
      ATTR_DB_OPERATION_NAME,
      ATTR_DB_COLLECTION_NAME,
    }).toEqual({
      ATTR_CONTEXT: "better_auth.context",
      ATTR_HOOK_TYPE: "better_auth.hook.type",
      ATTR_OPERATION_ID: "better_auth.operation_id",
      ATTR_HTTP_ROUTE: "http.route",
      ATTR_HTTP_RESPONSE_STATUS_CODE: "http.response.status_code",
      ATTR_DB_OPERATION_NAME: "db.operation.name",
      ATTR_DB_COLLECTION_NAME: "db.collection.name",
    });

    const exporter = new InMemorySpanExporter();
    const provider = new NodeTracerProvider({
      spanProcessors: [new SimpleSpanProcessor(exporter)],
    });
    provider.register();

    // The optional API is loaded lazily. The first call intentionally uses
    // Better Auth's no-op API while the dynamic import settles.
    expect(withSpan("lazy-noop", {}, () => 1)).toBe(1);
    await import("@opentelemetry/api");
    await new Promise((resolve) => setImmediate(resolve));

    expect(
      withSpan("oracle-success", { [ATTR_HTTP_ROUTE]: "/safe/:id" }, () => 7),
    ).toBe(7);

    const ordinary = new Error("ordinary failure");
    expect(() =>
      withSpan("oracle-error", {}, () => {
        throw ordinary;
      }),
    ).toThrow(ordinary);

    const redirect = { name: "APIError", statusCode: 302, message: "redirect" };
    let caughtRedirect;
    try {
      withSpan("oracle-redirect", {}, () => {
        throw redirect;
      });
    } catch (error) {
      caughtRedirect = error;
    }
    expect(caughtRedirect).toBe(redirect);

    const value = await withSpan("oracle-async", {}, async () => "value");
    expect(value).toBe("value");
    const rejected = new Error("rejected failure");
    await expect(
      withSpan("oracle-async-error", {}, async () => {
        throw rejected;
      }),
    ).rejects.toBe(rejected);

    withSpan("oracle-parent", {}, () =>
      withSpan("oracle-child", {}, () => undefined),
    );

    const spans = exporter.getFinishedSpans();
    const find = (name) => spans.find((span) => span.name === name);
    const success = find("oracle-success");
    expect(success.status).toEqual({ code: 0 });
    expect(success.kind).toBe(0);
    expect(success.instrumentationScope).toEqual({
      name: "better-auth",
      version: "1.7.2",
      schemaUrl: undefined,
    });
    expect(success.attributes).toEqual({ [ATTR_HTTP_ROUTE]: "/safe/:id" });

    const failed = find("oracle-error");
    expect(failed.status).toEqual({ code: 2, message: "ordinary failure" });
    expect(failed.events).toHaveLength(1);
    expect(failed.events[0].name).toBe("exception");

    const redirected = find("oracle-redirect");
    expect(redirected.status).toEqual({ code: 1 });
    expect(redirected.events).toHaveLength(0);
    expect(redirected.attributes).toEqual({
      [ATTR_HTTP_RESPONSE_STATUS_CODE]: 302,
    });
    expect(find("oracle-async").status).toEqual({ code: 0 });
    expect(find("oracle-async-error").status).toEqual({
      code: 2,
      message: "rejected failure",
    });
    expect(find("oracle-child").parentSpanContext.spanId).toBe(
      find("oracle-parent").spanContext().spanId,
    );

    expect(withPureSpan("pure-noop", {}, () => "unchanged")).toBe("unchanged");
    expect(find("pure-noop")).toBeUndefined();
    await provider.shutdown();
  });
});
