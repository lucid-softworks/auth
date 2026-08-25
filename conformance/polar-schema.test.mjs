import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, test } from "vitest";

import { Customer$inboundSchema } from "./node_modules/@polar-sh/sdk/dist/esm/models/components/customer.js";
import { CheckoutCreate$outboundSchema } from "./node_modules/@polar-sh/sdk/dist/esm/models/components/checkoutcreate.js";
import { CustomerCreate$outboundSchema } from "./node_modules/@polar-sh/sdk/dist/esm/models/components/customercreate.js";
import { EventsIngestResponse$inboundSchema } from "./node_modules/@polar-sh/sdk/dist/esm/models/components/eventsingestresponse.js";
import { ListResourceCustomer$inboundSchema } from "./node_modules/@polar-sh/sdk/dist/esm/models/components/listresourcecustomer.js";
import { CustomersListRequest$outboundSchema } from "./node_modules/@polar-sh/sdk/dist/esm/models/operations/customerslist.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const components = path.join(here, "node_modules", "@polar-sh", "sdk", "dist", "esm", "models", "components");
const catalogPath = path.join(here, "..", "src", "polar", "schema", "sdk-0.47.1.json");

const customer = {
  id: "customer_1",
  created_at: "2025-01-01T01:02:03.4567+01:00",
  modified_at: null,
  metadata: { dynamic_key: "kept" },
  email: "person@example.com",
  email_verified: true,
  type: "individual",
  name: null,
  billing_address: {
    line1: "1 Main Street",
    country: "GB",
    provider_only: true,
  },
  tax_id: null,
  organization_id: "organization_1",
  deleted_at: null,
  avatar_url: "https://example.test/avatar",
  provider_only: true,
};

describe("pinned Polar SDK schema oracle", () => {
  test("projects every object level, keeps record keys, and materializes Date values", () => {
    const normalized = Customer$inboundSchema.parse(customer);
    expect(normalized.createdAt).toBeInstanceOf(Date);
    expect(normalized.createdAt.toJSON()).toBe("2025-01-01T00:02:03.456Z");
    expect(normalized).not.toHaveProperty("providerOnly");
    expect(normalized.billingAddress).not.toHaveProperty("providerOnly");
    expect(normalized.metadata.dynamic_key).toBe("kept");
  });

  test("requires full nested objects, defaults ingestion duplicates, and enforces safe integers", () => {
    expect(() => Customer$inboundSchema.parse({ id: "customer_1" })).toThrow();
    expect(EventsIngestResponse$inboundSchema.parse({ inserted: 1 })).toEqual({
      inserted: 1,
      duplicates: 0,
    });
    expect(() => EventsIngestResponse$inboundSchema.parse({ inserted: Number.MAX_SAFE_INTEGER + 1 })).toThrow();
    expect(ListResourceCustomer$inboundSchema.parse({
      items: [customer],
      pagination: { total_count: 1, max_page: 1, provider_only: true },
      provider_only: true,
    })).toMatchObject({
      items: [{ id: "customer_1" }],
      pagination: { totalCount: 1, maxPage: 1 },
    });
  });

  test("the SDK recognizes exactly 35 webhook schemas and validates every data schema", async () => {
    const files = (await readdir(components)).filter(file => /^webhook.*payload\.js$/.test(file)).sort();
    const eventTypes = [];
    for (const file of files) {
      const module = await import(pathToFileURL(path.join(components, file)));
      const schema = Object.entries(module).find(([name]) => name.endsWith("$inboundSchema"))?.[1];
      if (!schema) continue;
      const type = schema._zod.def.type === "pipe"
        ? schema._zod.def.in._zod.def.shape.type._zod.def.values[0]
        : schema._zod.def.shape.type._zod.def.values[0];
      eventTypes.push(type);
      expect(() => schema.parse({
        type,
        timestamp: "2025-01-01T00:00:00Z",
        data: { id: "incomplete" },
      }), type).toThrow();
    }
    expect(new Set(eventTypes).size).toBe(35);
  });

  test("outbound schemas remap wire keys and materialize SDK defaults", () => {
    expect(CheckoutCreate$outboundSchema.parse({
      products: ["product_1"],
      externalCustomerId: "user_1",
      allowDiscountCodes: true,
      metadata: { referenceId: "reference_1" },
    })).toEqual({
      products: ["product_1"],
      external_customer_id: "user_1",
      allow_discount_codes: true,
      allow_trial: true,
      is_business_customer: false,
      metadata: { referenceId: "reference_1" },
      require_billing_address: false,
    });
    expect(CustomerCreate$outboundSchema.parse({
      email: "person@example.com",
      name: null,
    })).toEqual({
      email: "person@example.com",
      name: null,
      type: "individual",
    });
    expect(CustomersListRequest$outboundSchema.parse({ email: "person@example.com" })).toEqual({
      email: "person@example.com",
      page: 1,
      limit: 10,
    });
  });

  test("the checked-in native catalog records every pinned SDK root", async () => {
    const catalog = JSON.parse(await readFile(catalogPath, "utf8"));
    expect(catalog.generatedFrom).toBe("@polar-sh/sdk@0.47.1");
    expect(Object.keys(catalog.roots).filter(root => root.startsWith("webhook:"))).toHaveLength(35);
    expect(Object.keys(catalog.roots).filter(root => root.startsWith("outbound:"))).toHaveLength(12);
    expect(Object.keys(catalog.roots)).toHaveLength(58);
  });
});
