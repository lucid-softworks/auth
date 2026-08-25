import assert from "node:assert/strict";
import { AgentAuthClient, MemoryStorage } from "@auth/agent";

const AUTH_PATH = "/api/auth";

export async function agentAuthNativeConformance(origin) {
  const session = await FixtureSession.create(origin);
  await enrolledHostApprovalConformance(origin, session);
  await autonomousClaimConformance(origin, session);
  console.log("ok - official Agent Auth SDK against native server");
}

async function enrolledHostApprovalConformance(origin, session) {
  const created = await session.post("/host/create", {
    name: "Pre-enrolled SDK host",
  });
  assert.equal(created.status, "pending_enrollment");
  assert.equal(typeof created.enrollmentToken, "string");

  const state = { agentId: null };
  const approvals = ["device_authorization", "ciba"];
  const storage = new MemoryStorage();
  const client = new AgentAuthClient({
    urls: [origin],
    storage,
    hostName: "Enrolled SDK host",
    fetch: captureAgentId(state),
    approvalTimeoutMs: 20_000,
    onApprovalRequired: async (approval) => {
      const expected = approvals.shift();
      assert.equal(approval.method, expected);
      assert.equal(typeof state.agentId, "string");
      const body = {
        agent_id: state.agentId,
        action: "approve",
      };
      if (approval.method === "device_authorization") {
        assert.match(approval.user_code, /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
        body.user_code = approval.user_code;
      }
      const resolved = await session.post("/agent/approve-capability", body);
      assert.equal(resolved.status, "approved");
    },
  });
  try {
    const [provider] = await client.init();
    assert.equal(provider.provider_name, "Lucid Agent Conformance");
    const enrolled = await client.enrollHost({
      provider: provider.issuer,
      enrollmentToken: created.enrollmentToken,
      name: "Enrolled SDK host",
    });
    assert.equal(enrolled.hostId, created.hostId);
    assert.equal(enrolled.status, "active");
    assert.deepEqual(enrolled.default_capabilities, ["notes.read"]);

    const connection = await client.connectAgent({
      provider: provider.issuer,
      mode: "delegated",
      name: "Device-approved SDK agent",
      capabilities: ["notes.read"],
      preferredMethod: "device_authorization",
      forceApproval: true,
    });
    assert.equal(connection.status, "active");
    assert.deepEqual(
      connection.capabilityGrants.map((grant) => [grant.capability, grant.status]),
      [["notes.read", "active"]],
    );

    const batch = await client.batchExecuteCapabilities({
      agentId: connection.agentId,
      requests: [
        { id: "read-one", capability: "notes.read" },
        { id: "read-two", capability: "notes.read" },
      ],
    });
    assert.deepEqual(
      batch.responses.map((response) => [response.id, response.status]),
      [
        ["read-one", "completed"],
        ["read-two", "completed"],
      ],
    );

    const escalation = await client.requestCapability({
      agentId: connection.agentId,
      capabilities: ["notes.write"],
      preferredMethod: "ciba",
      loginHint: "luna@example.com",
      bindingMessage: "Approve notes.write for conformance",
    });
    assert.ok(escalation.granted.includes("notes.write"));
    assert.equal(approvals.length, 0);
    const executed = await client.executeCapability({
      agentId: connection.agentId,
      capability: "notes.write",
      arguments: { title: "native" },
    });
    assert.deepEqual(executed.data, {
      capability: "notes.write",
      arguments: { title: "native" },
      agent_id: connection.agentId,
    });
    await client.disconnectAgent(connection.agentId);
    assert.equal(await client.getConnection(connection.agentId), null);
  } finally {
    client.destroy();
  }
}

async function autonomousClaimConformance(origin, session) {
  const state = { agentId: null };
  const storage = new MemoryStorage();
  let approvalSeen = false;
  const client = new AgentAuthClient({
    urls: [origin],
    storage,
    hostName: "Autonomous claim SDK host",
    fetch: captureAgentId(state),
    approvalTimeoutMs: 20_000,
    onApprovalRequired: async (approval) => {
      approvalSeen = true;
      assert.equal(approval.method, "device_authorization");
      assert.equal(typeof state.agentId, "string");
      assert.match(approval.user_code, /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
      const resolved = await session.post("/agent/approve-capability", {
        agent_id: state.agentId,
        user_code: approval.user_code,
        action: "approve",
      });
      assert.equal(resolved.status, "approved");
      assert.equal(resolved.claimed, true);
    },
  });
  try {
    const [provider] = await client.init();
    const autonomous = await client.connectAgent({
      provider: provider.issuer,
      mode: "autonomous",
      name: "Claimable autonomous SDK agent",
      capabilities: ["notes.read"],
    });
    assert.equal(autonomous.status, "active");
    const original = await client.getConnection(autonomous.agentId);

    const claimed = await client.claimAgent({
      provider: provider.issuer,
      agentId: autonomous.agentId,
      preferredMethod: "device_authorization",
      bindingMessage: "Claim autonomous conformance agent",
    });
    assert.equal(approvalSeen, true);
    assert.equal(claimed.agentId, autonomous.agentId);
    assert.equal(claimed.hostId, autonomous.hostId);
    assert.equal(claimed.status, "claimed");

    const listed = await session.get("/agent/list?mode=autonomous");
    assert.ok(
      listed.agents.some(
        (agent) => agent.agent_id === autonomous.agentId && agent.status === "claimed",
      ),
    );

    // Upstream 0.6.2 stores a fresh unrelated keypair after claim without
    // sending that public key to the server. Assert the pinned defect instead
    // of teaching the server an alternate claim shape.
    const local = await client.getConnection(autonomous.agentId);
    assert.notDeepEqual(local.agentKeypair.publicKey, original.agentKeypair.publicKey);
  } finally {
    client.destroy();
  }
}

function captureAgentId(state) {
  return async (input, init) => {
    const response = await fetch(input, init);
    const path = new URL(input instanceof Request ? input.url : input).pathname;
    if (
      response.ok &&
      ["/agent/register", "/agent/request-capability", "/agent/claim"].some((suffix) =>
        path.endsWith(suffix),
      )
    ) {
      const body = await response.clone().json();
      if (typeof body.agent_id === "string") state.agentId = body.agent_id;
    }
    return response;
  };
}

class FixtureSession {
  constructor(origin, cookie) {
    this.origin = origin;
    this.cookie = cookie;
  }

  static async create(origin) {
    const response = await fetch(`${origin}/__conformance__/session/password`, {
      method: "POST",
    });
    assert.equal(response.status, 200);
    const setCookie = response.headers.getSetCookie()[0];
    assert.equal(typeof setCookie, "string");
    return new FixtureSession(origin, setCookie.split(";", 1)[0]);
  }

  async get(path) {
    return this.request(path, { method: "GET" });
  }

  async post(path, body) {
    return this.request(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  async request(path, init) {
    const headers = new Headers(init.headers);
    headers.set("cookie", this.cookie);
    headers.set("origin", this.origin);
    const response = await fetch(`${this.origin}${AUTH_PATH}${path}`, {
      ...init,
      headers,
    });
    const body = await response.json();
    assert.equal(
      response.ok,
      true,
      `${init.method} ${path} failed (${response.status}): ${JSON.stringify(body)}`,
    );
    return body;
  }
}
