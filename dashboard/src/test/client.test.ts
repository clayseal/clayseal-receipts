import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient, ApiClientError } from "../api/client";

function mockFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k: string) => headers[k.toLowerCase()] ?? null },
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
    json: async () => body,
    blob: async () => new Blob([JSON.stringify(body)]),
  });
}

afterEach(() => vi.restoreAllMocks());

describe("ApiClient", () => {
  it("attaches the API key header and parses JSON", async () => {
    const fetchMock = mockFetch(200, [{ id: "a1", agent_type: "x" }]);
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient("http://api.test", "aa_key");
    const agents = await client.agents();
    expect(agents).toHaveLength(1);
    const [, opts] = fetchMock.mock.calls[0];
    expect((opts.headers as Record<string, string>)["X-API-Key"]).toBe("aa_key");
  });

  it("builds query params, skipping empty values", async () => {
    const fetchMock = mockFetch(200, []);
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient("http://api.test", "k");
    await client.agents({ status: "active", agent_type: undefined });
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("status=active");
    expect(url).not.toContain("agent_type");
  });

  it("maps the backend error envelope to ApiClientError", async () => {
    const fetchMock = mockFetch(401, {
      error: { code: "invalid_api_key", message: "bad key", suggestion: "use a real key" },
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient("http://api.test", "nope");
    await expect(client.agents()).rejects.toMatchObject({
      code: "invalid_api_key",
      message: "bad key",
      suggestion: "use a real key",
      status: 401,
    });
  });

  it("raises a transport_error when fetch throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    const client = new ApiClient("http://api.test", "k");
    await expect(client.agents()).rejects.toBeInstanceOf(ApiClientError);
    await expect(client.agents()).rejects.toMatchObject({ code: "transport_error" });
  });

  it("revokes an agent", async () => {
    const fetchMock = mockFetch(200, { id: "a1", status: "revoked" });
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient("http://api.test", "k");
    const agent = await client.revokeAgent("a1");
    expect(agent.status).toBe("revoked");
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://api.test/v1/agents/a1/revoke");
    expect(opts.method).toBe("POST");
  });

  it("verifies a receipt bundle via POST /v1/verify", async () => {
    const fetchMock = mockFetch(200, {
      valid: false,
      reasons: ["shadow mode"],
      issues: [{ code: "proof_invalid", message: "shadow" }],
      schema: "receipt-bundle/v2",
      verifier_version: "0.2.1",
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient("http://api.test", "k");
    const result = await client.verifyBundle({ schema: "receipt-bundle/v2" });
    expect(result.valid).toBe(false);
    expect(result.issues[0].code).toBe("proof_invalid");
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://api.test/v1/verify");
    expect(opts.method).toBe("POST");
  });

  it("fetches the verifier version + supported schemas", async () => {
    const fetchMock = mockFetch(200, {
      verifier_version: "0.2.1",
      supported_schemas: ["receipt-bundle/v1", "receipt-bundle/v2"],
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient("http://api.test", "k");
    const v = await client.verifierVersion();
    expect(v.supported_schemas).toHaveLength(2);
    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://api.test/v1/version");
  });
});
