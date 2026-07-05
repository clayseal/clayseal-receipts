import type {
  AgentInfo,
  AuthorizeResult,
  BiscuitKey,
  Customer,
  VerifierVersion,
  VerifyResult,
} from "./types";

export class ApiClientError extends Error {
  code: string;
  suggestion: string;
  status: number;
  constructor(code: string, message: string, suggestion: string, status: number) {
    super(message);
    this.code = code;
    this.suggestion = suggestion;
    this.status = status;
  }
}

const DEFAULT_BASE_URL =
  (import.meta.env?.VITE_AGENTAUTH_BASE_URL as string | undefined) ??
  "http://localhost:8000";

export class ApiClient {
  baseUrl: string;
  apiKey: string | null;

  constructor(baseUrl: string = DEFAULT_BASE_URL, apiKey: string | null = null) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
  }

  private headers(json = true): HeadersInit {
    const h: Record<string, string> = {};
    if (json) h["Content-Type"] = "application/json";
    if (this.apiKey) h["X-API-Key"] = this.apiKey;
    return h;
  }

  async request<T>(
    method: string,
    path: string,
    opts: { body?: unknown; params?: Record<string, unknown> } = {},
  ): Promise<T> {
    let url = `${this.baseUrl}${path}`;
    if (opts.params) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.params)) {
        if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
      }
      const s = qs.toString();
      if (s) url += `?${s}`;
    }

    let resp: Response;
    try {
      resp = await fetch(url, {
        method,
        headers: this.headers(opts.body !== undefined),
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      });
    } catch (e) {
      throw new ApiClientError(
        "transport_error",
        `Could not reach AgentAuth at ${this.baseUrl}.`,
        "Check the API base URL and that the service is running.",
        0,
      );
    }

    if (!resp.ok) {
      let code = "request_failed";
      let message = `HTTP ${resp.status}`;
      let suggestion = "";
      try {
        const payload = await resp.json();
        if (payload?.error) {
          code = payload.error.code ?? code;
          message = payload.error.message ?? message;
          suggestion = payload.error.suggestion ?? "";
        }
      } catch {
        // non-JSON error body
      }
      throw new ApiClientError(code, message, suggestion, resp.status);
    }

    if (resp.status === 204) return undefined as T;
    const text = await resp.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  // --- tenant bootstrap (no key) ---------------------------------------- //
  createCustomer(name: string): Promise<Customer> {
    return this.request<Customer>("POST", "/v1/customers", { body: { name } });
  }

  // --- agents ------------------------------------------------------------ //
  agents(params: { status?: string; agent_type?: string } = {}): Promise<AgentInfo[]> {
    return this.request<AgentInfo[]>("GET", "/v1/agents", { params });
  }
  agent(id: string): Promise<AgentInfo> {
    return this.request<AgentInfo>("GET", `/v1/agents/${id}`);
  }
  revokeAgent(id: string): Promise<AgentInfo> {
    return this.request<AgentInfo>("POST", `/v1/agents/${id}/revoke`);
  }

  // --- capabilities ------------------------------------------------------ //
  biscuitKeys(): Promise<{ keys: BiscuitKey[] }> {
    return this.request<{ keys: BiscuitKey[] }>("GET", "/v1/biscuit-keys.json");
  }
  authorize(
    token: string,
    operation: { resource: string; action: string },
    pop?: { challenge: string; signature: string; pubkey_pem: string },
  ): Promise<AuthorizeResult> {
    return this.request<AuthorizeResult>("POST", "/v1/authorize", {
      body: { token, operation, pop },
    });
  }

  // --- receipts (L3/L4) -------------------------------------------------- //
  verifierVersion(): Promise<VerifierVersion> {
    return this.request<VerifierVersion>("GET", "/v1/version");
  }
  verifyBundle(bundle: unknown, minAssuranceTier?: string): Promise<VerifyResult> {
    return this.request<VerifyResult>("POST", "/v1/verify", {
      body: bundle,
      params: minAssuranceTier ? { min_assurance_tier: minAssuranceTier } : undefined,
    });
  }
}
