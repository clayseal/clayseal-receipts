// Response shapes mirror the backend Pydantic models (and the Python SDK
// dataclasses) 1:1, so the dashboard, SDK, and API never diverge.

export interface Capability {
  resource: string;
  action: string;
  constraints?: Record<string, unknown> | null;
}

export interface AgentInfo {
  id: string;
  agent_type: string;
  owner: string;
  capabilities: Capability[];
  scopes: string[];
  spiffe_id: string | null;
  selectors: string[];
  bound_keyhash?: string | null;
  has_biscuit?: boolean;
  status: "active" | "expired" | "revoked" | string;
  action_count: number;
  issued_at: string;
  expires_at: string;
}

export interface BiscuitKey {
  kid: string;
  public_key: string;
  alg: string;
  use: string;
  status: string;
}

export interface AuthorizeResult {
  allowed: boolean;
  reason: string;
}

export interface Customer {
  customer_id: string;
  name: string;
  api_key: string;
}

// --- receipts (L3/L4) ----------------------------------------------------- //
export interface VerifyIssue {
  code: string;
  message: string;
}

/** Result of POST /v1/verify — mirrors verifier_server.verify_bundle_payload. */
export interface VerifyResult {
  valid: boolean;
  reasons: string[];
  issues: VerifyIssue[];
  cryptographic?: Record<string, unknown> | null;
  decision?: Record<string, unknown> | null;
  authority?: Record<string, unknown> | null;
  session?: Record<string, unknown> | null;
  assurance?: Record<string, unknown> | null;
  signatures?: Record<string, unknown> | null;
  schema?: string | null;
  proof_id?: string | null;
  sdk_version?: string | null;
  verifier_version: string;
}

export interface VerifierVersion {
  verifier_version: string;
  supported_schemas: string[];
}

export interface ApiError {
  code: string;
  message: string;
  suggestion: string;
}
