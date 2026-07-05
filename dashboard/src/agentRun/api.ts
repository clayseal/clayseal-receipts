const BASE =
  import.meta.env.VITE_REPO_AGENT_UI_URL?.replace(/\/$/, "") || "/agent-run-api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(body || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export type TerminalLine = { kind: string; text: string };

export type ReceiptSummary = {
  tool: string;
  blocked: boolean;
  outcome: string;
  valid: boolean | null;
  violations: string[];
  proof_id: string | null;
};

export type SideBeat = {
  terminal: TerminalLine[];
  receipt: ReceiptSummary | null;
};

export type Beat = {
  id: string;
  title: string;
  narrative: string;
  highlight_file: string | null;
  highlight_line: number | null;
  unsecured: SideBeat;
  secured: SideBeat;
  step_index: number;
  total_steps: number;
  done: boolean;
};

export type AgentRunState = {
  step_index: number;
  total_steps: number;
  done: boolean;
  history: Beat[];
  receipts: Array<{
    tool: string;
    blocked: boolean;
    outcome: string;
    valid: boolean;
    proof_id: string | null;
  }>;
  commands?: {
    task: string;
    unsecured: string;
    secured: string;
  };
};

export type VerifyResult = {
  count: number;
  all_valid: boolean;
  receipts: Array<{
    proof_id: string | null;
    valid: boolean;
    issues: unknown[];
  }>;
};

export function fetchAgentRunState() {
  return request<AgentRunState>("/api/run/state");
}

export function resetAgentRun() {
  return request<AgentRunState>("/api/run/reset", { method: "POST" });
}

export function stepAgentRun() {
  return request<{ beat: Beat; state: AgentRunState }>("/api/run/step", { method: "POST" });
}

export function verifyAgentRun() {
  return request<VerifyResult>("/api/run/verify", { method: "POST" });
}

export function fetchRepoFile(path: string) {
  return request<{ path: string; content: string }>(
    `/api/repo/file?path=${encodeURIComponent(path)}`,
  );
}

export function fetchRepoFiles() {
  return request<{ files: string[] }>("/api/repo/files");
}
