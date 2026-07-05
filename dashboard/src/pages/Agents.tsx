import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "../auth/AuthContext";
import type { AgentInfo, Capability } from "../api/types";

/** Render a capability as a compact "resource:action" label. */
function capLabel(c: Capability): string {
  return `${c.resource}:${c.action}`;
}

/** The fine-grained capabilities, falling back to legacy scope strings. */
function capPills(agent: AgentInfo): string[] {
  if (agent.capabilities && agent.capabilities.length > 0) {
    return agent.capabilities.map(capLabel);
  }
  return agent.scopes;
}
import {
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Pill,
  Spinner,
  StatusBadge,
  fmtTime,
} from "../components/ui";

export function Agents() {
  const { client } = useAuth();
  const [status, setStatus] = useState("");
  const [type, setType] = useState("");
  const [selected, setSelected] = useState<AgentInfo | null>(null);

  const agentsQuery = useQuery({
    queryKey: ["agents", status, type],
    queryFn: () => client.agents({ status: status || undefined, agent_type: type || undefined }),
  });

  return (
    <div>
      <div className="mb-4 flex items-end justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-white">Agents</h1>
          <p className="text-sm text-slate-400">
            Every agent instance that has called your API key.
          </p>
        </div>
        <div className="flex gap-2">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
          >
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="expired">Expired</option>
            <option value="revoked">Revoked</option>
          </select>
          <input
            value={type}
            onChange={(e) => setType(e.target.value)}
            placeholder="Filter by type"
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
          />
        </div>
      </div>

      {agentsQuery.isLoading && <Spinner />}
      {agentsQuery.isError && <ErrorNote error={agentsQuery.error} />}
      {agentsQuery.data && agentsQuery.data.length === 0 && (
        <EmptyState>No agents yet. Call identify() from the SDK to create one.</EmptyState>
      )}

      {agentsQuery.data && agentsQuery.data.length > 0 && (
        <Card className="overflow-hidden">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-800 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-2">Type</th>
                <th className="px-4 py-2">Owner</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Capabilities</th>
                <th className="px-4 py-2">Actions</th>
                <th className="px-4 py-2">Expires</th>
              </tr>
            </thead>
            <tbody>
              {agentsQuery.data.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => setSelected(a)}
                  className="cursor-pointer border-b border-slate-800/50 hover:bg-slate-800/40"
                >
                  <td className="px-4 py-2 font-mono text-xs text-slate-200">{a.agent_type}</td>
                  <td className="px-4 py-2 text-slate-300">{a.owner}</td>
                  <td className="px-4 py-2"><StatusBadge status={a.status} /></td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {capPills(a).map((s) => <Pill key={s}>{s}</Pill>)}
                    </div>
                  </td>
                  <td className="px-4 py-2 text-slate-400">{a.action_count}</td>
                  <td className="px-4 py-2 text-xs text-slate-500">{fmtTime(a.expires_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {selected && <AgentDrawer agent={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function AgentDrawer({ agent, onClose }: { agent: AgentInfo; onClose: () => void }) {
  const { client } = useAuth();
  const qc = useQueryClient();

  const revoke = useMutation({
    mutationFn: () => client.revokeAgent(agent.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agents"] });
    },
  });

  return (
    <div className="fixed inset-0 z-20 flex justify-end bg-black/50" onClick={onClose}>
      <div
        className="h-full w-full max-w-lg overflow-y-auto border-l border-slate-800 bg-slate-950 p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div>
            <div className="font-mono text-sm text-white">{agent.agent_type}</div>
            <div className="font-mono text-xs text-slate-500">{agent.id}</div>
          </div>
          <Button variant="ghost" onClick={onClose}>Close</Button>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
          <Meta label="Owner" value={agent.owner} />
          <Meta label="Status"><StatusBadge status={agent.status} /></Meta>
          <Meta label="Action count" value={String(agent.action_count)} />
          <Meta label="SPIFFE ID" value={agent.spiffe_id ?? "—"} />
          <Meta label="Issued" value={fmtTime(agent.issued_at)} />
          <Meta label="Expires" value={fmtTime(agent.expires_at)} />
        </div>

        <h3 className="mt-6 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
          Capabilities
          <span
            className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
              agent.has_biscuit
                ? "bg-emerald-500/15 text-emerald-300"
                : "bg-slate-700/50 text-slate-400"
            }`}
          >
            {agent.has_biscuit ? "PoP-bound" : "JWT-only"}
          </span>
        </h3>
        <div className="mt-2 flex flex-wrap gap-1">
          {capPills(agent).map((s) => <Pill key={s}>{s}</Pill>)}
        </div>

        {agent.bound_keyhash && (
          <div className="mt-4">
            <Meta
              label="Bound workload key (sha256)"
              value={`${agent.bound_keyhash.slice(0, 16)}…`}
            />
          </div>
        )}

        {agent.selectors.length > 0 && (
          <>
            <h3 className="mt-6 text-xs font-semibold uppercase tracking-wide text-slate-400">
              Selectors
            </h3>
            <div className="mt-2 flex flex-wrap gap-1">
              {agent.selectors.map((s) => <Pill key={s}>{s}</Pill>)}
            </div>
          </>
        )}

        {agent.status === "active" && (
          <Button
            variant="danger"
            className="mt-6"
            disabled={revoke.isPending}
            onClick={() => revoke.mutate()}
          >
            {revoke.isPending ? "Revoking..." : "Revoke"}
          </Button>
        )}
        {revoke.isError && <div className="mt-2"><ErrorNote error={revoke.error} /></div>}
      </div>
    </div>
  );
}

function Meta({ label, value, children }: { label: string; value?: string; children?: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-0.5 break-words text-slate-200">{children ?? value}</div>
    </div>
  );
}
