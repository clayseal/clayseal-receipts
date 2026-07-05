import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import {
  fetchAgentRunState,
  fetchRepoFile,
  resetAgentRun,
  stepAgentRun,
  verifyAgentRun,
  type Beat,
  type TerminalLine,
} from "../agentRun/api";
import { Button, Card, ErrorNote, Spinner } from "../components/ui";

function CommandBanner({
  commands,
}: {
  commands?: { task: string; unsecured: string; secured: string };
}) {
  if (!commands) return null;
  return (
    <Card className="p-4 font-mono text-xs">
      <p className="mb-3 text-sm text-slate-300">{commands.task}</p>
      <div className="grid gap-3 lg:grid-cols-2">
        <div>
          <div className="mb-1 text-[10px] uppercase tracking-wide text-rose-400">Unsecured pane</div>
          <div className="rounded-md bg-slate-950 px-3 py-2 text-slate-200">
            <span className="text-slate-500">$ </span>
            {commands.unsecured}
          </div>
        </div>
        <div>
          <div className="mb-1 text-[10px] uppercase tracking-wide text-emerald-400">Secured pane</div>
          <div className="rounded-md bg-slate-950 px-3 py-2 text-slate-200">
            <span className="text-slate-500">$ </span>
            {commands.secured}
          </div>
        </div>
      </div>
      <p className="mt-2 text-[10px] text-slate-500">
        Live: same <span className="text-slate-400">arctl run-agent</span> command; receipts pane adds install only.
      </p>
    </Card>
  );
}

function Terminal({ lines, accent }: { lines: TerminalLine[]; accent: "rose" | "emerald" }) {
  const border = accent === "rose" ? "border-rose-500/30" : "border-emerald-500/30";
  const header =
    accent === "rose" ? "text-rose-300 bg-rose-500/10" : "text-emerald-300 bg-emerald-500/10";
  return (
    <div className={`rounded-lg border ${border} bg-slate-950 font-mono text-xs overflow-hidden`}>
      <div className={`px-3 py-1.5 text-[10px] uppercase tracking-wide ${header}`}>Agent log</div>
      <div className="max-h-56 overflow-y-auto p-3 space-y-1">
        {lines.length === 0 && <div className="text-slate-600">—</div>}
        {lines.map((line, i) => (
          <div
            key={i}
            className={
              line.kind === "stderr"
                ? "text-rose-400"
                : line.kind === "agent"
                  ? "text-sky-300"
                  : line.kind === "system"
                    ? "text-amber-300/90"
                    : "text-slate-300"
            }
          >
            {line.kind === "agent" && <span className="text-slate-500">› </span>}
            {line.text}
          </div>
        ))}
      </div>
    </div>
  );
}

function FileViewer({
  path,
  highlightLine,
}: {
  path: string | null;
  highlightLine: number | null;
}) {
  const fileQuery = useQuery({
    queryKey: ["agent-run-file", path],
    queryFn: () => fetchRepoFile(path!),
    enabled: Boolean(path),
  });

  if (!path) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-500">
        Select a step to view repo files.
      </div>
    );
  }

  if (fileQuery.isLoading) return <Spinner />;
  if (fileQuery.isError) return <ErrorNote error={fileQuery.error} />;

  const lines = (fileQuery.data?.content ?? "").split("\n");

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 overflow-hidden">
      <div className="border-b border-slate-800 px-3 py-1.5 font-mono text-[10px] text-slate-400">
        {path}
      </div>
      <pre className="max-h-48 overflow-auto p-3 text-xs leading-relaxed">
        {lines.map((line, idx) => {
          const n = idx + 1;
          const hot = highlightLine === n;
          return (
            <div
              key={n}
              className={hot ? "bg-amber-500/15 text-amber-100 -mx-3 px-3" : "text-slate-300"}
            >
              <span className="inline-block w-8 select-none text-slate-600">{n}</span>
              {line || " "}
            </div>
          );
        })}
      </pre>
    </div>
  );
}

function accumulateTerminal(history: Beat[], side: "unsecured" | "secured"): TerminalLine[] {
  const out: TerminalLine[] = [];
  for (const beat of history) {
    for (const line of beat[side].terminal) {
      out.push(line);
    }
  }
  return out;
}

function ReceiptLog({
  receipts,
}: {
  receipts: Array<{
    tool: string;
    blocked: boolean;
    outcome: string;
    valid: boolean;
    proof_id: string | null;
  }>;
}) {
  if (receipts.length === 0) {
    return (
      <p className="text-xs text-slate-500">Receipts appear as the secured agent acts.</p>
    );
  }
  return (
    <ul className="space-y-2">
      {receipts.map((r, i) => (
        <li
          key={r.proof_id ?? i}
          className="flex flex-wrap items-center gap-2 rounded-md border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs"
        >
          <span className="font-mono text-slate-200">{r.tool}</span>
          {r.blocked ? (
            <span className="rounded bg-rose-500/15 px-1.5 py-0.5 text-rose-300">blocked</span>
          ) : (
            <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-emerald-300">allowed</span>
          )}
          {r.valid && (
            <span className="rounded bg-indigo-500/15 px-1.5 py-0.5 text-indigo-300">verified</span>
          )}
        </li>
      ))}
    </ul>
  );
}

export function AgentRunCompare() {
  const queryClient = useQueryClient();
  const [history, setHistory] = useState<Beat[]>([]);
  const [receipts, setReceipts] = useState<
    Array<{ tool: string; blocked: boolean; outcome: string; valid: boolean; proof_id: string | null }>
  >([]);
  const [stepIndex, setStepIndex] = useState(0);
  const [totalSteps, setTotalSteps] = useState(0);
  const [done, setDone] = useState(false);
  const [currentBeat, setCurrentBeat] = useState<Beat | null>(null);
  const [verifyResult, setVerifyResult] = useState<{ all_valid: boolean; count: number } | null>(
    null,
  );
  const [commands, setCommands] = useState<
    { task: string; unsecured: string; secured: string } | undefined
  >(undefined);

  const initialStateQuery = useQuery({
    queryKey: ["agent-run-state"],
    queryFn: fetchAgentRunState,
  });

  const displayCommands = commands ?? initialStateQuery.data?.commands;

  const resetMut = useMutation({
    mutationFn: resetAgentRun,
    onSuccess: (state) => {
      setHistory([]);
      setReceipts(state.receipts);
      setCommands(state.commands);
      setStepIndex(state.step_index);
      setTotalSteps(state.total_steps);
      setDone(state.done);
      setCurrentBeat(null);
      setVerifyResult(null);
      queryClient.invalidateQueries({ queryKey: ["agent-run-file"] });
    },
  });

  const stepMut = useMutation({
    mutationFn: stepAgentRun,
    onSuccess: ({ beat, state }) => {
      setHistory((h) => [...h, beat]);
      setCurrentBeat(beat);
      setReceipts(state.receipts);
      setCommands(state.commands);
      setStepIndex(state.step_index);
      setTotalSteps(state.total_steps);
      setDone(state.done);
      setVerifyResult(null);
    },
  });

  const verifyMut = useMutation({
    mutationFn: verifyAgentRun,
    onSuccess: (result) => {
      setVerifyResult({ all_valid: result.all_valid, count: result.count });
    },
  });

  const unsecuredLog = useMemo(() => accumulateTerminal(history, "unsecured"), [history]);
  const securedLog = useMemo(() => accumulateTerminal(history, "secured"), [history]);

  const highlightFile = currentBeat?.highlight_file ?? "AGENTS.md";
  const highlightLine = currentBeat?.highlight_line ?? null;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-4 px-6 py-4">
          <div>
            <h1 className="text-lg font-semibold text-white">Agent run comparison</h1>
            <p className="text-sm text-slate-400">
              Same repository · unrestricted tools vs receipt-backed allowlist
            </p>
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-500">
              Step {stepIndex} / {totalSteps || "—"}
            </span>
            <Button variant="ghost" onClick={() => resetMut.mutate()} disabled={resetMut.isPending}>
              Reset
            </Button>
            <Button
              onClick={() => stepMut.mutate()}
              disabled={stepMut.isPending || done}
            >
              {stepMut.isPending ? "Running…" : done ? "Complete" : "Next step"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => verifyMut.mutate()}
              disabled={verifyMut.isPending || receipts.length === 0}
            >
              Verify session
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] px-6 py-6 space-y-6">
        <CommandBanner commands={displayCommands} />

        {(resetMut.isError || stepMut.isError || verifyMut.isError) && (
          <ErrorNote
            error={
              resetMut.error ?? stepMut.error ?? verifyMut.error ?? { message: "Request failed" }
            }
          />
        )}

        {currentBeat && (
          <Card className="p-4 border-indigo-500/20 bg-indigo-500/5">
            <h2 className="font-medium text-white">{currentBeat.title}</h2>
            <p className="mt-1 text-sm text-slate-300">{currentBeat.narrative}</p>
          </Card>
        )}

        <div className="grid gap-4 lg:grid-cols-2">
          <section>
            <h3 className="mb-2 text-sm font-semibold text-rose-300">Unsecured agent</h3>
            <p className="mb-3 text-xs text-slate-500">
              Full tools · follows AGENTS.md literally
            </p>
            <Terminal lines={unsecuredLog} accent="rose" />
          </section>
          <section>
            <h3 className="mb-2 text-sm font-semibold text-emerald-300">
              Secured agent + receipts
            </h3>
            <p className="mb-3 text-xs text-slate-500">
              bounded_auto allowlist · cryptographic receipt per action
            </p>
            <Terminal lines={securedLog} accent="emerald" />
          </section>
        </div>

        <div className="grid gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <h3 className="mb-2 text-sm font-medium text-slate-300">Repository</h3>
            <FileViewer path={highlightFile} highlightLine={highlightLine} />
          </div>
          <div>
            <h3 className="mb-2 text-sm font-medium text-slate-300">Secured receipt log</h3>
            <ReceiptLog receipts={receipts} />
            {verifyResult && (
              <div
                className={`mt-3 rounded-lg border px-3 py-2 text-sm ${
                  verifyResult.all_valid
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                    : "border-rose-500/30 bg-rose-500/10 text-rose-200"
                }`}
              >
                {verifyResult.all_valid
                  ? `All ${verifyResult.count} receipts verify offline.`
                  : "Some receipts failed verification."}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
