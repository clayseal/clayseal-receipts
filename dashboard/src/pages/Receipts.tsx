import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useAuth } from "../auth/AuthContext";
import type { VerifyResult } from "../api/types";
import { Button, Card, ErrorNote, Pill, Spinner } from "../components/ui";

/** Pull a string field out of a loose record (verifier returns nested JSON). */
function field(obj: Record<string, unknown> | null | undefined, key: string): string | null {
  if (!obj) return null;
  const v = obj[key];
  return v === null || v === undefined ? null : String(v);
}

function VerdictBadge({ valid }: { valid: boolean }) {
  const cls = valid
    ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30"
    : "bg-rose-500/15 text-rose-300 ring-rose-500/30";
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset ${cls}`}>
      {valid ? "verified" : "not verified"}
    </span>
  );
}

function ResultView({ result }: { result: VerifyResult }) {
  const decisionOutcome = field(result.decision, "outcome");
  const subject = field(result.authority, "subject_id");
  const tenant = field(result.authority, "tenant_id");
  const tier = field(result.assurance, "tier") ?? field(result.assurance, "level");

  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-center gap-3">
        <VerdictBadge valid={result.valid} />
        {result.schema && <Pill>{result.schema}</Pill>}
        {decisionOutcome && (
          <span className="text-sm text-slate-300">
            decision: <span className="font-medium text-white">{decisionOutcome}</span>
          </span>
        )}
        {tier && <span className="text-sm text-slate-400">assurance: {tier}</span>}
      </div>

      <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
        {subject && (
          <div>
            <dt className="text-slate-500">Authority subject</dt>
            <dd className="break-all font-mono text-xs text-slate-200">{subject}</dd>
          </div>
        )}
        {tenant && (
          <div>
            <dt className="text-slate-500">Tenant</dt>
            <dd className="font-mono text-xs text-slate-200">{tenant}</dd>
          </div>
        )}
        {result.proof_id && (
          <div>
            <dt className="text-slate-500">Proof ID</dt>
            <dd className="break-all font-mono text-xs text-slate-200">{result.proof_id}</dd>
          </div>
        )}
        <div>
          <dt className="text-slate-500">Verifier</dt>
          <dd className="font-mono text-xs text-slate-200">{result.verifier_version}</dd>
        </div>
      </dl>

      {result.issues.length > 0 && (
        <div className="mt-4">
          <div className="mb-1 text-sm font-medium text-slate-300">
            Issues ({result.issues.length})
          </div>
          <ul className="space-y-1">
            {result.issues.map((issue, i) => (
              <li
                key={i}
                className="rounded-md border border-amber-500/20 bg-amber-500/5 px-2.5 py-1.5 text-xs text-amber-200"
              >
                <span className="font-mono opacity-70">{issue.code}</span> — {issue.message}
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.reasons.length > 0 && (
        <div className="mt-3 text-xs text-slate-400">{result.reasons.join("; ")}</div>
      )}
    </Card>
  );
}

export function Receipts() {
  const { client } = useAuth();
  const [text, setText] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);

  const versionQuery = useQuery({
    queryKey: ["verifier-version"],
    queryFn: () => client.verifierVersion(),
  });

  const verify = useMutation({
    mutationFn: (bundle: unknown) => client.verifyBundle(bundle),
  });

  function onVerify() {
    setParseError(null);
    verify.reset();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      setParseError("That is not valid JSON. Paste a receipt bundle.");
      return;
    }
    verify.mutate(parsed);
  }

  return (
    <div>
      <div className="mb-4 flex items-end justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-white">Receipts</h1>
          <p className="text-sm text-slate-400">
            Verify an execution receipt bundle: its policy decision, authority binding, and proofs.
          </p>
        </div>
        <div className="text-right text-xs text-slate-500">
          {versionQuery.data && (
            <>
              <div>verifier {versionQuery.data.verifier_version}</div>
              <div className="mt-0.5">
                schemas: {versionQuery.data.supported_schemas.length}
              </div>
            </>
          )}
        </div>
      </div>

      <Card className="p-4">
        <label className="mb-1 block text-sm font-medium text-slate-300">Receipt bundle JSON</label>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={12}
          spellCheck={false}
          placeholder='{ "schema": "...", "execution_proof": { ... }, "decision": { ... } }'
          className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"
        />
        <div className="mt-2 flex items-center gap-3">
          <Button onClick={onVerify} disabled={!text.trim() || verify.isPending}>
            {verify.isPending ? "Verifying..." : "Verify"}
          </Button>
          {verify.isPending && <Spinner />}
        </div>
      </Card>

      {parseError && (
        <div className="mt-4">
          <ErrorNote error={{ message: parseError }} />
        </div>
      )}
      {verify.isError && (
        <div className="mt-4">
          <ErrorNote error={verify.error} />
        </div>
      )}
      {verify.data && (
        <div className="mt-4">
          <ResultView result={verify.data} />
        </div>
      )}
    </div>
  );
}
