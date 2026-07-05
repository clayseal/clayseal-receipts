import { useState } from "react";
import { ApiClient, ApiClientError } from "../api/client";
import { useAuth } from "./AuthContext";
import { Button, Card } from "../components/ui";

export function Connect() {
  const { baseUrl, setBaseUrl, connect } = useAuth();
  const [key, setKey] = useState("");
  const [url, setUrl] = useState(baseUrl);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<string | null>(null);

  async function handleConnect() {
    setError(null);
    setBaseUrl(url);
    connect(key.trim());
  }

  async function handleCreate() {
    setError(null);
    setBusy(true);
    try {
      setBaseUrl(url);
      const client = new ApiClient(url, null);
      const customer = await client.createCustomer(name || "My Org");
      setCreated(customer.api_key);
      setKey(customer.api_key);
    } catch (e) {
      const err = e as ApiClientError;
      setError(err.message + (err.suggestion ? ` — ${err.suggestion}` : ""));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <Card className="w-full max-w-md p-6">
        <h1 className="text-xl font-semibold text-white">AgentAuth</h1>
        <p className="mt-1 text-sm text-slate-400">
          Connect with your API key to manage agents.
        </p>

        <label className="mt-5 block text-xs font-medium uppercase tracking-wide text-slate-400">
          API base URL
        </label>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-indigo-500"
          placeholder="http://localhost:8000"
        />

        <label className="mt-4 block text-xs font-medium uppercase tracking-wide text-slate-400">
          API key
        </label>
        <input
          value={key}
          onChange={(e) => setKey(e.target.value)}
          className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-indigo-500"
          placeholder="aa_..."
        />
        <Button
          className="mt-3 w-full"
          disabled={!key.trim()}
          onClick={handleConnect}
        >
          Connect
        </Button>

        <div className="my-5 flex items-center gap-3 text-xs text-slate-600">
          <div className="h-px flex-1 bg-slate-800" />
          or create a new tenant
          <div className="h-px flex-1 bg-slate-800" />
        </div>

        <div className="flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="flex-1 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-indigo-500"
            placeholder="Org name"
          />
          <Button variant="secondary" disabled={busy} onClick={handleCreate}>
            Create
          </Button>
        </div>

        {created && (
          <div className="mt-3 rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-200">
            <div className="font-medium">API key created (shown once):</div>
            <div className="mt-1 break-all font-mono">{created}</div>
            <div className="mt-2">It has been filled in above — click Connect.</div>
          </div>
        )}

        {error && (
          <div className="mt-3 rounded-md border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
            {error}
          </div>
        )}
      </Card>
    </div>
  );
}
