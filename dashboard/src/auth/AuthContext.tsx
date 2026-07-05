import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { ApiClient } from "../api/client";

interface AuthState {
  apiKey: string | null;
  baseUrl: string;
  client: ApiClient;
  connect: (apiKey: string) => void;
  disconnect: () => void;
  setBaseUrl: (url: string) => void;
}

const KEY_STORAGE = "agentauth.apiKey";
const URL_STORAGE = "agentauth.baseUrl";
const DEFAULT_BASE_URL =
  (import.meta.env?.VITE_AGENTAUTH_BASE_URL as string | undefined) ??
  "http://localhost:8000";

const AuthCtx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [apiKey, setApiKey] = useState<string | null>(
    () => localStorage.getItem(KEY_STORAGE),
  );
  const [baseUrl, setBaseUrlState] = useState<string>(
    () => localStorage.getItem(URL_STORAGE) ?? DEFAULT_BASE_URL,
  );

  const connect = useCallback((key: string) => {
    localStorage.setItem(KEY_STORAGE, key);
    setApiKey(key);
  }, []);

  const disconnect = useCallback(() => {
    localStorage.removeItem(KEY_STORAGE);
    setApiKey(null);
  }, []);

  const setBaseUrl = useCallback((url: string) => {
    localStorage.setItem(URL_STORAGE, url);
    setBaseUrlState(url);
  }, []);

  const client = useMemo(() => new ApiClient(baseUrl, apiKey), [baseUrl, apiKey]);

  const value = useMemo(
    () => ({ apiKey, baseUrl, client, connect, disconnect, setBaseUrl }),
    [apiKey, baseUrl, client, connect, disconnect, setBaseUrl],
  );

  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}
