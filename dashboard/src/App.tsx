import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth/AuthContext";
import { Connect } from "./auth/Connect";
import { Layout } from "./components/Layout";
import { Agents } from "./pages/Agents";
import { AgentRunCompare } from "./pages/AgentRunCompare";
import { Receipts } from "./pages/Receipts";

function AuthenticatedApp() {
  const { apiKey } = useAuth();
  if (!apiKey) return <Connect />;

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/agents" replace />} />
        <Route path="/agents" element={<Agents />} />
        <Route path="/receipts" element={<Receipts />} />
        <Route path="*" element={<Navigate to="/agents" replace />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/agent-run" element={<AgentRunCompare />} />
      <Route path="*" element={<AuthenticatedApp />} />
    </Routes>
  );
}
