"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Session } from "@/lib/session";

export function RepositorySyncButton({ session }: { session: Session | null }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  if (!session) return null;

  async function synchronize() {
    const currentSession = session;
    if (!currentSession) return;
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const result = await api.syncRepositories(currentSession.accessToken);
      setMessage(`${result.repositories_synchronized} repositories synchronized.`);
      window.location.reload();
    } catch (caught) {
        setError(caught instanceof ApiError ? `${caught.message}${caught.code ? ` (${caught.code})` : ""}` : "Repository synchronization failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="repository-sync-control">
      <button className="secondary compact" onClick={synchronize} disabled={busy}>
        {busy ? "Refreshing…" : "Refresh repositories"}
      </button>
      {message && <span className="sync-message">{message}</span>}
      {error && <span className="sync-error" role="alert">{error}</span>}
    </div>
  );
}
