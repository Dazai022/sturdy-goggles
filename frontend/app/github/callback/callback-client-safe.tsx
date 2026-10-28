"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/components/session-provider";

export default function CallbackClientSafe() {
  const params = useSearchParams();
  const { session, ready } = useSession();
  const attempted = useRef<string | null>(null);
  const [message, setMessage] = useState("Completing GitHub connection…");

  useEffect(() => {
    if (!ready) return;
    const state = params.get("state");
    const code = params.get("code");
    const error = params.get("error");
    if (error) {
      setMessage("GitHub authorization was cancelled or denied.");
      return;
    }
    if (!state || !code) {
      setMessage("GitHub did not return a valid authorization response.");
      return;
    }
    if (!session) {
      setMessage("Authentication required. Sign in and try again.");
      return;
    }
    const requestKey = `${state}:${code}`;
    if (attempted.current === requestKey) return;
    attempted.current = requestKey;
    api.oauthCallback(state, code, session.accessToken)
      .then((result) => setMessage(`Connected as @${result.github_login}.`))
      .catch((caught: unknown) => setMessage(
        caught instanceof ApiError
          ? `GitHub connection failed: ${caught.message}${caught.code ? ` (${caught.code})` : ""}`
          : "GitHub connection failed. You can safely return to the dashboard and try again.",
      ));
  }, [params, ready, session]);

  return <main className="auth-shell"><div className="auth-card"><div className="eyebrow">GITHUB CONNECTION</div><h1>{message}</h1><Link href="/" className="primary button-link">Return to dashboard</Link></div></main>;
}
