import { Suspense } from "react";
import CallbackClient from "./callback-client-safe";
export default function GitHubCallback() { return <Suspense fallback={<main className="loading"><span><strong>SentraForge AI</strong><br />Completing GitHub connection…</span></main>}><CallbackClient /></Suspense>; }
