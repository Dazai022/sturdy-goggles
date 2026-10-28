export type Repository = { github_repo_id: number; installation_id: string; full_name: string; default_branch: string | null; description: string | null; private: boolean; selected: boolean };
export type Scan = { id: string; full_name?: string; status: string; summary?: string | null; error?: string | null; commit_sha?: string | null; files_eligible?: number; files_selected?: number; files_scanned?: number; files_failed?: number; files_skipped?: number; completed_at?: string | null };
export type Identity = { connected: boolean; github_user_id: number | null; github_login: string | null };
export type Report = { repository: string; commit_sha: string | null; scan: { status: string; eligible: number; selected: number; analyzed: number; failed: number; skipped: number; error: string | null }; findings: Array<{ title: string; severity: string; verification_status: string; file: string; line_start: number | null; line_end: number | null; evidence: string; concrete_impact: string | null }>; limitations: string[] };
const base = process.env.NEXT_PUBLIC_API_BASE_URL || "/backend";
export class ApiError extends Error { constructor(public status: number, message: string, public code?: string) { super(message); } }
async function request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const response = await fetch(`${base}${path}`, { ...init, headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(init.headers || {}) }, cache: "no-store" });
  if (!response.ok) { let message = `Request failed (${response.status})`; let code: string | undefined; try { const body = await response.json(); if (typeof body.detail === "string") message = body.detail; if (body.detail && typeof body.detail === "object") { if (typeof body.detail.message === "string") message = body.detail.message; if (typeof body.detail.code === "string") code = body.detail.code; } } catch {} throw new ApiError(response.status, message, code); }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
export const api = {
  register: (email: string, password: string) => request<{ user_id: string; email: string; access_token: string }>("/api/v1/auth/register", { method: "POST", body: JSON.stringify({ email, password }) }),
  login: (email: string, password: string) => request<{ user_id: string; email: string; access_token: string }>("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: (token: string) => request<void>("/api/v1/auth/logout", { method: "POST" }, token),
  identity: (token: string) => request<Identity>("/api/v1/github/identity", {}, token),
  oauthStart: (token: string) => request<{ authorize_url: string }>("/api/v1/github/oauth/start", {}, token),
  installationStart: (token: string) => request<{ install_url: string }>("/api/v1/github/installations/start", {}, token),
  repositories: (token: string) => request<Repository[]>("/api/v1/repositories", {}, token),
  syncRepositories: (token: string) => request<{ installations_synchronized: number; repositories_synchronized: number }>("/api/v1/repositories/sync", { method: "POST" }, token),
  selectRepository: (token: string, id: number, selected: boolean) => request<Repository>(`/api/v1/repositories/${id}/selection`, { method: "PUT", body: JSON.stringify({ selected }) }, token),
  scans: (token: string) => request<Scan[]>("/api/v1/scans?limit=20", {}, token),
  report: (token: string, id: string) => request<Report>(`/api/v1/scans/${encodeURIComponent(id)}/report`, {}, token),
  oauthCallback: (state: string, code: string, token?: string) => request<{ connected: boolean; github_login: string }>(`/api/v1/github/oauth/callback?state=${encodeURIComponent(state)}&code=${encodeURIComponent(code)}`, {}, token)
};
