"use client";

export type Session = { userId: string; email: string; accessToken: string };
const KEY = "sentraforge.session";

export function readSession(): Session | null {
  if (typeof window === "undefined") return null;
  try { return JSON.parse(window.sessionStorage.getItem(KEY) || "null") as Session | null; }
  catch { return null; }
}
export function saveSession(session: Session) { window.sessionStorage.setItem(KEY, JSON.stringify(session)); }
export function clearSession() { window.sessionStorage.removeItem(KEY); }
