"use client";
import { createContext, useContext, useEffect, useState } from "react";
import { clearSession, readSession, saveSession, type Session } from "@/lib/session";
import { RepositorySyncButton } from "@/components/repository-sync-button";
type Context = { session: Session | null; ready: boolean; setSession: (s: Session) => void; signOut: () => void };
const SessionContext = createContext<Context>({ session: null, ready: false, setSession: () => {}, signOut: () => {} });
export function SessionProvider({ children }: { children: React.ReactNode }) { const [session, set] = useState<Session | null>(null); const [ready, setReady] = useState(false); useEffect(() => { set(readSession()); setReady(true); }, []); return <SessionContext.Provider value={{ session, ready, setSession: (s) => { saveSession(s); set(s); }, signOut: () => { clearSession(); set(null); } }}>{children}<RepositorySyncButton session={session} /></SessionContext.Provider>; }
export const useSession = () => useContext(SessionContext);
