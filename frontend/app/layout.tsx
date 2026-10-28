import "./globals.css";
import { SessionProvider } from "@/components/session-provider";
export const metadata = { title: "SentraForge AI", description: "AI-assisted GitHub repository security and maintenance." };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body><SessionProvider>{children}</SessionProvider></body></html>; }
