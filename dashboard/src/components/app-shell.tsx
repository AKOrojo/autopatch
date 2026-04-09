"use client";

import { usePathname } from "next/navigation";
import { Sidebar } from "@/components/sidebar";
import { useAuth } from "@/lib/auth-context";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { isAuthenticated, isLoading } = useAuth();
  const isLoginPage = pathname === "/login";

  // Show nothing while checking auth on protected pages
  if (isLoading && !isLoginPage) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-muted-foreground text-sm animate-pulse">Loading...</div>
      </div>
    );
  }

  // Login page: no sidebar, full-width
  if (isLoginPage || !isAuthenticated) {
    return <>{children}</>;
  }

  // Authenticated: sidebar + main content
  return (
    <>
      <Sidebar />
      <main className="flex-1 p-8">{children}</main>
    </>
  );
}
