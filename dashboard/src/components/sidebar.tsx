"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { LogOut } from "lucide-react";

const navItems = [
  { href: "/", label: "Overview" },
  { href: "/assets", label: "Assets" },
  { href: "/scans", label: "Scans" },
  { href: "/vulnerabilities", label: "Vulnerabilities" },
  { href: "/remediations", label: "Remediations" },
  { href: "/approvals", label: "Approvals" },
  { href: "/audit-logs", label: "Audit Log" },
  { href: "/settings", label: "Settings" },
];

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  return (
    <aside className="w-64 border-r bg-muted/30 min-h-screen p-4 flex flex-col">
      <div className="mb-8">
        <h1 className="text-xl font-bold">Autopatch</h1>
        <p className="text-xs text-muted-foreground">Vulnerability Remediation</p>
      </div>
      <nav className="space-y-1 flex-1">
        {navItems.map((item) => {
          const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
          return (
            <Link key={item.href} href={item.href} className={`block px-3 py-2 rounded-md text-sm ${isActive ? "bg-primary text-primary-foreground font-medium" : "text-muted-foreground hover:bg-muted"}`}>
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* User info + logout */}
      <div className="border-t border-border pt-4 mt-4">
        {user && (
          <div className="px-3 mb-2">
            <p className="text-sm font-medium truncate">{user.user_id.slice(0, 8)}...</p>
            <p className="text-xs text-muted-foreground capitalize">{user.role}</p>
          </div>
        )}
        <button
          onClick={logout}
          className="flex items-center gap-2 w-full px-3 py-2 rounded-md text-sm text-muted-foreground hover:bg-muted transition-colors"
        >
          <LogOut className="size-4" />
          Sign out
        </button>
      </div>
    </aside>
  );
}
