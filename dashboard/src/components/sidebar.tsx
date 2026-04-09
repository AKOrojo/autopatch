"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

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
  return (
    <aside className="w-64 border-r bg-muted/30 min-h-screen p-4">
      <div className="mb-8">
        <h1 className="text-xl font-bold">Autopatch</h1>
        <p className="text-xs text-muted-foreground">Vulnerability Remediation</p>
      </div>
      <nav className="space-y-1">
        {navItems.map((item) => {
          const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
          return (
            <Link key={item.href} href={item.href} className={`block px-3 py-2 rounded-md text-sm ${isActive ? "bg-primary text-primary-foreground font-medium" : "text-muted-foreground hover:bg-muted"}`}>
              {item.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
