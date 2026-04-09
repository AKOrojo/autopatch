"use client";
import { useSettings } from "@/lib/hooks";
import { updateSettings } from "@/lib/api";
import { useQueryClient } from "@tanstack/react-query";
import Link from "next/link";

export default function SettingsPage() {
  const { data: settings, isLoading } = useSettings();
  const qc = useQueryClient();

  const toggleMode = async () => {
    if (!settings) return;
    const newMode = settings.global_mode === "auto" ? "manual" : "auto";
    await updateSettings({ global_mode: newMode });
    qc.invalidateQueries({ queryKey: ["settings"] });
  };

  const subPages = [
    { href: "/settings/policies", label: "Approval Policies", desc: "Configure auto-approval thresholds per asset tier" },
    { href: "/settings/notifications", label: "Notification Channels", desc: "Manage email and webhook notification destinations" },
    { href: "/settings/users", label: "User Management", desc: "Create, edit, and deactivate user accounts" },
  ];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Settings</h1>
      {!isLoading && settings && (
        <div className="border rounded-lg p-6 mb-8">
          <h2 className="text-lg font-semibold mb-4">Global Mode</h2>
          <div className="flex items-center gap-4">
            <button onClick={toggleMode} className={`px-4 py-2 rounded-lg text-sm font-medium ${settings.global_mode === "auto" ? "bg-green-100 text-green-800" : "bg-yellow-100 text-yellow-800"}`}>
              {settings.global_mode === "auto" ? "Auto Mode" : "Manual Mode"}
            </button>
            <p className="text-sm text-muted-foreground">
              {settings.global_mode === "auto" ? "Remediations auto-approve based on policy thresholds." : "All remediations require manual approval."}
            </p>
          </div>
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {subPages.map((p) => (
          <Link key={p.href} href={p.href} className="border rounded-lg p-6 hover:bg-muted/30">
            <h3 className="font-semibold">{p.label}</h3>
            <p className="text-sm text-muted-foreground mt-1">{p.desc}</p>
          </Link>
        ))}
      </div>
    </div>
  );
}
