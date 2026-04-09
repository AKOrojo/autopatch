"use client";
import { useState } from "react";
import { useAuditLogs } from "@/lib/hooks";
import { DataTable, type Column } from "@/components/data-table";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function AuditLogsPage() {
  const [search, setSearch] = useState("");
  const [action, setAction] = useState("");
  const [page, setPage] = useState(1);
  const params: Record<string, string> = { page: String(page), per_page: "50" };
  if (search) params.search = search;
  if (action) params.action = action;
  const { data, isLoading } = useAuditLogs(params);

  const eventTypes = ["", "login", "failed_login", "approval_approved", "approval_rejected",
    "user_created", "user_updated", "settings_changed", "policy_changed",
    "channel_created", "channel_updated", "channel_deleted"];

  const columns: Column<Record<string, unknown>>[] = [
    { key: "created_at", header: "Time", render: (row) => <span className="text-xs">{new Date(String(row.created_at)).toLocaleString()}</span> },
    { key: "event_type", header: "Event", render: (row) => <span className="font-mono text-xs">{String(row.event_type)}</span> },
    { key: "user_id", header: "User", render: (row) => <span className="text-xs">{row.user_id ? String(row.user_id).slice(0, 8) : "—"}</span> },
    { key: "correlation", header: "Related", render: (row) => {
      const links = [];
      if (row.remediation_id) links.push(<a key="r" href={`/remediations/${row.remediation_id}`} className="underline text-xs">remediation</a>);
      if (row.asset_id) links.push(<a key="a" href={`/assets/${row.asset_id}`} className="underline text-xs">asset</a>);
      return <span className="flex gap-2">{links.length > 0 ? links : "—"}</span>;
    }},
    { key: "action_detail", header: "Detail", render: (row) => <span className="text-xs text-muted-foreground max-w-xs truncate block">{JSON.stringify(row.action_detail)}</span> },
  ];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Audit Log</h1>
      <div className="flex gap-4 mb-6">
        <input type="text" placeholder="Search..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} className="px-3 py-2 border rounded-md text-sm w-64" />
        <a href={`${API_BASE}/api/v1/audit-logs/export?${new URLSearchParams(params).toString()}`} className="px-3 py-2 border rounded-md text-sm hover:bg-muted" download>Export CSV</a>
        <select value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }} className="px-3 py-2 border rounded-md text-sm">
          <option value="">All events</option>
          {eventTypes.filter(Boolean).map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>
      <DataTable columns={columns} data={(data?.data || []) as unknown as Record<string, unknown>[]} loading={isLoading} />
      {data && data.total > 50 && (
        <div className="flex items-center justify-between mt-4">
          <p className="text-sm text-muted-foreground">{data.total} total entries</p>
          <div className="flex gap-2">
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} className="px-3 py-1 border rounded text-sm disabled:opacity-50">Previous</button>
            <span className="px-3 py-1 text-sm">Page {page}</span>
            <button onClick={() => setPage((p) => p + 1)} disabled={page * 50 >= data.total} className="px-3 py-1 border rounded text-sm disabled:opacity-50">Next</button>
          </div>
        </div>
      )}
    </div>
  );
}
