"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { getVulnerabilities, type Vulnerability } from "@/lib/api";
import { DataTable, type Column } from "@/components/data-table";
import { Pagination } from "@/components/pagination";
import { SeverityBadge, StatusBadge } from "@/components/badge";

const columns: Column<Vulnerability>[] = [
  { key: "title", header: "Title" },
  { key: "cve_id", header: "CVE", render: (row) => row.cve_id || "—" },
  { key: "severity", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
  { key: "cvss_score", header: "CVSS", render: (row) => row.cvss_score?.toFixed(1) || "—" },
  { key: "epss_score", header: "EPSS", render: (row) => row.epss_score ? `${(row.epss_score * 100).toFixed(1)}%` : "—" },
  { key: "is_kev", header: "KEV", render: (row) => row.is_kev ? "Yes" : "—" },
  { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
];

export default function VulnerabilitiesPage() {
  const router = useRouter();
  const [data, setData] = useState<Vulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const limit = 50;

  useEffect(() => {
    setLoading(true);
    const params: Record<string, string> = { limit: String(limit), offset: String(offset) };
    if (severity) params.severity = severity;
    if (status) params.status = status;
    getVulnerabilities(params).then((res) => { setData(res.data); setTotal(res.total); }).catch(console.error).finally(() => setLoading(false));
  }, [offset, severity, status]);

  return (
    <div>
      <h1 className="text-2xl font-bold">Vulnerabilities</h1>
      <p className="mt-2 text-muted-foreground mb-6">Discovered vulnerabilities across all assets.</p>
      <div className="flex gap-4 mb-4">
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0); }} className="border rounded px-3 py-1.5 text-sm">
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }} className="border rounded px-3 py-1.5 text-sm">
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="remediated">Remediated</option>
          <option value="accepted_risk">Accepted Risk</option>
        </select>
      </div>
      <DataTable columns={columns} data={data} loading={loading} onRowClick={(row) => router.push(`/vulnerabilities/${row.id}`)} />
      <Pagination total={total} limit={limit} offset={offset} onPageChange={setOffset} />
    </div>
  );
}
