"use client";

import { useState, useEffect, useCallback } from "react";
import { getScans, type Scan } from "@/lib/api";
import { DataTable, type Column } from "@/components/data-table";
import { Pagination } from "@/components/pagination";
import { StatusBadge } from "@/components/badge";
import { InitiateScanDialog } from "@/components/initiate-scan-dialog";

const columns: Column<Scan>[] = [
  { key: "scanner_type", header: "Scanner" },
  { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
  { key: "vuln_count", header: "Vulnerabilities" },
  { key: "started_at", header: "Started", render: (row) => row.started_at ? new Date(row.started_at).toLocaleString() : "—" },
  { key: "completed_at", header: "Completed", render: (row) => row.completed_at ? new Date(row.completed_at).toLocaleString() : "—" },
];

export default function ScansPage() {
  const [data, setData] = useState<Scan[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const limit = 50;

  const fetchScans = useCallback(() => {
    setLoading(true);
    getScans(limit, offset).then((res) => { setData(res.data); setTotal(res.total); }).catch(console.error).finally(() => setLoading(false));
  }, [offset]);

  useEffect(() => { fetchScans(); }, [fetchScans]);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Scans</h1>
          <p className="mt-1 text-muted-foreground">Scan history and results.</p>
        </div>
        <InitiateScanDialog onScanCreated={fetchScans} />
      </div>
      <DataTable columns={columns} data={data} loading={loading} />
      <Pagination total={total} limit={limit} offset={offset} onPageChange={setOffset} />
    </div>
  );
}
