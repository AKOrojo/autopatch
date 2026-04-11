"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { getScanReports, getAssets, deleteScanReport, type ScanReport, type Asset } from "@/lib/api";
import { Pagination } from "@/components/pagination";
import { StatusBadge } from "@/components/badge";
import { InitiateScanDialog } from "@/components/initiate-scan-dialog";
import { Trash2 } from "lucide-react";

export default function ScansPage() {
  const router = useRouter();
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [assets, setAssets] = useState<Map<string, Asset>>(new Map());
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const limit = 50;

  const fetchData = useCallback(() => {
    setLoading(true);
    Promise.all([getScanReports(limit, offset), getAssets(200, 0)])
      .then(([reportRes, assetRes]) => {
        setReports(reportRes.data);
        setTotal(reportRes.total);
        const map = new Map<string, Asset>();
        for (const a of assetRes.data) map.set(a.id, a);
        setAssets(map);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [offset]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleDelete = async (id: string) => {
    setDeleting(id);
    try {
      await deleteScanReport(id);
      setReports((prev) => prev.filter((r) => r.id !== id));
      setTotal((prev) => prev - 1);
    } catch (err) {
      console.error("Failed to delete report:", err);
    } finally {
      setDeleting(null);
      setDeleteConfirm(null);
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Scan Reports</h1>
          <p className="mt-1 text-muted-foreground">Each report groups scanner results for one asset.</p>
        </div>
        <InitiateScanDialog onScanCreated={fetchData} />
      </div>

      {loading ? (
        <div className="border rounded-lg">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="px-4 py-3 border-b last:border-b-0 animate-pulse">
              <div className="h-4 bg-muted rounded w-48" />
            </div>
          ))}
        </div>
      ) : reports.length === 0 ? (
        <div className="border rounded-lg px-4 py-8 text-center text-muted-foreground">
          No scan reports yet. Initiate a scan to get started.
        </div>
      ) : (
        <div className="border rounded-lg overflow-hidden">
          <div className="grid grid-cols-[6rem_1fr_1fr_8rem_6rem_10rem_4rem] gap-2 px-4 py-2 bg-muted/50 text-xs font-medium text-muted-foreground uppercase tracking-wider">
            <div>Report ID</div>
            <div>Asset</div>
            <div>Scanners</div>
            <div>Status</div>
            <div>Vulns</div>
            <div>Created</div>
            <div></div>
          </div>
          {reports.map((report) => {
            const asset = assets.get(report.asset_id);
            const scanners = report.scanner_types.split(",");
            return (
              <div
                key={report.id}
                className="w-full grid grid-cols-[6rem_1fr_1fr_8rem_6rem_10rem_4rem] gap-2 px-4 py-3 text-sm text-left border-t hover:bg-muted/30 transition-colors items-center"
              >
                <div
                  className="text-xs font-mono text-muted-foreground cursor-pointer hover:text-foreground"
                  onClick={() => router.push(`/scans/${report.id}`)}
                  title={report.id}
                >
                  {report.id.slice(0, 8)}
                </div>
                <div
                  className="cursor-pointer"
                  onClick={() => router.push(`/scans/${report.id}`)}
                >
                  <span className="font-medium">{asset?.hostname || report.asset_id.slice(0, 8)}</span>
                  <span className="text-muted-foreground ml-2 text-xs">{asset?.ip_address || ""}</span>
                </div>
                <div
                  className="flex gap-1.5 flex-wrap cursor-pointer"
                  onClick={() => router.push(`/scans/${report.id}`)}
                >
                  {scanners.map((t) => (
                    <span key={t} className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-medium">{t}</span>
                  ))}
                </div>
                <div
                  className="cursor-pointer"
                  onClick={() => router.push(`/scans/${report.id}`)}
                >
                  <StatusBadge status={report.status} />
                </div>
                <div
                  className="text-muted-foreground cursor-pointer"
                  onClick={() => router.push(`/scans/${report.id}`)}
                >
                  {report.total_vulns}
                </div>
                <div
                  className="text-muted-foreground text-xs cursor-pointer"
                  onClick={() => router.push(`/scans/${report.id}`)}
                >
                  {new Date(report.created_at).toLocaleString()}
                </div>
                <div className="flex justify-end">
                  <button
                    onClick={(e) => { e.stopPropagation(); setDeleteConfirm(report.id); }}
                    className="p-1.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
                    title="Delete report"
                  >
                    <Trash2 className="size-4" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <Pagination total={total} limit={limit} offset={offset} onPageChange={setOffset} />

      {/* Delete confirmation dialog */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setDeleteConfirm(null)}>
          <div className="bg-background border rounded-lg p-6 max-w-sm w-full shadow-lg" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-semibold mb-2">Delete Report</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Are you sure you want to delete this scan report? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-3 py-1.5 text-sm rounded border hover:bg-muted transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteConfirm)}
                disabled={deleting === deleteConfirm}
                className="px-3 py-1.5 text-sm rounded bg-destructive text-destructive-foreground hover:bg-destructive/90 transition-colors disabled:opacity-50"
              >
                {deleting === deleteConfirm ? "Deleting..." : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
