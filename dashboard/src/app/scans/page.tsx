"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { getScanReports, getAssets, type ScanReport, type Asset } from "@/lib/api";
import { Pagination } from "@/components/pagination";
import { StatusBadge } from "@/components/badge";
import { InitiateScanDialog } from "@/components/initiate-scan-dialog";

export default function ScansPage() {
  const router = useRouter();
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [assets, setAssets] = useState<Map<string, Asset>>(new Map());
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
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
          <div className="grid grid-cols-[1fr_1fr_8rem_6rem_10rem] gap-2 px-4 py-2 bg-muted/50 text-xs font-medium text-muted-foreground uppercase tracking-wider">
            <div>Asset</div>
            <div>Scanners</div>
            <div>Status</div>
            <div>Vulns</div>
            <div>Created</div>
          </div>
          {reports.map((report) => {
            const asset = assets.get(report.asset_id);
            const scanners = report.scanner_types.split(",");
            return (
              <button
                key={report.id}
                onClick={() => router.push(`/scans/${report.id}`)}
                className="w-full grid grid-cols-[1fr_1fr_8rem_6rem_10rem] gap-2 px-4 py-3 text-sm text-left border-t hover:bg-muted/30 transition-colors items-center"
              >
                <div>
                  <span className="font-medium">{asset?.hostname || report.asset_id.slice(0, 8)}</span>
                  <span className="text-muted-foreground ml-2 text-xs">{asset?.ip_address || ""}</span>
                </div>
                <div className="flex gap-1.5 flex-wrap">
                  {scanners.map((t) => (
                    <span key={t} className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-medium">{t}</span>
                  ))}
                </div>
                <div><StatusBadge status={report.status} /></div>
                <div className="text-muted-foreground">{report.total_vulns}</div>
                <div className="text-muted-foreground text-xs">{new Date(report.created_at).toLocaleString()}</div>
              </button>
            );
          })}
        </div>
      )}

      <Pagination total={total} limit={limit} offset={offset} onPageChange={setOffset} />
    </div>
  );
}
