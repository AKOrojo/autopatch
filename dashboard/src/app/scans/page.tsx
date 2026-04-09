"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import { getScans, getAssets, type Scan, type Asset } from "@/lib/api";
import { Pagination } from "@/components/pagination";
import { StatusBadge } from "@/components/badge";
import { InitiateScanDialog } from "@/components/initiate-scan-dialog";
import { ChevronDown, ChevronRight } from "lucide-react";

interface AssetScanGroup {
  asset_id: string;
  hostname: string;
  ip_address: string;
  scans: Scan[];
  latestStatus: string;
  totalVulns: number;
  latestStarted: string | null;
}

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [assets, setAssets] = useState<Map<string, Asset>>(new Map());
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const limit = 50;

  const fetchData = useCallback(() => {
    setLoading(true);
    Promise.all([getScans(limit, offset), getAssets(200, 0)])
      .then(([scanRes, assetRes]) => {
        setScans(scanRes.data);
        setTotal(scanRes.total);
        const map = new Map<string, Asset>();
        for (const a of assetRes.data) map.set(a.id, a);
        setAssets(map);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [offset]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const groups = useMemo(() => {
    const byAsset = new Map<string, Scan[]>();
    for (const scan of scans) {
      const existing = byAsset.get(scan.asset_id) || [];
      existing.push(scan);
      byAsset.set(scan.asset_id, existing);
    }

    const result: AssetScanGroup[] = [];
    for (const [asset_id, assetScans] of byAsset) {
      const asset = assets.get(asset_id);
      const sorted = assetScans.sort((a, b) =>
        (b.started_at || b.created_at).localeCompare(a.started_at || a.created_at)
      );
      result.push({
        asset_id,
        hostname: asset?.hostname || asset_id.slice(0, 8),
        ip_address: asset?.ip_address || "",
        scans: sorted,
        latestStatus: sorted[0].status,
        totalVulns: sorted.reduce((sum, s) => sum + s.vuln_count, 0),
        latestStarted: sorted[0].started_at,
      });
    }
    return result.sort((a, b) =>
      (b.latestStarted || "").localeCompare(a.latestStarted || "")
    );
  }, [scans, assets]);

  const toggleExpand = (assetId: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(assetId)) next.delete(assetId);
      else next.add(assetId);
      return next;
    });
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Scans</h1>
          <p className="mt-1 text-muted-foreground">Scan history grouped by asset.</p>
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
      ) : groups.length === 0 ? (
        <div className="border rounded-lg px-4 py-8 text-center text-muted-foreground">
          No scans yet. Initiate a scan to get started.
        </div>
      ) : (
        <div className="border rounded-lg overflow-hidden">
          {/* Header */}
          <div className="grid grid-cols-[2rem_1fr_1fr_8rem_8rem_10rem] gap-2 px-4 py-2 bg-muted/50 text-xs font-medium text-muted-foreground uppercase tracking-wider">
            <div />
            <div>Asset</div>
            <div>Scanners</div>
            <div>Status</div>
            <div>Vulns</div>
            <div>Last Scan</div>
          </div>

          {groups.map((group) => {
            const isExpanded = expanded.has(group.asset_id);
            const scannerTypes = [...new Set(group.scans.map((s) => s.scanner_type))];

            return (
              <div key={group.asset_id}>
                {/* Asset row */}
                <button
                  onClick={() => toggleExpand(group.asset_id)}
                  className="w-full grid grid-cols-[2rem_1fr_1fr_8rem_8rem_10rem] gap-2 px-4 py-3 text-sm text-left border-t hover:bg-muted/30 transition-colors items-center"
                >
                  <div className="text-muted-foreground">
                    {isExpanded ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
                  </div>
                  <div>
                    <span className="font-medium">{group.hostname}</span>
                    <span className="text-muted-foreground ml-2 text-xs">{group.ip_address}</span>
                  </div>
                  <div className="flex gap-1.5 flex-wrap">
                    {scannerTypes.map((t) => (
                      <span key={t} className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-medium">
                        {t}
                      </span>
                    ))}
                  </div>
                  <div><StatusBadge status={group.latestStatus} /></div>
                  <div className="text-muted-foreground">{group.totalVulns}</div>
                  <div className="text-muted-foreground text-xs">
                    {group.latestStarted ? new Date(group.latestStarted).toLocaleString() : "—"}
                  </div>
                </button>

                {/* Expanded: individual scans */}
                {isExpanded && (
                  <div className="bg-muted/10">
                    {group.scans.map((scan) => (
                      <div
                        key={scan.id}
                        className="grid grid-cols-[2rem_1fr_1fr_8rem_8rem_10rem] gap-2 px-4 py-2 text-sm border-t border-dashed items-center"
                      >
                        <div />
                        <div className="text-xs text-muted-foreground font-mono">{scan.id.slice(0, 8)}</div>
                        <div className="text-xs">{scan.scanner_type}</div>
                        <div><StatusBadge status={scan.status} /></div>
                        <div className="text-muted-foreground">{scan.vuln_count}</div>
                        <div className="text-muted-foreground text-xs">
                          {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      <Pagination total={total} limit={limit} offset={offset} onPageChange={setOffset} />
    </div>
  );
}
