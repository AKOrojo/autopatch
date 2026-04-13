"use client";

import { useState, useEffect, useCallback, use } from "react";
import { useRouter } from "next/navigation";
import {
  getScanReport,
  getAsset,
  analyzeVulnerability,
  type ScanReportDetail,
  type Asset,
} from "@/lib/api";
import { SeverityBadge, StatusBadge } from "@/components/badge";
import { Button } from "@/components/ui/button";
import { Wrench, ArrowLeft, Shield, ShieldOff, RefreshCw, Loader2 } from "lucide-react";

export default function ReportDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();
  const [report, setReport] = useState<ScanReportDetail | null>(null);
  const [asset, setAsset] = useState<Asset | null>(null);
  const [loading, setLoading] = useState(true);
  const [launchingId, setLaunchingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);

  const fetchReport = useCallback(async () => {
    try {
      const r = await getScanReport(id);
      setReport(r);
      setError(null);
      try {
        setAsset(await getAsset(r.asset_id));
      } catch {}
      // Return whether we should keep polling
      const hasRunning = r.scans.some(
        (s) => s.status === "pending" || s.status === "running"
      );
      return hasRunning;
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load scan report."
      );
      return false;
    }
  }, [id]);

  // Initial load
  useEffect(() => {
    setLoading(true);
    fetchReport().finally(() => setLoading(false));
  }, [fetchReport]);

  // Auto-poll while scans are running
  useEffect(() => {
    if (!report) return;
    const hasRunning = report.scans.some(
      (s) => s.status === "pending" || s.status === "running"
    );
    if (!hasRunning) {
      setPolling(false);
      return;
    }
    setPolling(true);
    const interval = setInterval(() => {
      fetchReport();
    }, 5000);
    return () => clearInterval(interval);
  }, [report, fetchReport]);

  const handleRemediate = async (vulnId: string) => {
    setError(null);
    setLaunchingId(vulnId);
    try {
      const result = await analyzeVulnerability(vulnId);
      router.push(`/remediations/${result.task_id}`);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to launch remediation."
      );
      setLaunchingId(null);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-8 bg-muted rounded w-64" />
        <div className="h-4 bg-muted rounded w-48" />
        <div className="h-64 bg-muted rounded" />
      </div>
    );
  }

  if (error && !report) {
    return (
      <div>
        <button
          onClick={() => router.push("/scans")}
          className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-4"
        >
          <ArrowLeft className="size-4" /> Back to Reports
        </button>
        <div className="border rounded-lg px-6 py-12 text-center">
          <p className="text-destructive font-medium mb-2">Failed to load report</p>
          <p className="text-muted-foreground text-sm mb-4">{error}</p>
          <Button size="sm" variant="outline" onClick={() => { setLoading(true); fetchReport().finally(() => setLoading(false)); }}>
            <RefreshCw data-icon="inline-start" /> Retry
          </Button>
        </div>
      </div>
    );
  }

  if (!report) return <p>Report not found.</p>;

  return (
    <div>
      <button
        onClick={() => router.push("/scans")}
        className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-4"
      >
        <ArrowLeft className="size-4" /> Back to Reports
      </button>

      <div className="flex items-start justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold">
            Scan Report: {asset?.hostname || report.asset_id.slice(0, 8)}
          </h1>
          <p className="text-muted-foreground mt-1">
            {asset?.ip_address} &middot;{" "}
            {report.scanner_types.split(",").join(", ")} &middot;{" "}
            {new Date(report.created_at).toLocaleString()}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {polling && (
            <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Loader2 className="size-3 animate-spin" /> Auto-refreshing
            </span>
          )}
          <StatusBadge status={report.status} />
        </div>
      </div>

      {/* Scan progress cards */}
      <div className="grid grid-cols-3 gap-3 mb-6">
        {report.scans.map((scan) => {
          const pct = scan.progress ?? 0;
          const eta = (() => {
            if (scan.status !== "running" || !scan.started_at || pct <= 0) return null;
            const elapsed = (Date.now() - new Date(scan.started_at).getTime()) / 1000;
            const remaining = elapsed / (pct / 100) - elapsed;
            if (remaining < 60) return `~${Math.round(remaining)}s remaining`;
            return `~${Math.round(remaining / 60)}m remaining`;
          })();
          return (
            <div key={scan.id} className="border rounded-lg p-4">
              <div className="flex items-center justify-between mb-1">
                <span className="font-medium text-sm">{scan.scanner_type}</span>
                <StatusBadge status={scan.status} />
              </div>
              <p className="text-xs text-muted-foreground">
                {scan.status === "running" && scan.started_at
                  ? `Started ${new Date(scan.started_at).toLocaleString()}`
                  : scan.status === "pending"
                    ? "Waiting to start..."
                    : `${scan.vuln_count} vulnerabilities`}
                {scan.completed_at && scan.status === "completed"
                  ? ` · Completed ${new Date(scan.completed_at).toLocaleString()}`
                  : ""}
              </p>
              {(scan.status === "running" || scan.status === "pending") && (
                <>
                  <div className="mt-2 h-1.5 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full bg-blue-500 transition-all duration-500"
                      style={{ width: scan.status === "pending" ? "0%" : `${pct}%` }}
                    />
                  </div>
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-xs text-muted-foreground">
                      {scan.status === "running" ? `${pct}%` : ""}
                    </span>
                    {eta && (
                      <span className="text-xs text-muted-foreground">{eta}</span>
                    )}
                  </div>
                </>
              )}
            </div>
          );
        })}
      </div>

      {error && (
        <div className="rounded-lg bg-destructive/10 text-destructive px-4 py-2.5 text-sm mb-4">
          {error}
        </div>
      )}

      <h2 className="text-lg font-bold mb-3">
        Vulnerabilities ({report.vulnerabilities.length})
      </h2>

      {report.vulnerabilities.length === 0 ? (
        <div className="border rounded-lg px-4 py-8 text-center text-muted-foreground">
          {polling
            ? "Scan in progress — vulnerabilities will appear here as they are found."
            : "No vulnerabilities found in this scan."}
        </div>
      ) : (
        <div className="border rounded-lg overflow-hidden">
          <div className="grid grid-cols-[1fr_8rem_5rem_5rem_5rem_4rem_9rem] gap-2 px-4 py-2 bg-muted/50 text-xs font-medium text-muted-foreground uppercase tracking-wider">
            <div>Vulnerability</div>
            <div>CVE</div>
            <div>Severity</div>
            <div>CVSS</div>
            <div>Status</div>
            <div>Scope</div>
            <div>Action</div>
          </div>

          {report.vulnerabilities.map((vuln) => (
            <div
              key={vuln.id}
              className="grid grid-cols-[1fr_8rem_5rem_5rem_5rem_4rem_9rem] gap-2 px-4 py-3 text-sm border-t items-center"
            >
              <div>
                <div className="font-medium truncate">{vuln.title}</div>
                {vuln.affected_package && (
                  <div className="text-xs text-muted-foreground">
                    {vuln.affected_package}
                    {vuln.fixed_version ? ` \u2192 ${vuln.fixed_version}` : ""}
                  </div>
                )}
              </div>
              <div className="text-xs font-mono">{vuln.cve_id || "\u2014"}</div>
              <div>
                <SeverityBadge severity={vuln.severity} />
              </div>
              <div className="text-muted-foreground">
                {vuln.cvss_score?.toFixed(1) || "\u2014"}
              </div>
              <div>
                <StatusBadge status={vuln.status} />
              </div>
              <div>
                {vuln.in_scope ? (
                  <span
                    className="text-green-600"
                    title="In scope for remediation"
                  >
                    <Shield className="size-4" />
                  </span>
                ) : (
                  <span className="text-muted-foreground" title="Out of scope">
                    <ShieldOff className="size-4" />
                  </span>
                )}
              </div>
              <div>
                {vuln.in_scope ? (
                  <Button
                    size="xs"
                    onClick={() => handleRemediate(vuln.id)}
                    disabled={launchingId === vuln.id}
                  >
                    <Wrench data-icon="inline-start" />
                    {launchingId === vuln.id ? "..." : "Remediate"}
                  </Button>
                ) : (
                  <span className="text-xs text-muted-foreground">
                    {vuln.status !== "open" ? vuln.status : "No CVE"}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
