"use client";

import { useState, useEffect, use } from "react";
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
import { Wrench, ArrowLeft, Shield, ShieldOff } from "lucide-react";

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

  useEffect(() => {
    setLoading(true);
    getScanReport(id)
      .then(async (r) => {
        setReport(r);
        try {
          setAsset(await getAsset(r.asset_id));
        } catch {}
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [id]);

  const handleRemediate = async (vulnId: string) => {
    setError(null);
    setLaunchingId(vulnId);
    try {
      const result = await analyzeVulnerability(vulnId);
      router.push(`/remediations/${result.task_id}`);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to launch remediation.",
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
        <StatusBadge status={report.status} />
      </div>

      <div className="grid grid-cols-3 gap-3 mb-6">
        {report.scans.map((scan) => (
          <div key={scan.id} className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-1">
              <span className="font-medium text-sm">{scan.scanner_type}</span>
              <StatusBadge status={scan.status} />
            </div>
            <p className="text-xs text-muted-foreground">
              {scan.vuln_count} vulnerabilities
              {scan.completed_at
                ? ` \u00B7 ${new Date(scan.completed_at).toLocaleString()}`
                : ""}
            </p>
          </div>
        ))}
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
          No vulnerabilities found in this scan.
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
