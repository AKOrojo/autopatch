import { getVulnerability } from "@/lib/api";
import { SeverityBadge, StatusBadge } from "@/components/badge";
import { LaunchRemediationButton } from "@/components/launch-remediation-button";

export default async function VulnerabilityDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let vuln = null;
  try { vuln = await getVulnerability(id); } catch { return <p>Vulnerability not found.</p>; }

  return (
    <div>
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">{vuln.title}</h1>
          <div className="flex gap-2 mt-2">
            <SeverityBadge severity={vuln.severity} />
            <StatusBadge status={vuln.status} />
            {vuln.is_kev && <span className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium bg-red-100 text-red-800">KEV</span>}
          </div>
        </div>
        <LaunchRemediationButton vulnerabilityId={id} status={vuln.status} />
      </div>
      <div className="grid grid-cols-2 gap-4 mt-6 border rounded-lg p-6">
        <div><span className="text-sm text-muted-foreground">CVE:</span> {vuln.cve_id || "—"}</div>
        <div><span className="text-sm text-muted-foreground">CWE:</span> {vuln.cwe_id || "—"}</div>
        <div><span className="text-sm text-muted-foreground">CVSS:</span> {vuln.cvss_score?.toFixed(1) || "—"}</div>
        <div><span className="text-sm text-muted-foreground">EPSS:</span> {vuln.epss_score ? `${(vuln.epss_score * 100).toFixed(1)}%` : "—"}</div>
        <div><span className="text-sm text-muted-foreground">Package:</span> {vuln.affected_package || "—"}</div>
        <div><span className="text-sm text-muted-foreground">Version:</span> {vuln.affected_version || "—"}</div>
        <div><span className="text-sm text-muted-foreground">Fix Version:</span> {vuln.fixed_version || "—"}</div>
        <div><span className="text-sm text-muted-foreground">First Seen:</span> {vuln.first_seen_at?.slice(0, 10)}</div>
      </div>
      {vuln.description && (
        <div className="mt-6">
          <h2 className="text-lg font-bold mb-2">Description</h2>
          <p className="text-sm text-muted-foreground">{vuln.description}</p>
        </div>
      )}
    </div>
  );
}
