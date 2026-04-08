import { getAsset, getAssetScans, getAssetVulnerabilities } from "@/lib/api";
import { SeverityBadge, StatusBadge } from "@/components/badge";

export default async function AssetDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let asset = null;
  let scans = { data: [] as any[], total: 0 };
  let vulns = { data: [] as any[], total: 0 };
  try {
    [asset, scans, vulns] = await Promise.all([
      getAsset(id), getAssetScans(id, 10, 0), getAssetVulnerabilities(id, 10, 0),
    ]);
  } catch { return <p>Asset not found.</p>; }

  return (
    <div>
      <h1 className="text-2xl font-bold">{asset.hostname}</h1>
      <div className="grid grid-cols-2 gap-4 mt-4 border rounded-lg p-6">
        <div><span className="text-sm text-muted-foreground">IP:</span> {asset.ip_address}</div>
        <div><span className="text-sm text-muted-foreground">OS:</span> {asset.os_family} {asset.os_version}</div>
        <div><span className="text-sm text-muted-foreground">Environment:</span> {asset.environment}</div>
        <div><span className="text-sm text-muted-foreground">Criticality:</span> {asset.criticality}</div>
      </div>
      <h2 className="text-xl font-bold mt-8">Recent Scans ({scans.total})</h2>
      <div className="border rounded-lg mt-4 overflow-hidden">
        <table className="w-full"><thead><tr className="border-b bg-muted/50">
          <th className="px-4 py-3 text-left text-sm font-medium">Scanner</th>
          <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
          <th className="px-4 py-3 text-left text-sm font-medium">Vulns</th>
          <th className="px-4 py-3 text-left text-sm font-medium">Date</th>
        </tr></thead><tbody>
          {scans.data.map((s: any) => (
            <tr key={s.id} className="border-b">
              <td className="px-4 py-3 text-sm">{s.scanner_type}</td>
              <td className="px-4 py-3 text-sm"><StatusBadge status={s.status} /></td>
              <td className="px-4 py-3 text-sm">{s.vuln_count}</td>
              <td className="px-4 py-3 text-sm">{s.created_at?.slice(0, 10)}</td>
            </tr>
          ))}
        </tbody></table>
      </div>
      <h2 className="text-xl font-bold mt-8">Vulnerabilities ({vulns.total})</h2>
      <div className="border rounded-lg mt-4 overflow-hidden">
        <table className="w-full"><thead><tr className="border-b bg-muted/50">
          <th className="px-4 py-3 text-left text-sm font-medium">Title</th>
          <th className="px-4 py-3 text-left text-sm font-medium">CVE</th>
          <th className="px-4 py-3 text-left text-sm font-medium">Severity</th>
          <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
        </tr></thead><tbody>
          {vulns.data.map((v: any) => (
            <tr key={v.id} className="border-b">
              <td className="px-4 py-3 text-sm">{v.title}</td>
              <td className="px-4 py-3 text-sm">{v.cve_id || "—"}</td>
              <td className="px-4 py-3 text-sm"><SeverityBadge severity={v.severity} /></td>
              <td className="px-4 py-3 text-sm"><StatusBadge status={v.status} /></td>
            </tr>
          ))}
        </tbody></table>
      </div>
    </div>
  );
}
