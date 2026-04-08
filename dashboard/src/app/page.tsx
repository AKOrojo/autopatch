import { getAssets, getScans, getVulnerabilities } from "@/lib/api";

export default async function Home() {
  let assetCount = 0;
  let scanCount = 0;
  let vulnCount = 0;

  try {
    const [assets, scans, vulns] = await Promise.all([
      getAssets(1, 0),
      getScans(1, 0),
      getVulnerabilities({ limit: "1", offset: "0" }),
    ]);
    assetCount = assets.total;
    scanCount = scans.total;
    vulnCount = vulns.total;
  } catch {
    // API may not be running during build
  }

  const cards = [
    { label: "Total Assets", value: assetCount },
    { label: "Total Scans", value: scanCount },
    { label: "Open Vulnerabilities", value: vulnCount },
  ];

  return (
    <div>
      <h1 className="text-3xl font-bold">Dashboard</h1>
      <p className="mt-2 text-muted-foreground">Autonomous vulnerability remediation platform</p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
        {cards.map((card) => (
          <div key={card.label} className="border rounded-lg p-6">
            <p className="text-sm text-muted-foreground">{card.label}</p>
            <p className="text-3xl font-bold mt-2">{card.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
