interface KpiCardProps { label: string; value: string | number; delta?: number; href?: string; }

export function KpiCard({ label, value, delta, href }: KpiCardProps) {
  const content = (
    <div className="border rounded-lg p-6">
      <p className="text-sm text-muted-foreground">{label}</p>
      <p className="text-3xl font-bold mt-2">{value}</p>
      {delta !== undefined && (
        <p className={`text-sm mt-1 ${delta > 0 ? "text-red-600" : delta < 0 ? "text-green-600" : "text-muted-foreground"}`}>
          {delta > 0 ? "+" : ""}{delta} from previous period
        </p>
      )}
    </div>
  );
  if (href) return <a href={href}>{content}</a>;
  return content;
}
