"use client";

import { useState } from "react";
import { useDashboardOverview } from "@/lib/hooks";
import { KpiCard } from "@/components/kpi-card";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

export default function OverviewPage() {
  const [range, setRange] = useState("30d");
  const { data, isLoading, dataUpdatedAt } = useDashboardOverview(range);
  const ranges = ["7d", "30d", "90d"];

  const severityChartData = data
    ? Object.entries(data.charts.vulns_by_severity).map(([severity, count]) => ({ severity, count }))
    : [];

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Last updated: {dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleTimeString() : "—"}
          </p>
        </div>
        <div className="flex gap-1 border rounded-lg p-1">
          {ranges.map((r) => (
            <button key={r} onClick={() => setRange(r)}
              className={`px-3 py-1 rounded text-sm ${range === r ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted"}`}>
              {r}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="border rounded-lg p-6 animate-pulse">
              <div className="h-4 bg-muted rounded w-24 mb-4" />
              <div className="h-8 bg-muted rounded w-16" />
            </div>
          ))}
        </div>
      ) : data ? (
        <>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <KpiCard label="Open Vulnerabilities" value={data.kpi.open_vulnerabilities} delta={data.kpi.open_vulns_delta} />
            <KpiCard label="MTTR" value={`${data.kpi.mttr_hours.toFixed(1)}h`} />
            <KpiCard label="Success Rate" value={`${data.kpi.success_rate.toFixed(1)}%`} />
            <KpiCard label="Pending Approvals" value={data.kpi.pending_approvals} href="/approvals" />
          </div>
          <div className="border rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Vulnerabilities by Severity</h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={severityChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="severity" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#6366f1" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </>
      ) : null}
    </div>
  );
}
