"use client";

import { useState, useEffect, useCallback } from "react";
import { getSystemStatus, type SystemStatus } from "@/lib/api";
import { RefreshCw, Loader2, CheckCircle2, XCircle, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";

function StateIcon({ state, health }: { state: string; health: string }) {
  if (state === "running" && (health === "healthy" || health === "")) {
    return <CheckCircle2 className="size-4 text-green-500" />;
  }
  if (state === "running" && health === "unhealthy") {
    return <AlertCircle className="size-4 text-yellow-500" />;
  }
  return <XCircle className="size-4 text-red-500" />;
}

function StateBadge({ state, health }: { state: string; health: string }) {
  const label = health && health !== "healthy" ? `${state} (${health})` : state;
  const colors =
    state === "running"
      ? health === "unhealthy"
        ? "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300"
        : "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300"
      : "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300";

  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${colors}`}>
      <StateIcon state={state} health={health} />
      {label}
    </span>
  );
}

export default function SystemStatusPage() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const data = await getSystemStatus();
      setStatus(data);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch system status.");
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    fetchStatus().finally(() => setLoading(false));
  }, [fetchStatus]);

  // Auto-refresh every 10 seconds
  useEffect(() => {
    const interval = setInterval(fetchStatus, 10000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">System Status</h1>
          <p className="mt-1 text-muted-foreground">
            Docker container health for all Autopatch services.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdated && (
            <span className="text-xs text-muted-foreground">
              Updated {lastUpdated.toLocaleTimeString()}
            </span>
          )}
          <Button
            size="sm"
            variant="outline"
            onClick={() => fetchStatus()}
            disabled={loading}
          >
            {loading ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg bg-destructive/10 text-destructive px-4 py-2.5 text-sm mb-4">
          {error}
        </div>
      )}

      {loading && !status ? (
        <div className="border rounded-lg">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="px-4 py-3 border-b last:border-b-0 animate-pulse">
              <div className="h-4 bg-muted rounded w-48" />
            </div>
          ))}
        </div>
      ) : status ? (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className="border rounded-lg p-4">
              <div className="text-2xl font-bold">{status.summary.total}</div>
              <div className="text-sm text-muted-foreground">Total Containers</div>
            </div>
            <div className="border rounded-lg p-4">
              <div className="text-2xl font-bold text-green-600">{status.summary.running}</div>
              <div className="text-sm text-muted-foreground">Running</div>
            </div>
            <div className="border rounded-lg p-4">
              <div className="text-2xl font-bold text-red-600">{status.summary.stopped}</div>
              <div className="text-sm text-muted-foreground">Stopped</div>
            </div>
          </div>

          {/* Container table */}
          <div className="border rounded-lg overflow-hidden">
            <div className="grid grid-cols-[1fr_1fr_8rem_1fr_1fr] gap-2 px-4 py-2 bg-muted/50 text-xs font-medium text-muted-foreground uppercase tracking-wider">
              <div>Service</div>
              <div>Image</div>
              <div>State</div>
              <div>Status</div>
              <div>Ports</div>
            </div>
            {status.containers.map((c) => (
              <div
                key={c.name}
                className="grid grid-cols-[1fr_1fr_8rem_1fr_1fr] gap-2 px-4 py-3 text-sm border-t items-center"
              >
                <div>
                  <span className="font-medium">{c.service || c.name}</span>
                </div>
                <div className="text-muted-foreground text-xs font-mono truncate" title={c.image}>
                  {c.image.split("/").pop()?.split(":")[0] || c.image}
                </div>
                <div>
                  <StateBadge state={c.state} health={c.health} />
                </div>
                <div className="text-xs text-muted-foreground">{c.status}</div>
                <div className="text-xs text-muted-foreground">
                  {c.ports
                    .filter((p) => p.PublishedPort)
                    .map((p) => `${p.PublishedPort}→${p.TargetPort}`)
                    .join(", ") || "—"}
                </div>
              </div>
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
}
