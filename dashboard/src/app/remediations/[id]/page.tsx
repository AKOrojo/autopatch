"use client";
import { use, useState } from "react";
import { useRemediationStream } from "@/lib/hooks";
import { Timeline } from "@/components/timeline";

export default function RemediationDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [level, setLevel] = useState<"node" | "tool" | "llm">("node");
  const { events, connected } = useRemediationStream(id, level);
  const levels = ["node", "tool", "llm"] as const;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Remediation Detail</h1>
          <p className="text-sm text-muted-foreground font-mono">{id}</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${connected ? "bg-green-500" : "bg-red-500"}`} />
            <span className="text-sm text-muted-foreground">{connected ? "Live" : "Disconnected"}</span>
          </div>
          <div className="flex gap-1 border rounded-lg p-1">
            {levels.map((l) => (
              <button key={l} onClick={() => setLevel(l)}
                className={`px-3 py-1 rounded text-sm capitalize ${level === l ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted"}`}>
                {l}
              </button>
            ))}
          </div>
        </div>
      </div>
      <div className="border rounded-lg p-4">
        <h2 className="text-lg font-semibold mb-4">Event Timeline</h2>
        <Timeline events={events} />
      </div>
    </div>
  );
}
