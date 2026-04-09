"use client";
import type { RemediationEvent } from "@/lib/types";

const STATUS_ICONS: Record<string, string> = {
  started: "bg-blue-500", completed: "bg-green-500", error: "bg-red-500",
  waiting: "bg-yellow-500", approved: "bg-green-500", rejected: "bg-red-500",
};

interface TimelineProps { events: RemediationEvent[]; onNodeClick?: (nodeName: string) => void; }

export function Timeline({ events, onNodeClick }: TimelineProps) {
  if (events.length === 0) return <p className="text-muted-foreground">No events yet.</p>;
  return (
    <div className="space-y-0">
      {events.map((event, i) => (
        <div key={i} className={`flex items-start gap-3 p-3 border-l-2 ${i === events.length - 1 ? "border-primary" : "border-muted"} ${onNodeClick ? "cursor-pointer hover:bg-muted/30" : ""}`}
          onClick={() => onNodeClick?.(event.node_name)}>
          <div className={`w-3 h-3 rounded-full mt-1 shrink-0 ${STATUS_ICONS[event.event_type] || "bg-gray-400"}`} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium text-sm">{event.node_name}</span>
              <span className="text-xs text-muted-foreground">{event.event_type}</span>
            </div>
            <p className="text-xs text-muted-foreground">{new Date(event.timestamp).toLocaleTimeString()}</p>
            {event.level !== "node" && event.payload && Object.keys(event.payload).length > 0 && (
              <pre className="text-xs bg-muted rounded p-2 mt-1 overflow-x-auto max-h-48">
                {JSON.stringify(event.payload, null, 2)}
              </pre>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
