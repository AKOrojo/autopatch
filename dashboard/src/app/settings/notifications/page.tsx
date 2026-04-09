"use client";
import { useNotificationChannels } from "@/lib/hooks";
import { createNotificationChannel, deleteNotificationChannel, testNotificationChannel } from "@/lib/api";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

export default function NotificationsPage() {
  const { data: channels, isLoading } = useNotificationChannels();
  const qc = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [type, setType] = useState("webhook");
  const [configJson, setConfigJson] = useState('{"url": ""}');
  const [events, setEvents] = useState("approval_required,remediation_completed");

  const handleCreate = async () => {
    await createNotificationChannel({ type, config: JSON.parse(configJson), events: events.split(",").map((e) => e.trim()), enabled: true });
    qc.invalidateQueries({ queryKey: ["channels"] });
    setShowForm(false);
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Notification Channels</h1>
        <button onClick={() => setShowForm(!showForm)} className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm">{showForm ? "Cancel" : "Add Channel"}</button>
      </div>
      {showForm && (
        <div className="border rounded-lg p-4 mb-6 space-y-3">
          <select value={type} onChange={(e) => setType(e.target.value)} className="px-3 py-2 border rounded-md text-sm w-full">
            <option value="webhook">Webhook</option><option value="email">Email</option>
          </select>
          <textarea value={configJson} onChange={(e) => setConfigJson(e.target.value)} placeholder='{"url": "https://..."}'
            className="w-full px-3 py-2 border rounded-md text-sm font-mono h-20" />
          <input type="text" value={events} onChange={(e) => setEvents(e.target.value)} placeholder="Comma-separated events"
            className="w-full px-3 py-2 border rounded-md text-sm" />
          <button onClick={handleCreate} className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm">Create</button>
        </div>
      )}
      {isLoading ? (
        <div className="space-y-4">{Array.from({ length: 2 }).map((_, i) => <div key={i} className="h-20 bg-muted rounded-lg animate-pulse" />)}</div>
      ) : (
        <div className="space-y-4">
          {channels?.length === 0 && <p className="text-muted-foreground">No channels configured.</p>}
          {channels?.map((ch) => (
            <div key={ch.id} className="border rounded-lg p-4 flex items-center justify-between">
              <div>
                <span className="font-medium text-sm capitalize">{ch.type}</span>
                <p className="text-xs text-muted-foreground font-mono mt-1">{JSON.stringify(ch.config)}</p>
                <p className="text-xs text-muted-foreground mt-1">Events: {ch.events.join(", ")}</p>
              </div>
              <div className="flex gap-2">
                <button onClick={() => testNotificationChannel(ch.id)} className="px-3 py-1 border rounded text-sm hover:bg-muted">Test</button>
                <button onClick={async () => { await deleteNotificationChannel(ch.id); qc.invalidateQueries({ queryKey: ["channels"] }); }}
                  className="px-3 py-1 border border-red-300 text-red-600 rounded text-sm hover:bg-red-50">Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
