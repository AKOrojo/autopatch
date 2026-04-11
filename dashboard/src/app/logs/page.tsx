"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { getContainers, type ContainerInfo } from "@/lib/api";
import { useContainerLogs, type LogEvent } from "@/lib/hooks";
import { Download, Pause, Play, Search, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";

const TIME_RANGES = [
  { label: "15m", value: "15m" },
  { label: "1h", value: "1h" },
  { label: "6h", value: "6h" },
  { label: "24h", value: "24h" },
  { label: "All", value: "" },
];

const TAIL_OPTIONS = [200, 500, 1000];

function classifyLine(content: string): string {
  const upper = content.toUpperCase();
  if (upper.includes("ERROR") || upper.includes("FATAL") || upper.includes("CRITICAL") || upper.includes("PANIC"))
    return "text-red-400";
  if (upper.includes("WARNING") || upper.includes("WARN"))
    return "text-yellow-400";
  if (upper.includes("INFO"))
    return "text-blue-400";
  if (upper.includes("DEBUG"))
    return "text-zinc-500";
  return "text-zinc-300";
}

function highlightSearch(text: string, search: string): React.ReactNode {
  if (!search) return text;
  const idx = text.toLowerCase().indexOf(search.toLowerCase());
  if (idx === -1) return text;
  return (
    <>
      {text.slice(0, idx)}
      <mark className="bg-yellow-500/40 text-yellow-200 rounded px-0.5">{text.slice(idx, idx + search.length)}</mark>
      {text.slice(idx + search.length)}
    </>
  );
}

export default function LogsPage() {
  const [selectedService, setSelectedService] = useState<string | null>(null);
  const [searchInput, setSearchInput] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [since, setSince] = useState("1h");
  const [tail, setTail] = useState(200);
  const [follow, setFollow] = useState(true);
  const [autoScroll, setAutoScroll] = useState(true);
  const logEndRef = useRef<HTMLDivElement>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);

  const { data: containers } = useQuery<ContainerInfo[]>({
    queryKey: ["containers"],
    queryFn: getContainers,
    refetchInterval: 30_000,
  });

  const { lines, connected, paused, setPaused } = useContainerLogs(selectedService, {
    tail,
    search: debouncedSearch || undefined,
    since: since || undefined,
    follow,
  });

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchInput), 500);
    return () => clearTimeout(timer);
  }, [searchInput]);

  // Auto-select first container
  useEffect(() => {
    if (!selectedService && containers?.length) {
      setSelectedService(containers[0].service);
    }
  }, [containers, selectedService]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && !paused && logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [lines, autoScroll, paused]);

  // Detect manual scroll
  const handleScroll = useCallback(() => {
    const el = logContainerRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 50;
    setAutoScroll(atBottom);
  }, []);

  const visibleLines = paused ? [] : lines;

  const handleDownload = () => {
    const text = lines.map((l) => `${l.timestamp} [${l.stream}] ${l.line}`).join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${selectedService || "container"}-logs.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)]">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3 mb-3">
        {/* Container selector */}
        <select
          className="rounded-md border bg-background px-3 py-1.5 text-sm"
          value={selectedService || ""}
          onChange={(e) => setSelectedService(e.target.value || null)}
        >
          <option value="">Select container...</option>
          {containers?.map((c) => (
            <option key={c.service} value={c.service}>
              {c.service} ({c.state})
            </option>
          ))}
        </select>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
          <input
            type="text"
            placeholder="Filter logs..."
            className="rounded-md border bg-background pl-8 pr-3 py-1.5 text-sm w-56"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </div>

        {/* Time range */}
        <div className="flex items-center rounded-md border overflow-hidden">
          {TIME_RANGES.map((t) => (
            <button
              key={t.value}
              className={`px-2.5 py-1.5 text-xs font-medium transition-colors ${
                since === t.value
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted"
              }`}
              onClick={() => setSince(t.value)}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Tail */}
        <select
          className="rounded-md border bg-background px-2 py-1.5 text-sm"
          value={tail}
          onChange={(e) => setTail(Number(e.target.value))}
        >
          {TAIL_OPTIONS.map((n) => (
            <option key={n} value={n}>
              {n} lines
            </option>
          ))}
        </select>

        {/* Pause / Resume */}
        <Button
          size="sm"
          variant={paused ? "default" : "outline"}
          onClick={() => setPaused(!paused)}
        >
          {paused ? <Play className="size-3.5 mr-1.5" /> : <Pause className="size-3.5 mr-1.5" />}
          {paused ? "Resume" : "Pause"}
        </Button>

        {/* Download */}
        <Button size="sm" variant="outline" onClick={handleDownload} disabled={lines.length === 0}>
          <Download className="size-3.5 mr-1.5" />
          Download
        </Button>
      </div>

      {/* Log viewer */}
      <div
        ref={logContainerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto rounded-lg border bg-zinc-950 p-4 font-mono text-xs leading-relaxed"
      >
        {!selectedService ? (
          <div className="flex items-center justify-center h-full text-zinc-500">
            Select a container to view logs
          </div>
        ) : visibleLines.length === 0 && !connected ? (
          <div className="flex items-center justify-center h-full text-zinc-500">
            <Loader2 className="size-4 animate-spin mr-2" />
            Connecting...
          </div>
        ) : (
          visibleLines.map((entry, i) => (
            <div key={i} className={`${classifyLine(entry.line)} whitespace-pre-wrap break-all`}>
              {entry.timestamp && (
                <span className="text-zinc-600 mr-2 select-none">
                  {entry.timestamp.slice(11, 23)}
                </span>
              )}
              {entry.stream === "stderr" && (
                <span className="text-red-600 mr-1 select-none">[ERR]</span>
              )}
              {highlightSearch(entry.line, debouncedSearch)}
            </div>
          ))
        )}
        <div ref={logEndRef} />
      </div>

      {/* Status bar */}
      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <span
            className={`inline-block size-2 rounded-full ${
              connected ? "bg-green-500" : "bg-red-500"
            }`}
          />
          {connected ? "Connected" : "Disconnected"}
        </div>
        <div>{lines.length} lines</div>
        {selectedService && <div>{selectedService}</div>}
        {paused && <div className="text-yellow-500 font-medium">PAUSED</div>}
        {!autoScroll && !paused && (
          <button
            className="text-blue-400 hover:underline"
            onClick={() => {
              setAutoScroll(true);
              logEndRef.current?.scrollIntoView({ behavior: "smooth" });
            }}
          >
            Scroll to bottom
          </button>
        )}
      </div>
    </div>
  );
}
