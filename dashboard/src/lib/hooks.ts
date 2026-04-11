"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  getDashboardOverview, getApprovals, approveRequest, rejectRequest,
  getAuditLogs, getUsers, getApprovalPolicies, getNotificationChannels, getSettings,
} from "./api";
import type { RemediationEvent } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export function useDashboardOverview(range = "30d") {
  return useQuery({ queryKey: ["dashboard-overview", range], queryFn: () => getDashboardOverview(range), refetchInterval: 30_000 });
}

export function useApprovals(params: Record<string, string> = {}) {
  return useQuery({ queryKey: ["approvals", params], queryFn: () => getApprovals(params), refetchInterval: 10_000 });
}

export function useApproveRequest() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: ({ id, reason }: { id: string; reason?: string }) => approveRequest(id, reason), onSuccess: () => qc.invalidateQueries({ queryKey: ["approvals"] }) });
}

export function useRejectRequest() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: ({ id, reason }: { id: string; reason: string }) => rejectRequest(id, reason), onSuccess: () => qc.invalidateQueries({ queryKey: ["approvals"] }) });
}

export function useAuditLogs(params: Record<string, string> = {}) {
  return useQuery({ queryKey: ["audit-logs", params], queryFn: () => getAuditLogs(params) });
}

export function useUsers() {
  return useQuery({ queryKey: ["users"], queryFn: getUsers });
}

export function usePolicies() {
  return useQuery({ queryKey: ["policies"], queryFn: getApprovalPolicies });
}

export function useNotificationChannels() {
  return useQuery({ queryKey: ["channels"], queryFn: getNotificationChannels });
}

export function useSettings() {
  return useQuery({ queryKey: ["settings"], queryFn: getSettings });
}

export function useRemediationStream(remediationId: string | null, level = "node") {
  const [events, setEvents] = useState<RemediationEvent[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!remediationId) return;
    const token = localStorage.getItem("autopatch_token");
    const authParam = token ? `&token=${encodeURIComponent(token)}` : "";
    const url = `${API_BASE}/api/v1/remediations/${remediationId}/stream?level=${level}${authParam}`;
    const es = new EventSource(url);

    const handleEvent = (e: MessageEvent) => {
      const event: RemediationEvent = JSON.parse(e.data);
      setEvents((prev) => [...prev, event]);
    };

    es.addEventListener("node", handleEvent);
    es.addEventListener("tool", handleEvent);
    es.addEventListener("llm", handleEvent);
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    return () => { es.close(); };
  }, [remediationId, level]);

  return { events, connected };
}

export interface LogEvent {
  line: string;
  timestamp: string;
  stream: "stdout" | "stderr";
}

export function useContainerLogs(
  service: string | null,
  options: { tail?: number; search?: string; since?: string; follow?: boolean } = {},
) {
  const { tail = 200, search, since, follow = true } = options;
  const [lines, setLines] = useState<LogEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (!service) return;
    setLines([]);
    setConnected(false);

    const token = localStorage.getItem("autopatch_token");
    const params = new URLSearchParams();
    params.set("tail", String(tail));
    params.set("follow", String(follow));
    if (search) params.set("search", search);
    if (since) params.set("since", since);
    if (token) params.set("token", encodeURIComponent(token));

    const url = `${API_BASE}/api/v1/system/logs/${service}?${params}`;
    const es = new EventSource(url);

    es.addEventListener("connected", () => setConnected(true));

    es.addEventListener("message", (e: MessageEvent) => {
      const event: LogEvent = JSON.parse(e.data);
      setLines((prev) => {
        const next = [...prev, event];
        return next.length > 5000 ? next.slice(-5000) : next;
      });
    });

    es.onerror = () => setConnected(false);

    return () => {
      es.close();
    };
  }, [service, tail, search, since, follow]);

  return { lines, connected, paused, setPaused };
}
