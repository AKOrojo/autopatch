import type {
  ApprovalRequest, ApprovalPolicy, DashboardOverview, AuditLogEntry,
  UserRecord, NotificationChannel, AppSettings,
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
}

function getAuthHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = localStorage.getItem("autopatch_token");
  if (token) return { Authorization: `Bearer ${token}` };
  const apiKey = process.env.NEXT_PUBLIC_API_KEY;
  if (apiKey) return { "X-API-Key": apiKey };
  return {};
}

export async function apiFetch(path: string, options: RequestInit = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
      ...options.headers,
    },
  });
  if (!res.ok) {
    if (res.status === 401) {
      if (typeof window !== "undefined" && !path.includes("/auth/login")) {
        localStorage.removeItem("autopatch_token");
        window.location.href = "/login";
      }
      throw new Error("Unauthorized. Please log in.");
    }
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res;
}

// Auth
export interface LoginResponse {
  access_token: string;
  token_type: string;
  user_id: string;
  role: string;
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  const url = `${API_BASE}/api/v1/auth/login`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    if (res.status === 401) throw new Error("Invalid email or password.");
    throw new Error(`Login failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

async function fetchPaginated<T>(path: string, params: Record<string, string> = {}): Promise<PaginatedResponse<T>> {
  const query = new URLSearchParams(params).toString();
  const fullPath = query ? `${path}?${query}` : path;
  const res = await apiFetch(fullPath);
  const total = parseInt(res.headers.get("x-total-count") || "0", 10);
  const data = await res.json();
  return { data, total };
}

export interface Asset {
  id: string;
  hostname: string;
  ip_address: string;
  os_family: string | null;
  os_version: string | null;
  environment: string;
  criticality: string;
  tags: Record<string, unknown>;
  ssh_port: number;
  scan_config: Record<string, unknown>;
  last_scan_at: string | null;
  created_at: string;
  updated_at: string;
}

export function getAssets(limit = 50, offset = 0) {
  return fetchPaginated<Asset>("/api/v1/assets", { limit: String(limit), offset: String(offset) });
}

export interface AssetCreate {
  hostname: string;
  ip_address: string;
  os_family?: string;
  os_version?: string;
  environment?: string;
  criticality?: string;
  tags?: Record<string, unknown>;
}

export async function createAsset(data: AssetCreate): Promise<Asset> {
  const res = await apiFetch("/api/v1/assets", { method: "POST", body: JSON.stringify(data) });
  return res.json();
}

export function getAsset(id: string) {
  return apiFetch(`/api/v1/assets/${id}`).then(r => r.json()) as Promise<Asset>;
}

export interface Scan {
  id: string;
  asset_id: string;
  scanner_type: string;
  status: string;
  scanner_task_id: string | null;
  config: Record<string, unknown> | null;
  started_at: string | null;
  completed_at: string | null;
  vuln_count: number;
  created_at: string;
}

export function getScans(limit = 50, offset = 0) {
  return fetchPaginated<Scan>("/api/v1/scans", { limit: String(limit), offset: String(offset) });
}

export interface ScanCreate {
  asset_id: string;
  scanner_type: string;
  config?: Record<string, unknown>;
}

export async function createScan(data: ScanCreate): Promise<Scan> {
  const res = await apiFetch("/api/v1/scans", { method: "POST", body: JSON.stringify(data) });
  return res.json();
}

export function getAssetScans(assetId: string, limit = 50, offset = 0) {
  return fetchPaginated<Scan>(`/api/v1/assets/${assetId}/scans`, { limit: String(limit), offset: String(offset) });
}

export interface Vulnerability {
  id: string;
  scan_id: string | null;
  asset_id: string;
  cve_id: string | null;
  cwe_id: string | null;
  title: string;
  description: string | null;
  severity: string;
  cvss_score: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  is_kev: boolean;
  status: string;
  affected_package: string | null;
  affected_version: string | null;
  fixed_version: string | null;
  priority_score: number | null;
  first_seen_at: string;
  created_at: string;
}

export function getVulnerabilities(params: Record<string, string> = {}) {
  return fetchPaginated<Vulnerability>("/api/v1/vulnerabilities", params);
}

export function getVulnerability(id: string) {
  return apiFetch(`/api/v1/vulnerabilities/${id}`).then(r => r.json()) as Promise<Vulnerability>;
}

export function getAssetVulnerabilities(assetId: string, limit = 50, offset = 0) {
  return fetchPaginated<Vulnerability>(`/api/v1/assets/${assetId}/vulnerabilities`, { limit: String(limit), offset: String(offset) });
}

// Remediations
export async function analyzeVulnerability(vulnerabilityId: string) {
  const res = await apiFetch("/api/v1/remediations/analyze", {
    method: "POST",
    body: JSON.stringify({ vulnerability_id: vulnerabilityId }),
  });
  return res.json() as Promise<{ task_id: string; vulnerability_id: string; status: string }>;
}

export async function getAnalysisStatus(taskId: string) {
  const res = await apiFetch(`/api/v1/remediations/analyze/${taskId}`);
  return res.json() as Promise<{ task_id: string; status: string; result?: unknown }>;
}

// Dashboard
export async function getDashboardOverview(range = "30d"): Promise<DashboardOverview> {
  const res = await apiFetch(`/api/v1/dashboard/overview?range=${range}`);
  return res.json();
}

// Approvals
export function getApprovals(params: Record<string, string> = {}) {
  return fetchPaginated<ApprovalRequest>("/api/v1/approvals", params);
}

export async function approveRequest(id: string, reason?: string) {
  return apiFetch(`/api/v1/approvals/${id}/approve`, { method: "POST", body: JSON.stringify({ reason }) });
}

export async function rejectRequest(id: string, reason: string) {
  return apiFetch(`/api/v1/approvals/${id}/reject`, { method: "POST", body: JSON.stringify({ reason }) });
}

// Policies
export async function getApprovalPolicies(): Promise<ApprovalPolicy[]> {
  const res = await apiFetch("/api/v1/approval-policies");
  return res.json();
}

export async function updateApprovalPolicy(tier: string, data: Partial<ApprovalPolicy>) {
  return apiFetch(`/api/v1/approval-policies/${tier}`, { method: "PUT", body: JSON.stringify(data) });
}

// Audit logs
export async function getAuditLogs(params: Record<string, string> = {}) {
  const query = new URLSearchParams(params).toString();
  const res = await apiFetch(`/api/v1/audit-logs${query ? `?${query}` : ""}`);
  return res.json() as Promise<{ data: AuditLogEntry[]; total: number; page: number; per_page: number }>;
}

// Users
export async function getUsers(): Promise<UserRecord[]> {
  const res = await apiFetch("/api/v1/users");
  return res.json();
}

export async function createUser(data: { email: string; name: string; password: string; role: string }) {
  return apiFetch("/api/v1/users", { method: "POST", body: JSON.stringify(data) });
}

export async function updateUser(id: string, data: { name?: string; role?: string; is_active?: boolean }) {
  return apiFetch(`/api/v1/users/${id}`, { method: "PUT", body: JSON.stringify(data) });
}

export async function deleteUser(id: string) {
  return apiFetch(`/api/v1/users/${id}`, { method: "DELETE" });
}

// Notification channels
export async function getNotificationChannels(): Promise<NotificationChannel[]> {
  const res = await apiFetch("/api/v1/notification-channels");
  return res.json();
}

export async function createNotificationChannel(data: { type: string; config: Record<string, unknown>; events: string[]; enabled: boolean }) {
  return apiFetch("/api/v1/notification-channels", { method: "POST", body: JSON.stringify(data) });
}

export async function deleteNotificationChannel(id: string) {
  return apiFetch(`/api/v1/notification-channels/${id}`, { method: "DELETE" });
}

export async function testNotificationChannel(id: string) {
  return apiFetch(`/api/v1/notification-channels/${id}/test`, { method: "POST" });
}

// Settings
export async function getSettings(): Promise<AppSettings> {
  const res = await apiFetch("/api/v1/settings");
  return res.json();
}

export async function updateSettings(data: { global_mode?: string }) {
  return apiFetch("/api/v1/settings", { method: "PUT", body: JSON.stringify(data) });
}
