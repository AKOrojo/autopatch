const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
}

export async function apiFetch(path: string, options: RequestInit = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res;
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
