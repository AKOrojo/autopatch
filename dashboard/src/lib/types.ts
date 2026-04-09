export interface ApprovalRequest {
  id: string; remediation_id: string; asset_id: string; risk_score: number;
  asset_tier: string; auto_approved: boolean; status: string;
  decided_by: string | null; decided_at: string | null; reason: string | null; created_at: string;
}

export interface ApprovalPolicy {
  id: string; asset_tier: string; max_auto_approve_cvss: number;
  auto_approve_config_only: boolean; require_approval_for_service_restart: boolean;
}

export interface RemediationEvent {
  level: string; node_name: string; event_type: string;
  payload: Record<string, unknown>; timestamp: string;
}

export interface DashboardOverview {
  kpi: { open_vulnerabilities: number; open_vulns_delta: number;
    pending_approvals: number; success_rate: number; mttr_hours: number; };
  charts: { vulns_by_severity: Record<string, number>; };
}

export interface AuditLogEntry {
  id: number; event_type: string; remediation_id: string | null;
  vulnerability_id: string | null; asset_id: string | null; scan_id: string | null;
  agent_id: string | null; action_detail: Record<string, unknown>;
  user_id: string | null; created_at: string;
}

export interface UserRecord {
  id: string; email: string; name: string; role: string;
  is_active: boolean; last_login_at: string | null; created_at: string;
}

export interface NotificationChannel {
  id: string; type: string; config: Record<string, unknown>;
  events: string[]; enabled: boolean; created_by: string; created_at: string;
}

export interface AppSettings {
  global_mode: string; gmp_host: string; gmp_port: number;
  llm_model: string; smtp_host: string; smtp_from_email: string;
}
