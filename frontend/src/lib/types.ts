export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Origin = "real" | "simulated";
export type OriginFilter = "all" | Origin;
export type Role = "admin" | "analyst" | "viewer";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface User {
  id: number;
  username: string;
  email: string;
  full_name: string | null;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

export interface EventRow {
  id: number;
  timestamp: string;
  received_at: string;
  agent_id: number | null;
  source: string;
  event_type: string;
  hostname: string | null;
  username: string | null;
  source_ip: string | null;
  dest_ip: string | null;
  dest_port: number | null;
  http_method: string | null;
  http_path: string | null;
  status_code: number | null;
  user_agent: string | null;
  message: string | null;
  severity: Severity;
  risk_score: number;
  anomaly_score: number | null;
  data_origin: Origin;
  extra: Record<string, unknown> | null;
}

export type AlertStatus = "open" | "acknowledged" | "resolved" | "false_positive";

export interface Alert {
  id: number;
  rule_key: string;
  detection_type: "rule" | "ml" | "intel";
  title: string;
  description: string | null;
  category: string | null;
  mitre: string | null;
  severity: Severity;
  risk_score: number;
  anomaly_score: number | null;
  status: AlertStatus;
  source_ip: string | null;
  username: string | null;
  hostname: string | null;
  event_count: number;
  data_origin: Origin;
  details: Record<string, unknown> | null;
  incident_id: number | null;
  first_seen: string;
  last_seen: string;
  created_at: string;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  resolved_by: string | null;
  resolved_at: string | null;
  resolution_note: string | null;
}

export interface AlertDetail extends Alert {
  events: EventRow[];
}

export type IncidentStatus = "open" | "investigating" | "contained" | "resolved" | "closed";

export interface Incident {
  id: number;
  title: string;
  description: string | null;
  severity: Severity;
  status: IncidentStatus;
  source_ip: string | null;
  data_origin: Origin;
  assigned_to_id: number | null;
  assignee_name: string | null;
  created_by: string | null;
  resolution: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  alert_count: number;
}

export interface Note {
  id: number;
  author: string;
  kind: string;
  body: string;
  created_at: string;
}

export interface IncidentDetail extends Incident {
  notes: Note[];
  alerts: Alert[];
}

export interface TimelineItem {
  kind: "event" | "alert";
  time: string;
  event: EventRow | null;
  alert: Alert | null;
}

export interface Agent {
  id: number;
  name: string;
  hostname: string | null;
  os_type: string | null;
  version: string | null;
  ip_address: string | null;
  api_key_prefix: string;
  is_active: boolean;
  created_at: string;
  last_seen: string | null;
  events_received: number;
  online: boolean;
}

export interface AgentCreated extends Agent {
  api_key: string;
}

export interface Rule {
  key: string;
  name: string;
  description: string | null;
  enabled: boolean;
  severity: Severity;
  category: string | null;
  mitre: string | null;
  params: Record<string, number | string[]>;
  updated_at: string;
}

export interface Reputation {
  score: number;
  is_malicious: boolean;
  source: string;
  country: string | null;
  isp: string | null;
  total_reports: number;
}

export interface Overview {
  window_hours: number;
  bucket_seconds: number;
  totals: {
    events_total: number;
    events_window: number;
    threats_total: number;
    threats_window: number;
    active_alerts: number;
    critical_alerts_active: number;
    open_incidents: number;
    critical_incidents: number;
    agents_total: number;
    agents_online: number;
    failed_logins_window: number;
    success_logins_window: number;
    suspicious_ips_window: number;
  };
  severity_distribution: Record<Severity, number>;
  timeseries: { t: string; events: number; failed_logins: number; alerts: number }[];
  top_ips: { ip: string; events: number; failed_logins: number }[];
  by_source: Record<string, number>;
  top_rules: { rule_key: string; count: number }[];
}

export interface Trends {
  daily: { date: string; events: number; failed_logins: number; alerts: number; high_alerts: number }[];
  weekly: { week_start: string; events: number; failed_logins: number; alerts: number; high_alerts: number }[];
}

export interface MlStatus {
  enabled?: boolean;
  trained: boolean;
  algorithm: string;
  trained_at?: string;
  samples?: number;
  threshold?: number;
  min_train_samples: number;
  bucket_seconds?: number;
  baseline?: Record<string, { mean: number; std: number }>;
}

export interface AiAnalytics {
  model: MlStatus;
  ml_enabled: boolean;
  window_days: number;
  ml_alerts_total: number;
  average_risk: number;
  detections_by_day: { date: string; rule: number; ml: number; intel: number }[];
  risk_histogram: { range: string; count: number }[];
  top_anomalies: {
    id: number;
    entity: string | null;
    title: string;
    anomaly_score: number | null;
    risk_score: number;
    severity: Severity;
    status: AlertStatus;
    reasons: string[];
    last_seen: string;
    data_origin: Origin;
  }[];
}

export interface IpRow {
  ip: string;
  events: number;
  failed_logins: number;
  last_seen: string;
  max_risk: number;
  alerts: number;
  active_alerts: number;
  is_public: boolean;
  reputation: Reputation | null;
}

export interface IpDetail {
  ip: string;
  is_public: boolean;
  reputation: Reputation | null;
  intel_configured: boolean;
  total_events: number;
  first_seen: string | null;
  last_seen: string | null;
  events_by_type: Record<string, number>;
  targeted_users: { username: string; count: number }[];
  alerts: Alert[];
  incidents: { id: number; title: string; severity: Severity; status: IncidentStatus; created_at: string }[];
  recent_events: EventRow[];
}

export interface AppSettings {
  alert_webhook_url: string;
  notify_min_severity: Severity;
  auto_incident_min_severity: Severity;
  alert_cooldown_seconds: number;
  ml_enabled: boolean;
  abuseipdb_configured: boolean;
  threat_feeds: string[];
  retention_days: number;
  simulator_enabled: boolean;
}

export interface AuditEntry {
  id: number;
  created_at: string;
  actor: string | null;
  action: string;
  detail: string | null;
  ip_address: string | null;
}

export interface Assignable {
  id: number;
  username: string;
  full_name: string | null;
  role: Role;
}
