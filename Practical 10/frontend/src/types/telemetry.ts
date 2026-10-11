export interface ClassifiedRequest {
  id?: number;
  run_id?: string;
  line_number: number;
  line_index?: number;
  client_ip: string;
  ip?: string;
  timestamp: string;
  method: string;
  resource: string;
  path?: string;
  status_code: number;
  bytes_sent: number;
  response_size?: number;
  user_agent: string;
  anomaly_score: number;
  predicted_label: string;
  display_name: string;
  confidence_pct: number;
  severity: "Low" | "Medium" | "High" | "Critical";
  recommended_action: string;
  is_attack: boolean;
  is_anomaly?: boolean;
  raw_log?: string;
}

export interface RunSummary {
  run_id: string;
  filename: string;
  timestamp: string;
  total_requests: number;
  benign_count: number;
  attack_count: number;
  attack_rate_pct: number;
  mean_anomaly_score: number;
  max_anomaly_score: number;
  anomalies_flagged?: number;
  execution_time_ms: number;
  model_used: string;
  risk_level: "Nominal" | "Elevated" | "High" | "Critical";
  top_attack_type: string;
  attack_breakdown: Record<string, number>;
  top_ips: Array<{ ip: string; attack_count: number; primary_vector: string; percentage: number }>;
}

export interface AnalysisResponse {
  summary: RunSummary;
  requests: ClassifiedRequest[];
}

export interface ModelOption {
  key: string;
  filename: string;
  is_champion: boolean;
  type: string;
}

export interface HistoryItem {
  id: number;
  run_id: string;
  filename: string;
  timestamp: string;
  total_requests: number;
  benign_count: number;
  attack_count: number;
  attack_rate_pct: number;
  mean_anomaly_score: number;
  max_anomaly_score: number;
  execution_time_ms: number;
  model_used: string;
  risk_level: string;
  top_attack_type: string;
  attack_breakdown: Record<string, number>;
}
