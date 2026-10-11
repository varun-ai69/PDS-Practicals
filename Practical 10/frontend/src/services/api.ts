import { AnalysisResponse, HistoryItem, ModelOption } from "@/types/telemetry";

const API_BASE = "/api";

export async function fetchHealth(): Promise<{ status: string; current_model: string; available_models: string[] }> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error("Backend service unreachable");
  return res.json();
}

export async function fetchModels(): Promise<{ models: ModelOption[]; current_model: string }> {
  const res = await fetch(`${API_BASE}/models`);
  if (!res.ok) throw new Error("Failed to load model registry");
  return res.json();
}

export async function fetchSampleLogs(): Promise<Record<string, string>> {
  const res = await fetch(`${API_BASE}/sample-logs`);
  if (!res.ok) throw new Error("Failed to load sample telemetry");
  return res.json();
}

export async function analyzeLogs(logContent: string, modelKey: string = "Random Forest Ensemble (Champion)", filename: string = "live_stream.log"): Promise<AnalysisResponse> {
  const res = await fetch(`${API_BASE}/analyze-log`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      log_content: logContent,
      model_key: modelKey,
      filename: filename,
    }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || "Analysis pipeline execution failed");
  }
  return res.json();
}

export async function fetchHistory(limit: number = 50): Promise<HistoryItem[]> {
  const res = await fetch(`${API_BASE}/history?limit=${limit}`);
  if (!res.ok) throw new Error("Failed to fetch historical runs");
  return res.json();
}

export async function fetchRunDetails(runId: string): Promise<AnalysisResponse> {
  const res = await fetch(`${API_BASE}/runs/${runId}`);
  if (!res.ok) throw new Error(`Run ${runId} not found`);
  const data = await res.json();
  // Transform DB run response to standard AnalysisResponse
  const summary = {
    run_id: data.run_id,
    filename: data.filename,
    timestamp: data.timestamp,
    total_requests: data.total_requests,
    benign_count: data.benign_count,
    attack_count: data.attack_count,
    attack_rate_pct: data.attack_rate_pct,
    mean_anomaly_score: data.mean_anomaly_score,
    max_anomaly_score: data.max_anomaly_score,
    execution_time_ms: data.execution_time_ms,
    model_used: data.model_used,
    risk_level: data.risk_level,
    top_attack_type: data.top_attack_type,
    attack_breakdown: data.attack_breakdown || {},
    top_ips: [],
  };
  return {
    summary,
    requests: data.requests || [],
  };
}

export function getExportPdfUrl(runId: string): string {
  return `${API_BASE}/export-pdf/${runId}`;
}

export async function deleteRun(runId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/runs/${runId}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete audit record");
}
