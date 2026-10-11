"use client";

import React from "react";
import { BarChart3, Globe, Layers } from "lucide-react";
import { ClassifiedRequest, RunSummary } from "@/types/telemetry";

interface ThreatAnalyticsGridProps {
  summary: RunSummary;
  requests: ClassifiedRequest[];
  selectedClassFilter: string | null;
  onSelectClassFilter: (className: string | null) => void;
  selectedIpFilter: string | null;
  onSelectIpFilter: (ip: string | null) => void;
}

export function ThreatAnalyticsGrid({
  summary,
  requests,
  selectedClassFilter,
  onSelectClassFilter,
  selectedIpFilter,
  onSelectIpFilter,
}: ThreatAnalyticsGridProps) {
  // Label color formatting
  const getClassColor = (name: string) => {
    const lower = name.toLowerCase();
    if (lower.includes("benign") || lower.includes("normal")) {
      return { bar: "bg-emerald-500", text: "text-emerald-400" };
    }
    if (lower.includes("sqli") || lower.includes("sql")) {
      return { bar: "bg-rose-500", text: "text-rose-400" };
    }
    if (lower.includes("xss")) {
      return { bar: "bg-amber-500", text: "text-amber-400" };
    }
    if (lower.includes("traversal") || lower.includes("lfi")) {
      return { bar: "bg-purple-500", text: "text-purple-400" };
    }
    if (lower.includes("command") || lower.includes("rce")) {
      return { bar: "bg-red-600", text: "text-red-400" };
    }
    if (lower.includes("ssrf")) {
      return { bar: "bg-cyan-500", text: "text-cyan-400" };
    }
    if (lower.includes("brute")) {
      return { bar: "bg-orange-500", text: "text-orange-400" };
    }
    return { bar: "bg-blue-500", text: "text-blue-400" };
  };

  // Compute anomaly score bands
  const anomalyBands = {
    nominal: requests.filter((r) => r.anomaly_score < 0.45).length,
    elevated: requests.filter((r) => r.anomaly_score >= 0.45 && r.anomaly_score < 0.52).length,
    critical: requests.filter((r) => r.anomaly_score >= 0.52).length,
  };

  const total = summary.total_requests || 1;

  // Build full distribution including benign
  const classBreakdown: Record<string, number> = {
    Benign: summary.benign_count,
    ...summary.attack_breakdown,
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 my-4">
      {/* Column 1: Multi-Class Attack Distribution */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div className="flex items-center space-x-2">
              <BarChart3 className="w-4 h-4 text-blue-400" />
              <h3 className="text-xs font-semibold text-slate-200">
                Threat Classification Distribution
              </h3>
            </div>
            {selectedClassFilter && (
              <button
                onClick={() => onSelectClassFilter(null)}
                className="text-[10px] font-mono text-blue-400 hover:underline cursor-pointer"
              >
                Reset Filter
              </button>
            )}
          </div>
          <p className="text-[11px] font-mono text-slate-400 mt-1.5 mb-3">
            Pure model multi-class predictions (click to filter log table)
          </p>

          <div className="space-y-2.5">
            {Object.entries(classBreakdown).map(([className, count]) => {
              if (count === 0 && className !== "Benign") return null;
              const colors = getClassColor(className);
              const pct = (count / total) * 100;
              const isSelected = selectedClassFilter === className;

              return (
                <div
                  key={className}
                  onClick={() => onSelectClassFilter(isSelected ? null : className)}
                  className={`p-2 rounded-lg border transition-all cursor-pointer ${
                    isSelected
                      ? "border-blue-500 bg-blue-950/30"
                      : "border-slate-800/60 hover:border-slate-700 bg-slate-950/40"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className={`font-semibold font-mono ${colors.text}`}>{className}</span>
                    <span className="font-mono text-slate-300 text-[11px]">
                      {count} <span className="text-slate-500">({pct.toFixed(1)}%)</span>
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className={`h-full ${colors.bar} transition-all duration-500`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 flex items-center justify-between">
          <span>Inference: Champion Classifier</span>
          <span>Zero Regex Overrides</span>
        </div>
      </div>

      {/* Column 2: Top Threat Actor IPs */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div className="flex items-center space-x-2">
              <Globe className="w-4 h-4 text-emerald-400" />
              <h3 className="text-xs font-semibold text-slate-200">
                Top Malicious Actor IPs
              </h3>
            </div>
            {selectedIpFilter && (
              <button
                onClick={() => onSelectIpFilter(null)}
                className="text-[10px] font-mono text-emerald-400 hover:underline cursor-pointer"
              >
                Reset IP
              </button>
            )}
          </div>
          <p className="text-[11px] font-mono text-slate-400 mt-1.5 mb-3">
            Source IP frequency and dominant exploit category
          </p>

          {summary.top_ips && summary.top_ips.length > 0 ? (
            <div className="space-y-2">
              {summary.top_ips.slice(0, 5).map((actor) => {
                const isSelected = selectedIpFilter === actor.ip;
                return (
                  <div
                    key={actor.ip}
                    onClick={() => onSelectIpFilter(isSelected ? null : actor.ip)}
                    className={`flex items-center justify-between p-2 rounded-lg border text-xs cursor-pointer transition-all ${
                      isSelected
                        ? "border-emerald-500 bg-emerald-950/30"
                        : "border-slate-800/60 hover:border-slate-700 bg-slate-950/40"
                    }`}
                  >
                    <div>
                      <div className="font-mono font-medium text-slate-200">{actor.ip}</div>
                      <div className="text-[10px] font-mono text-rose-400">
                        {actor.primary_vector}
                      </div>
                    </div>
                    <div className="text-right">
                      <span className="font-mono text-xs font-bold text-slate-200">
                        {actor.attack_count}
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono ml-1">hits</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="p-6 text-center text-slate-500 font-mono text-xs">
              No malicious actors detected in this log stream.
            </div>
          )}
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 flex items-center justify-between">
          <span>Aggregated Telemetry (P7)</span>
          <span>Click IP to isolate stream</span>
        </div>
      </div>

      {/* Column 3: Isolation Forest Anomaly Engine Profile */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div className="flex items-center space-x-2">
              <Layers className="w-4 h-4 text-purple-400" />
              <h3 className="text-xs font-semibold text-slate-200">
                Isolation Forest Telemetry
              </h3>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300">
              P5 Model
            </span>
          </div>
          <p className="text-[11px] font-mono text-slate-400 mt-1.5 mb-3">
            Unsupervised density anomaly distribution across 30 features
          </p>

          <div className="space-y-3">
            {/* Band 1: Nominal */}
            <div className="p-2.5 rounded-lg border border-slate-800/70 bg-slate-950/50">
              <div className="flex justify-between text-xs mb-1">
                <span className="text-emerald-400 font-mono">Nominal Density (&lt; 0.45)</span>
                <span className="font-mono text-slate-300 text-[11px]">
                  {anomalyBands.nominal} ({((anomalyBands.nominal / total) * 100).toFixed(1)}%)
                </span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-1.5">
                <div
                  className="h-full bg-emerald-500 rounded-full"
                  style={{ width: `${(anomalyBands.nominal / total) * 100}%` }}
                />
              </div>
            </div>

            {/* Band 2: Elevated */}
            <div className="p-2.5 rounded-lg border border-slate-800/70 bg-slate-950/50">
              <div className="flex justify-between text-xs mb-1">
                <span className="text-amber-400 font-mono">Elevated Variance (0.45 - 0.52)</span>
                <span className="font-mono text-slate-300 text-[11px]">
                  {anomalyBands.elevated} ({((anomalyBands.elevated / total) * 100).toFixed(1)}%)
                </span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-1.5">
                <div
                  className="h-full bg-amber-500 rounded-full"
                  style={{ width: `${(anomalyBands.elevated / total) * 100}%` }}
                />
              </div>
            </div>

            {/* Band 3: Critical Anomaly */}
            <div className="p-2.5 rounded-lg border border-slate-800/70 bg-slate-950/50">
              <div className="flex justify-between text-xs mb-1">
                <span className="text-rose-400 font-mono">High Anomaly (&ge; 0.52)</span>
                <span className="font-mono text-slate-300 text-[11px]">
                  {anomalyBands.critical} ({((anomalyBands.critical / total) * 100).toFixed(1)}%)
                </span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-1.5">
                <div
                  className="h-full bg-rose-500 rounded-full"
                  style={{ width: `${(anomalyBands.critical / total) * 100}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 flex items-center justify-between">
          <span>Formula: -score_samples(X)</span>
          <span>Contamination: 1.5%</span>
        </div>
      </div>
    </div>
  );
}
