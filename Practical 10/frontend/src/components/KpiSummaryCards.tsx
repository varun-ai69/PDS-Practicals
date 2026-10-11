"use client";

import React from "react";
import { AlertTriangle, CheckCircle, Clock, Download, FileText, Gauge, ShieldAlert } from "lucide-react";
import { RunSummary } from "@/types/telemetry";

interface KpiSummaryCardsProps {
  summary: RunSummary;
  onExportPdf: () => void;
  isExportingPdf: boolean;
}

export function KpiSummaryCards({ summary, onExportPdf, isExportingPdf }: KpiSummaryCardsProps) {
  const getSeverityBadgeClass = (riskLevel: string) => {
    switch (riskLevel) {
      case "Critical":
        return "bg-rose-950/80 text-rose-300 border-rose-800";
      case "High":
        return "bg-orange-950/80 text-orange-300 border-orange-800";
      case "Elevated":
        return "bg-amber-950/80 text-amber-300 border-amber-800";
      default:
        return "bg-emerald-950/80 text-emerald-300 border-emerald-800";
    }
  };

  return (
    <div className="w-full space-y-4 my-4">
      {/* Top Banner with Run Details and PDF Export */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3.5 bg-slate-900 border border-slate-800 rounded-xl gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-blue-950 border border-blue-800/60 text-blue-400">
            <FileText className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold text-slate-200">
                Audit Run: <span className="font-mono text-blue-400">{summary.run_id}</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {summary.model_used}
              </span>
            </div>
            <p className="text-[11px] font-mono text-slate-400 mt-0.5">
              Persisted in SQLite DB (telemetry.db) | Execution Latency: {summary.execution_time_ms.toFixed(1)} ms
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={onExportPdf}
          disabled={isExportingPdf}
          className="flex items-center justify-center space-x-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold tracking-wide border border-emerald-500 shadow-md shadow-emerald-600/20 transition-all cursor-pointer"
        >
          {isExportingPdf ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              <span>Generating PDF...</span>
            </>
          ) : (
            <>
              <Download className="w-3.5 h-3.5" />
              <span>Export Executive PDF Report</span>
            </>
          )}
        </button>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {/* Card 1: Total Volume */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono uppercase tracking-wider">Total Evaluated</span>
            <FileText className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {summary.total_requests}
            </span>
            <span className="text-[10px] font-mono text-slate-400 ml-1">requests</span>
          </div>
          <div className="mt-2 text-[10px] font-mono text-slate-400">
            Pipeline: 100% processed
          </div>
        </div>

        {/* Card 2: Attack Detection Rate */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono uppercase tracking-wider">Attack Ratio</span>
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="mt-2">
            <span
              className={`text-2xl font-bold font-mono ${
                summary.attack_rate_pct > 0 ? "text-rose-400" : "text-emerald-400"
              }`}
            >
              {summary.attack_rate_pct.toFixed(1)}%
            </span>
          </div>
          <div className="mt-2 text-[10px] font-mono text-slate-400">
            {summary.attack_count} malicious requests
          </div>
        </div>

        {/* Card 3: Benign Traffic */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono uppercase tracking-wider">Benign Volume</span>
            <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              {summary.benign_count}
            </span>
            <span className="text-[10px] font-mono text-slate-400 ml-1">benign</span>
          </div>
          <div className="mt-2 text-[10px] font-mono text-slate-400">
            {summary.total_requests > 0
              ? `${((summary.benign_count / summary.total_requests) * 100).toFixed(1)}% nominal`
              : "0%"}
          </div>
        </div>

        {/* Card 4: Mean Anomaly Score (Isolation Forest) */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono uppercase tracking-wider">Anomaly Score</span>
            <Gauge className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-purple-400">
              {summary.mean_anomaly_score.toFixed(4)}
            </span>
          </div>
          <div className="mt-2 text-[10px] font-mono text-slate-400">
            Isolation Forest (P5)
          </div>
        </div>

        {/* Card 5: Highest Severity */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono uppercase tracking-wider">Risk Level</span>
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="mt-2">
            <span
              className={`inline-block px-2.5 py-1 text-xs font-mono font-bold rounded border ${getSeverityBadgeClass(
                summary.risk_level
              )}`}
            >
              {summary.risk_level.toUpperCase()}
            </span>
          </div>
          <div className="mt-2 text-[10px] font-mono text-slate-400">
            WAF Dynamic Escalation
          </div>
        </div>

        {/* Card 6: Pipeline Latency */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-[11px] font-mono uppercase tracking-wider">Total Latency</span>
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-cyan-400">
              {summary.execution_time_ms.toFixed(1)}
            </span>
            <span className="text-[10px] font-mono text-slate-400 ml-1">ms</span>
          </div>
          <div className="mt-2 text-[10px] font-mono text-slate-400">
            Stages 1-5 End-to-End
          </div>
        </div>
      </div>
    </div>
  );
}
