"use client";

import React, { useState } from "react";
import { X, Database, Download, Eye, Trash2, Clock } from "lucide-react";
import { HistoryItem } from "@/types/telemetry";
import { deleteRun, getExportPdfUrl } from "@/services/api";

interface HistoricalRunsModalProps {
  isOpen: boolean;
  onClose: () => void;
  historyRuns: HistoryItem[];
  onSelectRun: (runId: string) => void;
  onRefreshHistory: () => void;
}

export function HistoricalRunsModal({
  isOpen,
  onClose,
  historyRuns,
  onSelectRun,
  onRefreshHistory,
}: HistoricalRunsModalProps) {
  const [isDeleting, setIsDeleting] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleDelete = async (e: React.MouseEvent, runId: string) => {
    e.stopPropagation();
    if (confirm(`Delete audit run ${runId} and all its classified requests from the database?`)) {
      setIsDeleting(runId);
      try {
        await deleteRun(runId);
        onRefreshHistory();
      } catch (err) {
        console.error("Failed to delete run:", err);
      } finally {
        setIsDeleting(null);
      }
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[85vh] bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-2.5">
            <div className="p-1.5 rounded-lg bg-emerald-950 border border-emerald-800 text-emerald-400">
              <Database className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Persistent Audit Telemetry History (SQLite)
              </h2>
              <p className="text-[11px] font-mono text-slate-400">
                Database: Practical 10/data/telemetry.db | {historyRuns.length} Total Runs
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {historyRuns.length > 0 ? (
            <div className="divide-y divide-slate-800/80">
              {historyRuns.map((run) => (
                <div
                  key={run.run_id}
                  onClick={() => {
                    onSelectRun(run.run_id);
                    onClose();
                  }}
                  className="py-3 px-3 hover:bg-slate-800/40 rounded-xl cursor-pointer transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-semibold text-blue-400">
                        {run.run_id}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {run.model_used}
                      </span>
                    </div>
                    <div className="flex items-center space-x-3 text-[11px] font-mono text-slate-400 mt-1">
                      <span className="flex items-center space-x-1">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{run.timestamp}</span>
                      </span>
                      <span>Total: {run.total_requests} reqs</span>
                      <span className={run.attack_count > 0 ? "text-rose-400" : "text-emerald-400"}>
                        {run.attack_count} attacks ({run.attack_rate_pct.toFixed(1)}%)
                      </span>
                      <span>Anomaly: {run.mean_anomaly_score.toFixed(4)}</span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      type="button"
                      onClick={() => {
                        onSelectRun(run.run_id);
                        onClose();
                      }}
                      className="flex items-center space-x-1 px-2.5 py-1 text-xs font-mono rounded bg-blue-950 text-blue-300 border border-blue-800 hover:bg-blue-900 transition-colors cursor-pointer"
                      title="Load into dashboard"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Inspect</span>
                    </button>

                    <a
                      href={getExportPdfUrl(run.run_id)}
                      download
                      onClick={(e) => e.stopPropagation()}
                      className="flex items-center space-x-1 px-2.5 py-1 text-xs font-mono rounded bg-emerald-950 text-emerald-300 border border-emerald-800 hover:bg-emerald-900 transition-colors cursor-pointer"
                      title="Export executive PDF report"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>PDF</span>
                    </a>

                    <button
                      type="button"
                      disabled={isDeleting === run.run_id}
                      onClick={(e) => handleDelete(e, run.run_id)}
                      className="p-1 text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 rounded transition-colors cursor-pointer"
                      title="Delete run record"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500 font-mono text-xs">
              No historical runs in SQLite database yet. Ingest a log stream to record your first run.
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/60 flex justify-between items-center text-xs font-mono text-slate-400">
          <span>Persisted across application reboots via SQLite database engine</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
