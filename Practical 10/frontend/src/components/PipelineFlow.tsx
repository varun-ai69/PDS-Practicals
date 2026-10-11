"use client";

import React from "react";
import { ArrowRight, CheckCircle2, Circle, Cpu, Database, FileText, Layers, ShieldCheck } from "lucide-react";

interface PipelineFlowProps {
  currentStage: "idle" | "running" | "completed";
  recordsProcessed?: number;
  modelUsed?: string;
}

export function PipelineFlow({ currentStage, recordsProcessed = 0, modelUsed = "Random Forest" }: PipelineFlowProps) {
  const stages = [
    {
      id: 1,
      title: "Practical 1",
      subtitle: "Ingestion Engine",
      detail: "Raw Log Buffer & Preprocessing",
      icon: FileText,
      color: "border-blue-500/30 text-blue-400 bg-blue-950/20",
    },
    {
      id: 2,
      title: "Practical 2",
      subtitle: "Combined Lexer",
      detail: "IP, RFC-1123, HTTP Verb & Size",
      icon: Layers,
      color: "border-cyan-500/30 text-cyan-400 bg-cyan-950/20",
    },
    {
      id: 3,
      title: "Practical 3",
      subtitle: "Data Normalizer",
      detail: "Cleaning & Missing Imputation",
      icon: Database,
      color: "border-indigo-500/30 text-indigo-400 bg-indigo-950/20",
    },
    {
      id: 4,
      title: "Practical 5",
      subtitle: "Isolation Forest",
      detail: "30 Canonical Features + Anomaly Engine",
      icon: Cpu,
      color: "border-purple-500/30 text-purple-400 bg-purple-950/20",
    },
    {
      id: 5,
      title: "Practical 9",
      subtitle: "Champion ML Classifier",
      detail: `${modelUsed} (Pure Multi-Class ML)`,
      icon: ShieldCheck,
      color: "border-emerald-500/30 text-emerald-400 bg-emerald-950/20",
    },
  ];

  return (
    <div className="w-full bg-slate-900/60 border border-slate-800/80 rounded-xl p-4 my-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
            End-to-End Pipeline Architecture
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
            Zero Heuristics / 100% Machine Learning
          </span>
        </div>
        <div className="text-[11px] font-mono text-slate-400">
          Status:{" "}
          {currentStage === "running" && (
            <span className="text-amber-400 font-medium">Processing Pipeline...</span>
          )}
          {currentStage === "completed" && (
            <span className="text-emerald-400 font-medium">
              Pipeline Completed ({recordsProcessed} requests)
            </span>
          )}
          {currentStage === "idle" && (
            <span className="text-slate-500">Standby (Awaiting Input)</span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        {stages.map((stage, idx) => {
          const Icon = stage.icon;
          const isDone = currentStage === "completed";
          const isCurrent = currentStage === "running";

          return (
            <div
              key={stage.id}
              className={`relative flex flex-col p-3 rounded-lg border transition-all ${
                isDone
                  ? "border-emerald-600/40 bg-slate-900/90"
                  : isCurrent
                  ? "border-blue-500/50 bg-blue-950/20 shadow-sm shadow-blue-500/20"
                  : "border-slate-800/90 bg-slate-950/40"
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] font-mono text-slate-400 tracking-wider">
                  {stage.title}
                </span>
                {isDone ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                ) : isCurrent ? (
                  <div className="w-2 h-2 rounded-full bg-blue-400 animate-ping" />
                ) : (
                  <Circle className="w-3 h-3 text-slate-600" />
                )}
              </div>
              <div className="flex items-center space-x-2 mb-1">
                <div className={`p-1.5 rounded border ${stage.color}`}>
                  <Icon className="w-3.5 h-3.5" />
                </div>
                <h4 className="text-xs font-semibold text-slate-200 truncate">{stage.subtitle}</h4>
              </div>
              <p className="text-[10px] text-slate-400 font-mono line-clamp-1">{stage.detail}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
