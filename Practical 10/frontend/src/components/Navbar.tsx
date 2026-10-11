"use client";

import React from "react";
import { Shield, Database, BarChart3, Activity } from "lucide-react";
import { ModelOption } from "@/types/telemetry";

interface NavbarProps {
  models: ModelOption[];
  selectedModel: string;
  onSelectModel: (modelKey: string) => void;
  isBackendOnline: boolean;
  onOpenHistory: () => void;
  onOpenBenchmark: () => void;
  historyCount: number;
}

export function Navbar({
  models,
  selectedModel,
  onSelectModel,
  isBackendOnline,
  onOpenHistory,
  onOpenBenchmark,
  historyCount,
}: NavbarProps) {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-blue-600/10 border border-blue-500/20 text-blue-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold tracking-wider text-base text-slate-100">
                SENTINEL<span className="text-blue-500">.SOC</span>
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-950/60 border border-blue-800 text-blue-400 font-medium">
                P10 THREAT PLATFORM
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono hidden sm:block">
              Practical 1-9 Ingestion, Isolation Forest & Pure ML Inference
            </p>
          </div>
        </div>

        {/* Center / Right Controls */}
        <div className="flex items-center space-x-3">
          {/* Health Status */}
          <div className="hidden md:flex items-center space-x-2 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs">
            {isBackendOnline ? (
              <>
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-slate-300 font-mono">BACKEND ONLINE</span>
              </>
            ) : (
              <>
                <div className="w-2 h-2 rounded-full bg-rose-500" />
                <span className="text-rose-400 font-mono">BACKEND OFFLINE</span>
              </>
            )}
          </div>

          {/* Model Switcher */}
          <div className="flex items-center space-x-1.5 bg-slate-900 border border-slate-800 rounded-lg p-1">
            <span className="text-[11px] font-medium text-slate-400 px-2 font-mono hidden lg:inline">
              MODEL:
            </span>
            <select
              value={selectedModel}
              onChange={(e) => onSelectModel(e.target.value)}
              className="bg-slate-950 text-slate-200 text-xs font-mono rounded px-2.5 py-1 border border-slate-700/60 focus:outline-none focus:border-blue-500 transition-colors cursor-pointer"
            >
              {models.map((m) => (
                <option key={m.key} value={m.key}>
                  {m.key} {m.is_champion ? "★" : ""}
                </option>
              ))}
            </select>
          </div>

          {/* Model Benchmarks Modal Trigger */}
          <button
            onClick={onOpenBenchmark}
            className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors cursor-pointer"
            title="View P5 & P9 Model Training Benchmarks"
          >
            <BarChart3 className="w-3.5 h-3.5 text-blue-400" />
            <span className="hidden sm:inline">Benchmarks</span>
          </button>

          {/* Audit History Trigger */}
          <button
            onClick={onOpenHistory}
            className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors relative cursor-pointer"
            title="View Database Telemetry Runs"
          >
            <Database className="w-3.5 h-3.5 text-emerald-400" />
            <span>Audit History</span>
            {historyCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-blue-600 text-white font-mono">
                {historyCount}
              </span>
            )}
          </button>
        </div>
      </div>
    </header>
  );
}
