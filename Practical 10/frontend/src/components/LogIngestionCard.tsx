"use client";

import React, { useState, useRef } from "react";
import { Upload, Play, Trash2, FileText, Sparkles, Check, AlertCircle } from "lucide-react";

interface LogIngestionCardProps {
  logContent: string;
  setLogContent: (val: string) => void;
  onAnalyze: () => void;
  isLoading: boolean;
  sampleLogs: Record<string, string>;
  onClear: () => void;
}

export function LogIngestionCard({
  logContent,
  setLogContent,
  onAnalyze,
  isLoading,
  sampleLogs,
  onClear,
}: LogIngestionCardProps) {
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const lineCount = logContent ? logContent.trim().split("\n").filter((l) => l.trim().length > 0).length : 0;
  const byteSize = new Blob([logContent]).size;

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      readFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      readFile(e.target.files[0]);
    }
  };

  const readFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setLogContent(content);
      }
    };
    reader.readAsText(file);
  };

  const loadSample = (key: string) => {
    if (sampleLogs[key]) {
      setLogContent(sampleLogs[key]);
    }
  };

  return (
    <div className="w-full bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-xl shadow-black/40">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
            <FileText className="w-4 h-4 text-blue-400" />
            <span>Telemetry Ingestion & Raw Log Buffer</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Accepts Apache Combined Log Format (.log, .txt) with query strings and payloads
          </p>
        </div>

        {/* Quick Sample Buttons */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-mono text-slate-400 mr-1">Presets:</span>
          {Object.keys(sampleLogs).map((key) => {
            const labelMap: Record<string, string> = {
              mixed_attack_stream: "Mixed Vectors",
              clean_benign: "Benign Stream",
              sqli_wave: "SQLi Attacks",
              path_traversal_wave: "Path Traversal",
            };
            return (
              <button
                key={key}
                type="button"
                onClick={() => loadSample(key)}
                className="px-2.5 py-1 text-[11px] font-mono rounded bg-slate-800/90 hover:bg-slate-700 text-slate-300 border border-slate-700/60 hover:border-blue-500/50 transition-colors"
              >
                {labelMap[key] || key}
              </button>
            );
          })}
        </div>
      </div>

      {/* Drop Zone & Editor */}
      <div className="mt-4">
        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          className={`relative rounded-lg border transition-all ${
            dragActive
              ? "border-blue-500 bg-blue-950/20"
              : "border-slate-800 bg-slate-950/70"
          }`}
        >
          <textarea
            value={logContent}
            onChange={(e) => setLogContent(e.target.value)}
            placeholder="Paste raw web server logs here, drag-and-drop a .log file, or select a preset above..."
            rows={7}
            className="w-full bg-transparent text-slate-200 font-mono text-xs p-3.5 focus:outline-none resize-y min-h-[140px] placeholder:text-slate-600"
          />

          <input
            ref={fileInputRef}
            type="file"
            accept=".log,.txt"
            onChange={handleFileChange}
            className="hidden"
          />
        </div>

        {/* Action Bar */}
        <div className="mt-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-3 text-xs font-mono text-slate-400">
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5 text-blue-400" />
              <span>Browse File</span>
            </button>
            <span>
              Lines: <strong className="text-slate-200">{lineCount}</strong>
            </span>
            <span>
              Size: <strong className="text-slate-200">{(byteSize / 1024).toFixed(1)} KB</strong>
            </span>
          </div>

          <div className="flex items-center space-x-2">
            {lineCount > 0 && (
              <button
                type="button"
                onClick={onClear}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 border border-slate-800 hover:border-rose-900 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}

            <button
              type="button"
              disabled={lineCount === 0 || isLoading}
              onClick={onAnalyze}
              className={`flex items-center space-x-2 px-5 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all ${
                lineCount === 0 || isLoading
                  ? "bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-800"
                  : "bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/30 cursor-pointer border border-blue-500"
              }`}
            >
              {isLoading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Executing Pipeline...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Execute Threat Analysis</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
