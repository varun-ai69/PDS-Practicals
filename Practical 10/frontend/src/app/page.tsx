"use client";

import React, { useState, useEffect } from "react";
import { Navbar } from "@/components/Navbar";
import { PipelineFlow } from "@/components/PipelineFlow";
import { LogIngestionCard } from "@/components/LogIngestionCard";
import { KpiSummaryCards } from "@/components/KpiSummaryCards";
import { ThreatAnalyticsGrid } from "@/components/ThreatAnalyticsGrid";
import { RequestTable } from "@/components/RequestTable";
import { HistoricalRunsModal } from "@/components/HistoricalRunsModal";
import { ModelBenchmarkModal } from "@/components/ModelBenchmarkModal";
import {
  analyzeLogs,
  fetchHealth,
  fetchHistory,
  fetchModels,
  fetchRunDetails,
  fetchSampleLogs,
  getExportPdfUrl,
} from "@/services/api";
import { AnalysisResponse, HistoryItem, ModelOption } from "@/types/telemetry";
import { AlertCircle } from "lucide-react";

export default function SOCDashboard() {
  const [models, setModels] = useState<ModelOption[]>([]);
  const [selectedModel, setSelectedModel] = useState<string>("Random Forest Ensemble (Champion)");
  const [sampleLogs, setSampleLogs] = useState<Record<string, string>>({});
  const [logContent, setLogContent] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isBackendOnline, setIsBackendOnline] = useState<boolean>(true);
  const [pipelineStage, setPipelineStage] = useState<"idle" | "running" | "completed">("idle");
  const [analysisResult, setAnalysisResult] = useState<AnalysisResponse | null>(null);
  const [historyRuns, setHistoryRuns] = useState<HistoryItem[]>([]);
  const [isHistoryOpen, setIsHistoryOpen] = useState<boolean>(false);
  const [isBenchmarkOpen, setIsBenchmarkOpen] = useState<boolean>(false);
  const [isExportingPdf, setIsExportingPdf] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Filters
  const [selectedClassFilter, setSelectedClassFilter] = useState<string | null>(null);
  const [selectedIpFilter, setSelectedIpFilter] = useState<string | null>(null);

  // Initial load
  useEffect(() => {
    async function initDashboard() {
      try {
        const health = await fetchHealth();
        setIsBackendOnline(health.status === "healthy" || health.status === "ok");

        const modelsData = await fetchModels();
        setModels(modelsData.models);
        if (modelsData.current_model) {
          setSelectedModel(modelsData.current_model);
        }

        const samples = await fetchSampleLogs();
        setSampleLogs(samples);

        // Preload default sample
        if (samples["mixed_attack_stream"]) {
          setLogContent(samples["mixed_attack_stream"]);
        }

        const history = await fetchHistory();
        setHistoryRuns(history);
      } catch (err) {
        console.warn("Backend initialization warning:", err);
        setIsBackendOnline(false);
      }
    }
    initDashboard();
  }, []);

  const refreshHistory = async () => {
    try {
      const history = await fetchHistory();
      setHistoryRuns(history);
    } catch (err) {
      console.error("Failed to refresh history:", err);
    }
  };

  const handleAnalyze = async () => {
    if (!logContent.trim()) return;
    setIsLoading(true);
    setPipelineStage("running");
    setErrorMessage(null);

    try {
      const response = await analyzeLogs(logContent, selectedModel);
      setAnalysisResult(response);
      setPipelineStage("completed");
      refreshHistory();
    } catch (err: any) {
      console.error("Analysis execution error:", err);
      setErrorMessage(err.message || "Failed to process log telemetry through ML pipeline");
      setPipelineStage("idle");
    } finally {
      setIsLoading(false);
    }
  };

  const handleExportPdf = () => {
    if (!analysisResult?.summary.run_id) return;
    setIsExportingPdf(true);
    const pdfUrl = getExportPdfUrl(analysisResult.summary.run_id);
    const link = document.createElement("a");
    link.href = pdfUrl;
    link.download = `soc_report_${analysisResult.summary.run_id}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => setIsExportingPdf(false), 1500);
  };

  const handleSelectHistoricalRun = async (runId: string) => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const response = await fetchRunDetails(runId);
      setAnalysisResult(response);
      setPipelineStage("completed");
      setSelectedClassFilter(null);
      setSelectedIpFilter(null);
    } catch (err: any) {
      console.error("Failed to load historical run:", err);
      setErrorMessage(`Failed to retrieve run ${runId}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClear = () => {
    setLogContent("");
    setAnalysisResult(null);
    setPipelineStage("idle");
    setSelectedClassFilter(null);
    setSelectedIpFilter(null);
    setErrorMessage(null);
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#090d16] text-slate-100 selection:bg-blue-600 selection:text-white">
      {/* Navigation */}
      <Navbar
        models={models}
        selectedModel={selectedModel}
        onSelectModel={setSelectedModel}
        isBackendOnline={isBackendOnline}
        onOpenHistory={() => setIsHistoryOpen(true)}
        onOpenBenchmark={() => setIsBenchmarkOpen(true)}
        historyCount={historyRuns.length}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Error Notification */}
        {errorMessage && (
          <div className="p-3.5 rounded-xl border border-rose-900 bg-rose-950/40 text-rose-300 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-rose-400" />
              <span>{errorMessage}</span>
            </div>
            <button onClick={() => setErrorMessage(null)} className="font-bold hover:text-white cursor-pointer">
              &times;
            </button>
          </div>
        )}

        {/* Pipeline Flow Architecture */}
        <PipelineFlow
          currentStage={pipelineStage}
          recordsProcessed={analysisResult?.summary.total_requests || 0}
          modelUsed={selectedModel}
        />

        {/* Ingestion & Telemetry Buffer */}
        <LogIngestionCard
          logContent={logContent}
          setLogContent={setLogContent}
          onAnalyze={handleAnalyze}
          isLoading={isLoading}
          sampleLogs={sampleLogs}
          onClear={handleClear}
        />

        {/* Dynamic Threat Analytics Dashboard */}
        {analysisResult && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* KPI Cards */}
            <KpiSummaryCards
              summary={analysisResult.summary}
              onExportPdf={handleExportPdf}
              isExportingPdf={isExportingPdf}
            />

            {/* Visual Threat Analytics Grid */}
            <ThreatAnalyticsGrid
              summary={analysisResult.summary}
              requests={analysisResult.requests}
              selectedClassFilter={selectedClassFilter}
              onSelectClassFilter={setSelectedClassFilter}
              selectedIpFilter={selectedIpFilter}
              onSelectIpFilter={setSelectedIpFilter}
            />

            {/* Granular Telemetry & Model Classification Table */}
            <RequestTable
              requests={analysisResult.requests}
              selectedClassFilter={selectedClassFilter}
              onSelectClassFilter={setSelectedClassFilter}
              selectedIpFilter={selectedIpFilter}
              onSelectIpFilter={setSelectedIpFilter}
            />
          </div>
        )}
      </main>

      {/* Audit History Drawer / Modal */}
      <HistoricalRunsModal
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        historyRuns={historyRuns}
        onSelectRun={handleSelectHistoricalRun}
        onRefreshHistory={refreshHistory}
      />

      {/* Model Benchmark Drawer / Modal */}
      <ModelBenchmarkModal
        isOpen={isBenchmarkOpen}
        onClose={() => setIsBenchmarkOpen(false)}
      />

      {/* Executive Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-4 text-center text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>SentinelSOC Threat Platform | Practical 10 Deployment</span>
          <span>Zero RegEx Fallbacks | 30 Canonical Features | Pure Machine Learning</span>
        </div>
      </footer>
    </div>
  );
}
