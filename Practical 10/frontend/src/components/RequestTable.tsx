"use client";

import React, { useState, useMemo } from "react";
import {
  Search,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Shield,
  Copy,
  Check,
  Code2,
} from "lucide-react";
import { ClassifiedRequest } from "@/types/telemetry";

interface RequestTableProps {
  requests: ClassifiedRequest[];
  selectedClassFilter: string | null;
  onSelectClassFilter: (className: string | null) => void;
  selectedIpFilter: string | null;
  onSelectIpFilter: (ip: string | null) => void;
}

export function RequestTable({
  requests,
  selectedClassFilter,
  onSelectClassFilter,
  selectedIpFilter,
  onSelectIpFilter,
}: RequestTableProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("All");
  const [expandedRowId, setExpandedRowId] = useState<number | null>(null);
  const [copiedLogId, setCopiedLogId] = useState<number | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [sortBy, setSortBy] = useState<"line" | "anomaly" | "confidence">("line");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("asc");

  // Filtering
  const filteredRequests = useMemo(() => {
    return requests.filter((req) => {
      const ip = req.client_ip || req.ip || "";
      const path = req.resource || req.path || "";
      const label = req.predicted_label || "";
      const display = req.display_name || "";

      // Class filter
      if (selectedClassFilter) {
        const filterLower = selectedClassFilter.toLowerCase();
        const matchesClass =
          label.toLowerCase().includes(filterLower) ||
          display.toLowerCase().includes(filterLower) ||
          (selectedClassFilter === "Benign" && !req.is_attack);
        if (!matchesClass) return false;
      }

      // IP filter
      if (selectedIpFilter && ip !== selectedIpFilter) {
        return false;
      }

      // Severity filter
      if (severityFilter !== "All" && req.severity !== severityFilter) {
        return false;
      }

      // Search term
      if (searchTerm.trim().length > 0) {
        const term = searchTerm.toLowerCase();
        const matchesTerm =
          ip.toLowerCase().includes(term) ||
          path.toLowerCase().includes(term) ||
          display.toLowerCase().includes(term) ||
          label.toLowerCase().includes(term) ||
          req.method.toLowerCase().includes(term) ||
          (req.raw_log && req.raw_log.toLowerCase().includes(term));
        if (!matchesTerm) return false;
      }
      return true;
    });
  }, [requests, selectedClassFilter, selectedIpFilter, severityFilter, searchTerm]);

  // Sorting
  const sortedRequests = useMemo(() => {
    return [...filteredRequests].sort((a, b) => {
      let diff = 0;
      if (sortBy === "anomaly") {
        diff = a.anomaly_score - b.anomaly_score;
      } else if (sortBy === "confidence") {
        diff = a.confidence_pct - b.confidence_pct;
      } else {
        diff = a.line_number - b.line_number;
      }
      return sortDirection === "asc" ? diff : -diff;
    });
  }, [filteredRequests, sortBy, sortDirection]);

  // Pagination
  const totalPages = Math.ceil(sortedRequests.length / pageSize) || 1;
  const paginatedRequests = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedRequests.slice(start, start + pageSize);
  }, [sortedRequests, currentPage, pageSize]);

  const toggleRow = (lineNum: number) => {
    setExpandedRowId((prev) => (prev === lineNum ? null : lineNum));
  };

  const copyToClipboard = (text: string, id: number) => {
    navigator.clipboard.writeText(text);
    setCopiedLogId(id);
    setTimeout(() => setCopiedLogId(null), 2000);
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "bg-rose-950/80 text-rose-300 border-rose-800";
      case "High":
        return "bg-orange-950/80 text-orange-300 border-orange-800";
      case "Medium":
        return "bg-amber-950/80 text-amber-300 border-amber-800";
      default:
        return "bg-emerald-950/80 text-emerald-300 border-emerald-800";
    }
  };

  const getActionBadge = (action: string) => {
    if (action.includes("Drop") || action.includes("Blacklist") || action.includes("Block")) {
      return "bg-rose-950/60 text-rose-300 border-rose-800/80";
    }
    if (action.includes("Sanitize") || action.includes("Alert") || action.includes("Challenge")) {
      return "bg-amber-950/60 text-amber-300 border-amber-800/80";
    }
    return "bg-emerald-950/60 text-emerald-300 border-emerald-800/80";
  };

  const getClassBadge = (isAttack: boolean) => {
    if (!isAttack) {
      return "bg-emerald-950/60 text-emerald-400 border-emerald-800/60";
    }
    return "bg-rose-950/60 text-rose-400 border-rose-800/60 font-semibold";
  };

  return (
    <div className="w-full bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden my-4 shadow-xl">
      {/* Table Toolbar */}
      <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <Shield className="w-4 h-4 text-blue-400" />
          <h3 className="text-xs font-semibold text-slate-200">
            Granular Telemetry & ML Classification Stream
          </h3>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
            Showing {sortedRequests.length} of {requests.length}
          </span>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IP, URI, payload..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className="pl-8 pr-3 py-1 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 w-44 sm:w-56"
            />
          </div>

          {/* Severity Select */}
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 px-2 py-1 focus:outline-none focus:border-blue-500 cursor-pointer"
          >
            <option value="All">All Severity</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          {/* Sort By Select */}
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as "line" | "anomaly" | "confidence")}
            className="bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 px-2 py-1 focus:outline-none focus:border-blue-500 cursor-pointer"
          >
            <option value="line">Sort: Line #</option>
            <option value="anomaly">Sort: Anomaly Score</option>
            <option value="confidence">Sort: ML Confidence</option>
          </select>

          {/* Sort Direction Toggle */}
          <button
            onClick={() => setSortDirection((d) => (d === "asc" ? "desc" : "asc"))}
            className="p-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-400 hover:text-slate-200 cursor-pointer"
            title="Toggle sort direction"
          >
            {sortDirection === "asc" ? (
              <ChevronUp className="w-3.5 h-3.5" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
      </div>

      {/* Active Filter Badges */}
      {(selectedClassFilter || selectedIpFilter) && (
        <div className="px-4 py-2 bg-slate-950/60 border-b border-slate-800/80 flex items-center space-x-2 text-xs font-mono">
          <span className="text-slate-400">Active Filters:</span>
          {selectedClassFilter && (
            <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-blue-950 border border-blue-800 text-blue-300">
              <span>Class: {selectedClassFilter}</span>
              <button
                onClick={() => onSelectClassFilter(null)}
                className="hover:text-white font-bold ml-1 cursor-pointer"
              >
                &times;
              </button>
            </span>
          )}
          {selectedIpFilter && (
            <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">
              <span>IP: {selectedIpFilter}</span>
              <button
                onClick={() => onSelectIpFilter(null)}
                className="hover:text-white font-bold ml-1 cursor-pointer"
              >
                &times;
              </button>
            </span>
          )}
        </div>
      )}

      {/* Table Content */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
            <tr>
              <th className="py-2.5 px-3 w-10 text-center">#</th>
              <th className="py-2.5 px-3">Timestamp / IP</th>
              <th className="py-2.5 px-3">Method & Resource</th>
              <th className="py-2.5 px-3 text-center">Status</th>
              <th className="py-2.5 px-3">Isolation Anomaly (P5)</th>
              <th className="py-2.5 px-3">ML Prediction (P9)</th>
              <th className="py-2.5 px-3 text-center">Severity</th>
              <th className="py-2.5 px-3">Recommended Mitigation</th>
              <th className="py-2.5 px-2 text-center w-8"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {paginatedRequests.map((req) => {
              const lineNum = req.line_number || req.line_index || 1;
              const isExpanded = expandedRowId === lineNum;
              const ip = req.client_ip || req.ip || "127.0.0.1";
              const path = req.resource || req.path || "/";

              return (
                <React.Fragment key={lineNum}>
                  <tr
                    onClick={() => toggleRow(lineNum)}
                    className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                      isExpanded ? "bg-slate-800/30" : ""
                    }`}
                  >
                    <td className="py-2.5 px-3 text-center text-slate-500 font-mono">
                      {lineNum}
                    </td>

                    <td className="py-2.5 px-3">
                      <div className="text-slate-200 font-semibold">{ip}</div>
                      <div className="text-[10px] text-slate-500">{req.timestamp}</div>
                    </td>

                    <td className="py-2.5 px-3 max-w-xs">
                      <div className="flex items-center space-x-1.5 truncate">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            req.method === "GET"
                              ? "bg-blue-950 text-blue-400 border border-blue-800"
                              : req.method === "POST"
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                              : "bg-amber-950 text-amber-400 border border-amber-800"
                          }`}
                        >
                          {req.method}
                        </span>
                        <span className="text-slate-300 truncate" title={path}>
                          {path}
                        </span>
                      </div>
                    </td>

                    <td className="py-2.5 px-3 text-center">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          req.status_code === 200
                            ? "text-emerald-400"
                            : req.status_code >= 400 && req.status_code < 500
                            ? "text-amber-400"
                            : "text-rose-400"
                        }`}
                      >
                        {req.status_code}
                      </span>
                    </td>

                    <td className="py-2.5 px-3">
                      <div className="flex items-center space-x-2">
                        <div className="w-16 bg-slate-800 rounded-full h-1.5">
                          <div
                            className={`h-full rounded-full ${
                              req.anomaly_score >= 0.52
                                ? "bg-rose-500"
                                : req.anomaly_score >= 0.45
                                ? "bg-amber-500"
                                : "bg-emerald-500"
                            }`}
                            style={{ width: `${Math.min(req.anomaly_score * 100, 100)}%` }}
                          />
                        </div>
                        <span className="text-slate-300 text-[11px]">
                          {req.anomaly_score.toFixed(4)}
                        </span>
                      </div>
                    </td>

                    <td className="py-2.5 px-3">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] border ${getClassBadge(
                            req.is_attack
                          )}`}
                        >
                          {req.display_name || req.predicted_label}
                        </span>
                        <span className="text-[10px] text-slate-400">
                          {req.confidence_pct ? `${req.confidence_pct.toFixed(1)}%` : ""}
                        </span>
                      </div>
                    </td>

                    <td className="py-2.5 px-3 text-center">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                          req.severity
                        )}`}
                      >
                        {req.severity}
                      </span>
                    </td>

                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] border ${getActionBadge(
                          req.recommended_action
                        )}`}
                      >
                        {req.recommended_action}
                      </span>
                    </td>

                    <td className="py-2.5 px-2 text-center text-slate-500">
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4 text-blue-400" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </td>
                  </tr>

                  {/* Expanded Row Details */}
                  {isExpanded && (
                    <tr className="bg-slate-950/90 border-b border-slate-800">
                      <td colSpan={9} className="p-4 space-y-3">
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                          {/* Left: Request Context & Raw Line */}
                          <div>
                            <div className="flex items-center justify-between mb-1.5">
                              <span className="text-xs font-semibold text-slate-300 flex items-center space-x-1.5">
                                <Code2 className="w-3.5 h-3.5 text-blue-400" />
                                <span>Parsed Telemetry Details</span>
                              </span>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  copyToClipboard(
                                    `${req.method} ${path} - ${req.status_code}`,
                                    lineNum
                                  );
                                }}
                                className="flex items-center space-x-1 px-2 py-0.5 text-[10px] rounded bg-slate-800 text-slate-300 hover:text-white cursor-pointer"
                              >
                                {copiedLogId === lineNum ? (
                                  <>
                                    <Check className="w-3 h-3 text-emerald-400" />
                                    <span>Copied</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3 h-3" />
                                    <span>Copy Info</span>
                                  </>
                                )}
                              </button>
                            </div>

                            <div className="mt-2 grid grid-cols-2 gap-2 text-[11px] font-mono">
                              <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                                <span className="text-slate-400">User Agent:</span>
                                <div className="text-slate-200 truncate" title={req.user_agent}>
                                  {req.user_agent || "N/A"}
                                </div>
                              </div>
                              <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                                <span className="text-slate-400">Bytes Sent:</span>
                                <div className="text-slate-200">
                                  {req.bytes_sent} bytes
                                </div>
                              </div>
                            </div>
                          </div>

                          {/* Right: Security & ML Metrics */}
                          <div>
                            <div className="text-xs font-semibold text-slate-300 mb-1.5">
                              Machine Learning Inference Attributes
                            </div>
                            <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                              <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                                <span className="text-slate-400">Class Label:</span>
                                <div className="text-slate-200 font-bold">
                                  {req.predicted_label}
                                </div>
                              </div>
                              <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                                <span className="text-slate-400">Classification Confidence:</span>
                                <div className="text-emerald-400 font-bold">
                                  {req.confidence_pct ? `${req.confidence_pct.toFixed(2)}%` : "N/A"}
                                </div>
                              </div>
                              <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                                <span className="text-slate-400">Isolation Anomaly Score:</span>
                                <div className="text-purple-400 font-bold">
                                  {req.anomaly_score.toFixed(4)}
                                </div>
                              </div>
                              <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                                <span className="text-slate-400">WAF Policy Action:</span>
                                <div className="text-blue-400 font-bold">
                                  {req.recommended_action}
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>

                        {/* Model Inference Footnote */}
                        <div className="p-2 rounded bg-blue-950/20 border border-blue-900/40 text-[11px] font-mono text-blue-300 flex items-center justify-between">
                          <span>
                            Pure Machine Learning Classification: Zero hardcoded regex overrides. Model output confidence:{" "}
                            {req.confidence_pct ? `${req.confidence_pct.toFixed(2)}%` : "N/A"} | Anomaly:{" "}
                            {req.anomaly_score.toFixed(4)}
                          </span>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}

            {paginatedRequests.length === 0 && (
              <tr>
                <td colSpan={9} className="py-8 text-center text-slate-500 font-mono text-xs">
                  No telemetry requests match the active filters or search query.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div className="p-3 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono text-slate-400">
        <div className="flex items-center space-x-2">
          <span>Rows per page:</span>
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setCurrentPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-0.5 text-slate-300 focus:outline-none cursor-pointer"
          >
            <option value={10}>10</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
          <span>
            Showing {(currentPage - 1) * pageSize + 1} -{" "}
            {Math.min(currentPage * pageSize, sortedRequests.length)} of {sortedRequests.length}
          </span>
        </div>

        <div className="flex items-center space-x-2">
          <button
            disabled={currentPage <= 1}
            onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
            className="p-1 rounded bg-slate-950 border border-slate-800 disabled:opacity-30 disabled:cursor-not-allowed hover:text-white cursor-pointer"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span>
            Page {currentPage} of {totalPages}
          </span>
          <button
            disabled={currentPage >= totalPages}
            onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
            className="p-1 rounded bg-slate-950 border border-slate-800 disabled:opacity-30 disabled:cursor-not-allowed hover:text-white cursor-pointer"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
