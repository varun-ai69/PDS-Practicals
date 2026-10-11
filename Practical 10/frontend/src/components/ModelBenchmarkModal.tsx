"use client";

import React from "react";
import { X, BarChart3, ShieldCheck, Cpu, CheckCircle2 } from "lucide-react";

interface ModelBenchmarkModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function ModelBenchmarkModal({ isOpen, onClose }: ModelBenchmarkModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[85vh] bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-2.5">
            <div className="p-1.5 rounded-lg bg-blue-950 border border-blue-800 text-blue-400">
              <BarChart3 className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Model Evaluation & Benchmark Telemetry
              </h2>
              <p className="text-[11px] font-mono text-slate-400">
                Trained on 275,000 Balanced Vectors | Evaluated on 100,000 Locked Test Records (P9)
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

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6">
          {/* Section 1: Champion Multi-Class Classifiers */}
          <div>
            <div className="flex items-center space-x-2 mb-3">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Supervised Multi-Class Threat Classifiers (Practical 9 Scorecard)
              </h3>
            </div>

            <div className="overflow-x-auto border border-slate-800 rounded-xl bg-slate-950/60">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <tr>
                    <th className="p-2.5">Classifier Architecture</th>
                    <th className="p-2.5 text-center">Dataset</th>
                    <th className="p-2.5 text-center">100k Test Acc</th>
                    <th className="p-2.5 text-center">Macro Recall</th>
                    <th className="p-2.5 text-center">Macro F1</th>
                    <th className="p-2.5 text-center">Audit Recall (225 reqs)</th>
                    <th className="p-2.5">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  <tr className="bg-blue-950/20">
                    <td className="p-2.5 font-semibold text-slate-100">
                      Random Forest (Tuned: 150 trees, entropy)
                    </td>
                    <td className="p-2.5 text-center text-slate-400">Balanced (275k)</td>
                    <td className="p-2.5 text-center font-bold text-emerald-400">98.72%</td>
                    <td className="p-2.5 text-center text-blue-400 font-bold">99.62%</td>
                    <td className="p-2.5 text-center text-slate-200 font-bold">0.9881</td>
                    <td className="p-2.5 text-center font-bold text-emerald-400">97.93% (142/145)</td>
                    <td className="p-2.5">
                      <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300 text-[10px] font-bold">
                        CHAMPION DEPLOYED
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td className="p-2.5 text-slate-200">
                      Decision Tree (Tuned: d=20, entropy)
                    </td>
                    <td className="p-2.5 text-center text-slate-400">Balanced (275k)</td>
                    <td className="p-2.5 text-center text-emerald-400">99.01%</td>
                    <td className="p-2.5 text-center text-blue-400">99.58%</td>
                    <td className="p-2.5 text-center text-slate-200">0.9908</td>
                    <td className="p-2.5 text-center text-slate-300">58.62% (85/145)</td>
                    <td className="p-2.5">
                      <span className="px-2 py-0.5 rounded bg-blue-950 border border-blue-800 text-blue-300 text-[10px]">
                        ULTRA-FAST (0.01s)
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td className="p-2.5 text-slate-300">
                      Random Forest (Base: 100 trees, gini)
                    </td>
                    <td className="p-2.5 text-center text-slate-400">Balanced (275k)</td>
                    <td className="p-2.5 text-center text-slate-300">97.07%</td>
                    <td className="p-2.5 text-center text-slate-300">99.20%</td>
                    <td className="p-2.5 text-center text-slate-300">0.9720</td>
                    <td className="p-2.5 text-center text-slate-300">97.93% (142/145)</td>
                    <td className="p-2.5">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
                        BASE ENSEMBLE
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td className="p-2.5 text-slate-300">
                      Decision Tree (Base: d=15, gini)
                    </td>
                    <td className="p-2.5 text-center text-slate-400">Balanced (275k)</td>
                    <td className="p-2.5 text-center text-slate-300">97.32%</td>
                    <td className="p-2.5 text-center text-slate-300">99.14%</td>
                    <td className="p-2.5 text-center text-slate-300">0.9737</td>
                    <td className="p-2.5 text-center text-slate-300">82.07% (119/145)</td>
                    <td className="p-2.5">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
                        BASE CART
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td className="p-2.5 text-slate-300">Logistic Regression (Linear)</td>
                    <td className="p-2.5 text-center text-slate-400">Balanced (275k)</td>
                    <td className="p-2.5 text-center text-slate-300">94.95%</td>
                    <td className="p-2.5 text-center text-slate-300">98.02%</td>
                    <td className="p-2.5 text-center text-slate-300">0.9503</td>
                    <td className="p-2.5 text-center text-slate-300">93.79% (136/145)</td>
                    <td className="p-2.5">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
                        LINEAR BASELINE
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 2: Unsupervised Anomaly Engine */}
          <div>
            <div className="flex items-center space-x-2 mb-3">
              <Cpu className="w-4 h-4 text-purple-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Unsupervised Isolation Forest Anomaly Engine (Practical 5)
              </h3>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 font-mono text-xs">
                <span className="text-slate-400 text-[10px]">HYPERPARAMETERS</span>
                <div className="mt-1 text-slate-200 space-y-0.5 text-[11px]">
                  <div>n_estimators: 100 trees</div>
                  <div>contamination: 0.015 (1.5%)</div>
                  <div>max_samples: 0.8 sub-sample</div>
                  <div>random_state: 42</div>
                </div>
              </div>

              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 font-mono text-xs">
                <span className="text-slate-400 text-[10px]">FEATURE SPACE</span>
                <div className="mt-1 text-slate-200 space-y-0.5 text-[11px]">
                  <div>Vector Dimension: 30 features</div>
                  <div>Preprocessing: Standard Scaler</div>
                  <div>Zero Imputation: Median/Mode</div>
                  <div>Zero Data Leakage: Clean Train/Test</div>
                </div>
              </div>

              <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 font-mono text-xs">
                <span className="text-slate-400 text-[10px]">SCORING FORMULA</span>
                <div className="mt-1 text-slate-200 space-y-0.5 text-[11px]">
                  <div>Raw: -score_samples(X)</div>
                  <div>Min-Max Scaled: [0.0, 1.0]</div>
                  <div>Threshold: 0.52 (Critical Alert)</div>
                  <div>Mode: Pure physical joblib model</div>
                </div>
              </div>
            </div>
          </div>

          {/* Section 3: Zero Regex / Pure ML Guarantee */}
          <div className="p-4 rounded-xl border border-emerald-800/40 bg-emerald-950/10">
            <div className="flex items-start space-x-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-semibold text-emerald-300">
                  Strict Zero Regex / Zero Heuristic Fallback Architecture
                </h4>
                <p className="text-[11px] font-mono text-slate-300 mt-1 leading-relaxed">
                  Every request classification displayed in SentinelSOC is executed strictly through the 30-feature numerical extraction pipeline and evaluated by the scikit-learn models (`isolation_forest.joblib` and `random_forest_tuned.joblib`). All hardcoded keyword checks, pattern escalations, and mock formula fallbacks have been permanently excised.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/60 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition-colors cursor-pointer"
          >
            Close Benchmarks
          </button>
        </div>
      </div>
    </div>
  );
}
