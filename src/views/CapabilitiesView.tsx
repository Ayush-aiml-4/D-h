import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Search,
  Filter,
  Eye,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Cpu,
  FileCheck,
  Lock,
  Layers,
  X,
  Sparkles,
} from 'lucide-react';
import { CapabilityDefinition, CapabilityEvaluationResult, Program } from '../types';
import { api } from '../api/client';
import { CAPABILITIES } from '../constants/capabilities';

interface CapabilitiesViewProps {
  programs: Program[];
}

export const CapabilitiesView: React.FC<CapabilitiesViewProps> = ({ programs }) => {
  const [capabilities, setCapabilities] = useState<CapabilityDefinition[]>(CAPABILITIES);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');

  // Evaluation Modal state
  const [evalModalCapability, setEvalModalCapability] = useState<CapabilityDefinition | null>(null);
  const [evalProgramId, setEvalProgramId] = useState<string>(programs[0]?.id || '');
  const [evalTarget, setEvalTarget] = useState<string>(programs[0]?.targets?.[0] || 'api.acme-security.test');
  const [evalResult, setEvalResult] = useState<CapabilityEvaluationResult | null>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [evalError, setEvalError] = useState<string | null>(null);

  // Passive Analysis Execution state
  const [analysisResult, setAnalysisResult] = useState<any | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  useEffect(() => {
    // Load capabilities from API
    api
      .getCapabilities()
      .then((data) => {
        if (data && data.length > 0) setCapabilities(data);
      })
      .catch(() => {
        // Fallback to imported constants
      });
  }, []);

  const categories = ['ALL', ...Array.from(new Set(capabilities.map((c) => c.category)))];
  const statuses = ['ALL', 'SUPPORTED', 'PARTIAL', 'MANUAL', 'PLANNED'];

  const filteredCapabilities = capabilities.filter((c) => {
    const matchesSearch =
      c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.description.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCat = selectedCategory === 'ALL' || c.category === selectedCategory;
    const matchesStat = selectedStatus === 'ALL' || c.implementationStatus === selectedStatus;
    return matchesSearch && matchesCat && matchesStat;
  });

  const handleOpenEvaluationModal = (cap: CapabilityDefinition) => {
    setEvalModalCapability(cap);
    setEvalResult(null);
    setEvalError(null);
    setAnalysisResult(null);
    setAnalysisError(null);
    const selectedProg = programs.find((p) => p.id === evalProgramId) || programs[0];
    if (selectedProg && selectedProg.targets && selectedProg.targets.length > 0) {
      setEvalTarget(selectedProg.targets[0]);
    }
  };

  const handleRunEvaluation = async () => {
    if (!evalModalCapability || !evalProgramId || !evalTarget) return;

    setIsEvaluating(true);
    setEvalError(null);
    setEvalResult(null);
    setAnalysisResult(null);
    setAnalysisError(null);

    try {
      const res = await api.evaluateCapability(
        evalProgramId,
        evalTarget.trim(),
        evalModalCapability.id
      );
      setEvalResult(res);
    } catch (err: any) {
      setEvalError(err.message || 'Policy evaluation failed');
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleRunAnalysis = async () => {
    if (!evalModalCapability || !evalProgramId || !evalTarget) return;

    setIsAnalyzing(true);
    setAnalysisError(null);
    setAnalysisResult(null);

    try {
      const res = await api.analyzeCapability(
        evalProgramId,
        evalTarget.trim(),
        evalModalCapability.id
      );
      setAnalysisResult(res);
    } catch (err: any) {
      setAnalysisError(err.message || 'Passive research analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'SUPPORTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-emerald-950/60 border border-emerald-600/40 text-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            SUPPORTED
          </span>
        );
      case 'PARTIAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-amber-950/60 border border-amber-600/40 text-amber-300">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            PARTIAL
          </span>
        );
      case 'MANUAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-blue-950/60 border border-blue-600/40 text-blue-300">
            <Cpu className="w-3.5 h-3.5 text-blue-400" />
            MANUAL
          </span>
        );
      case 'PLANNED':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-slate-800/80 border border-slate-600/40 text-slate-400">
            <Sparkles className="w-3.5 h-3.5 text-slate-400" />
            PLANNED
          </span>
        );
    }
  };

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-mono font-bold bg-emerald-950/80 border border-emerald-500/50 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.2)]">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ALLOW
          </span>
        );
      case 'REVIEW_REQUIRED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-mono font-bold bg-amber-950/80 border border-amber-500/50 text-amber-300 shadow-[0_0_12px_rgba(245,158,11,0.2)]">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            REVIEW REQUIRED
          </span>
        );
      case 'BLOCK':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-mono font-bold bg-red-950/80 border border-red-500/50 text-red-300 shadow-[0_0_12px_rgba(239,68,68,0.2)]">
            <XCircle className="w-4 h-4 text-red-400" />
            BLOCK
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-red-950/40 border border-white/10 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 text-xs font-mono font-semibold text-red-400 tracking-wider uppercase mb-1">
            <ShieldCheck className="w-4 h-4 text-red-400" />
            Capabilities & Policy Matrix
          </div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
            Security Research Capability Directory
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Authoritative registry of security research capabilities, policy controls, evidence formats, and preview-only authorization evaluation engines.
          </p>
        </div>

        <div className="flex items-center gap-3 bg-slate-950/60 p-3 rounded-lg border border-white/10">
          <div className="text-right font-mono">
            <div className="text-xs text-slate-400">REGISTERED CAPABILITIES</div>
            <div className="text-xl font-bold text-slate-100">{capabilities.length}</div>
          </div>
          <div className="w-px h-8 bg-white/10" />
          <div className="text-right font-mono">
            <div className="text-xs text-slate-400">SUPPORTED</div>
            <div className="text-xl font-bold text-emerald-400">
              {capabilities.filter((c) => c.implementationStatus === 'SUPPORTED').length}
            </div>
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-white/10 flex flex-col sm:flex-row gap-3 sm:gap-4 items-stretch sm:items-center justify-between">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search capabilities by name, ID, or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-white/10 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-red-500/50"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3 w-full sm:w-auto">
          <div className="flex items-center gap-2 flex-1 sm:flex-initial">
            <Filter className="w-4 h-4 text-slate-400 shrink-0" />
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full sm:w-auto bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500/50"
            >
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  Category: {cat}
                </option>
              ))}
            </select>
          </div>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="w-full sm:w-auto bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500/50"
          >
            {statuses.map((st) => (
              <option key={st} value={st}>
                Status: {st}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Capability Directory Table */}
      <div className="rounded-xl border border-white/10 bg-slate-900/60 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/80 border-b border-white/10 text-xs font-mono font-semibold uppercase tracking-wider text-slate-400">
              <tr>
                <th className="py-3.5 px-4">Capability</th>
                <th className="py-3.5 px-4">Category</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">Automation</th>
                <th className="py-3.5 px-4">Policy Req</th>
                <th className="py-3.5 px-4">Evidence</th>
                <th className="py-3.5 px-4">Validation</th>
                <th className="py-3.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 font-sans">
              {filteredCapabilities.map((cap) => (
                <tr key={cap.id} className="hover:bg-white/[0.02] transition-colors">
                  {/* Capability Column */}
                  <td className="py-4 px-4">
                    <div className="font-semibold text-slate-100 flex items-center gap-2">
                      {cap.name}
                    </div>
                    <div className="text-xs font-mono text-slate-400 mt-0.5">{cap.id}</div>
                    <div className="text-xs text-slate-400 mt-1 line-clamp-1 max-w-xs">
                      {cap.description}
                    </div>
                  </td>

                  {/* Category */}
                  <td className="py-4 px-4 font-mono text-xs">
                    <span className="px-2 py-1 rounded bg-slate-800/80 border border-slate-700/60 text-slate-300">
                      {cap.category}
                    </span>
                  </td>

                  {/* Status */}
                  <td className="py-4 px-4">{getStatusBadge(cap.implementationStatus)}</td>

                  {/* Automation Level */}
                  <td className="py-4 px-4 font-mono text-xs text-slate-300">
                    {cap.automationLevel}
                  </td>

                  {/* Policy Requirement */}
                  <td className="py-4 px-4 font-mono text-xs text-slate-400">
                    <div className="flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5 text-slate-500" />
                      {cap.policyRequirement}
                    </div>
                  </td>

                  {/* Evidence Support */}
                  <td className="py-4 px-4 font-mono text-xs text-slate-400">
                    <div className="flex items-center gap-1.5">
                      <FileCheck className="w-3.5 h-3.5 text-slate-500" />
                      {cap.evidenceSupport}
                    </div>
                  </td>

                  {/* Validation Support */}
                  <td className="py-4 px-4 font-mono text-xs text-slate-400">
                    {cap.humanValidationRequirement}
                  </td>

                  {/* Action */}
                  <td className="py-4 px-4 text-right">
                    <button
                      onClick={() => handleOpenEvaluationModal(cap)}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-950/60 border border-red-700/50 hover:bg-red-900/60 text-red-200 transition-colors inline-flex items-center gap-1.5 shadow-sm"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      Preview
                    </button>
                  </td>
                </tr>
              ))}

              {filteredCapabilities.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-mono text-sm">
                    No capabilities matched the specified filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Authorization Preview Modal (PREVIEW ONLY - NO EXECUTE BUTTON) */}
      {evalModalCapability && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-slate-900 border border-white/10 rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl">
            {/* Modal Header */}
            <div className="p-5 border-b border-white/10 flex items-center justify-between bg-slate-950/60">
              <div>
                <div className="flex items-center gap-2 text-xs font-mono text-red-400 uppercase tracking-wider mb-1">
                  <ShieldCheck className="w-4 h-4 text-red-400" />
                  Authorization Preview Evaluation
                </div>
                <h3 className="text-lg font-bold text-slate-100">{evalModalCapability.name}</h3>
              </div>
              <button
                onClick={() => setEvalModalCapability(null)}
                className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-white/5 rounded-lg transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-5">
              <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-500/30 text-xs text-amber-200 flex items-center gap-2.5">
                <Lock className="w-4 h-4 shrink-0 text-amber-400" />
                <span>
                  <strong>PREVIEW ONLY MODE:</strong> This engine evaluates policy rules and scope boundaries. It does <strong>NOT</strong> launch tasks, execute scans, or make network requests.
                </span>
              </div>

              {/* Input Form */}
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1.5">
                    Target Program
                  </label>
                  <select
                    value={evalProgramId}
                    onChange={(e) => {
                      setEvalProgramId(e.target.value);
                      const prog = programs.find((p) => p.id === e.target.value);
                      if (prog && prog.targets && prog.targets.length > 0) {
                        setEvalTarget(prog.targets[0]);
                      }
                    }}
                    className="w-full bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-red-500/50"
                  >
                    {programs.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} ({p.id})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1.5">
                    Target Host / Domain / Path
                  </label>
                  <input
                    type="text"
                    value={evalTarget}
                    onChange={(e) => setEvalTarget(e.target.value)}
                    placeholder="e.g. api.acme-security.test or /api/v1/auth"
                    className="w-full bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-100 font-mono placeholder-slate-600 focus:outline-none focus:border-red-500/50"
                  />
                </div>
              </div>

              {/* Evaluate Action Button */}
              <div className="pt-2">
                <button
                  onClick={handleRunEvaluation}
                  disabled={isEvaluating || !evalTarget.trim()}
                  className="w-full py-2.5 px-4 rounded-xl font-semibold text-sm bg-gradient-to-r from-red-600 to-red-800 hover:from-red-500 hover:to-red-700 text-white shadow-lg shadow-red-900/30 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {isEvaluating ? (
                    <span className="font-mono text-xs">Evaluating Policy Rules...</span>
                  ) : (
                    <>
                      <Eye className="w-4 h-4" />
                      Evaluate Authorization Preview
                    </>
                  )}
                </button>
              </div>

              {/* Error Box */}
              {evalError && (
                <div className="p-3 rounded-lg bg-red-950/60 border border-red-500/40 text-xs font-mono text-red-300">
                  {evalError}
                </div>
              )}

              {/* Results Display */}
              {evalResult && (
                <div className="p-4 rounded-xl bg-slate-950 border border-white/10 space-y-3 font-mono text-xs animate-fade-in">
                  <div className="flex items-center justify-between pb-2 border-b border-white/10">
                    <span className="text-slate-400">Policy Decision</span>
                    {getDecisionBadge(evalResult.decision)}
                  </div>

                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">Capability</span>
                    <span className="text-slate-100 font-semibold">{evalResult.capability.name}</span>
                  </div>

                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">Program ID</span>
                    <span className="text-slate-100">{evalResult.programId}</span>
                  </div>

                  <div className="flex items-center justify-between text-slate-300">
                    <span className="text-slate-500">Target</span>
                    <span className="text-slate-100">{evalResult.target}</span>
                  </div>

                  <div className="pt-2 border-t border-white/5">
                    <span className="text-slate-500 block mb-1">Authorization Reason:</span>
                    <p className="text-slate-200 font-sans text-xs bg-slate-900 p-2.5 rounded border border-white/5">
                      {evalResult.reason}
                    </p>
                  </div>

                  {evalResult.decision === 'ALLOW' && (
                    <div className="pt-3 border-t border-white/10 space-y-3">
                      <button
                        onClick={handleRunAnalysis}
                        disabled={isAnalyzing}
                        className="w-full py-2 px-3 rounded-lg font-semibold text-xs bg-emerald-600 hover:bg-emerald-500 text-white shadow-md transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        {isAnalyzing ? (
                          <span>Executing Controlled Passive Research Adapter...</span>
                        ) : (
                          <>
                            <Sparkles className="w-3.5 h-3.5" />
                            Run Passive Research Analysis
                          </>
                        )}
                      </button>

                      {analysisError && (
                        <div className="p-2.5 rounded bg-red-950/60 border border-red-500/40 text-xs text-red-300">
                          {analysisError}
                        </div>
                      )}

                      {analysisResult && (
                        <div className="p-3 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-3 font-mono text-xs">
                          <div className="flex items-center justify-between text-emerald-400 font-bold border-b border-white/10 pb-1.5">
                            <span>PASSIVE ANALYSIS COMPLETE</span>
                            <span className="text-[10px] text-slate-400 font-normal">
                              Status: POTENTIAL (Requires Human Validation)
                            </span>
                          </div>

                          {/* Observations */}
                          <div>
                            <span className="text-slate-400 font-semibold block mb-1">Observations ({analysisResult.observations?.length || 0})</span>
                            <div className="bg-slate-950 p-2 rounded text-[11px] text-slate-300 max-h-32 overflow-y-auto space-y-1">
                              {analysisResult.observations?.map((obs: any, idx: number) => (
                                <div key={idx} className="border-b border-white/5 pb-1">
                                  <span className="text-emerald-300 font-bold">[{obs.type}]</span> {obs.summary}
                                </div>
                              ))}
                              {(!analysisResult.observations || analysisResult.observations.length === 0) && (
                                <span className="text-slate-500">No passive anomalies observed.</span>
                              )}
                            </div>
                          </div>

                          {/* Finding Candidates */}
                          <div>
                            <span className="text-slate-400 font-semibold block mb-1">Finding Candidates ({analysisResult.findingCandidates?.length || 0})</span>
                            <div className="space-y-1.5">
                              {analysisResult.findingCandidates?.map((fc: any, idx: number) => (
                                <div key={idx} className="p-2 rounded bg-slate-950 border border-amber-500/30 font-sans text-xs">
                                  <div className="flex items-center justify-between font-mono font-bold text-amber-300">
                                    <span>{fc.title}</span>
                                    <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 text-[10px] border border-amber-600/40">
                                      {fc.severity} | Conf: {Math.round((fc.confidence || 0) * 100)}%
                                    </span>
                                  </div>
                                  <p className="text-slate-300 text-[11px] mt-1">{fc.whatWeFound}</p>
                                  <div className="mt-1 text-[10px] text-slate-400 font-mono">
                                    Lifecycle State: <strong className="text-amber-400">{fc.status || 'Potential'}</strong> (Awaiting Human Review)
                                  </div>
                                </div>
                              ))}
                              {(!analysisResult.findingCandidates || analysisResult.findingCandidates.length === 0) && (
                                <span className="text-slate-500">No candidate findings produced.</span>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  <div className="text-[10px] text-slate-500 text-right pt-1">
                    Evaluated at: {new Date(evalResult.evaluatedAt).toLocaleTimeString()}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-white/10 bg-slate-950/80 flex justify-end">
              <button
                onClick={() => setEvalModalCapability(null)}
                className="px-4 py-2 rounded-lg text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 transition-colors"
              >
                Close Preview
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
