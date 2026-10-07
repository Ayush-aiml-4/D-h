import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { Program, ResearchCase } from '../types';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Zap,
  Activity,
  Layers,
  StopCircle,
  Info,
  ChevronRight,
  Sparkles,
} from 'lucide-react';

interface ActiveTestingViewProps {
  programs: Program[];
}

export const ActiveTestingView: React.FC<ActiveTestingViewProps> = ({ programs }) => {
  const [capabilities, setCapabilities] = useState<any[]>([]);
  const [cases, setCases] = useState<ResearchCase[]>([]);
  const [executions, setExecutions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Selection states
  const [selectedProgramId, setSelectedProgramId] = useState<string>(programs[0]?.id || 'prog-acme-01');
  const [selectedCaseId, setSelectedCaseId] = useState<string>('');
  const [selectedAssetId, setSelectedAssetId] = useState<string>('');
  const [selectedCapabilityId, setSelectedCapabilityId] = useState<string>('active-http-method-validation');
  const [targetInput, setTargetInput] = useState<string>('api.acme-security.test');

  // Execution & Approval states
  const [isExecuting, setIsExecuting] = useState(false);
  const [activeResult, setActiveResult] = useState<any | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Approval Modal State
  const [pendingApproval, setPendingApproval] = useState<any | null>(null);
  const [isConfirmingApproval, setIsConfirmingApproval] = useState(false);
  const [approvalConfirmed, setApprovalConfirmed] = useState(false);

  const selectedProgram = programs.find((p) => p.id === selectedProgramId) || programs[0];
  const selectedCapability = capabilities.find((c) => c.capabilityId === selectedCapabilityId);

  const loadData = async () => {
    try {
      setLoading(true);
      const [capsData, casesData, execsData] = await Promise.all([
        api.getActiveCapabilities().catch(() => []),
        api.getCases().catch(() => []),
        api.getActiveExecutions().catch(() => []),
      ]);

      setCapabilities(capsData);
      setCases(casesData);
      setExecutions(execsData);

      if (casesData.length > 0 && !selectedCaseId) {
        setSelectedCaseId(casesData[0].id);
        if (casesData[0].programId) {
          setSelectedProgramId(casesData[0].programId);
        }
      }
    } catch (err: any) {
      console.error('Failed to load active testing framework data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRequestOrExecute = async () => {
    if (!selectedCaseId || !selectedCapabilityId) {
      setErrorMessage('Please select an active research case and capability.');
      return;
    }

    setErrorMessage(null);
    setActiveResult(null);
    setIsExecuting(true);

    try {
      // Step 1: Send execution request
      const res = await api.executeActiveCapability({
        caseId: selectedCaseId,
        capabilityId: selectedCapabilityId,
        assetId: selectedAssetId || 'asset-api-01',
        target: targetInput.trim() || 'api.acme-security.test',
      });

      if (res.status === 'AUTHORIZED' && res.policyDecision === 'REVIEW_REQUIRED' && res.approvalId) {
        // Explicit approval requirement triggered
        setPendingApproval({
          approvalId: res.approvalId,
          capability: selectedCapability,
          target: targetInput,
        });
        setApprovalConfirmed(false);
      } else {
        setActiveResult(res);
        await loadData();
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Active execution failed');
    } finally {
      setIsExecuting(false);
    }
  };

  const handleConfirmApprovalAndExecute = async () => {
    if (!pendingApproval?.approvalId) return;

    try {
      setIsConfirmingApproval(true);
      setErrorMessage(null);

      // Step 1: Explicitly confirm server-side approval requirement
      await api.confirmActiveApproval(pendingApproval.approvalId);
      setApprovalConfirmed(true);

      // Step 2: Execute capability with confirmed approval ID
      const res = await api.executeActiveCapability({
        caseId: selectedCaseId,
        capabilityId: selectedCapabilityId,
        assetId: selectedAssetId || 'asset-api-01',
        target: targetInput.trim() || 'api.acme-security.test',
        approvalId: pendingApproval.approvalId,
      });

      setActiveResult(res);
      setPendingApproval(null);
      await loadData();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to confirm approval and execute');
    } finally {
      setIsConfirmingApproval(false);
    }
  };

  const handleCancelExecution = async (executionId: string) => {
    try {
      await api.cancelActiveExecution(executionId, 'User requested stop');
      await loadData();
      if (activeResult?.executionId === executionId) {
        setActiveResult((prev: any) => ({ ...prev, status: 'CANCELLED' }));
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to cancel execution');
    }
  };

  const getTierBadge = (tier: string) => {
    switch (tier) {
      case 'LOW_RISK_ACTIVE':
        return (
          <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-blue-950/80 text-blue-300 border border-blue-700/50 flex items-center gap-1">
            <Zap className="w-3 h-3 text-blue-400" /> LOW_RISK_ACTIVE
          </span>
        );
      case 'APPROVAL_REQUIRED':
        return (
          <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-700/50 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-amber-400" /> APPROVAL_REQUIRED
          </span>
        );
      case 'RESTRICTED':
        return (
          <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-red-950/80 text-red-300 border border-red-700/50 flex items-center gap-1">
            <Lock className="w-3 h-3 text-red-400" /> RESTRICTED
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-slate-900 text-slate-300 border border-white/10 flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-slate-400" /> PASSIVE
          </span>
        );
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500/20 to-red-500/20 border border-amber-500/30 flex items-center justify-center">
              <Zap className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <h1 className="text-2xl font-black font-outfit uppercase tracking-wider text-slate-100">
                Governed Active Security Testing
              </h1>
              <p className="text-xs font-mono text-slate-400">
                Policy-guarded, budget-bounded active testing framework against authorized bug-bounty targets
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="px-3 py-1.5 rounded-xl bg-slate-900/80 border border-white/10 font-mono text-xs text-slate-300 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-emerald-400" />
            <span>SSRF & Scope Protected</span>
          </div>
        </div>
      </div>

      {errorMessage && (
        <div className="p-4 rounded-xl bg-red-950/80 border border-red-700/50 text-red-300 text-xs font-mono flex items-center justify-between">
          <span>{errorMessage}</span>
          <button onClick={() => setErrorMessage(null)} className="text-red-400 hover:text-red-200">
            ✕
          </button>
        </div>
      )}

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Capability & Target Selector */}
        <div className="lg:col-span-1 space-y-6">
          <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
            <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-amber-400" />
              <span>Target & Capability Selection</span>
            </h2>

            {/* Research Case Selector */}
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">
                Research Case
              </label>
              <select
                value={selectedCaseId}
                onChange={(e) => {
                  setSelectedCaseId(e.target.value);
                  const c = cases.find((item) => item.id === e.target.value);
                  if (c?.programId) setSelectedProgramId(c.programId);
                }}
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500/50"
              >
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.title} ({c.id}) [{c.status}]
                  </option>
                ))}
              </select>
            </div>

            {/* Program & Target Input */}
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">
                Target Host / URL
              </label>
              <input
                type="text"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                placeholder="api.acme-security.test"
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500/50"
              />
            </div>

            {/* Capability Selector */}
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase mb-1">
                Active Capability
              </label>
              <div className="space-y-2">
                {capabilities.map((cap) => {
                  const isSelected = selectedCapabilityId === cap.capabilityId;
                  return (
                    <button
                      key={cap.capabilityId}
                      type="button"
                      onClick={() => setSelectedCapabilityId(cap.capabilityId)}
                      className={`w-full text-left p-3 rounded-xl border transition-all text-xs font-mono flex flex-col gap-1.5 ${
                        isSelected
                          ? 'bg-amber-950/40 border-amber-500/60 shadow-[0_0_15px_rgba(245,158,11,0.15)]'
                          : 'bg-slate-900/60 border-white/5 hover:border-white/20'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className={`font-bold ${isSelected ? 'text-amber-300' : 'text-slate-200'}`}>
                          {cap.canonicalName}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[10px]">
                        <span className="text-slate-400">{cap.category}</span>
                        {getTierBadge(cap.authorizationTier)}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Launch Button */}
            <div className="pt-2">
              <button
                onClick={handleRequestOrExecute}
                disabled={isExecuting || !selectedCapability || selectedCapability?.authorizationTier === 'RESTRICTED'}
                className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-amber-600 to-red-600 hover:from-amber-500 hover:to-red-500 text-white font-mono text-xs font-bold uppercase tracking-wider transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-amber-950/50"
              >
                {isExecuting ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Evaluating Governance & Executing...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    <span>Execute Governed Capability</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Execution Governance & Output */}
        <div className="lg:col-span-2 space-y-6">
          {/* Active Capability Spec & Governance Specs */}
          {selectedCapability && (
            <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                  <Info className="w-4 h-4 text-blue-400" />
                  <span>Capability Specification & Budget Envelope</span>
                </h3>
                {getTierBadge(selectedCapability.authorizationTier)}
              </div>

              <p className="text-xs font-mono text-slate-300 leading-relaxed">
                {selectedCapability.description}
              </p>

              {/* Specs Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs pt-2">
                <div className="bg-slate-900/80 p-3 rounded-xl border border-white/5">
                  <span className="text-slate-500 text-[10px] block uppercase">Request Budget</span>
                  <span className="text-amber-400 font-bold text-sm">
                    {selectedCapability.maximumRequestBudget} max reqs
                  </span>
                </div>
                <div className="bg-slate-900/80 p-3 rounded-xl border border-white/5">
                  <span className="text-slate-500 text-[10px] block uppercase">Concurrency</span>
                  <span className="text-blue-400 font-bold text-sm">
                    {selectedCapability.maximumConcurrency} concurrent
                  </span>
                </div>
                <div className="bg-slate-900/80 p-3 rounded-xl border border-white/5">
                  <span className="text-slate-500 text-[10px] block uppercase">Timeout Limit</span>
                  <span className="text-emerald-400 font-bold text-sm">
                    {selectedCapability.timeout / 1000}s limit
                  </span>
                </div>
                <div className="bg-slate-900/80 p-3 rounded-xl border border-white/5">
                  <span className="text-slate-500 text-[10px] block uppercase">Mutation Level</span>
                  <span className="text-purple-400 font-bold text-sm">
                    {selectedCapability.mutationLevel}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Execution Result Panel */}
          {activeResult && (
            <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  {activeResult.status === 'COMPLETED' ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  ) : activeResult.status === 'CANCELLED' ? (
                    <StopCircle className="w-5 h-5 text-amber-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400" />
                  )}
                  <div>
                    <h4 className="text-sm font-mono font-bold uppercase text-slate-100">
                      Execution Result: {activeResult.status}
                    </h4>
                    <span className="text-[10px] font-mono text-slate-500">
                      ID: {activeResult.executionId} | Duration: {activeResult.durationMs}ms | Reqs: {activeResult.requestsExecuted}
                    </span>
                  </div>
                </div>

                {activeResult.evidenceHash && (
                  <div className="px-3 py-1 bg-emerald-950/60 border border-emerald-700/50 rounded-lg text-[10px] font-mono text-emerald-300">
                    Hash: {activeResult.evidenceHash.substring(0, 16)}...
                  </div>
                )}
              </div>

              {activeResult.error && (
                <div className="p-3 bg-red-950/40 rounded-xl border border-red-700/40 text-red-300 font-mono text-xs">
                  {activeResult.error}
                </div>
              )}

              {/* Observations */}
              {activeResult.observations && activeResult.observations.length > 0 && (
                <div className="space-y-3 font-mono text-xs">
                  <h5 className="text-[11px] text-slate-400 uppercase font-bold">
                    Sanitized Observations ({activeResult.observations.length})
                  </h5>
                  {activeResult.observations.map((obs: any, i: number) => (
                    <div key={i} className="p-4 bg-slate-900/90 rounded-xl border border-white/10 space-y-2">
                      <div className="flex items-center justify-between text-[11px] text-amber-400 font-bold">
                        <span>{obs.observationType}</span>
                        <span className="text-slate-500">{new Date(obs.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <pre className="p-3 bg-black/60 rounded-lg border border-white/5 text-[11px] text-slate-300 overflow-x-auto">
                        {JSON.stringify(obs.sanitizedData, null, 2)}
                      </pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Execution History */}
          <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Clock className="w-4 h-4 text-emerald-400" />
              <span>Recent Active Testing Executions ({executions.length})</span>
            </h3>

            {executions.length === 0 ? (
              <div className="text-center text-xs font-mono text-slate-500 py-6">
                No active testing executions recorded yet.
              </div>
            ) : (
              <div className="space-y-2 font-mono text-xs">
                {executions.map((exec) => (
                  <div
                    key={exec.executionId}
                    className="p-3 bg-slate-900/60 rounded-xl border border-white/5 flex items-center justify-between gap-2"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-slate-400">{exec.capabilityName}</span>
                      <span className="text-slate-500 text-[10px]">[{exec.target}]</span>
                    </div>

                    <div className="flex items-center gap-3">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                          exec.status === 'COMPLETED'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : exec.status === 'CANCELLED'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-red-950 text-red-400 border border-red-800'
                        }`}
                      >
                        {exec.status}
                      </span>

                      {exec.status === 'RUNNING' && (
                        <button
                          onClick={() => handleCancelExecution(exec.executionId)}
                          className="px-2 py-1 bg-red-900/60 hover:bg-red-800 text-red-200 rounded text-[10px]"
                        >
                          Cancel
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Explicit Approval Confirmation Modal */}
      {pendingApproval && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-panel max-w-lg w-full p-6 rounded-2xl border border-amber-500/40 bg-slate-950 space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2 text-amber-400">
                <AlertTriangle className="w-5 h-5" />
                <h3 className="text-base font-black font-outfit uppercase tracking-wider text-slate-100">
                  Explicit Researcher Approval Required
                </h3>
              </div>
              <button
                onClick={() => setPendingApproval(null)}
                className="text-slate-500 hover:text-slate-300 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <div className="p-4 bg-amber-950/30 rounded-xl border border-amber-700/40 space-y-2 text-xs font-mono text-amber-200/90">
              <p className="font-bold">
                Capability: {pendingApproval.capability?.canonicalName}
              </p>
              <p>
                Target: <span className="text-slate-100">{pendingApproval.target}</span>
              </p>
              <p className="text-[11px] text-amber-300/80">
                This capability operates in the <strong>APPROVAL_REQUIRED</strong> tier. By confirming, you acknowledge that this active testing request will send bounded probes through the governed execution pipeline.
              </p>
            </div>

            <div className="text-xs font-mono text-slate-400 space-y-1">
              <p>Approval ID: <span className="text-slate-200">{pendingApproval.approvalId}</span></p>
              <p>Validity: 5 Minutes (Server Enforced)</p>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-white/10">
              <button
                onClick={() => setPendingApproval(null)}
                className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 font-mono text-xs rounded-xl border border-white/10"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmApprovalAndExecute}
                disabled={isConfirmingApproval}
                className="px-5 py-2 bg-amber-600 hover:bg-amber-500 text-black font-mono font-bold text-xs rounded-xl transition-all flex items-center gap-2"
              >
                {isConfirmingApproval ? 'Authorizing & Executing...' : 'Explicitly Confirm & Execute'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
