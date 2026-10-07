import React, { useState, useEffect } from 'react';
import { ResearchCase, ResearchActivity, CanonicalCaseStatus } from '../types';
import { api } from '../api/client';
import {
  Briefcase,
  Plus,
  Play,
  Pause,
  CheckCircle2,
  Archive,
  Layers,
  FileSearch,
  FileText,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  Activity,
  GitBranch,
  Calendar,
  User,
  ShieldAlert,
} from 'lucide-react';

export const ResearchCasesView: React.FC = () => {
  const [cases, setCases] = useState<ResearchCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [caseLineage, setCaseLineage] = useState<any | null>(null);
  const [activities, setActivities] = useState<ResearchActivity[]>([]);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);

  // Form State
  const [programId, setProgramId] = useState('prog-acme-01');
  const [title, setTitle] = useState('');
  const [objective, setObjective] = useState('');
  const [scopeSummary, setScopeSummary] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const loadCases = async () => {
    try {
      setLoading(true);
      const data = await api.getCases();
      setCases(data);
      if (data.length > 0 && !selectedCaseId) {
        setSelectedCaseId(data[0].id);
      }
    } catch (err: any) {
      console.error('Failed to load research cases:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  useEffect(() => {
    if (!selectedCaseId) return;
    const loadDetails = async () => {
      try {
        const fullCase = await api.getCaseById(selectedCaseId);
        setCaseLineage(fullCase.lineage);
        const acts = await api.getCaseActivities(selectedCaseId);
        setActivities(acts);
      } catch (err) {
        console.error('Failed to load case details:', err);
      }
    };
    loadDetails();
  }, [selectedCaseId]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !objective.trim()) return;

    try {
      setIsSubmitting(true);
      setErrorMsg(null);
      const newCase = await api.createCase(programId, title, objective, scopeSummary);
      setIsCreateModalOpen(false);
      setTitle('');
      setObjective('');
      setScopeSummary('');
      await loadCases();
      setSelectedCaseId(newCase.id);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to create research case');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTransition = async (caseId: string, status: CanonicalCaseStatus) => {
    try {
      await api.transitionCase(caseId, status);
      await loadCases();
      if (selectedCaseId === caseId) {
        const fullCase = await api.getCaseById(caseId);
        setCaseLineage(fullCase.lineage);
      }
    } catch (err: any) {
      alert(`Transition failed: ${err.message}`);
    }
  };

  const getStatusBadge = (st: CanonicalCaseStatus) => {
    switch (st) {
      case 'DRAFT':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      case 'ACTIVE':
        return 'bg-emerald-950/80 text-emerald-400 border-emerald-700/50';
      case 'PAUSED':
        return 'bg-amber-950/80 text-amber-400 border-amber-700/50';
      case 'UNDER_REVIEW':
        return 'bg-blue-950/80 text-blue-400 border-blue-700/50';
      case 'CLOSED':
        return 'bg-purple-950/80 text-purple-400 border-purple-700/50';
      case 'ARCHIVED':
        return 'bg-zinc-900 text-zinc-500 border-zinc-800';
      default:
        return 'bg-slate-900 text-slate-400 border-slate-800';
    }
  };

  const filteredCases = cases.filter((c) => {
    if (statusFilter === 'ALL') return true;
    return c.status === statusFilter;
  });

  const selectedCase = cases.find((c) => c.id === selectedCaseId);

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 uppercase tracking-wider mb-1">
            <Briefcase className="w-4 h-4" />
            <span>DEVILHUNT #0003.4-C</span>
          </div>
          <h1 className="text-2xl font-black font-outfit uppercase tracking-wider text-slate-100">
            Research Case & Campaign Management
          </h1>
          <p className="text-xs text-slate-400 font-sans">
            Trace authorized security campaigns connecting Discovery, Assets, Research Activities, Findings, Evidence, and Reports.
          </p>
        </div>

        <button
          onClick={() => setIsCreateModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-mono font-bold uppercase tracking-wider transition-all shadow-lg shadow-emerald-950/50"
        >
          <Plus className="w-4 h-4" />
          <span>New Research Case</span>
        </button>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-white/5">
        {['ALL', 'DRAFT', 'ACTIVE', 'PAUSED', 'UNDER_REVIEW', 'CLOSED', 'ARCHIVED'].map((st) => (
          <button
            key={st}
            onClick={() => setStatusFilter(st)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono uppercase tracking-wider transition-all ${
              statusFilter === st
                ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-700/50'
                : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
            }`}
          >
            {st.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Main Grid: Cases List & Active Case Lineage */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Cases List */}
        <div className="lg:col-span-5 space-y-4">
          <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Layers className="w-4 h-4 text-emerald-400" />
            <span>Campaign Cases ({filteredCases.length})</span>
          </h2>

          {loading ? (
            <div className="glass-panel p-8 rounded-2xl text-center text-xs font-mono text-slate-400">
              Loading research cases...
            </div>
          ) : filteredCases.length === 0 ? (
            <div className="glass-panel p-8 rounded-2xl text-center text-xs font-mono text-slate-500">
              No research cases found matching current filter.
            </div>
          ) : (
            filteredCases.map((c) => (
              <div
                key={c.id}
                onClick={() => setSelectedCaseId(c.id)}
                className={`glass-panel p-5 rounded-2xl border transition-all cursor-pointer space-y-3 ${
                  selectedCaseId === c.id
                    ? 'border-emerald-500/80 bg-slate-900/90 shadow-lg shadow-emerald-950/30'
                    : 'border-white/10 hover:border-slate-700 bg-slate-950/40'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase">{c.id}</span>
                    <h3 className="text-sm font-bold text-slate-100 font-outfit">{c.title}</h3>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded-full text-[10px] font-mono border uppercase ${getStatusBadge(
                      c.status
                    )}`}
                  >
                    {c.status}
                  </span>
                </div>

                <p className="text-xs text-slate-400 line-clamp-2">{c.objective}</p>

                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-2 border-t border-white/5">
                  <span className="flex items-center gap-1 text-slate-300">
                    <ShieldAlert className="w-3.5 h-3.5 text-emerald-400" />
                    {c.programName}
                  </span>
                  <span className="text-slate-500">{new Date(c.createdAt).toLocaleDateString()}</span>
                </div>

                {/* Case Metrics Bar */}
                <div className="grid grid-cols-6 gap-1 text-center bg-black/40 p-2 rounded-xl border border-white/5 text-[10px] font-mono">
                  <div>
                    <div className="text-slate-500 text-[8px] uppercase">Disc</div>
                    <div className="text-slate-200">{c.metrics.discoverySessionCount}</div>
                  </div>
                  <div>
                    <div className="text-slate-500 text-[8px] uppercase">Asset</div>
                    <div className="text-slate-200">{c.metrics.assetCount}</div>
                  </div>
                  <div>
                    <div className="text-slate-500 text-[8px] uppercase">Act</div>
                    <div className="text-slate-200">{c.metrics.activityCount}</div>
                  </div>
                  <div>
                    <div className="text-slate-500 text-[8px] uppercase">Find</div>
                    <div className="text-amber-400 font-bold">{c.metrics.findingCount}</div>
                  </div>
                  <div>
                    <div className="text-slate-500 text-[8px] uppercase">Evid</div>
                    <div className="text-emerald-400 font-bold">{c.metrics.evidenceCount}</div>
                  </div>
                  <div>
                    <div className="text-slate-500 text-[8px] uppercase">Rep</div>
                    <div className="text-purple-400 font-bold">{c.metrics.reportCount}</div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Selected Case Detail & Lineage Tree */}
        <div className="lg:col-span-7 space-y-6">
          {selectedCase ? (
            <>
              {/* Case Summary Card */}
              <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
                <div className="flex items-start justify-between gap-4 border-b border-white/10 pb-4">
                  <div>
                    <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                      <span>{selectedCase.id}</span>
                      <span>•</span>
                      <span className="text-emerald-400">{selectedCase.programName}</span>
                    </div>
                    <h2 className="text-xl font-black font-outfit text-slate-100 uppercase tracking-wide mt-1">
                      {selectedCase.title}
                    </h2>
                  </div>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-mono border uppercase tracking-wider ${getStatusBadge(
                      selectedCase.status
                    )}`}
                  >
                    {selectedCase.status}
                  </span>
                </div>

                <div className="space-y-3">
                  <div>
                    <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1">Objective</h4>
                    <p className="text-xs text-slate-300 bg-black/40 p-3 rounded-xl border border-white/5">
                      {selectedCase.objective}
                    </p>
                  </div>

                  <div>
                    <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1">Scope Summary</h4>
                    <p className="text-xs text-slate-400 font-mono bg-black/20 p-2.5 rounded-xl border border-white/5">
                      {selectedCase.scopeSummary}
                    </p>
                  </div>
                </div>

                {/* State Machine Transition Actions */}
                <div className="pt-3 border-t border-white/10 flex flex-wrap items-center gap-2">
                  <span className="text-xs font-mono text-slate-400 mr-2">Lifecycle Controls:</span>

                  {selectedCase.status === 'DRAFT' && (
                    <>
                      <button
                        onClick={() => handleTransition(selectedCase.id, 'ACTIVE')}
                        className="px-3 py-1.5 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/60 rounded-xl text-xs font-mono flex items-center gap-1.5"
                      >
                        <Play className="w-3.5 h-3.5" /> Activate
                      </button>
                      <button
                        onClick={() => handleTransition(selectedCase.id, 'ARCHIVED')}
                        className="px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 text-zinc-400 border border-zinc-700/60 rounded-xl text-xs font-mono flex items-center gap-1.5"
                      >
                        <Archive className="w-3.5 h-3.5" /> Archive
                      </button>
                    </>
                  )}

                  {selectedCase.status === 'ACTIVE' && (
                    <>
                      <button
                        onClick={() => handleTransition(selectedCase.id, 'PAUSED')}
                        className="px-3 py-1.5 bg-amber-950 hover:bg-amber-900 text-amber-300 border border-amber-700/60 rounded-xl text-xs font-mono flex items-center gap-1.5"
                      >
                        <Pause className="w-3.5 h-3.5" /> Pause
                      </button>
                      <button
                        onClick={() => handleTransition(selectedCase.id, 'UNDER_REVIEW')}
                        className="px-3 py-1.5 bg-blue-950 hover:bg-blue-900 text-blue-300 border border-blue-700/60 rounded-xl text-xs font-mono flex items-center gap-1.5"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" /> Under Review
                      </button>
                      <button
                        onClick={() => handleTransition(selectedCase.id, 'CLOSED')}
                        className="px-3 py-1.5 bg-purple-950 hover:bg-purple-900 text-purple-300 border border-purple-700/60 rounded-xl text-xs font-mono flex items-center gap-1.5"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" /> Close Case
                      </button>
                    </>
                  )}

                  {selectedCase.status === 'PAUSED' && (
                    <>
                      <button
                        onClick={() => handleTransition(selectedCase.id, 'ACTIVE')}
                        className="px-3 py-1.5 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/60 rounded-xl text-xs font-mono flex items-center gap-1.5"
                      >
                        <Play className="w-3.5 h-3.5" /> Resume
                      </button>
                      <button
                        onClick={() => handleTransition(selectedCase.id, 'CLOSED')}
                        className="px-3 py-1.5 bg-purple-950 hover:bg-purple-900 text-purple-300 border border-purple-700/60 rounded-xl text-xs font-mono flex items-center gap-1.5"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" /> Close Case
                      </button>
                    </>
                  )}

                  {selectedCase.status === 'UNDER_REVIEW' && (
                    <>
                      <button
                        onClick={() => handleTransition(selectedCase.id, 'ACTIVE')}
                        className="px-3 py-1.5 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/60 rounded-xl text-xs font-mono flex items-center gap-1.5"
                      >
                        <Play className="w-3.5 h-3.5" /> Reactivate
                      </button>
                      <button
                        onClick={() => handleTransition(selectedCase.id, 'CLOSED')}
                        className="px-3 py-1.5 bg-purple-950 hover:bg-purple-900 text-purple-300 border border-purple-700/60 rounded-xl text-xs font-mono flex items-center gap-1.5"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" /> Close Case
                      </button>
                    </>
                  )}

                  {selectedCase.status === 'CLOSED' && (
                    <button
                      onClick={() => handleTransition(selectedCase.id, 'ARCHIVED')}
                      className="px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 text-zinc-400 border border-zinc-700/60 rounded-xl text-xs font-mono flex items-center gap-1.5"
                    >
                      <Archive className="w-3.5 h-3.5" /> Archive Case
                    </button>
                  )}

                  {selectedCase.status === 'ARCHIVED' && (
                    <span className="text-xs font-mono text-zinc-500 italic">Case is Archived & Immutable</span>
                  )}
                </div>
              </div>

              {/* Case Lineage Hierarchy */}
              <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
                <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-emerald-400" />
                  <span>Case Provenance & Lineage Tree</span>
                </h3>

                <div className="space-y-3 font-mono text-xs">
                  {/* Program Node */}
                  <div className="p-3 bg-slate-900/80 rounded-xl border border-white/10 flex items-center justify-between">
                    <span className="text-slate-400 uppercase">Program:</span>
                    <span className="text-emerald-400 font-bold">{selectedCase.programName}</span>
                  </div>

                  {/* Arrow */}
                  <div className="text-center text-slate-600 text-[10px]">↓</div>

                  {/* Case Node */}
                  <div className="p-3 bg-emerald-950/40 rounded-xl border border-emerald-700/50 flex items-center justify-between">
                    <span className="text-slate-300 uppercase">Research Case:</span>
                    <span className="text-emerald-300 font-bold">{selectedCase.id}</span>
                  </div>

                  {/* Arrow */}
                  <div className="text-center text-slate-600 text-[10px]">↓</div>

                  {/* Lineage Breakdown */}
                  {caseLineage ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                      <div className="bg-black/30 p-3 rounded-xl border border-white/5 space-y-1">
                        <div className="text-slate-400 text-[10px] uppercase font-bold flex items-center gap-1">
                          <Activity className="w-3 h-3 text-blue-400" /> Discovery Sessions ({caseLineage.discoverySessions?.length || 0})
                        </div>
                        {caseLineage.discoverySessions?.map((ds: any) => (
                          <div key={ds.id} className="text-[11px] text-slate-300 flex justify-between">
                            <span>{ds.id}</span>
                            <span className="text-slate-500">{ds.status}</span>
                          </div>
                        ))}
                      </div>

                      <div className="bg-black/30 p-3 rounded-xl border border-white/5 space-y-1">
                        <div className="text-slate-400 text-[10px] uppercase font-bold flex items-center gap-1">
                          <Layers className="w-3 h-3 text-cyan-400" /> Target Assets ({caseLineage.assets?.length || 0})
                        </div>
                        {caseLineage.assets?.map((a: any) => (
                          <div key={a.id} className="text-[11px] text-slate-300 flex justify-between">
                            <span>{a.domain || a.hostname}</span>
                            <span className="text-slate-500">{a.type}</span>
                          </div>
                        ))}
                      </div>

                      <div className="bg-black/30 p-3 rounded-xl border border-white/5 space-y-1">
                        <div className="text-slate-400 text-[10px] uppercase font-bold flex items-center gap-1">
                          <FileSearch className="w-3 h-3 text-amber-400" /> Findings ({caseLineage.findings?.length || 0})
                        </div>
                        {caseLineage.findings?.map((f: any) => (
                          <div key={f.id} className="text-[11px] text-slate-300 flex justify-between">
                            <span className="truncate max-w-[150px]">{f.title}</span>
                            <span className="text-amber-400 font-bold">{f.severity}</span>
                          </div>
                        ))}
                      </div>

                      <div className="bg-black/30 p-3 rounded-xl border border-white/5 space-y-1">
                        <div className="text-slate-400 text-[10px] uppercase font-bold flex items-center gap-1">
                          <FileText className="w-3 h-3 text-purple-400" /> Reports ({caseLineage.reports?.length || 0})
                        </div>
                        {caseLineage.reports?.map((r: any) => (
                          <div key={r.id} className="text-[11px] text-slate-300 flex justify-between">
                            <span>{r.id}</span>
                            <span className="text-purple-400">{r.status}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="text-center text-slate-500 py-4">Loading lineage tree...</div>
                  )}
                </div>
              </div>

              {/* Activities Audit Timeline */}
              <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
                <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-emerald-400" />
                  <span>Logged Research Activities ({activities.length})</span>
                </h3>

                {activities.length === 0 ? (
                  <div className="text-center text-xs font-mono text-slate-500 py-6">
                    No research activities logged yet for this case.
                  </div>
                ) : (
                  <div className="space-y-3 font-mono text-xs">
                    {activities.map((act) => (
                      <div
                        key={act.id}
                        className="p-3 bg-slate-900/60 rounded-xl border border-white/5 flex flex-col gap-1.5"
                      >
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-emerald-400 font-bold">{act.action}</span>
                          <span className="text-slate-500">{new Date(act.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div className="flex items-center justify-between text-[10px] text-slate-400">
                          <span>Target: {act.target}</span>
                          <span className="text-blue-400">Decision: {act.policyDecision}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="glass-panel p-12 rounded-2xl border border-white/10 text-center text-xs font-mono text-slate-500">
              Select a research case to view details, lineage tree, and activities.
            </div>
          )}
        </div>
      </div>

      {/* Create Case Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-panel max-w-lg w-full p-6 rounded-2xl border border-white/10 space-y-4 bg-slate-950">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-base font-black font-outfit uppercase tracking-wider text-slate-100 flex items-center gap-2">
                <Briefcase className="w-5 h-5 text-emerald-400" />
                <span>Create Research Case</span>
              </h3>
              <button
                onClick={() => setIsCreateModalOpen(false)}
                className="text-slate-500 hover:text-slate-300 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            {errorMsg && (
              <div className="p-3 rounded-xl bg-red-950/80 border border-red-700/50 text-red-300 text-xs font-mono">
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleCreateCase} className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-slate-400 uppercase tracking-wider mb-1">Program ID</label>
                <input
                  type="text"
                  value={programId}
                  onChange={(e) => setProgramId(e.target.value)}
                  className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/50"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 uppercase tracking-wider mb-1">Case Title</label>
                <input
                  type="text"
                  placeholder="e.g. API Authorization Boundary Assessment"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/50"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 uppercase tracking-wider mb-1">Objective</label>
                <textarea
                  placeholder="Describe the research campaign objectives..."
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                  rows={3}
                  className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/50"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-400 uppercase tracking-wider mb-1">Scope Summary (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. In-scope endpoints and domain boundaries"
                  value={scopeSummary}
                  onChange={(e) => setScopeSummary(e.target.value)}
                  className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/50"
                />
              </div>

              <div className="pt-2 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-xl font-bold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl font-bold uppercase tracking-wider flex items-center gap-1.5"
                >
                  {isSubmitting ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
