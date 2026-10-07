import React, { useState } from 'react';
import { Finding } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { EmptyState } from '../components/FeedbackStates';
import { FileSearch, ArrowRight, ShieldCheck } from 'lucide-react';

interface FindingsViewProps {
  findings: Finding[];
  onSelectFinding: (findingId: string) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  onSelectFinding,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<string>('All');

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== 'All' && f.severity !== severityFilter) return false;
    if (statusFilter !== 'All' && f.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-red-400 uppercase tracking-wider mb-1">
            <FileSearch className="w-4 h-4" />
            <span>Vulnerability Assessment Results</span>
          </div>
          <h1 className="text-2xl font-black font-outfit uppercase tracking-wider text-slate-100">
            Security Findings
          </h1>
          <p className="text-xs text-slate-400 font-sans">
            Review potential security vulnerabilities verified by DevilHunt's policy enforcer.
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex items-center gap-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-900 border border-white/10 rounded-xl px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500/50"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900 border border-white/10 rounded-xl px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500/50"
          >
            <option value="All">All Statuses</option>
            <option value="Potential">Potential</option>
            <option value="Under review">Under Review</option>
            <option value="Needs review">Needs Review</option>
            <option value="Validated">Validated</option>
            <option value="Verified">Verified</option>
            <option value="Rejected">Rejected</option>
            <option value="Closed">Closed</option>
            <option value="Resolved">Resolved</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <EmptyState type="findings" />
      ) : (
        <div className="space-y-4">
          {filteredFindings.map((finding) => (
            <div
              key={finding.id}
              onClick={() => onSelectFinding(finding.id)}
              className="glass-panel card-lift rounded-2xl p-6 border border-white/10 hover:border-red-500/40 cursor-pointer group relative overflow-hidden hover:bg-slate-900/90"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-3">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={finding.severity} />
                  <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-2.5 py-0.5 rounded-full">
                    Confidence: {finding.confidence}%
                  </span>
                  <span className="text-xs font-mono text-slate-400">• {finding.category}</span>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-xs font-mono text-slate-300 font-semibold px-2.5 py-1 rounded bg-slate-900 border border-white/10">
                    {finding.status}
                  </span>
                  <button className="px-4 py-1.5 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 font-outfit text-xs font-bold uppercase tracking-wider shadow-[0_0_12px_rgba(220,38,38,0.3)] transition-colors flex items-center gap-1.5">
                    <span>VIEW FINDING</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              <h3 className="text-lg font-bold font-outfit text-slate-100 group-hover:text-red-300 transition-colors mb-1.5">
                {finding.title}
              </h3>

              <p className="text-xs text-slate-300 font-sans leading-relaxed mb-4 max-w-3xl">
                {finding.whatWeFound}
              </p>

              <div className="pt-3 border-t border-white/5 flex flex-wrap items-center justify-between text-xs font-mono text-slate-400 gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 uppercase text-[10px]">Target:</span>
                  <span className="text-slate-200 font-bold">{finding.affectedTarget}</span>
                </div>
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Policy Verified ✓</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
