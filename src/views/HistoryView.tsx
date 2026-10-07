import React, { useState } from 'react';
import { HistorySession } from '../types';
import { EmptyState } from '../components/FeedbackStates';
import { History, Search, Award, CheckCircle2, Clock } from 'lucide-react';

interface HistoryViewProps {
  history: HistorySession[];
}

export const HistoryView: React.FC<HistoryViewProps> = ({ history }) => {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredHistory = history.filter(
    (item) =>
      item.programName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.target.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-red-400 uppercase tracking-wider mb-1">
            <History className="w-4 h-4" />
            <span>Research Audit Log</span>
          </div>
          <h1 className="text-2xl font-black font-outfit uppercase tracking-wider text-slate-100">
            Hunt Session History
          </h1>
          <p className="text-xs text-slate-400 font-sans">
            Archive of completed security research sessions, verified vulnerabilities, and bounty rewards.
          </p>
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search history..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900 border border-white/10 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500/50 font-sans"
          />
        </div>
      </div>

      {/* History Table / Cards */}
      {filteredHistory.length === 0 ? (
        <EmptyState type="history" />
      ) : (
        <div className="space-y-3 font-mono text-xs">
          {filteredHistory.map((session) => (
            <div
              key={session.id}
              className="glass-panel rounded-xl p-4 border border-white/10 hover:border-white/20 transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400 uppercase text-[10px] font-semibold">{session.programName}</span>
                  <span className="text-slate-500">•</span>
                  <span className="text-slate-500 text-[10px]">{session.date}</span>
                </div>

                <h3 className="text-base font-bold text-slate-100 font-mono">
                  {session.target}
                </h3>
              </div>

              <div className="flex flex-wrap items-center gap-6 text-slate-300">
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Duration</span>
                  <span className="font-semibold flex items-center gap-1 mt-0.5">
                    <Clock className="w-3.5 h-3.5 text-slate-400" />
                    {session.duration}
                  </span>
                </div>

                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Verified Bugs</span>
                  <span className="font-bold text-emerald-400 flex items-center gap-1 mt-0.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    {session.verifiedFindings}
                  </span>
                </div>

                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Bounty Reward</span>
                  <span className="font-bold text-red-400 flex items-center gap-1 mt-0.5">
                    <Award className="w-3.5 h-3.5 text-red-400" />
                    {session.bountyEarned}
                  </span>
                </div>

                <div className="px-3 py-1 rounded bg-slate-900 border border-white/10 text-slate-300 text-[11px]">
                  {session.reportStatus}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
