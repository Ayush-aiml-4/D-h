import React from 'react';
import { Hunt, Finding } from '../types';
import { EmptyState } from '../components/FeedbackStates';
import { Flame, Plus, Radio, ArrowRight } from 'lucide-react';
import {
  getHuntPotentialCount,
  getHuntVerifiedCount,
  getHuntPolicyViolationsCount,
} from '../utils/selectors';

interface HuntsViewProps {
  hunts: Hunt[];
  findings?: Finding[];
  onSelectHunt: (huntId: string) => void;
  onStartHuntClick: () => void;
}

export const HuntsView: React.FC<HuntsViewProps> = ({
  hunts,
  findings = [],
  onSelectHunt,
  onStartHuntClick,
}) => {
  return (
    <div className="space-y-6 animate-fade-in pb-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-red-400 uppercase tracking-wider mb-1">
            <Flame className="w-4 h-4" />
            <span>Research Sessions</span>
          </div>
          <h1 className="text-2xl font-black font-outfit uppercase tracking-wider text-slate-100">
            Active & Past Hunts
          </h1>
          <p className="text-xs text-slate-400 font-sans">
            Monitor real-time security checks and review past hunt sessions.
          </p>
        </div>

        <button
          onClick={onStartHuntClick}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 text-xs font-bold font-outfit uppercase tracking-wider shadow-[0_0_20px_rgba(220,38,38,0.3)] transition-all cursor-pointer shrink-0"
        >
          <Plus className="w-4 h-4" />
          <span>START NEW HUNT</span>
        </button>
      </div>

      {hunts.length === 0 ? (
        <EmptyState type="hunts" onAction={onStartHuntClick} actionLabel="START A HUNT" />
      ) : (
        <div className="space-y-4">
          {hunts.map((hunt) => {
            const isLive = hunt.status === 'Hunting' || hunt.status === 'Analyzing' || hunt.status === 'Running';
            const potentialCount = getHuntPotentialCount(findings, hunt.id);
            const verifiedCount = getHuntVerifiedCount(findings, hunt.id);
            const policyViolations = getHuntPolicyViolationsCount(findings, hunt.id);

            return (
              <div
                key={hunt.id}
                onClick={() => onSelectHunt(hunt.id)}
                className={`glass-panel card-lift rounded-2xl p-6 border cursor-pointer group relative overflow-hidden ${
                  isLive
                    ? 'border-red-600/50 bg-gradient-to-r from-[#18090c] via-[#0d0d18] to-[#090a0f] shadow-[0_0_25px_rgba(220,38,38,0.15)]'
                    : 'border-white/10 hover:border-white/20'
                }`}
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-3">
                      <span className="text-xs font-mono uppercase text-slate-400 font-semibold">
                        {hunt.programName}
                      </span>
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase border flex items-center gap-1.5 ${
                          isLive
                            ? 'bg-red-950/80 text-red-400 border-red-700/60 shadow-[0_0_10px_rgba(220,38,38,0.3)]'
                            : 'bg-slate-900 text-slate-300 border-slate-700'
                        }`}
                      >
                        {isLive && <Radio className="w-3 h-3 text-red-500 animate-pulse" />}
                        {hunt.status}
                      </span>
                    </div>

                    <h3 className="text-xl font-bold font-mono text-slate-100 group-hover:text-red-300 transition-colors">
                      {hunt.targetDomain}
                    </h3>

                    <p className="text-xs text-slate-400 font-sans">
                      Scope: {hunt.scopeCount} targets • Started {hunt.startedAt}
                    </p>
                  </div>

                  <div className="flex items-center gap-4 text-xs font-mono shrink-0">
                    <div className="text-right">
                      <span className="text-slate-500 text-[10px] uppercase block">Potential Findings</span>
                      <span className="text-amber-400 font-bold">{potentialCount}</span>
                    </div>
                    <div className="text-right">
                      <span className="text-slate-500 text-[10px] uppercase block">Verified Bugs</span>
                      <span className="text-emerald-400 font-bold">{verifiedCount}</span>
                    </div>
                    <div className="text-right">
                      <span className="text-slate-500 text-[10px] uppercase block">Policy Violations</span>
                      <span className="text-emerald-400 font-bold">{policyViolations}</span>
                    </div>
                  </div>
                </div>

                {/* Progress & Task status */}
                <div className="pt-4 border-t border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
                  <div className="flex items-center gap-2 text-slate-300 truncate">
                    <span className="text-slate-500 uppercase text-[10px]">Current Task:</span>
                    <span className="truncate max-w-[320px]">{hunt.currentTask}</span>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-red-400 font-bold">{hunt.progressPercent}% Complete</span>
                    <button className="px-3 py-1 rounded-lg bg-slate-900 border border-white/10 text-slate-200 group-hover:border-red-500/50 group-hover:text-red-300 transition-colors font-outfit uppercase font-bold text-[11px] flex items-center gap-1">
                      <span>OPEN HUNT</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
