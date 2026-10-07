import React from 'react';
import { Program } from '../types';
import { PolicyPanel } from '../components/PolicyPanel';
import { ShieldAlert, Crosshair, ShieldCheck, ArrowLeft, Globe, DollarSign, Lock, AlertCircle } from 'lucide-react';

interface ProgramDetailViewProps {
  program: Program;
  onBack: () => void;
  onStartHunt: (programId: string, targetDomain: string) => void;
}

export const ProgramDetailView: React.FC<ProgramDetailViewProps> = ({
  program,
  onBack,
  onStartHunt,
}) => {
  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Back button */}
      <button
        onClick={onBack}
        className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-slate-100 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" /> Back to Programs
      </button>

      {/* Hero card */}
      <div className="glass-panel-accent rounded-2xl p-5 sm:p-8 border border-red-700/40 relative overflow-hidden bg-gradient-to-r from-[#18090c] via-[#0d0a14] to-[#090a0f]">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-5 sm:gap-6 relative z-10">
          <div className="space-y-2 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono uppercase text-slate-400 font-bold">{program.organization}</span>
              <span className="px-2.5 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-700/50 text-emerald-400 text-xs font-mono font-bold">
                All rules loaded ✓
              </span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-extrabold font-outfit uppercase tracking-wider text-slate-100">
              {program.name}
            </h1>

            <p className="text-slate-300 text-xs sm:text-sm font-sans max-w-2xl leading-relaxed">
              {program.description}
            </p>
          </div>

          <button
            onClick={() => onStartHunt(program.id, program.targets[0] || 'api.acme-security.test')}
            className="w-full sm:w-auto flex items-center justify-center gap-3 px-6 sm:px-8 py-3.5 sm:py-4 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 font-outfit font-black uppercase tracking-wider text-sm sm:text-base shadow-[0_0_30px_rgba(220,38,38,0.5)] transition-all transform hover:-translate-y-0.5 cursor-pointer shrink-0"
          >
            <Crosshair className="w-5 h-5 animate-pulse" />
            <span>START HUNT</span>
          </button>
        </div>

        {/* Quick parameters grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 sm:mt-8 pt-5 sm:pt-6 border-t border-white/10 font-mono text-xs">
          <div className="min-w-0">
            <span className="text-slate-500 uppercase text-[10px] block">Primary Target</span>
            <span className="text-slate-100 font-bold text-xs sm:text-sm truncate block">{program.targets[0] || 'example.com'}</span>
          </div>
          <div>
            <span className="text-slate-500 uppercase text-[10px] block">Scope Size</span>
            <span className="text-slate-100 font-bold text-xs sm:text-sm">{program.targetCount} Assets</span>
          </div>
          <div>
            <span className="text-slate-500 uppercase text-[10px] block">Max Reward</span>
            <span className="text-red-400 font-bold text-xs sm:text-sm">Up to {program.rewardMax}</span>
          </div>
          <div>
            <span className="text-slate-500 uppercase text-[10px] block">Research Status</span>
            <span className="text-emerald-400 font-bold text-xs sm:text-sm">Ready</span>
          </div>
        </div>
      </div>

      {/* Policy & Rules Panel */}
      <PolicyPanel rulesAllowed={program.rulesAllowed} rulesBlocked={program.rulesBlocked} />

      {/* Target Assets List */}
      <div className="glass-panel rounded-2xl p-4 sm:p-6 border border-white/10 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-white/10">
          <div className="flex items-center gap-2 font-outfit uppercase font-bold text-slate-100 text-sm sm:text-base">
            <Globe className="w-5 h-5 text-red-400 shrink-0" />
            <span>Authorized In-Scope Targets ({program.targets.length})</span>
          </div>
          <span className="text-xs font-mono text-slate-400">Strict scope boundary</span>
        </div>

        <div className="space-y-2 font-mono text-xs">
          {program.targets.map((tgt, idx) => (
            <div
              key={tgt}
              className="p-3 sm:p-3.5 rounded-xl bg-slate-900/80 border border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 hover:border-white/20 transition-colors"
            >
              <div className="flex items-center gap-2.5 sm:gap-3 min-w-0 flex-wrap">
                <span className="w-6 h-6 rounded bg-slate-950 text-slate-500 flex items-center justify-center text-[10px] shrink-0">
                  0{idx + 1}
                </span>
                <span className="font-bold text-slate-100 text-xs sm:text-sm break-all">{tgt}</span>
                <span className="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/40 text-emerald-400 text-[10px] shrink-0">
                  In Scope ✓
                </span>
              </div>

              <button
                onClick={() => onStartHunt(program.id, tgt)}
                className="w-full sm:w-auto px-3 py-1.5 rounded-lg bg-red-950/80 border border-red-700/50 hover:bg-red-900 text-red-300 font-outfit font-bold uppercase text-[11px] transition-colors shrink-0"
              >
                Launch Hunt
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
