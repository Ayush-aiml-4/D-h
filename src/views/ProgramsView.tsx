import React from 'react';
import { Program } from '../types';
import { EmptyState } from '../components/FeedbackStates';
import { ShieldAlert, Plus, ShieldCheck, Globe, DollarSign } from 'lucide-react';

interface ProgramsViewProps {
  programs: Program[];
  onSelectProgram: (programId: string) => void;
  onOpenAddProgramModal: () => void;
  onStartHuntForProgram: (programId: string) => void;
}

export const ProgramsView: React.FC<ProgramsViewProps> = ({
  programs,
  onSelectProgram,
  onOpenAddProgramModal,
  onStartHuntForProgram,
}) => {
  return (
    <div className="space-y-6 animate-fade-in pb-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-red-400 uppercase tracking-wider mb-1">
            <ShieldAlert className="w-4 h-4" />
            <span>Authorized Scope Directory</span>
          </div>
          <h1 className="text-2xl font-black font-outfit uppercase tracking-wider text-slate-100">
            Bug Bounty Programs
          </h1>
          <p className="text-xs text-slate-400 font-sans">
            Manage authorized research targets, load policies, and launch hunts.
          </p>
        </div>

        <button
          onClick={onOpenAddProgramModal}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 text-xs font-bold font-outfit uppercase tracking-wider shadow-[0_0_20px_rgba(220,38,38,0.3)] transition-all cursor-pointer shrink-0"
        >
          <Plus className="w-4 h-4" />
          <span>ADD PROGRAM</span>
        </button>
      </div>

      {programs.length === 0 ? (
        <EmptyState type="programs" onAction={onOpenAddProgramModal} actionLabel="ADD PROGRAM" />
      ) : (
        /* Program Cards Grid */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {programs.map((program) => (
            <div
              key={program.id}
              className="glass-panel card-lift rounded-2xl p-6 border border-white/10 hover:border-red-500/40 flex flex-col justify-between group hover:bg-slate-900/90 relative overflow-hidden cursor-pointer"
            >
              {/* Top subtle glow */}
              <div className="absolute -top-12 -right-12 w-32 h-32 bg-red-600/10 rounded-full blur-2xl pointer-events-none group-hover:bg-red-600/20 transition-all" />

              <div>
                <div className="flex items-start justify-between gap-3 mb-4">
                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">
                      {program.organization}
                    </span>
                    <h3 className="text-lg font-bold font-outfit text-slate-100 group-hover:text-red-300 transition-colors">
                      {program.name}
                    </h3>
                  </div>

                  <span className="px-2.5 py-1 rounded-full bg-emerald-950/60 border border-emerald-800/40 text-emerald-400 text-[10px] font-mono font-bold shrink-0 flex items-center gap-1">
                    <ShieldCheck className="w-3 h-3" />
                    Rules loaded ✓
                  </span>
                </div>

                {program.description && (
                  <p className="text-xs text-slate-300 font-sans leading-relaxed mb-4 line-clamp-2">
                    {program.description}
                  </p>
                )}

                <div className="grid grid-cols-2 gap-3 p-3 rounded-xl bg-slate-950/80 border border-white/5 text-xs font-mono mb-6">
                  <div>
                    <span className="text-slate-500 text-[10px] uppercase block">In-Scope Assets</span>
                    <span className="text-slate-200 font-bold flex items-center gap-1 mt-0.5">
                      <Globe className="w-3.5 h-3.5 text-slate-400" />
                      {program.targetCount} targets
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px] uppercase block">Highest Reward</span>
                    <span className="text-red-400 font-bold flex items-center gap-1 mt-0.5">
                      <DollarSign className="w-3.5 h-3.5 text-red-400" />
                      {program.rewardMax}
                    </span>
                  </div>
                </div>
              </div>

              <div className="space-y-2 pt-2 border-t border-white/5">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-2">
                  <span>Last hunt: {program.lastHunt}</span>
                  <span className="text-emerald-400 font-semibold">{program.status}</span>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => onSelectProgram(program.id)}
                    className="w-full py-2 px-3 rounded-xl bg-slate-900 border border-white/10 hover:bg-slate-800 text-slate-200 font-outfit text-xs font-bold uppercase tracking-wider transition-colors text-center"
                  >
                    OPEN PROGRAM
                  </button>
                  <button
                    onClick={() => onStartHuntForProgram(program.id)}
                    className="w-full py-2 px-3 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 font-outfit text-xs font-bold uppercase tracking-wider shadow-[0_0_12px_rgba(220,38,38,0.3)] transition-colors text-center"
                  >
                    START HUNT
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
