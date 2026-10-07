import React from 'react';
import { Program } from '../types';
import { EmptyState } from '../components/FeedbackStates';
import { ShieldAlert, Plus, ShieldCheck, Globe, DollarSign } from 'lucide-react';

const PROGRAMS_BG_IMAGE_URL =
  'https://res.cloudinary.com/r67amuba/image/upload/v1791398233/Cosmic_Milky_Way_Over_Frozen_Wilderness.png';

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
    <div className="animate-fade-in pb-6 max-w-7xl mx-auto w-full">
      {/* Defined Main Programs Workspace Container — Subtle Border + Scoped Cosmic Milky Way Background */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-700/65 bg-[#080712] p-5 sm:p-6 lg:p-7 min-h-[calc(100vh-8.5rem)] flex flex-col justify-between shadow-[0_24px_60px_-15px_rgba(0,0,0,0.92),inset_0_1px_0_0_rgba(148,163,184,0.16)] ring-1 ring-inset ring-indigo-400/10">
        {/* Layer 1: Cosmic Milky Way Background Image — Scoped strictly to Programs Main Content */}
        <img
          src={PROGRAMS_BG_IMAGE_URL}
          alt=""
          aria-hidden="true"
          className="absolute inset-0 w-full h-full object-cover object-center opacity-80 brightness-[0.86] contrast-[1.12] saturate-[1.12] pointer-events-none select-none"
        />

        {/* Layer 2: Controlled Dark Navy/Black Translucent Surface Overlay */}
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-[#070611]/55 pointer-events-none"
        />

        {/* Layer 3: Subtle Atmospheric Vignette & Depth Gradient */}
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-gradient-to-b from-[#080713]/70 via-[#080713]/25 to-[#06060e]/75 pointer-events-none"
        />

        {/* Subtle Top Identity Hairline Accent */}
        <div
          aria-hidden="true"
          className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-red-500/35 to-transparent pointer-events-none"
        />

        {/* Foreground Programs Workspace Content */}
        <div className="relative z-10 space-y-6">
          {/* LEVEL 1 & 2: Programs Page Header & Add Program CTA */}
          <div className="rounded-xl border border-slate-700/60 bg-[#090b15]/78 backdrop-blur-md px-5 py-4 sm:px-6 sm:py-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm">
            <div className="space-y-1">
              <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-red-950/70 border border-red-500/30 text-[11px] font-mono font-semibold text-red-400 uppercase tracking-wider">
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Authorized Scope Directory</span>
              </div>
              <h1 className="text-2xl sm:text-[26px] font-black font-outfit uppercase tracking-wider text-slate-100 drop-shadow-[0_2px_8px_rgba(0,0,0,0.8)]">
                Bug Bounty Programs
              </h1>
              <p className="text-xs sm:text-sm text-slate-300 font-sans">
                Manage authorized research targets, load policies, and launch hunts.
              </p>
            </div>

            <button
              onClick={onOpenAddProgramModal}
              className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white text-xs font-bold font-outfit uppercase tracking-wider border border-red-400/30 shadow-[0_8px_24px_-4px_rgba(220,38,38,0.45)] hover:shadow-[0_12px_28px_-4px_rgba(239,68,68,0.6)] transition-all cursor-pointer shrink-0"
            >
              <Plus className="w-4 h-4" />
              <span>ADD PROGRAM</span>
            </button>
          </div>

          {programs.length === 0 ? (
            <EmptyState type="programs" onAction={onOpenAddProgramModal} actionLabel="ADD PROGRAM" />
          ) : (
            /* LEVEL 3, 4 & 5: Program Cards Grid */
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 items-stretch">
              {programs.map((program) => (
                <div
                  key={program.id}
                  className="rounded-xl p-5 border border-slate-700/65 bg-[#0a0d18]/86 backdrop-blur-md hover:border-red-500/45 flex flex-col justify-between group hover:bg-[#0d1120]/92 transition-all relative overflow-hidden shadow-[0_12px_32px_-8px_rgba(0,0,0,0.75)]"
                >
                  {/* Top subtle glow */}
                  <div className="absolute -top-12 -right-12 w-28 h-28 bg-red-600/10 rounded-full blur-2xl pointer-events-none group-hover:bg-red-600/20 transition-all" />

                  <div>
                    <div className="flex items-start justify-between gap-3 mb-3.5">
                      <div className="min-w-0">
                        <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block truncate">
                          {program.organization}
                        </span>
                        <h3 className="text-lg font-bold font-outfit text-slate-100 group-hover:text-red-300 transition-colors truncate">
                          {program.name}
                        </h3>
                      </div>

                      <span className="px-2.5 py-1 rounded-full bg-emerald-950/75 border border-emerald-700/50 text-emerald-400 text-[10px] font-mono font-bold shrink-0 flex items-center gap-1">
                        <ShieldCheck className="w-3 h-3" />
                        Rules loaded ✓
                      </span>
                    </div>

                    {program.description && (
                      <p className="text-xs text-slate-300 font-sans leading-relaxed mb-4 line-clamp-2">
                        {program.description}
                      </p>
                    )}

                    <div className="grid grid-cols-2 gap-3 p-3 rounded-xl bg-[#060811]/85 border border-white/10 text-xs font-mono mb-5">
                      <div>
                        <span className="text-slate-400 text-[10px] uppercase block">In-Scope Assets</span>
                        <span className="text-slate-100 font-bold flex items-center gap-1.5 mt-0.5">
                          <Globe className="w-3.5 h-3.5 text-slate-400" />
                          {program.targetCount} targets
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 text-[10px] uppercase block">Highest Reward</span>
                        <span className="text-red-400 font-bold flex items-center gap-1 mt-0.5">
                          <DollarSign className="w-3.5 h-3.5 text-red-400" />
                          {program.rewardMax}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2.5 pt-3 border-t border-white/10">
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span>Last hunt: {program.lastHunt}</span>
                      <span className="text-emerald-400 font-semibold">{program.status}</span>
                    </div>

                    <div className="grid grid-cols-2 gap-2.5">
                      <button
                        onClick={() => onSelectProgram(program.id)}
                        className="w-full py-2 px-3 rounded-xl bg-slate-900/90 border border-slate-700/70 hover:bg-slate-800 hover:border-slate-500/70 text-slate-200 font-outfit text-xs font-bold uppercase tracking-wider transition-colors text-center cursor-pointer"
                      >
                        OPEN PROGRAM
                      </button>
                      <button
                        onClick={() => onStartHuntForProgram(program.id)}
                        className="w-full py-2 px-3 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white font-outfit text-xs font-bold uppercase tracking-wider border border-red-400/25 shadow-[0_0_14px_rgba(220,38,38,0.3)] transition-colors text-center cursor-pointer"
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

        {/* Subtle Workspace Footer Status Bar — Anchors the Defined Container Frame */}
        <div className="relative z-10 mt-8 pt-3.5 border-t border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            <span>
              {programs.length} Authorized {programs.length === 1 ? 'Program' : 'Programs'} Indexed • Scope & Policy Guards Active
            </span>
          </div>
          <span className="text-slate-400/80 uppercase">Directory Sync: Ready</span>
        </div>
      </div>
    </div>
  );
};
