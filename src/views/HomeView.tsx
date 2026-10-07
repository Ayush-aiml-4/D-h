import React, { useEffect, useRef, useState } from 'react';
import { Program, Hunt, Finding, Report, HistorySession, UserProfile } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { PolicyPanel } from '../components/PolicyPanel';
import { EmptyState } from '../components/FeedbackStates';
import { Crosshair, ArrowRight, Flame, Shield, Award, CheckCircle2, ExternalLink } from 'lucide-react';
import {
  getActiveHuntsCount,
  getVerifiedBugsCount,
  getOpenReportsCount,
  getCalculatedBounty,
  getWorthCheckingFindings,
  getHuntPotentialCount,
  getHuntVerifiedCount,
  getHuntPolicyViolationsCount,
} from '../utils/selectors';

const HERO_VIDEO_URL =
  'https://res.cloudinary.com/r67amuba/video/upload/v1791394018/Demonic_entity_expanding_wings_20261007152351.mp4';

const DASHBOARD_BG_IMAGE_URL =
  'https://res.cloudinary.com/r67amuba/image/upload/v1791395866/Moonlit_Blossom_Cliffscape.png';

interface HomeViewProps {
  profile: UserProfile;
  hunts: Hunt[];
  findings: Finding[];
  programs: Program[];
  reports: Report[];
  history: HistorySession[];
  onStartHuntClick: () => void;
  onSelectHunt: (huntId: string) => void;
  onSelectFinding: (findingId: string) => void;
  onSelectProgram: (programId: string) => void;
  onNavigateTab: (tab: any) => void;
}

export const HomeView: React.FC<HomeViewProps> = ({
  profile,
  hunts,
  findings,
  programs,
  reports = [],
  history = [],
  onStartHuntClick,
  onSelectHunt,
  onSelectFinding,
  onSelectProgram,
  onNavigateTab,
}) => {
  const activeCount = getActiveHuntsCount(hunts);
  const verifiedBugsCount = getVerifiedBugsCount(findings);
  const openReportsCount = getOpenReportsCount(reports);
  const bountyData = getCalculatedBounty(history, reports);
  const worthCheckingFindings = getWorthCheckingFindings(findings);

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);

    const handleChange = (e: MediaQueryListEvent) => {
      setPrefersReducedMotion(e.matches);
    };
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  useEffect(() => {
    const videoEl = videoRef.current;
    if (!videoEl) return;
    if (prefersReducedMotion) {
      videoEl.pause();
    } else {
      videoEl.play().catch(() => {
        // Autoplay fallback handled silently by browser
      });
    }
  }, [prefersReducedMotion]);

  const hour = new Date().getHours();
  const greeting =
    hour < 5 ? 'GOOD NIGHT' :
    hour < 12 ? 'GOOD MORNING' :
    hour < 17 ? 'GOOD AFTERNOON' :
    hour < 21 ? 'GOOD EVENING' : 'GOOD NIGHT';

  return (
    <div className="animate-fade-in pb-6 max-w-7xl mx-auto w-full">
      {/* Defined Main Home Content Workspace Container — Subtle Border + Scoped Moonlit Landscape Background */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-700/65 bg-[#070a13] p-4 sm:p-5 lg:p-6 shadow-[0_24px_60px_-15px_rgba(0,0,0,0.92),inset_0_1px_0_0_rgba(148,163,184,0.16)] ring-1 ring-inset ring-blue-400/10 space-y-5">
        {/* Layer 1: Moonlit Landscape Background Image (Image 2) — Scoped to Main Home Content */}
        <img
          src={DASHBOARD_BG_IMAGE_URL}
          alt=""
          aria-hidden="true"
          className="absolute inset-0 w-full h-full object-cover object-[center_62%] opacity-80 brightness-[0.84] contrast-[1.12] saturate-[1.12] pointer-events-none select-none"
        />

        {/* Layer 2: Controlled Dark Navy/Black Translucent Surface Overlay */}
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-[#060913]/56 pointer-events-none"
        />

        {/* Layer 3: Subtle Edge Vignette & Top/Bottom Depth Gradient */}
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-gradient-to-b from-[#070912]/65 via-[#070a14]/25 to-[#060810]/70 pointer-events-none"
        />

        {/* Subtle Top Red/Blue Identity Hairline Accent */}
        <div
          aria-hidden="true"
          className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-red-500/35 to-transparent pointer-events-none"
        />

        {/* Foreground Workspace Content */}
        <div className="relative z-10 space-y-4 sm:space-y-5">
          {/* LEVEL 1: Hero Section — Scoped Devil Video Background (UNCHANGED SOURCE & TREATMENT) */}
          <section
            aria-label="Command Center Hero"
            className="relative overflow-hidden rounded-xl border border-red-500/35 bg-[#060407] px-4 py-5 sm:px-8 sm:py-8 lg:px-10 lg:py-9 min-h-[190px] sm:min-h-[220px] lg:min-h-[235px] flex items-center shadow-[0_16px_40px_-10px_rgba(0,0,0,0.9),0_0_32px_-6px_rgba(220,38,38,0.22)]"
          >
            {/* Layer 1: Scoped HTML5 Video Background — high clarity, enhanced contrast & color */}
            <video
              ref={videoRef}
              src={HERO_VIDEO_URL}
              autoPlay={!prefersReducedMotion}
              muted
              loop
              playsInline
              preload="auto"
              aria-hidden="true"
              className="absolute inset-0 w-full h-full object-cover object-center opacity-95 brightness-[1.12] contrast-[1.18] saturate-[1.35] pointer-events-none select-none"
            />

            {/* Layer 2: Subtle crimson color-grade accent over the wings area */}
            <div
              aria-hidden="true"
              className="absolute inset-0 bg-[radial-gradient(ellipse_75%_85%_at_68%_50%,rgba(220,38,38,0.16),transparent_70%)] pointer-events-none"
            />

            {/* Layer 3: Targeted left-side scrim for text legibility — leaves center/right video vivid and unobstructed */}
            <div
              aria-hidden="true"
              className="absolute inset-0 bg-gradient-to-r from-[#070509]/85 via-[#08050a]/35 to-transparent pointer-events-none"
            />

            {/* Layer 4: Light edge vignette & inner border ring */}
            <div
              aria-hidden="true"
              className="absolute inset-0 bg-gradient-to-t from-[#090a0f]/60 via-transparent to-[#090a0f]/20 ring-1 ring-inset ring-red-500/20 rounded-xl pointer-events-none"
            />

            {/* Layer 5: Hero Content */}
            <div className="relative z-10 w-full flex flex-col md:flex-row md:items-center justify-between gap-4 sm:gap-5 lg:gap-8">
              <div className="space-y-2.5 max-w-2xl min-w-0">
                <div className="inline-flex items-center gap-2 px-2.5 sm:px-3 py-1 rounded-full bg-[#16070a]/85 border border-red-500/35 text-red-400 text-[10px] sm:text-[11px] font-mono font-semibold uppercase tracking-[0.1em] sm:tracking-[0.14em] shadow-sm backdrop-blur-sm max-w-full">
                  <span className="relative flex h-2 w-2 shrink-0">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
                  </span>
                  <span className="truncate">PRIVATE RESEARCH COMMAND CENTER</span>
                </div>

                <h1 className="text-xl sm:text-3xl lg:text-[38px] font-extrabold font-outfit uppercase tracking-wider text-white leading-[1.15] sm:leading-[1.1] drop-shadow-[0_2px_12px_rgba(0,0,0,0.85)]">
                  {greeting},{' '}
                  <span className="text-slate-100">{profile.name}</span>
                </h1>

                <p className="text-slate-200/95 text-xs sm:text-[15px] font-sans font-medium leading-relaxed max-w-xl drop-shadow-[0_1px_8px_rgba(0,0,0,0.8)]">
                  Ready to hunt? Authorized targets are loaded and policy guards are active.
                </p>
              </div>

              <div className="flex items-center shrink-0 w-full sm:w-auto">
                <button
                  type="button"
                  onClick={onStartHuntClick}
                  className="group w-full sm:w-auto inline-flex items-center justify-center gap-3 px-6 py-3 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white font-outfit font-bold uppercase tracking-wider text-xs sm:text-sm border border-red-400/30 shadow-[0_8px_24px_-4px_rgba(220,38,38,0.45)] hover:shadow-[0_12px_28px_-4px_rgba(239,68,68,0.6)] transition-all duration-200 transform hover:-translate-y-0.5 active:translate-y-0 active:scale-[0.98] cursor-pointer whitespace-nowrap"
                >
                  <Crosshair className="w-4 h-4 text-red-100 transition-transform duration-200 group-hover:rotate-45" />
                  <span>START A HUNT</span>
                  <ArrowRight className="w-4 h-4 text-red-100 transition-transform duration-200 group-hover:translate-x-0.5" />
                </button>
              </div>
            </div>
          </section>

          {/* LEVEL 2: Primary Statistics Grid — Equal Height, Compact, Aligned Row */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 items-stretch">
            {/* Active Hunts */}
            <div className="rounded-xl p-4 border border-slate-700/60 bg-[#0a0d16]/82 hover:border-slate-500/70 transition-colors flex flex-col justify-between shadow-sm">
              <div className="flex items-center justify-between text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                <span>ACTIVE HUNTS</span>
                <div className="w-7 h-7 rounded-lg bg-red-950/60 border border-red-800/40 flex items-center justify-center">
                  <Flame className="w-3.5 h-3.5 text-red-400" />
                </div>
              </div>
              <div>
                <div className="text-2xl sm:text-3xl font-extrabold font-mono text-slate-100 tracking-tight leading-none">
                  {activeCount < 10 ? `0${activeCount}` : activeCount}
                </div>
                <p className="text-[11px] text-slate-400 font-mono mt-1.5">In progress right now</p>
              </div>
            </div>

            {/* Verified Bugs */}
            <div className="rounded-xl p-4 border border-slate-700/60 bg-[#0a0d16]/82 hover:border-slate-500/70 transition-colors flex flex-col justify-between shadow-sm">
              <div className="flex items-center justify-between text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                <span>VERIFIED BUGS</span>
                <div className="w-7 h-7 rounded-lg bg-emerald-950/60 border border-emerald-800/40 flex items-center justify-center">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                </div>
              </div>
              <div>
                <div className="text-2xl sm:text-3xl font-extrabold font-mono text-emerald-400 tracking-tight leading-none">
                  {verifiedBugsCount < 10 ? `0${verifiedBugsCount}` : verifiedBugsCount}
                </div>
                <p className="text-[11px] text-slate-400 font-mono mt-1.5">Confirmed with evidence</p>
              </div>
            </div>

            {/* Open Reports */}
            <div className="rounded-xl p-4 border border-slate-700/60 bg-[#0a0d16]/82 hover:border-slate-500/70 transition-colors flex flex-col justify-between shadow-sm">
              <div className="flex items-center justify-between text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                <span>OPEN REPORTS</span>
                <div className="w-7 h-7 rounded-lg bg-amber-950/60 border border-amber-800/40 flex items-center justify-center">
                  <Shield className="w-3.5 h-3.5 text-amber-400" />
                </div>
              </div>
              <div>
                <div className="text-2xl sm:text-3xl font-extrabold font-mono text-slate-100 tracking-tight leading-none">
                  {openReportsCount < 10 ? `0${openReportsCount}` : openReportsCount}
                </div>
                <p className="text-[11px] text-slate-400 font-mono mt-1.5">Active in disclosure workflow</p>
              </div>
            </div>

            {/* Paid / Pending Bounty Metrics */}
            <div className="rounded-xl p-4 border border-red-900/55 bg-gradient-to-br from-[#190a10]/88 to-[#0a0d16]/88 hover:border-red-600/60 transition-colors flex flex-col justify-between relative overflow-hidden shadow-sm">
              <div className="flex items-center justify-between text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-300 mb-1">
                <span className="flex items-center gap-1.5">
                  <span>PAID BOUNTY</span>
                  {profile.isDemoMode && (
                    <span className="text-[9px] bg-red-950 border border-red-700/50 text-red-300 px-1.5 py-0.2 rounded font-mono">
                      DEMO
                    </span>
                  )}
                </span>
                <div className="w-7 h-7 rounded-lg bg-red-950/70 border border-red-700/50 flex items-center justify-center">
                  <Award className="w-3.5 h-3.5 text-red-400" />
                </div>
              </div>

              <div className="text-2xl font-black font-mono text-red-400 tracking-tight leading-none my-0.5">
                {bountyData.paidFormatted}
              </div>

              {/* Pending and Potential Breakdown */}
              <div className="pt-2 border-t border-white/10 grid grid-cols-2 text-[10px] font-mono">
                <div>
                  <span className="text-slate-400 block">PENDING</span>
                  <span className="text-amber-300 font-bold">{bountyData.pendingFormatted}</span>
                </div>
                <div>
                  <span className="text-slate-400 block">POTENTIAL</span>
                  <span className="text-slate-200 font-bold">{bountyData.potentialFormatted}</span>
                </div>
              </div>
            </div>
          </div>

          {/* LEVEL 3, 4 & 5: Balanced Main Content Grid (Your Hunts ~67% | Intelligence & Policy ~33%) */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
            {/* Left 8 Cols (~67%): Your Hunts Operations Queue */}
            <div className="lg:col-span-8 rounded-xl border border-slate-700/55 bg-[#080b13]/65 p-4 sm:p-5 space-y-3.5">
              <div className="flex items-center justify-between pb-2.5 border-b border-white/10">
                <div className="flex items-center gap-2.5">
                  <h2 className="text-base font-bold font-outfit uppercase tracking-wider text-slate-100">
                    Your Hunts
                  </h2>
                  <span className="px-2 py-0.5 rounded-md bg-slate-800/80 border border-slate-700/60 text-[11px] font-mono text-slate-300">
                    {hunts.length} Sessions
                  </span>
                </div>
                <button
                  onClick={() => onNavigateTab('hunts')}
                  className="text-xs font-mono font-semibold text-red-400 hover:text-red-300 transition-colors flex items-center gap-1"
                >
                  View all <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              {hunts.length === 0 ? (
                <EmptyState type="hunts" onAction={onStartHuntClick} actionLabel="START A HUNT" />
              ) : (
                <div className="space-y-2.5">
                  {hunts.map((hunt) => {
                    const getStatusStyle = (st: string) => {
                      switch (st) {
                        case 'Hunting':
                        case 'Running':
                          return 'bg-red-950/85 text-red-400 border-red-800/60 shadow-[0_0_10px_rgba(220,38,38,0.25)]';
                        case 'Analyzing':
                          return 'bg-amber-950/85 text-amber-400 border-amber-800/60';
                        case 'Ready':
                          return 'bg-emerald-950/85 text-emerald-400 border-emerald-800/60';
                        default:
                          return 'bg-slate-900 text-slate-300 border-slate-700/60';
                      }
                    };

                    const huntPot = getHuntPotentialCount(findings, hunt.id);
                    const huntVer = getHuntVerifiedCount(findings, hunt.id);

                    return (
                      <div
                        key={hunt.id}
                        onClick={() => onSelectHunt(hunt.id)}
                        className="rounded-xl p-3.5 sm:p-4 border border-slate-700/60 bg-[#0b0f19]/88 hover:border-red-500/45 transition-all cursor-pointer group hover:bg-[#0e1320]/95"
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="space-y-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-[11px] font-mono uppercase text-slate-400 font-semibold">
                                {hunt.programName}
                              </span>
                              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getStatusStyle(hunt.status)}`}>
                                {hunt.status}
                              </span>
                            </div>
                            <h3 className="text-sm sm:text-base font-bold font-mono text-slate-100 group-hover:text-red-300 transition-colors truncate">
                              {hunt.targetDomain}
                            </h3>
                            <p className="text-xs text-slate-400 font-sans">
                              Scope: {hunt.scopeCount} targets • Started {hunt.startedAt}
                            </p>
                          </div>

                          <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
                            <div className="text-right text-[11px] sm:text-xs font-mono">
                              <span className="text-emerald-400 font-bold">{huntVer} Verified</span>
                              {huntPot > 0 && <span className="text-amber-400 block">{huntPot} Review</span>}
                            </div>
                            <button className="p-2 rounded-lg bg-slate-900/90 border border-white/10 group-hover:border-red-500/50 group-hover:text-red-400 text-slate-400 transition-colors">
                              <ExternalLink className="w-4 h-4" />
                            </button>
                          </div>
                        </div>

                        {/* Progress Bar if Hunting/Analyzing */}
                        {(hunt.status === 'Hunting' || hunt.status === 'Analyzing' || hunt.status === 'Running') && (
                          <div className="mt-3 pt-2.5 border-t border-white/5 space-y-1.5">
                            <div className="flex justify-between text-xs font-mono text-slate-400">
                              <span className="truncate max-w-[320px]">{hunt.currentTask}</span>
                              <span className="text-red-400 font-bold">{hunt.progressPercent}%</span>
                            </div>
                            <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden border border-white/5">
                              <div
                                className="bg-gradient-to-r from-red-600 to-red-400 h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(220,38,38,0.7)]"
                                style={{ width: `${hunt.progressPercent}%` }}
                              />
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Right 4 Cols (~33%): Security Intelligence & Policy Guards Stack */}
            <div className="lg:col-span-4 space-y-4">
              {/* LEVEL 4: WHAT'S WORTH CHECKING Research Priority Feed */}
              <div className="rounded-xl border border-slate-700/55 bg-[#080b13]/65 p-4 sm:p-5 space-y-3.5">
                <div className="flex items-center justify-between pb-2.5 border-b border-white/10">
                  <h2 className="text-sm sm:text-base font-bold font-outfit uppercase tracking-wider text-slate-100">
                    WHAT'S WORTH CHECKING
                  </h2>
                  <span className="text-[11px] font-mono text-red-400/90 font-semibold">Priority Review</span>
                </div>

                {worthCheckingFindings.length === 0 ? (
                  <EmptyState type="verified-findings" onAction={onStartHuntClick} actionLabel="START A HUNT" />
                ) : (
                  <div className="space-y-2.5">
                    {worthCheckingFindings.map((finding) => (
                      <div
                        key={finding.id}
                        onClick={() => onSelectFinding(finding.id)}
                        className="rounded-xl p-3.5 border border-red-900/45 hover:border-red-500/60 transition-all cursor-pointer group bg-gradient-to-b from-[#150b0f]/90 to-[#0b0e17]/90"
                      >
                        <div className="flex items-center justify-between gap-2 mb-1.5">
                          <SeverityBadge severity={finding.severity} />
                          <span className="text-[10px] font-mono text-emerald-400 font-bold bg-emerald-950/60 border border-emerald-800/40 px-2 py-0.5 rounded">
                            Confidence: {finding.confidence}%
                          </span>
                        </div>

                        <h3 className="text-sm font-bold font-outfit text-slate-100 group-hover:text-red-300 transition-colors mb-1">
                          {finding.title}
                        </h3>

                        <p className="text-xs text-slate-300 font-sans line-clamp-2 leading-relaxed mb-2.5">
                          {finding.whatWeFound}
                        </p>

                        <div className="flex items-center justify-between text-[11px] font-mono pt-2 border-t border-white/5 text-slate-400">
                          <span className="truncate max-w-[160px] text-slate-300">{finding.target}</span>
                          <span className="text-amber-400 font-semibold">{finding.status}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* LEVEL 5: Supporting Policy & Guardrails Panel */}
              <div>
                <PolicyPanel compact statusState="ENFORCED" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
