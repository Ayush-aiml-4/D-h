import React from 'react';
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

  const hour = new Date().getHours();
  const greeting =
    hour < 5 ? 'GOOD NIGHT' :
    hour < 12 ? 'GOOD MORNING' :
    hour < 17 ? 'GOOD AFTERNOON' :
    hour < 21 ? 'GOOD EVENING' : 'GOOD NIGHT';

  return (
    <div className="space-y-8 animate-fade-in pb-12 max-w-7xl mx-auto w-full">
      {/* Hero Section */}
      <div className="glass-panel-accent rounded-2xl p-8 border border-red-700/40 bg-gradient-to-r from-[#18090c] via-[#0d0a14] to-[#090a0f] relative overflow-hidden shadow-[0_0_40px_rgba(220,38,38,0.15)]">
        {/* Glow backdrop */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-red-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-64 h-64 bg-red-900/5 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-950/80 border border-red-700/50 text-red-400 text-xs font-mono uppercase tracking-wider">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping" />
              <span>PRIVATE RESEARCH COMMAND CENTER</span>
            </div>

            <h1 className="text-3xl sm:text-4xl font-extrabold font-outfit uppercase tracking-wider text-slate-100">
              {greeting}, {profile.name}
            </h1>

            <p className="text-slate-300 text-base font-sans font-medium">
              Ready to hunt? Authorized targets are loaded and policy guards are active.
            </p>
          </div>

          <button
            onClick={onStartHuntClick}
            className="self-start md:self-auto flex items-center gap-3 px-6 py-3.5 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 font-outfit font-bold uppercase tracking-wider text-sm shadow-[0_0_25px_rgba(220,38,38,0.4)] transition-all transform hover:-translate-y-0.5 active:scale-95 cursor-pointer shrink-0"
          >
            <Crosshair className="w-5 h-5 animate-pulse" />
            <span>START A HUNT</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Primary Statistics Grid - Derived directly from underlying relational data */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Active Hunts */}
        <div className="glass-panel rounded-xl p-5 border border-white/10 hover:border-white/20 transition-all">
          <div className="flex items-center justify-between text-xs font-mono uppercase text-slate-400 mb-2">
            <span>ACTIVE HUNTS</span>
            <Flame className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-3xl font-extrabold font-mono text-slate-100 tracking-tight">
            {activeCount < 10 ? `0${activeCount}` : activeCount}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">In progress right now</p>
        </div>

        {/* Verified Bugs */}
        <div className="glass-panel rounded-xl p-5 border border-white/10 hover:border-white/20 transition-all">
          <div className="flex items-center justify-between text-xs font-mono uppercase text-slate-400 mb-2">
            <span>VERIFIED BUGS</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-extrabold font-mono text-emerald-400 tracking-tight">
            {verifiedBugsCount < 10 ? `0${verifiedBugsCount}` : verifiedBugsCount}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Confirmed with evidence</p>
        </div>

        {/* Requirement 1: OPEN REPORTS (Ready + Submitted) */}
        <div className="glass-panel rounded-xl p-5 border border-white/10 hover:border-white/20 transition-all">
          <div className="flex items-center justify-between text-xs font-mono uppercase text-slate-400 mb-2">
            <span>OPEN REPORTS</span>
            <Shield className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-extrabold font-mono text-slate-100 tracking-tight">
            {openReportsCount < 10 ? `0${openReportsCount}` : openReportsCount}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Active in disclosure workflow</p>
        </div>

        {/* Paid / Pending Bounty Metrics */}
        <div className="glass-panel rounded-xl p-5 border border-red-900/40 bg-gradient-to-br from-red-950/30 to-slate-950 hover:border-red-600/50 transition-all relative overflow-hidden">
          <div className="flex items-center justify-between text-xs font-mono uppercase text-slate-400 mb-1">
            <span className="flex items-center gap-1.5">
              <span>PAID BOUNTY</span>
              {profile.isDemoMode && (
                <span className="text-[9px] bg-red-950 border border-red-700/50 text-red-300 px-1.5 py-0.2 rounded font-mono">
                  DEMO
                </span>
              )}
            </span>
            <Award className="w-4 h-4 text-red-400" />
          </div>

          <div className="text-2xl font-black font-mono text-red-400 tracking-tight">
            {bountyData.paidFormatted}
          </div>

          {/* Pending and Potential Breakdown */}
          <div className="mt-2 pt-2 border-t border-white/10 grid grid-cols-2 text-[10px] font-mono">
            <div>
              <span className="text-slate-500 block">PENDING</span>
              <span className="text-amber-300 font-bold">{bountyData.pendingFormatted}</span>
            </div>
            <div>
              <span className="text-slate-500 block">POTENTIAL</span>
              <span className="text-slate-300 font-bold">{bountyData.potentialFormatted}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Grid: Your Hunts & What's Worth Checking */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: Your Hunts Section */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold font-outfit uppercase tracking-wider text-slate-100">
                Your Hunts
              </h2>
              <span className="text-xs font-mono text-slate-400">({hunts.length} Sessions)</span>
            </div>
            <button
              onClick={() => onNavigateTab('hunts')}
              className="text-xs font-mono text-red-400 hover:text-red-300 transition-colors flex items-center gap-1"
            >
              View all <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {hunts.length === 0 ? (
            <EmptyState type="hunts" onAction={onStartHuntClick} actionLabel="START A HUNT" />
          ) : (
            <div className="space-y-3">
              {hunts.map((hunt) => {
                const getStatusStyle = (st: string) => {
                  switch (st) {
                    case 'Hunting':
                    case 'Running':
                      return 'bg-red-950/80 text-red-400 border-red-800/60 shadow-[0_0_10px_rgba(220,38,38,0.3)]';
                    case 'Analyzing':
                      return 'bg-amber-950/80 text-amber-400 border-amber-800/60';
                    case 'Ready':
                      return 'bg-emerald-950/80 text-emerald-400 border-emerald-800/60';
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
                    className="glass-panel rounded-xl p-4 border border-white/10 hover:border-red-500/40 transition-all cursor-pointer group hover:bg-slate-900/90"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono uppercase text-slate-400 font-semibold">
                            {hunt.programName}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getStatusStyle(hunt.status)}`}>
                            {hunt.status}
                          </span>
                        </div>
                        <h3 className="text-base font-bold font-mono text-slate-100 group-hover:text-red-300 transition-colors">
                          {hunt.targetDomain}
                        </h3>
                        <p className="text-xs text-slate-400 font-sans">
                          Scope: {hunt.scopeCount} targets • Started {hunt.startedAt}
                        </p>
                      </div>

                      <div className="flex items-center gap-3">
                        <div className="text-right text-xs font-mono hidden sm:block">
                          <span className="text-emerald-400 font-bold">{huntVer} Verified</span>
                          {huntPot > 0 && <span className="text-amber-400 block">{huntPot} Review</span>}
                        </div>
                        <button className="p-2 rounded-lg bg-slate-900 border border-white/10 group-hover:border-red-500/50 group-hover:text-red-400 text-slate-400 transition-colors">
                          <ExternalLink className="w-4 h-4" />
                        </button>
                      </div>
                    </div>

                    {/* Progress Bar if Hunting/Analyzing */}
                    {(hunt.status === 'Hunting' || hunt.status === 'Analyzing' || hunt.status === 'Running') && (
                      <div className="mt-4 pt-3 border-t border-white/5 space-y-1.5">
                        <div className="flex justify-between text-xs font-mono text-slate-400">
                          <span className="truncate max-w-[280px]">{hunt.currentTask}</span>
                          <span className="text-red-400 font-bold">{hunt.progressPercent}%</span>
                        </div>
                        <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden border border-white/5">
                          <div
                            className="bg-gradient-to-r from-red-600 to-red-400 h-full rounded-full transition-all duration-500 shadow-[0_0_10px_rgba(220,38,38,0.8)]"
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

        {/* Right 1 Col: WHAT'S WORTH CHECKING Research Priority Feed */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold font-outfit uppercase tracking-wider text-slate-100">
              WHAT'S WORTH CHECKING
            </h2>
            <span className="text-xs font-mono text-slate-400">Priority Review</span>
          </div>

          {worthCheckingFindings.length === 0 ? (
            <EmptyState type="verified-findings" onAction={onStartHuntClick} actionLabel="START A HUNT" />
          ) : (
            <div className="space-y-3">
              {worthCheckingFindings.map((finding) => (
                <div
                  key={finding.id}
                  onClick={() => onSelectFinding(finding.id)}
                  className="glass-panel-accent rounded-xl p-4 border border-red-800/40 hover:border-red-500 transition-all cursor-pointer group bg-gradient-to-b from-[#140b0e] to-[#0c0e17]"
                >
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <SeverityBadge severity={finding.severity} />
                    <span className="text-[11px] font-mono text-emerald-400 font-bold bg-emerald-950/60 border border-emerald-800/40 px-2 py-0.5 rounded">
                      Confidence: {finding.confidence}%
                    </span>
                  </div>

                  <h3 className="text-sm font-bold font-outfit text-slate-100 group-hover:text-red-300 transition-colors mb-1">
                    {finding.title}
                  </h3>

                  <p className="text-xs text-slate-300 font-sans line-clamp-2 leading-relaxed mb-3">
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

          {/* Quick Policy summary */}
          <div className="pt-2">
            <PolicyPanel compact statusState="ENFORCED" />
          </div>
        </div>
      </div>
    </div>
  );
};
