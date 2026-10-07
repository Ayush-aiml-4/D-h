import React, { useState, useEffect } from 'react';
import { Hunt, Finding } from '../types';
import { Radio, ShieldCheck, CheckCircle2, AlertTriangle, Terminal, Pause, Play, ArrowLeft, Bug, Square } from 'lucide-react';
import { SeverityBadge } from '../components/SeverityBadge';
import { ConfirmationModal } from '../components/ConfirmationModal';

interface ActiveHuntViewProps {
  hunt: Hunt;
  findings?: Finding[];
  onBack: () => void;
  onViewFindings: () => void;
  onSelectFinding?: (findingId: string) => void;
  onStopHunt?: (huntId: string) => void;
}

export const ActiveHuntView: React.FC<ActiveHuntViewProps> = ({
  hunt,
  findings = [],
  onBack,
  onViewFindings,
  onSelectFinding,
  onStopHunt,
}) => {
  const [isPaused, setIsPaused] = useState(false);
  const [showStopConfirm, setShowStopConfirm] = useState(false);
  const [logs, setLogs] = useState<string[]>(hunt.liveLogs);
  const [progress, setProgress] = useState(hunt.progressPercent);

  // Filter findings belonging specifically to this Hunt
  const huntFindings = findings.filter((f) => f.huntId === hunt.id);

  // Simulated live activity stream updates
  useEffect(() => {
    if (isPaused) return;

    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 98) return 98;
        return prev + 1;
      });

      const dynamicLogMessages = [
        `Testing X-Tenant-Override headers on ${hunt.targetDomain}/v2/transact...`,
        `Fuzzing authorization state boundaries (policy check: PASS)`,
        `Inspecting GraphQL query reflection rate limits...`,
        `Analyzing API response headers for security misconfigurations...`,
        `Evidence capture verified with SHA256 proof hash`,
      ];

      const randomLog = dynamicLogMessages[Math.floor(Math.random() * dynamicLogMessages.length)];
      setLogs((prev) => [randomLog, ...prev.slice(0, 12)]);
    }, 3500);

    return () => clearInterval(interval);
  }, [isPaused, hunt.targetDomain]);

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Back button */}
      <button
        onClick={onBack}
        className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-slate-100 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" /> Back to Hunts
      </button>

      {/* Hero Header */}
      <div className="glass-panel-accent rounded-2xl p-8 border border-red-700/50 bg-gradient-to-r from-[#1b080c] via-[#0d0d18] to-[#08090e] relative overflow-hidden shadow-[0_0_40px_rgba(220,38,38,0.2)]">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="px-3 py-1 rounded-full bg-red-950/80 border border-red-700/60 text-red-400 text-xs font-mono font-bold uppercase flex items-center gap-1.5 shadow-[0_0_10px_rgba(220,38,38,0.4)]">
                <Radio className="w-3.5 h-3.5 text-red-500 animate-pulse" />
                {isPaused ? 'HUNT PAUSED' : 'HUNT IN PROGRESS'}
              </span>
              <span className="text-xs font-mono text-slate-400">• {hunt.programName}</span>
            </div>

            <h1 className="text-3xl sm:text-4xl font-extrabold font-mono text-slate-100 tracking-tight">
              {hunt.targetDomain}
            </h1>

            <p className="text-slate-300 text-xs font-mono">
              Current Task: <span className="text-red-300 font-semibold">{hunt.currentTask}</span>
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => setIsPaused(!isPaused)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900 border border-white/10 hover:border-white/20 text-slate-200 text-xs font-mono uppercase font-semibold transition-colors cursor-pointer"
            >
              {isPaused ? <Play className="w-4 h-4 text-emerald-400" /> : <Pause className="w-4 h-4 text-amber-400" />}
              <span>{isPaused ? 'Resume' : 'Pause'}</span>
            </button>

            <button
              onClick={() => setShowStopConfirm(true)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-red-950/80 border border-red-700/60 hover:bg-red-900 text-red-200 text-xs font-mono uppercase font-semibold transition-colors cursor-pointer"
            >
              <Square className="w-3.5 h-3.5 text-red-400" />
              <span>STOP HUNT</span>
            </button>

            <button
              onClick={onViewFindings}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 text-xs font-bold font-outfit uppercase tracking-wider shadow-[0_0_20px_rgba(220,38,38,0.3)] transition-all cursor-pointer"
            >
              <span>VIEW ALL FINDINGS</span>
            </button>
          </div>
        </div>

        {/* Stop Hunt Confirmation Modal */}
        <ConfirmationModal
          isOpen={showStopConfirm}
          title="STOP HUNT SESSION?"
          message={`Are you sure you want to stop active security testing on ${hunt.targetDomain}? Active scanning will terminate immediately and log state.`}
          confirmLabel="STOP HUNT"
          cancelLabel="KEEP HUNTING"
          isDanger={true}
          onClose={() => setShowStopConfirm(false)}
          onConfirm={() => {
            if (onStopHunt) onStopHunt(hunt.id);
          }}
        />

        {/* Global Progress Bar */}
        <div className="mt-8 pt-6 border-t border-white/10 space-y-2">
          <div className="flex justify-between items-center text-xs font-mono">
            <span className="text-slate-400 uppercase">Overall Security Analysis Progress</span>
            <span className="text-red-400 font-bold text-sm">{progress}%</span>
          </div>
          <div className="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-white/10 p-0.5">
            <div
              className="bg-gradient-to-r from-red-600 via-red-500 to-amber-400 h-full rounded-full transition-all duration-500 shadow-[0_0_15px_rgba(220,38,38,0.9)]"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-panel rounded-xl p-5 border border-white/10 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono uppercase text-slate-400 block mb-1">Potential Findings</span>
            <span className="text-3xl font-extrabold font-mono text-amber-400">{hunt.potentialFindingsCount}</span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-amber-950/50 border border-amber-800/40 flex items-center justify-center text-amber-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>

        <div className="glass-panel rounded-xl p-5 border border-white/10 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono uppercase text-slate-400 block mb-1">Verified Findings</span>
            <span className="text-3xl font-extrabold font-mono text-emerald-400">{hunt.verifiedFindingsCount}</span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-emerald-950/50 border border-emerald-800/40 flex items-center justify-center text-emerald-400">
            <CheckCircle2 className="w-5 h-5" />
          </div>
        </div>

        <div className="glass-panel rounded-xl p-5 border border-emerald-900/40 bg-emerald-950/20 flex items-center justify-between">
          <div>
            <span className="text-xs font-mono uppercase text-slate-400 block mb-1">Policy Violations</span>
            <span className="text-3xl font-extrabold font-mono text-emerald-400">0</span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-emerald-950/80 border border-emerald-700/50 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Session Findings Section */}
      {huntFindings.length > 0 && (
        <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-white/10">
            <div className="flex items-center gap-2">
              <Bug className="w-4 h-4 text-red-400" />
              <h3 className="text-sm font-bold font-outfit uppercase tracking-wider text-slate-100">
                Discovered Findings in This Session ({huntFindings.length})
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-400">Linked to Hunt #{hunt.id}</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {huntFindings.map((f) => (
              <div
                key={f.id}
                onClick={() => onSelectFinding && onSelectFinding(f.id)}
                className="p-4 rounded-xl bg-slate-900/80 border border-white/10 hover:border-red-500/40 transition-all cursor-pointer flex flex-col justify-between gap-3 group"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-2 py-0.5 rounded">
                      Confidence: {f.confidence}%
                    </span>
                  </div>
                  <h4 className="text-sm font-bold font-outfit text-slate-100 group-hover:text-red-300 transition-colors">
                    {f.title}
                  </h4>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    {f.affectedTarget}
                  </p>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-white/5 text-xs font-mono">
                  <span className="text-slate-500 uppercase">{f.status}</span>
                  <span className="text-red-400 font-bold group-hover:translate-x-1 transition-transform inline-flex items-center gap-1">
                    INSPECT FINDING &rarr;
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Step Breakdown Progress Visualization & Live Activity Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Col: Step Breakdown */}
        <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
          <h3 className="text-sm font-bold font-outfit uppercase tracking-wider text-slate-100 pb-3 border-b border-white/10">
            Workflow Steps
          </h3>

          <div className="space-y-3 font-mono text-xs">
            {hunt.steps.map((step, idx) => {
              const isDone = step.status === 'done';
              const isActive = step.status === 'active';

              return (
                <div
                  key={step.id}
                  className={`p-3 rounded-xl border flex items-center justify-between transition-all ${
                    isDone
                      ? 'bg-emerald-950/20 border-emerald-900/40 text-emerald-300'
                      : isActive
                      ? 'bg-red-950/30 border-red-700/50 text-slate-100 shadow-[0_0_12px_rgba(220,38,38,0.15)]'
                      : 'bg-slate-900/40 border-white/5 text-slate-500'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className="font-bold text-[10px]">0{idx + 1}</span>
                    <span className="font-semibold">{step.name}</span>
                  </div>

                  <div>
                    {isDone && <span className="text-emerald-400 font-bold">✓</span>}
                    {isActive && <span className="text-red-400 font-bold animate-pulse">{step.progress || 72}%</span>}
                    {step.status === 'pending' && <span className="text-slate-600">Pending</span>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right 2 Cols: Live Activity Stream */}
        <div className="lg:col-span-2 glass-panel rounded-2xl p-6 border border-white/10 flex flex-col justify-between bg-[#08090f]">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-red-400" />
                <h3 className="text-sm font-bold font-outfit uppercase tracking-wider text-slate-100">
                  Live Security Activity Stream
                </h3>
              </div>
              <span className="text-[10px] font-mono text-slate-500">Real-time Policy Logger</span>
            </div>

            <div className="font-mono text-xs space-y-2.5 max-h-80 overflow-y-auto pr-2">
              {logs.map((log, i) => (
                <div
                  key={i}
                  className="p-2.5 rounded-lg bg-slate-950 border border-white/5 text-slate-300 flex items-start gap-2.5 leading-relaxed"
                >
                  <span className="text-red-500 font-bold shrink-0">&gt;</span>
                  <span className="flex-1 font-mono text-[11px]">{log}</span>
                  <span className="text-[9px] text-slate-600 shrink-0">NOW</span>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-4 border-t border-white/10 mt-4 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Policy Enforcer: ACTIVE</span>
            <span className="text-emerald-400 font-bold">0 Restricted Actions Attempted</span>
          </div>
        </div>
      </div>
    </div>
  );
};

