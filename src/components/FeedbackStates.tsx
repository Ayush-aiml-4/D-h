import React from 'react';
import { ShieldAlert, Crosshair, FileSearch, FileText, History, AlertTriangle, RefreshCw, ArrowRight, Plus } from 'lucide-react';

interface EmptyStateProps {
  type: 'programs' | 'hunts' | 'findings' | 'verified-findings' | 'reports' | 'history';
  onAction?: () => void;
  actionLabel?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ type, onAction, actionLabel }) => {
  const config = {
    programs: {
      title: 'NO PROGRAMS REGISTERED',
      description: 'No authorized bug bounty programs loaded. Add a program scope to configure policy guards and start hunting.',
      icon: ShieldAlert,
      defaultAction: 'ADD PROGRAM',
    },
    hunts: {
      title: 'NO ACTIVE HUNTS',
      description: 'Standing by for researcher initiation command. Select an in-scope program target to begin policy-enforced security analysis.',
      icon: Crosshair,
      defaultAction: 'START A HUNT',
    },
    findings: {
      title: 'NO FINDINGS DETECTED',
      description: 'No security findings recorded for the selected criteria. Run a target hunt to analyze endpoint authorization boundaries.',
      icon: FileSearch,
      defaultAction: 'START A HUNT',
    },
    'verified-findings': {
      title: 'NO VERIFIED FINDINGS',
      description: 'Nothing has been verified yet. Run security check workflows with policy evidence validation.',
      icon: FileSearch,
      defaultAction: 'START A HUNT',
    },
    reports: {
      title: 'NO REPORTS GENERATED',
      description: 'No responsible disclosure reports generated yet. Reports are automatically created when findings are verified.',
      icon: FileText,
      defaultAction: 'VIEW FINDINGS',
    },
    history: {
      title: 'NO HUNT HISTORY',
      description: 'Completed research sessions, evidence logs, and bounty milestones will be archived here.',
      icon: History,
      defaultAction: 'START A HUNT',
    },
  };

  const current = config[type];
  const Icon = current.icon;

  return (
    <div className="glass-panel rounded-2xl p-12 text-center border border-white/10 max-w-lg mx-auto my-8 space-y-4">
      <div className="w-14 h-14 rounded-2xl bg-red-950/60 border border-red-700/40 flex items-center justify-center text-red-400 mx-auto shadow-[0_0_20px_rgba(220,38,38,0.2)]">
        <Icon className="w-7 h-7" />
      </div>

      <div className="space-y-1">
        <h3 className="text-lg font-extrabold font-outfit uppercase tracking-wider text-slate-100">
          {current.title}
        </h3>
        <p className="text-xs text-slate-400 font-sans leading-relaxed max-w-sm mx-auto">
          {current.description}
        </p>
      </div>

      {onAction && (
        <div className="pt-2">
          <button
            onClick={onAction}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 font-outfit text-xs font-bold uppercase tracking-wider shadow-[0_0_15px_rgba(220,38,38,0.3)] transition-all cursor-pointer"
          >
            <span>{actionLabel || current.defaultAction}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      )}
    </div>
  );
};

export const SkeletonLoader: React.FC<{ rows?: number }> = ({ rows = 3 }) => {
  return (
    <div className="space-y-4">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="glass-panel rounded-xl p-6 border border-white/5 space-y-3 animate-fade-in"
          style={{ animationDelay: `${i * 0.08}s` }}
        >
          <div className="flex justify-between items-center">
            <div className="h-4 skeleton-shimmer w-1/3" />
            <div className="h-4 skeleton-shimmer w-16" />
          </div>
          <div className="h-3 skeleton-shimmer w-2/3" />
          <div className="h-8 skeleton-shimmer w-full" />
        </div>
      ))}
    </div>
  );
};

interface ErrorStateProps {
  title?: string;
  whatHappened: string;
  whatToDo: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'RESEARCH MODULE WARNING',
  whatHappened,
  whatToDo,
  onRetry,
}) => {
  return (
    <div className="glass-panel-accent rounded-2xl p-8 border border-red-700/50 bg-gradient-to-r from-[#1b080c] via-[#0d0d18] to-[#08090e] max-w-xl mx-auto my-8 space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-red-950 border border-red-600/60 flex items-center justify-center text-red-400">
          <AlertTriangle className="w-5 h-5" />
        </div>
        <div>
          <span className="text-[10px] font-mono uppercase text-red-400 font-bold tracking-wider block">
            POLICY & ENGINE AUDIT
          </span>
          <h3 className="text-lg font-bold font-outfit uppercase tracking-wider text-slate-100">
            {title}
          </h3>
        </div>
      </div>

      <div className="space-y-4 font-sans text-xs">
        <div className="p-4 rounded-xl bg-slate-950/90 border border-white/10 space-y-1">
          <span className="text-slate-400 font-mono text-[10px] uppercase font-bold text-red-300 block">
            WHAT HAPPENED
          </span>
          <p className="text-slate-200 leading-relaxed">{whatHappened}</p>
        </div>

        <div className="p-4 rounded-xl bg-slate-950/90 border border-white/10 space-y-1">
          <span className="text-slate-400 font-mono text-[10px] uppercase font-bold text-emerald-300 block">
            WHAT TO DO
          </span>
          <p className="text-slate-200 leading-relaxed">{whatToDo}</p>
        </div>
      </div>

      {onRetry && (
        <div className="pt-2 flex justify-end">
          <button
            onClick={onRetry}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 border border-white/15 hover:border-white/30 text-slate-200 font-outfit text-xs font-bold uppercase tracking-wider transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>RETRY ACTION</span>
          </button>
        </div>
      )}
    </div>
  );
};
