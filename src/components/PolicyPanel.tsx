import React from 'react';
import { ShieldCheck, Check, X, Lock, AlertTriangle, HelpCircle, ShieldAlert } from 'lucide-react';

export type PolicyStatusState = 'LOADED' | 'ENFORCED' | 'WARNING' | 'BLOCKED' | 'UNKNOWN';

interface PolicyPanelProps {
  rulesAllowed?: string[];
  rulesBlocked?: string[];
  statusState?: PolicyStatusState;
  compact?: boolean;
}

export const PolicyPanel: React.FC<PolicyPanelProps> = ({
  rulesAllowed = [
    'Web application security testing',
    'API endpoint testing & authorization verification',
    'Authentication state and JWT validation',
    'Row-level access control & IDOR verification',
  ],
  rulesBlocked = [
    'Denial of Service (DoS / DDoS) testing',
    'Social engineering or phishing against staff',
    'Physical office security or facility testing',
    'Third-party cloud infrastructure modifications',
  ],
  statusState = 'ENFORCED',
  compact = false,
}) => {
  const getBadgeStyle = (state: string) => {
    switch (state) {
      case 'ENFORCED':
        return {
          bg: 'bg-emerald-950/80 border-emerald-700/60 text-emerald-400',
          icon: Lock,
          label: 'POLICY ENFORCED',
        };
      case 'LOADED':
        return {
          bg: 'bg-blue-950/80 border-blue-700/60 text-blue-400',
          icon: ShieldCheck,
          label: 'POLICY LOADED',
        };
      case 'WARNING':
        return {
          bg: 'bg-amber-950/80 border-amber-700/60 text-amber-400',
          icon: AlertTriangle,
          label: 'POLICY WARNING',
        };
      case 'BLOCKED':
        return {
          bg: 'bg-red-950/90 border-red-700/80 text-red-400 shadow-[0_0_10px_rgba(220,38,38,0.3)]',
          icon: ShieldAlert,
          label: 'POLICY BLOCKED',
        };
      case 'UNKNOWN':
      default:
        return {
          bg: 'bg-yellow-950/90 border-yellow-600/80 text-yellow-300 shadow-[0_0_12px_rgba(234,179,8,0.3)]',
          icon: HelpCircle,
          label: 'POLICY UNKNOWN — DO NOT PROCEED',
        };
    }
  };

  const badgeStyle = getBadgeStyle(statusState);
  const BadgeIcon = badgeStyle.icon;

  return (
    <div
      className={`glass-panel ${
        compact
          ? 'rounded-xl p-4 border border-slate-700/60 bg-[#080b13]/75'
          : 'rounded-2xl p-5 border border-red-900/30 bg-gradient-to-b from-[#12141d] to-[#0d0e14]'
      } relative overflow-hidden`}
    >
      {/* Top accent glow */}
      <div className="absolute -top-12 -right-12 w-32 h-32 bg-red-600/10 rounded-full blur-2xl pointer-events-none" />

      <div className={`flex flex-col sm:flex-row sm:items-center justify-between ${compact ? 'pb-3 mb-3' : 'pb-4 mb-4'} border-b border-white/10 gap-2.5`}>
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-red-950/80 border border-red-700/50 flex items-center justify-center text-red-400 shrink-0">
            <ShieldCheck className="w-3.5 h-3.5" />
          </div>
          <div>
            <h3 className="text-xs sm:text-sm font-bold font-outfit uppercase tracking-wider text-slate-100">
              Program Rules & Policy Guards
            </h3>
            <p className="text-[11px] text-slate-400 font-sans">Policy-aware research boundary enforcer</p>
          </div>
        </div>

        <div className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-[10px] font-mono font-bold tracking-wider shrink-0 ${badgeStyle.bg}`}>
          <BadgeIcon className="w-3 h-3" />
          <span>{badgeStyle.label}</span>
        </div>
      </div>

      {statusState === 'UNKNOWN' ? (
        <div className="p-4 rounded-xl bg-yellow-950/40 border border-yellow-700/60 text-xs font-sans text-yellow-200 space-y-2 mb-4">
          <div className="flex items-center gap-2 font-bold uppercase font-mono text-yellow-300">
            <HelpCircle className="w-4 h-4 text-yellow-400" />
            <span>Policy Status Unconfirmed</span>
          </div>
          <p>
            Scope boundaries or allowed research vectors are not fully established for this target. Automatic guardrails are halting further testing until clear program rules are confirmed.
          </p>
        </div>
      ) : (
        <div className={`grid ${compact ? 'grid-cols-1 gap-3 mb-3' : 'grid-cols-1 md:grid-cols-2 gap-4 mb-4'}`}>
          {/* Allowed Section */}
          <div className="bg-emerald-950/25 rounded-lg p-3 border border-emerald-900/35">
            <div className="flex items-center gap-1.5 text-[11px] font-mono font-semibold text-emerald-400 uppercase tracking-wider mb-2">
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span>Allowed Research Vectors ({rulesAllowed.length})</span>
            </div>
            <ul className="space-y-1.5">
              {rulesAllowed.map((rule, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                  <span className="text-emerald-400 font-bold shrink-0 mt-0.5">✓</span>
                  <span className="leading-snug">{rule}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Blocked Section */}
          <div className="bg-red-950/25 rounded-lg p-3 border border-red-900/35">
            <div className="flex items-center gap-1.5 text-[11px] font-mono font-semibold text-red-400 uppercase tracking-wider mb-2">
              <X className="w-3.5 h-3.5 text-red-400" />
              <span>Restricted Actions ({rulesBlocked.length})</span>
            </div>
            <ul className="space-y-1.5">
              {rulesBlocked.map((rule, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                  <span className="text-red-400 font-bold shrink-0 mt-0.5">✕</span>
                  <span className="leading-snug">{rule}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <div className="pt-2.5 border-t border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-[11px] text-slate-400">
        <p className="italic">
          Everything permitted by the program can be tested. Restricted actions automatically stay blocked.
        </p>
        <span className="font-mono text-[10px] text-slate-500 uppercase shrink-0">Engine: Policy-Guard v2</span>
      </div>
    </div>
  );
};
