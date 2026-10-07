import React from 'react';
import { SeverityLevel } from '../types';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
  showDot?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  className = '',
  showDot = true,
}) => {
  const getStyles = (sev: SeverityLevel) => {
    switch (sev) {
      case 'Critical':
        return {
          bg: 'bg-red-950/60 text-red-400 border-red-800/50',
          dot: 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]',
          label: 'CRITICAL',
        };
      case 'High':
        return {
          bg: 'bg-orange-950/60 text-orange-400 border-orange-800/50',
          dot: 'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.8)]',
          label: 'HIGH',
        };
      case 'Medium':
        return {
          bg: 'bg-amber-950/60 text-amber-400 border-amber-800/50',
          dot: 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.8)]',
          label: 'MEDIUM',
        };
      case 'Low':
        return {
          bg: 'bg-blue-950/60 text-blue-400 border-blue-800/50',
          dot: 'bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.8)]',
          label: 'LOW',
        };
      default:
        return {
          bg: 'bg-slate-900 text-slate-300 border-slate-700/50',
          dot: 'bg-slate-400',
          label: severity,
        };
    }
  };

  const style = getStyles(severity);

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-semibold uppercase tracking-wider border ${style.bg} ${className}`}
    >
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />}
      {style.label}
    </span>
  );
};
