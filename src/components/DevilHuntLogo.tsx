import React from 'react';

interface DevilHuntLogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showText?: boolean;
  showTagline?: boolean;
  className?: string;
}

export const DevilHuntLogo: React.FC<DevilHuntLogoProps> = ({
  size = 'md',
  showText = true,
  showTagline = false,
  className = '',
}) => {
  const sizeMap = {
    sm: { container: 'w-7 h-7', icon: 'w-4 h-4', title: 'text-sm', tagline: 'text-[9px]' },
    md: { container: 'w-9 h-9', icon: 'w-5 h-5', title: 'text-base', tagline: 'text-[10px]' },
    lg: { container: 'w-11 h-11', icon: 'w-6 h-6', title: 'text-xl', tagline: 'text-xs' },
    xl: { container: 'w-14 h-14', icon: 'w-8 h-8', title: 'text-2xl', tagline: 'text-xs' },
  };

  const currentSize = sizeMap[size];

  return (
    <div className={`flex items-center gap-3 ${className}`}>
      {/* Refined Geometric Devil & Crosshair Emblem */}
      <div
        className={`relative ${currentSize.container} rounded-lg bg-gradient-to-br from-red-600 via-red-900 to-[#120406] border border-red-500/50 flex items-center justify-center shrink-0 shadow-[0_0_18px_rgba(220,38,38,0.35)] overflow-hidden group`}
      >
        {/* Subtle background glow */}
        <div className="absolute inset-0 bg-gradient-to-t from-red-600/30 to-transparent opacity-60" />

        <svg
          viewBox="0 0 32 32"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className={`${currentSize.icon} text-slate-100 relative z-10 transform transition-transform group-hover:scale-105`}
        >
          {/* Subtle sharp horn silhouettes at top corners */}
          <path
            d="M 6 10 L 9 3 L 13 8 L 6 10 Z"
            fill="currentColor"
            className="text-red-500 opacity-90"
          />
          <path
            d="M 26 10 L 23 3 L 19 8 L 26 10 Z"
            fill="currentColor"
            className="text-red-500 opacity-90"
          />

          {/* Precision Hunt Crosshair Outer Shield Ring */}
          <circle
            cx="16"
            cy="17"
            r="10"
            stroke="currentColor"
            strokeWidth="1.8"
            className="text-slate-100"
          />

          {/* Crosshair ticks */}
          <line x1="16" y1="4" x2="16" y2="9" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" className="text-red-400" />
          <line x1="16" y1="25" x2="16" y2="30" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" className="text-red-400" />
          <line x1="3" y1="17" x2="8" y2="17" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" className="text-red-400" />
          <line x1="24" y1="17" x2="29" y2="17" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" className="text-red-400" />

          {/* Central Precision Target Core */}
          <circle cx="16" cy="17" r="3.5" fill="currentColor" className="text-red-500" />
          <circle cx="16" cy="17" r="1.5" fill="#FFFFFF" />
        </svg>

        {/* Live active dot */}
        <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse border border-[#0c0e17]" />
      </div>

      {showText && (
        <div className="flex flex-col">
          <span className={`font-outfit font-black tracking-wider ${currentSize.title} text-slate-100 uppercase leading-none`}>
            DEVIL<span className="text-red-500">HUNT</span>
          </span>
          <span className={`${currentSize.tagline} text-slate-400 font-sans tracking-tight mt-1 truncate font-medium`}>
            {showTagline ? 'Hunt the Flaw. Claim the Bounty.' : 'Hunt the Flaw.'}
          </span>
        </div>
      )}
    </div>
  );
};
