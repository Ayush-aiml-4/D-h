import React, { useState, useEffect, useRef } from 'react';
import { ShieldCheck, Plus, Search, Radio, X } from 'lucide-react';
import { NavTab } from './Sidebar';
import { Program, Hunt, Finding, Report, HistorySession } from '../types';

interface TopBarProps {
  onStartHuntClick: () => void;
  onNavigate: (tab: NavTab | 'program-detail' | 'active-hunt' | 'finding-detail' | 'report-detail') => void;
  activeHuntCount: number;
  programs?: Program[];
  hunts?: Hunt[];
  findings?: Finding[];
  reports?: Report[];
  history?: HistorySession[];
  onSelectProgram?: (id: string) => void;
  onSelectHunt?: (id: string) => void;
  onSelectFinding?: (id: string) => void;
  onSelectReport?: (id: string) => void;
}

interface SearchResultItem {
  id: string;
  type: 'PROGRAM' | 'HUNT' | 'FINDING' | 'REPORT' | 'HISTORY';
  title: string;
  subtitle: string;
  action: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  onStartHuntClick,
  onNavigate,
  activeHuntCount,
  programs = [],
  hunts = [],
  findings = [],
  reports = [],
  history = [],
  onSelectProgram,
  onSelectHunt,
  onSelectFinding,
  onSelectReport,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearchFocused, setIsSearchFocused] = useState(false);
  const searchRef = useRef<HTMLDivElement>(null);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setIsSearchFocused(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Compute search results
  const getSearchResults = (): SearchResultItem[] => {
    if (!searchQuery.trim()) return [];
    const query = searchQuery.toLowerCase();
    const results: SearchResultItem[] = [];

    // Search Programs
    programs.forEach((p) => {
      if (
        p.name.toLowerCase().includes(query) ||
        p.organization.toLowerCase().includes(query) ||
        p.targets.some((t) => t.toLowerCase().includes(query))
      ) {
        results.push({
          id: p.id,
          type: 'PROGRAM',
          title: p.name,
          subtitle: `${p.organization} • ${p.targetCount} targets`,
          action: () => {
            if (onSelectProgram) onSelectProgram(p.id);
            onNavigate('program-detail');
          },
        });
      }
    });

    // Search Hunts
    hunts.forEach((h) => {
      if (
        h.targetDomain.toLowerCase().includes(query) ||
        h.programName.toLowerCase().includes(query)
      ) {
        results.push({
          id: h.id,
          type: 'HUNT',
          title: h.targetDomain,
          subtitle: `${h.programName} • Status: ${h.status}`,
          action: () => {
            if (onSelectHunt) onSelectHunt(h.id);
            onNavigate('active-hunt');
          },
        });
      }
    });

    // Search Findings
    findings.forEach((f) => {
      if (
        f.title.toLowerCase().includes(query) ||
        f.target.toLowerCase().includes(query) ||
        f.category.toLowerCase().includes(query)
      ) {
        results.push({
          id: f.id,
          type: 'FINDING',
          title: f.title,
          subtitle: `Target: ${f.affectedTarget} • ${f.severity} Severity`,
          action: () => {
            if (onSelectFinding) onSelectFinding(f.id);
            onNavigate('finding-detail');
          },
        });
      }
    });

    // Search Reports
    reports.forEach((r) => {
      if (
        r.title.toLowerCase().includes(query) ||
        r.target.toLowerCase().includes(query) ||
        r.programName.toLowerCase().includes(query)
      ) {
        results.push({
          id: r.id,
          type: 'REPORT',
          title: r.title,
          subtitle: `${r.programName} • Status: ${r.status}`,
          action: () => {
            if (onSelectReport) onSelectReport(r.id);
            onNavigate('report-detail');
          },
        });
      }
    });

    // Search History
    history.forEach((hist) => {
      if (
        hist.programName.toLowerCase().includes(query) ||
        hist.target.toLowerCase().includes(query)
      ) {
        results.push({
          id: hist.id,
          type: 'HISTORY',
          title: hist.target,
          subtitle: `${hist.programName} • ${hist.date} • Bounty: ${hist.bountyEarned}`,
          action: () => {
            onNavigate('history');
          },
        });
      }
    });

    return results.slice(0, 8); // Max 8 results
  };

  const searchResults = getSearchResults();

  const handleResultClick = (item: SearchResultItem) => {
    item.action();
    setSearchQuery('');
    setIsSearchFocused(false);
  };

  const getTypeBadgeStyle = (type: SearchResultItem['type']) => {
    switch (type) {
      case 'PROGRAM':
        return 'bg-blue-950/80 text-blue-400 border-blue-800/60';
      case 'HUNT':
        return 'bg-red-950/80 text-red-400 border-red-800/60';
      case 'FINDING':
        return 'bg-amber-950/80 text-amber-400 border-amber-800/60';
      case 'REPORT':
        return 'bg-purple-950/80 text-purple-400 border-purple-800/60';
      case 'HISTORY':
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <header className="h-16 border-b border-white/10 bg-[#0c0e17]/90 backdrop-blur-md sticky top-0 z-30 px-6 flex items-center justify-between">
      {/* Left: Quick search & Status */}
      <div className="flex items-center gap-4">
        {/* Global Search Box */}
        <div ref={searchRef} className="relative hidden sm:block w-64 md:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            placeholder="Search targets, findings, or programs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onFocus={() => setIsSearchFocused(true)}
            className="w-full bg-slate-900/80 border border-white/10 rounded-lg pl-9 pr-8 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500/50 transition-colors font-sans"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Search Results Dropdown */}
          {isSearchFocused && searchQuery.trim().length > 0 && (
            <div className="absolute top-full left-0 right-0 mt-2 bg-[#0d0e17] border border-white/15 rounded-xl shadow-2xl overflow-hidden z-50 animate-fade-in max-h-96 overflow-y-auto">
              {searchResults.length === 0 ? (
                <div className="p-4 text-xs font-mono text-slate-500 text-center">
                  No matching entities found for "{searchQuery}"
                </div>
              ) : (
                <div className="p-1 space-y-1">
                  {searchResults.map((res) => (
                    <div
                      key={`${res.type}-${res.id}`}
                      onClick={() => handleResultClick(res)}
                      className="p-2.5 rounded-lg hover:bg-white/5 transition-colors cursor-pointer flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="font-bold text-slate-200 font-sans truncate">{res.title}</div>
                        <div className="text-[11px] text-slate-400 font-mono truncate">{res.subtitle}</div>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border uppercase shrink-0 ${getTypeBadgeStyle(res.type)}`}>
                        {res.type}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Live Hunt Status Indicator */}
        {activeHuntCount > 0 ? (
          <div
            onClick={() => onNavigate('hunts')}
            className="cursor-pointer flex items-center gap-2 px-3 py-1 rounded-full bg-red-950/40 border border-red-800/40 text-xs text-red-300 hover:bg-red-950/70 transition-colors"
          >
            <Radio className="w-3.5 h-3.5 text-red-500 animate-pulse" />
            <span className="font-mono text-[11px]">
              {activeHuntCount} Hunt{activeHuntCount > 1 ? 's' : ''} Active
            </span>
          </div>
        ) : (
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-white/5 text-xs text-slate-400">
            <span className="w-2 h-2 rounded-full bg-slate-500" />
            <span className="font-mono text-[11px]">Engine Ready</span>
          </div>
        )}
      </div>

      {/* Right: Actions & Researcher Profile */}
      <div className="flex items-center gap-3">
        {/* Policy Enforced Shield */}
        <div className="hidden lg:flex items-center gap-1.5 px-3 py-1 rounded-lg bg-emerald-950/50 border border-emerald-800/40 text-emerald-400 text-xs font-mono font-medium">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>POLICY ENFORCED</span>
        </div>

        {/* Primary CTA: START A HUNT */}
        <button
          onClick={onStartHuntClick}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 font-outfit text-xs font-bold uppercase tracking-wider shadow-[0_0_15px_rgba(220,38,38,0.3)] transition-all transform active:scale-95 cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>START HUNT</span>
        </button>

        {/* Researcher Pill */}
        <div
          onClick={() => onNavigate('settings')}
          className="cursor-pointer flex items-center gap-2 pl-3 pr-2 py-1 rounded-lg bg-slate-900 border border-white/10 hover:border-white/20 transition-colors"
        >
          <div className="flex flex-col text-right">
            <span className="text-xs font-bold text-slate-200 tracking-wide font-outfit">AYUSH</span>
            <span className="text-[9px] font-mono text-red-400 uppercase">Researcher</span>
          </div>
          <div className="w-7 h-7 rounded-md bg-gradient-to-br from-red-900 to-slate-900 border border-red-700/50 flex items-center justify-center font-bold text-xs text-slate-100 font-mono">
            A
          </div>
        </div>
      </div>
    </header>
  );
};

