import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Flame,
  FileSearch,
  FileText,
  History,
  Settings,
  ChevronLeft,
  ChevronRight,
  Layers,
  ShieldCheck,
  Briefcase,
  Zap,
  Gauge,
  ClipboardList,
  Lock,
} from 'lucide-react';
import { DevilHuntLogo } from './DevilHuntLogo';

export type NavTab =
  | 'home'
  | 'programs'
  | 'operational-readiness'
  | 'cases'
  | 'hunts'
  | 'attack-surface'
  | 'capabilities'
  | 'active-testing'
  | 'findings'
  | 'reports'
  | 'history'
  | 'security-program-ops'
  | 'security-program-admin'
  | 'devil-hunt-live'
  | 'settings';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  actionableCount?: number;
  activeHuntCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  collapsed,
  onToggleCollapse,
  actionableCount = 0,
  activeHuntCount = 0,
}) => {
  const navItems = [
    { id: 'home', label: 'Home', icon: LayoutDashboard },
    { id: 'programs', label: 'Programs', icon: ShieldAlert },
    { id: 'operational-readiness', label: 'Readiness & Governance', icon: Gauge },
    { id: 'security-program-ops', label: 'Program Ops', icon: ClipboardList },
    { id: 'security-program-admin', label: 'Admin Disclosure', icon: Lock },
    { id: 'devil-hunt-live', label: 'Devil Hunt Live', icon: Flame },
    { id: 'cases', label: 'Research Cases', icon: Briefcase },
    { id: 'hunts', label: 'Hunts', icon: Flame, badge: activeHuntCount > 0 ? `${activeHuntCount}` : undefined },
    { id: 'attack-surface', label: 'Attack Surface', icon: Layers },
    { id: 'capabilities', label: 'Capabilities', icon: ShieldCheck },
    { id: 'active-testing', label: 'Active Testing', icon: Zap },
    { id: 'findings', label: 'Findings', icon: FileSearch, badge: actionableCount > 0 ? `${actionableCount}` : undefined },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'history', label: 'History', icon: History },
  ];

  return (
    <aside
      className={`fixed top-0 left-0 bottom-0 z-40 bg-[#0c0e17] border-r border-white/10 transition-all duration-300 flex flex-col justify-between ${
        collapsed ? 'w-18' : 'w-64'
      }`}
    >
      {/* Top Header & Brand */}
      <div>
        <div className="h-16 flex items-center px-4 border-b border-white/5 justify-between">
          <div
            className="flex items-center gap-3 cursor-pointer overflow-hidden"
            onClick={() => onSelectTab('home')}
            title="DEVILHUNT | Hunt the Flaw. Claim the Bounty."
          >
            <DevilHuntLogo
              size="md"
              showText={!collapsed}
              showTagline={!collapsed}
            />
          </div>

          <button
            onClick={onToggleCollapse}
            className="p-1.5 rounded-md text-slate-400 hover:text-slate-100 hover:bg-white/5 transition-colors"
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Main Nav Items */}
        <nav className="p-3 space-y-1.5">
          {!collapsed && (
            <div className="px-3 pt-2 pb-1 text-[10px] font-mono font-semibold text-slate-500 uppercase tracking-wider">
              Command Center
            </div>
          )}

          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id as NavTab)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-red-950/80 to-red-900/40 text-slate-100 border border-red-600/40 shadow-[0_0_12px_rgba(220,38,38,0.15)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5 border border-transparent'
                }`}
                title={collapsed ? item.label : undefined}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <Icon
                    className={`w-4 h-4 shrink-0 transition-colors ${
                      isActive ? 'text-red-400' : 'text-slate-400'
                    }`}
                  />
                  {!collapsed && <span className="truncate">{item.label}</span>}
                </div>

                {!collapsed && item.badge && (
                  <span className="ml-2 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-red-900/60 border border-red-700/50 text-red-300">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Lower Section: Settings & Status */}
      <div className="p-3 border-t border-white/5 space-y-2">
        <button
          onClick={() => onSelectTab('settings')}
          className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
            currentTab === 'settings'
              ? 'bg-gradient-to-r from-red-950/80 to-red-900/40 text-slate-100 border border-red-600/40'
              : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
          }`}
          title={collapsed ? 'Settings' : undefined}
        >
          <Settings className="w-4 h-4 shrink-0 text-slate-400" />
          {!collapsed && <span>Settings</span>}
        </button>

        {!collapsed && (
          <div className="p-3 rounded-lg bg-slate-900/60 border border-white/5 text-xs text-slate-400">
            <div className="flex items-center justify-between font-mono text-[11px] mb-1">
              <span className="text-slate-300">SINGLE RESEARCHER</span>
              <span className="text-emerald-400 font-bold">ONLINE</span>
            </div>
            <p className="text-[11px] text-slate-400 truncate">Ayush (Owner)</p>
          </div>
        )}
      </div>
    </aside>
  );
};
