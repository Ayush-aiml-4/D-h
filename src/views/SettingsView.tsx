import React, { useState } from 'react';
import { UserProfile } from '../types';
import { Settings, User, Sliders, Bell, Cpu, Shield, Download, RefreshCw, CheckCircle2 } from 'lucide-react';

interface SettingsViewProps {
  profile: UserProfile;
  onUpdateProfile: (name: string) => void;
  onResetData: () => void;
  onShowToast: (title: string, msg?: string) => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  profile,
  onUpdateProfile,
  onResetData,
  onShowToast,
}) => {
  const [researcherName, setResearcherName] = useState(profile.name);
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);

  const handleSaveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    onUpdateProfile(researcherName);
    onShowToast('Profile Updated', `Researcher handle saved as ${researcherName}`);
  };

  const handleExportState = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(profile));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", "DevilHunt_Config.json");
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    onShowToast('Config Exported', 'Downloaded DevilHunt_Config.json');
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12 max-w-4xl">
      {/* Top Header */}
      <div className="pb-4 border-b border-white/10">
        <div className="flex items-center gap-2 text-xs font-mono text-red-400 uppercase tracking-wider mb-1">
          <Settings className="w-4 h-4" />
          <span>System Configuration</span>
        </div>
        <h1 className="text-2xl font-black font-outfit uppercase tracking-wider text-slate-100">
          Settings & Preferences
        </h1>
        <p className="text-xs text-slate-400 font-sans">
          Configure single-researcher preferences, AI engine hooks, and policy safeguards.
        </p>
      </div>

      <div className="space-y-6">
        {/* Researcher Profile */}
        <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold font-outfit uppercase text-slate-100 pb-3 border-b border-white/10">
            <User className="w-4 h-4 text-red-400" />
            <span>Researcher Profile</span>
          </div>

          <form onSubmit={handleSaveProfile} className="space-y-4 font-mono text-xs">
            <div>
              <label className="block text-slate-400 uppercase text-[10px] mb-1">
                Researcher Name / Handle
              </label>
              <input
                type="text"
                value={researcherName}
                onChange={(e) => setResearcherName(e.target.value)}
                className="w-full max-w-md bg-slate-900 border border-white/15 rounded-xl px-4 py-2 text-slate-100 focus:outline-none focus:border-red-500/60"
              />
            </div>

            <div>
              <label className="block text-slate-400 uppercase text-[10px] mb-1">
                Role & Authority
              </label>
              <input
                type="text"
                disabled
                value="Lead Security Researcher (Owner)"
                className="w-full max-w-md bg-slate-950 border border-white/10 rounded-xl px-4 py-2 text-slate-500 cursor-not-allowed"
              />
            </div>

            <button
              type="submit"
              className="px-5 py-2 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 text-xs font-bold font-outfit uppercase tracking-wider transition-all cursor-pointer"
            >
              SAVE PROFILE
            </button>
          </form>
        </div>

        {/* AI Engine & Gemini Integration Status */}
        <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold font-outfit uppercase text-slate-100 pb-3 border-b border-white/10">
            <Cpu className="w-4 h-4 text-amber-400" />
            <span>AI Reasoning Engine</span>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-white/10 space-y-2 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-300">Gemini AI API Status:</span>
              <span className="text-emerald-400 font-bold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Injectable via Environment
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              DevilHunt leverages Gemini for automated HTTP payload analysis, vulnerability verification reasoning, and report generation.
            </p>
          </div>
        </div>

        {/* Notifications & Policy Guard */}
        <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold font-outfit uppercase text-slate-100 pb-3 border-b border-white/10">
            <Bell className="w-4 h-4 text-red-400" />
            <span>Notifications & Policy Alerts</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <label className="flex items-center justify-between p-3 rounded-xl bg-slate-900 border border-white/5 cursor-pointer">
              <div>
                <span className="text-slate-200 font-bold block">Policy Breach Safeguard Notifications</span>
                <span className="text-slate-400 text-[11px]">Instant alert if target request approaches scope boundary</span>
              </div>
              <input
                type="checkbox"
                checked={notificationsEnabled}
                onChange={(e) => setNotificationsEnabled(e.target.checked)}
                className="w-4 h-4 rounded border-slate-700 bg-slate-950 text-red-600"
              />
            </label>
          </div>
        </div>

        {/* Data & Backup */}
        <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold font-outfit uppercase text-slate-100 pb-3 border-b border-white/10">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span>Data Management</span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleExportState}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 border border-white/10 hover:border-white/20 text-slate-200 text-xs font-mono uppercase font-semibold transition-colors cursor-pointer"
            >
              <Download className="w-4 h-4 text-slate-400" />
              <span>EXPORT CONFIG JSON</span>
            </button>

            <button
              onClick={() => {
                onResetData();
                onShowToast('Demo Data Reset', 'Restored default DevilHunt state');
              }}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-red-950/40 border border-red-800/40 hover:bg-red-950/70 text-red-300 text-xs font-mono uppercase font-semibold transition-colors cursor-pointer"
            >
              <RefreshCw className="w-4 h-4 text-red-400" />
              <span>RESET DEMO DATA</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
