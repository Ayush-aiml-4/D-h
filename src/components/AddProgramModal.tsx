import React, { useState, useEffect } from 'react';
import { Program } from '../types';
import { ShieldAlert, Plus, X, AlertCircle } from 'lucide-react';

interface AddProgramModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddProgram: (program: Program) => void;
}

export const AddProgramModal: React.FC<AddProgramModalProps> = ({
  isOpen,
  onClose,
  onAddProgram,
}) => {
  const [name, setName] = useState('');
  const [organization, setOrganization] = useState('');
  const [rewardMax, setRewardMax] = useState('$10,000');
  const [targetsInput, setTargetsInput] = useState('demo-app.test, api.demo-app.test');
  const [description, setDescription] = useState('Authorized bug bounty program target.');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // ESC key listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (!name.trim()) {
      setErrorMsg('Program name is required.');
      return;
    }

    if (!organization.trim()) {
      setErrorMsg('Organization name is required.');
      return;
    }

    const parsedTargets = targetsInput
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);

    if (parsedTargets.length === 0) {
      setErrorMsg('At least one in-scope target domain is required.');
      return;
    }

    const newProg: Program = {
      id: `prog-${Date.now()}`,
      name: name.trim(),
      organization: organization.trim(),
      targetCount: parsedTargets.length,
      scopeStatus: `In Scope (${parsedTargets.length} Assets)`,
      rulesLoaded: true,
      rewardMax: rewardMax.trim() || '$5,000',
      lastHunt: 'Just added',
      status: 'Active',
      description: description.trim(),
      targets: parsedTargets,
      rulesAllowed: [
        'Web security vulnerability research',
        'API endpoint & authorization verification',
        'Authentication state validation',
      ],
      rulesBlocked: [
        'Denial of service attempts',
        'Social engineering or phishing',
      ],
    };

    onAddProgram(newProg);
    setName('');
    setOrganization('');
    setErrorMsg(null);
    onClose();
  };

  return (
    <div
      onClick={onClose}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="glass-panel w-full max-w-xl rounded-2xl p-6 border border-white/10 relative overflow-hidden text-slate-100"
      >
        <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-950/80 border border-red-700/50 flex items-center justify-center text-red-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-xl font-bold font-outfit uppercase tracking-wider text-slate-100">
                Add Security Program
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Register authorized bug-bounty program scope & rules
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-white/10 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {errorMsg && (
            <div className="p-3 rounded-xl bg-red-950/80 border border-red-600/60 text-red-300 text-xs font-mono flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
              Program Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              placeholder="e.g. Acme Security Program"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                setErrorMsg(null);
              }}
              className="w-full bg-slate-900 border border-white/15 rounded-xl px-4 py-2 text-sm text-slate-100 focus:outline-none focus:border-red-500/60"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Organization <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                placeholder="e.g. Acme Corp"
                value={organization}
                onChange={(e) => {
                  setOrganization(e.target.value);
                  setErrorMsg(null);
                }}
                className="w-full bg-slate-900 border border-white/15 rounded-xl px-4 py-2 text-sm text-slate-100 focus:outline-none focus:border-red-500/60"
              />
            </div>
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Max Bounty Reward
              </label>
              <input
                type="text"
                placeholder="e.g. $10,000"
                value={rewardMax}
                onChange={(e) => setRewardMax(e.target.value)}
                className="w-full bg-slate-900 border border-white/15 rounded-xl px-4 py-2 text-sm font-mono text-slate-100 focus:outline-none focus:border-red-500/60"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
              In-Scope Target Domains (Comma separated) <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              placeholder="e.g. demo-app.test, api.demo-app.test"
              value={targetsInput}
              onChange={(e) => {
                setTargetsInput(e.target.value);
                setErrorMsg(null);
              }}
              className="w-full bg-slate-900 border border-white/15 rounded-xl px-4 py-2 text-sm font-mono text-slate-100 focus:outline-none focus:border-red-500/60"
            />
          </div>

          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
              Program Scope Description
            </label>
            <textarea
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-slate-900 border border-white/15 rounded-xl px-4 py-2 text-sm text-slate-100 focus:outline-none focus:border-red-500/60"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/10">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 rounded-xl border border-white/10 text-xs font-semibold text-slate-400 hover:text-slate-200 transition-colors uppercase tracking-wider"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 text-xs font-bold font-outfit uppercase tracking-wider shadow-[0_0_20px_rgba(220,38,38,0.3)] transition-all cursor-pointer flex items-center gap-1.5"
            >
              <Plus className="w-4 h-4" /> ADD PROGRAM
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

