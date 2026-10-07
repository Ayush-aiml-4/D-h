import React, { useState, useEffect } from 'react';
import { Program } from '../types';
import { ShieldCheck, Crosshair, X, AlertTriangle, AlertCircle } from 'lucide-react';

interface StartHuntModalProps {
  isOpen: boolean;
  onClose: () => void;
  programs: Program[];
  onConfirmStartHunt: (programId: string, targetDomain: string) => void;
}

export const StartHuntModal: React.FC<StartHuntModalProps> = ({
  isOpen,
  onClose,
  programs,
  onConfirmStartHunt,
}) => {
  const [selectedProgramId, setSelectedProgramId] = useState<string>(programs[0]?.id || '');
  const [targetDomain, setTargetDomain] = useState<string>(programs[0]?.targets[0] || '');
  const [validationError, setValidationError] = useState<string | null>(null);

  // Keyboard shortcut (Escape key) to close modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Keep state updated when modal opens or programs change
  useEffect(() => {
    if (isOpen && programs.length > 0) {
      const activeProg = programs.find((p) => p.id === selectedProgramId) || programs[0];
      setSelectedProgramId(activeProg.id);
      if (activeProg.targets.length > 0) {
        setTargetDomain(activeProg.targets[0]);
      }
      setValidationError(null);
    }
  }, [isOpen, programs]);

  if (!isOpen) return null;

  const currentProgram = programs.find((p) => p.id === selectedProgramId) || programs[0];

  const handleProgramChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const progId = e.target.value;
    setSelectedProgramId(progId);
    setValidationError(null);
    const prog = programs.find((p) => p.id === progId);
    if (prog && prog.targets.length > 0) {
      setTargetDomain(prog.targets[0]);
    } else {
      setTargetDomain('');
    }
  };

  const handleStart = () => {
    setValidationError(null);

    // 1. Validate Program
    if (!currentProgram) {
      setValidationError('Selected program is invalid or missing.');
      return;
    }

    if (currentProgram.status === 'Paused' || currentProgram.status === 'Archived') {
      setValidationError(`Program is currently ${currentProgram.status.toLowerCase()} and cannot accept new hunt sessions.`);
      return;
    }

    // 2. Validate Target
    if (!targetDomain || targetDomain.trim() === '') {
      setValidationError('Target asset domain is required.');
      return;
    }

    // 3. Confirm Scope Exists
    if (!currentProgram.targetCount || currentProgram.targetCount <= 0 || currentProgram.targets.length === 0) {
      setValidationError('Scope is missing. No authorized targets configured for this program.');
      return;
    }

    // 4. Confirm Rules are Loaded
    if (!currentProgram.rulesLoaded) {
      setValidationError('Program rules are not loaded. Reload program configuration before hunting.');
      return;
    }

    // 5. Confirm Policy Enforceable
    if (currentProgram.rulesAllowed.length === 0) {
      setValidationError('Policy cannot be verified. No authorized research testing vectors declared in program rules.');
      return;
    }

    // Success -> trigger hunt
    onConfirmStartHunt(selectedProgramId, targetDomain);
    onClose();
  };

  return (
    <div
      onClick={onClose}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="glass-panel-accent w-full max-w-xl rounded-2xl p-6 border border-red-700/40 shadow-[0_0_50px_rgba(220,38,38,0.2)] relative overflow-hidden text-slate-100"
      >
        {/* Subtle glow circle */}
        <div className="absolute -top-16 -right-16 w-48 h-48 bg-red-600/20 rounded-full blur-3xl pointer-events-none" />

        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-950/90 border border-red-600/50 flex items-center justify-center text-red-400">
              <Crosshair className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h2 className="text-xl font-bold font-outfit uppercase tracking-wider text-slate-100">
                Ready to Hunt
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Initiate policy-bounded security check session
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

        {/* Target & Program Selector */}
        <div className="space-y-4 mb-6">
          {validationError && (
            <div className="p-3.5 rounded-xl bg-red-950/90 border border-red-600 text-red-200 text-xs font-mono flex items-start gap-2.5 shadow-[0_0_15px_rgba(220,38,38,0.3)] animate-shake">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold uppercase block mb-0.5 text-red-300">Validation Error</span>
                <span>{validationError}</span>
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
              Authorized Program
            </label>
            <select
              value={selectedProgramId}
              onChange={handleProgramChange}
              className="w-full bg-slate-900 border border-white/15 rounded-xl px-4 py-2.5 text-sm font-sans text-slate-100 focus:outline-none focus:border-red-500/60 transition-colors"
            >
              {programs.map((prog) => (
                <option key={prog.id} value={prog.id}>
                  {prog.name} ({prog.targetCount} targets • Reward up to {prog.rewardMax})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
              Target Asset Domain
            </label>
            <select
              value={targetDomain}
              onChange={(e) => {
                setTargetDomain(e.target.value);
                setValidationError(null);
              }}
              className="w-full bg-slate-900 border border-white/15 rounded-xl px-4 py-2.5 text-sm font-mono text-slate-100 focus:outline-none focus:border-red-500/60 transition-colors"
            >
              {currentProgram?.targets.map((tgt) => (
                <option key={tgt} value={tgt}>
                  {tgt}
                </option>
              ))}
            </select>
          </div>

          {/* Scope and Policy checklist summary */}
          <div className="bg-slate-950/80 rounded-xl p-4 border border-white/10 space-y-2.5 font-mono text-xs">
            <div className="flex items-center justify-between text-slate-300">
              <span className="text-slate-400">Target Scope:</span>
              <span className="text-slate-100 font-semibold">{currentProgram?.targetCount || 0} assets</span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span className="text-slate-400">Rules Loaded:</span>
              <span className={currentProgram?.rulesLoaded ? "text-emerald-400 font-bold flex items-center gap-1" : "text-red-400 font-bold"}>
                {currentProgram?.rulesLoaded ? 'Loaded ✓' : 'Not Loaded ✕'}
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span className="text-slate-400">Policy Guard:</span>
              <span className="text-emerald-400 font-bold flex items-center gap-1">
                Enforced ✓
              </span>
            </div>
          </div>

          {/* Reassuring Policy Banner */}
          <div className="p-3.5 rounded-xl bg-gradient-to-r from-red-950/50 to-slate-900 border border-red-800/40 text-xs text-slate-300 leading-relaxed flex items-start gap-3">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-slate-100 mb-0.5 font-outfit uppercase">Policy Safeguard Active</p>
              <p className="text-slate-400">
                Authorized research rules strictly enforced. Unauthorized vectors like DoS or phishing remain automatically blocked.
              </p>
            </div>
          </div>
        </div>

        {/* Buttons */}
        <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/10">
          <button
            onClick={onClose}
            className="px-4 py-2.5 rounded-xl border border-white/10 text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-colors uppercase tracking-wider"
          >
            Cancel
          </button>
          <button
            onClick={handleStart}
            className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 text-xs font-bold font-outfit uppercase tracking-wider shadow-[0_0_20px_rgba(220,38,38,0.4)] transition-all cursor-pointer"
          >
            START HUNT
          </button>
        </div>
      </div>
    </div>
  );
};

