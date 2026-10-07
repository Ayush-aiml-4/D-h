import React, { useState, useEffect } from 'react';
import { Report } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { Send, CheckCircle2, X, AlertCircle } from 'lucide-react';

interface DisclosureModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: Report;
  onConfirmDisclosure: (reportId: string) => void;
}

export const DisclosureModal: React.FC<DisclosureModalProps> = ({
  isOpen,
  onClose,
  report,
  onConfirmDisclosure,
}) => {
  const [recipient, setRecipient] = useState<string>(report.recipientContact || 'security@acme-security.test');
  const [confirmedCheck, setConfirmedCheck] = useState<boolean>(false);

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

  const handlePrepare = () => {
    if (!confirmedCheck) return;
    onConfirmDisclosure(report.id);
    onClose();
  };

  return (
    <div
      onClick={onClose}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-fade-in"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="glass-panel-accent w-full max-w-xl max-h-[90vh] overflow-y-auto rounded-2xl p-4 sm:p-6 border border-red-700/40 shadow-[0_0_50px_rgba(220,38,38,0.25)] relative text-slate-100"
      >
        <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-950/90 border border-red-600/50 flex items-center justify-center text-red-400">
              <Send className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-xl font-bold font-outfit uppercase tracking-wider text-slate-100">
                Disclosure Ready
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Prepare responsible disclosure report payload
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

        <div className="space-y-4 mb-6">
          {/* Recipient */}
          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
              Official Security Contact
            </label>
            <input
              type="text"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              className="w-full bg-slate-900 border border-white/15 rounded-xl px-4 py-2 text-sm font-mono text-slate-100 focus:outline-none focus:border-red-500/60"
            />
          </div>

          {/* Report summary card */}
          <div className="bg-slate-950/80 rounded-xl p-4 border border-white/10 space-y-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <span className="text-[10px] font-mono uppercase text-slate-500">{report.programName}</span>
                <h3 className="text-sm font-bold text-slate-100 font-outfit">{report.title}</h3>
              </div>
              <SeverityBadge severity={report.severity} />
            </div>

            <div className="text-xs text-slate-400 space-y-1 font-mono">
              <div>Target: <span className="text-slate-200">{report.target}</span></div>
              <div>Researcher: <span className="text-slate-200">{report.researcher}</span></div>
            </div>

            {/* Included Attachments */}
            <div className="pt-2 border-t border-white/5">
              <span className="text-[11px] font-mono text-slate-400 block mb-2">Verified Attachments:</span>
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/60 border border-emerald-800/40 text-emerald-300">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> Security Report (PDF/MD) ✓
                </span>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/60 border border-emerald-800/40 text-emerald-300">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> HTTP Evidence Logs ✓
                </span>
              </div>
            </div>
          </div>

          {/* Human Confirmation Checklist */}
          <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-800/30 text-xs text-slate-300 space-y-2">
            <div className="flex items-center gap-2 text-amber-400 font-semibold font-mono">
              <AlertCircle className="w-4 h-4" />
              <span>Human Confirmation Required</span>
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Review everything before sending. DevilHunt will generate the confidential disclosure bundle. No external requests are sent automatically without manual dispatch.
            </p>
            <label className="flex items-center gap-2 pt-1 cursor-pointer">
              <input
                type="checkbox"
                checked={confirmedCheck}
                onChange={(e) => setConfirmedCheck(e.target.checked)}
                className="w-4 h-4 rounded border-slate-700 bg-slate-900 text-red-600 focus:ring-red-500"
              />
              <span className="text-xs text-slate-200 font-medium">
                I have verified the report content, impact summary, and recipient address.
              </span>
            </label>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/10">
          <button
            onClick={onClose}
            className="px-4 py-2.5 rounded-xl border border-white/10 text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-colors uppercase tracking-wider"
          >
            Cancel
          </button>
          <button
            onClick={handlePrepare}
            disabled={!confirmedCheck}
            className={`px-6 py-2.5 rounded-xl font-outfit text-xs font-bold uppercase tracking-wider transition-all ${
              confirmedCheck
                ? 'bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 shadow-[0_0_20px_rgba(220,38,38,0.4)] cursor-pointer'
                : 'bg-slate-800 text-slate-500 cursor-not-allowed'
            }`}
          >
            REVIEW & SUBMIT
          </button>
        </div>
      </div>
    </div>
  );
};

