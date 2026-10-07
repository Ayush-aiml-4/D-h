import React, { useEffect } from 'react';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info';
  title: string;
  message?: string;
}

interface ToastProps {
  toast: ToastMessage | null;
  onClose: () => void;
}

export const Toast: React.FC<ToastProps> = ({ toast, onClose }) => {
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => {
      onClose();
    }, 4000);
    return () => clearTimeout(timer);
  }, [toast, onClose]);

  if (!toast) return null;

  const borderByType = {
    success: 'border-emerald-600/40 shadow-[0_0_25px_rgba(16,185,129,0.2)]',
    error: 'border-red-600/50 shadow-[0_0_25px_rgba(220,38,38,0.3)]',
    info: 'border-blue-600/40 shadow-[0_0_25px_rgba(59,130,246,0.2)]',
  }[toast.type];

  return (
    <div className="fixed bottom-6 right-6 z-50 animate-bounce-in max-w-sm w-full">
      <div className={`glass-panel rounded-xl p-4 border ${borderByType} flex items-start justify-between gap-3 text-slate-100 backdrop-blur-xl`}>
        <div className="flex items-start gap-3">
          {toast.type === 'success' && <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />}
          {toast.type === 'error' && <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />}
          {toast.type === 'info' && <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />}

          <div>
            <h4 className="text-xs font-bold font-outfit uppercase tracking-wider text-slate-100">
              {toast.title}
            </h4>
            {toast.message && (
              <p className="text-xs text-slate-300 font-sans mt-0.5 leading-snug">
                {toast.message}
              </p>
            )}
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1 rounded-md text-slate-400 hover:text-slate-100 transition-colors cursor-pointer"
          aria-label="Dismiss notification"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
