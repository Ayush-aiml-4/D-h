import React, { useState } from 'react';
import { EvidenceData, PolicyCheckResult } from '../types';
import { ShieldCheck, Copy, Check, Terminal, FileCode, Hash, Lock } from 'lucide-react';

interface EvidenceViewerProps {
  evidence: EvidenceData;
  policyCheck: PolicyCheckResult;
}

export const EvidenceViewer: React.FC<EvidenceViewerProps> = ({
  evidence,
  policyCheck,
}) => {
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const copyToClipboard = (text: string, section: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(section);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const rawRequestText = `${evidence.requestMethod} ${evidence.requestUrl} HTTP/1.1\n${Object.entries(
    evidence.requestHeaders
  )
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n')}${evidence.requestBody ? `\n\n${evidence.requestBody}` : ''}`;

  const rawResponseText = `HTTP/1.1 ${evidence.responseStatus} OK\n${Object.entries(
    evidence.responseHeaders
  )
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n')}\n\n${evidence.responseBodySnippet}`;

  return (
    <div className="space-y-6">
      {/* Policy Verification Bar */}
      <div className="bg-slate-950/80 rounded-xl p-4 border border-emerald-900/40 bg-gradient-to-r from-emerald-950/30 via-slate-950 to-slate-950">
        <div className="flex items-center justify-between mb-3 pb-2 border-b border-white/5">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">
              Policy & Audit Integrity
            </h4>
          </div>
          <span className="text-[10px] font-mono text-slate-400">
            Hash: {evidence.proofHash.substring(0, 18)}...
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className="text-emerald-400 font-bold">✓</span>
            <span>In Scope: {policyCheck.inScope ? 'Yes' : 'No'}</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className="text-emerald-400 font-bold">✓</span>
            <span>Test Permitted: {policyCheck.testPermitted ? 'Yes' : 'No'}</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className="text-emerald-400 font-bold">✓</span>
            <span>Validation: {policyCheck.validationCompleted ? 'Completed' : 'Pending'}</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className="text-emerald-400 font-bold">✓</span>
            <span>Restricted Actions: None</span>
          </div>
        </div>
      </div>

      {/* HTTP Request & Response split */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Request Side */}
        <div className="bg-[#0b0d14] rounded-xl border border-white/10 overflow-hidden">
          <div className="px-4 py-2.5 bg-slate-900/80 border-b border-white/10 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2 text-slate-300">
              <Terminal className="w-3.5 h-3.5 text-red-400" />
              <span className="font-bold text-red-400">{evidence.requestMethod}</span>
              <span className="text-slate-400 truncate max-w-[200px]">{evidence.requestUrl}</span>
            </div>
            <button
              onClick={() => copyToClipboard(rawRequestText, 'request')}
              className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-slate-200 transition-colors"
            >
              {copiedSection === 'request' ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" /> Copied
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" /> Copy
                </>
              )}
            </button>
          </div>
          <div className="p-4 overflow-x-auto font-mono text-[11px] text-slate-300 leading-relaxed bg-[#08090e]">
            <div className="text-red-400 font-bold mb-2">
              {evidence.requestMethod} {evidence.requestUrl} HTTP/1.1
            </div>
            {Object.entries(evidence.requestHeaders).map(([k, v]) => (
              <div key={k} className="text-slate-400">
                <span className="text-slate-500">{k}:</span> {v}
              </div>
            ))}
            {evidence.requestBody && (
              <div className="mt-3 pt-2 border-t border-white/5 text-amber-300">
                {evidence.requestBody}
              </div>
            )}
          </div>
        </div>

        {/* Response Side */}
        <div className="bg-[#0b0d14] rounded-xl border border-white/10 overflow-hidden">
          <div className="px-4 py-2.5 bg-slate-900/80 border-b border-white/10 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2 text-slate-300">
              <FileCode className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-bold text-emerald-400">HTTP {evidence.responseStatus}</span>
              <span className="text-slate-400">OK</span>
            </div>
            <button
              onClick={() => copyToClipboard(rawResponseText, 'response')}
              className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-slate-200 transition-colors"
            >
              {copiedSection === 'response' ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" /> Copied
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" /> Copy
                </>
              )}
            </button>
          </div>
          <div className="p-4 overflow-x-auto font-mono text-[11px] text-slate-300 leading-relaxed bg-[#08090e]">
            <div className="text-emerald-400 font-bold mb-2">HTTP/1.1 {evidence.responseStatus} OK</div>
            {Object.entries(evidence.responseHeaders).map(([k, v]) => (
              <div key={k} className="text-slate-400">
                <span className="text-slate-500">{k}:</span> {v}
              </div>
            ))}
            <div className="mt-3 pt-2 border-t border-white/5 text-emerald-300">
              <pre className="whitespace-pre-wrap font-mono">{evidence.responseBodySnippet}</pre>
            </div>
          </div>
        </div>
      </div>

      {/* Metadata Footnote */}
      <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 px-2">
        <span>Captured: {evidence.timestamp}</span>
        <span>Validation Status: {evidence.validationStatus}</span>
      </div>
    </div>
  );
};
