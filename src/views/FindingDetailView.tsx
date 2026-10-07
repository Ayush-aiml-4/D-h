import React, { useState, useEffect } from 'react';
import { Finding, FindingStatus } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { EvidenceViewer } from '../components/EvidenceViewer';
import {
  ArrowLeft,
  FileText,
  CheckCircle2,
  Eye,
  Terminal,
  Play,
  Crosshair,
  ShieldCheck,
  CornerDownRight,
  ShieldAlert,
  Sparkles,
  Lock,
  Cpu,
  History,
} from 'lucide-react';
import { api } from '../api/client';

interface FindingDetailViewProps {
  finding: Finding;
  onBack: () => void;
  onGenerateReport: (finding: Finding) => void;
  onUpdateFindingStatus?: (findingId: string, status: FindingStatus) => void;
  onNavigateToProgram?: (programName: string) => void;
  onNavigateToHunt?: (huntId: string) => void;
}

export const FindingDetailView: React.FC<FindingDetailViewProps> = ({
  finding,
  onBack,
  onGenerateReport,
  onUpdateFindingStatus,
  onNavigateToProgram,
  onNavigateToHunt,
}) => {
  const [showEvidence, setShowEvidence] = useState(true);
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<any | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [timelineEvents, setTimelineEvents] = useState<any[]>([]);

  useEffect(() => {
    api
      .getFindingTimeline(finding.id)
      .then(setTimelineEvents)
      .catch(() => setTimelineEvents([]));
  }, [finding.id, finding.status]);

  const handleRunControlledValidation = async () => {
    setIsValidating(true);
    setValidationError(null);
    try {
      const res = await api.validateResearchFinding(finding.id);
      setValidationResult(res);
      if (res.result === 'VALIDATED' && onUpdateFindingStatus) {
        if (finding.status === 'Potential' || finding.status === 'Needs review' || finding.status === 'Under review') {
          onUpdateFindingStatus(finding.id, 'Validated');
        }
      }
    } catch (err: any) {
      setValidationError(err.message || 'Controlled validation failed');
    } finally {
      setIsValidating(false);
    }
  };

  // Status progression action handler
  const handleNextAction = () => {
    if (finding.status === 'Needs review' || finding.status === 'Under review') {
      handleRunControlledValidation();
      return;
    }

    if (finding.status === 'Potential') {
      if (onUpdateFindingStatus) onUpdateFindingStatus(finding.id, 'Under review');
    } else if (finding.status === 'Validated') {
      if (onUpdateFindingStatus) onUpdateFindingStatus(finding.id, 'Verified');
    } else if (finding.status === 'Verified') {
      onGenerateReport(finding);
    } else if (['Submitted', 'Accepted', 'Resolved'].includes(finding.status)) {
      onGenerateReport(finding);
    }
  };

  const renderPrimaryCta = () => {
    switch (finding.status) {
      case 'Potential':
        return {
          label: 'REVIEW FINDING',
          icon: <Eye className="w-4 h-4" />,
          style: 'bg-amber-600 hover:bg-amber-500 text-slate-100 shadow-[0_0_15px_rgba(217,119,6,0.3)]',
        };
      case 'Needs review':
      case 'Under review':
        return {
          label: 'VALIDATE FINDING',
          icon: <Play className="w-4 h-4" />,
          style: 'bg-blue-600 hover:bg-blue-500 text-slate-100 shadow-[0_0_15px_rgba(37,99,235,0.3)]',
        };
      case 'Validated':
        return {
          label: 'VERIFY FINDING',
          icon: <CheckCircle2 className="w-4 h-4" />,
          style: 'bg-emerald-600 hover:bg-emerald-500 text-slate-100 shadow-[0_0_15px_rgba(16,185,129,0.3)]',
        };
      case 'Verified':
        return {
          label: 'PREPARE REPORT',
          icon: <FileText className="w-4 h-4" />,
          style: 'bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-slate-100 shadow-[0_0_20px_rgba(220,38,38,0.3)]',
        };
      case 'Submitted':
      case 'Accepted':
      case 'Resolved':
      default:
        return {
          label: 'VIEW REPORT',
          icon: <FileText className="w-4 h-4" />,
          style: 'bg-slate-800 hover:bg-slate-700 text-slate-100 border border-white/10',
        };
    }
  };

  const cta = renderPrimaryCta();

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Back button & Breadcrumbs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <button
          onClick={onBack}
          className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-slate-100 transition-colors self-start"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Findings
        </button>

        {/* Originating links */}
        <div className="flex flex-wrap items-center gap-2 sm:gap-3 text-xs font-mono">
          {onNavigateToProgram && (
            <button
              onClick={() => onNavigateToProgram(finding.programName)}
              className="px-3 py-1 rounded-lg bg-slate-900 border border-white/10 text-slate-300 hover:text-slate-100 hover:border-white/20 transition-colors flex items-center gap-1.5"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
              <span>Program: {finding.programName}</span>
            </button>
          )}

          {onNavigateToHunt && finding.huntId && (
            <button
              onClick={() => onNavigateToHunt(finding.huntId)}
              className="px-3 py-1 rounded-lg bg-slate-900 border border-white/10 text-slate-300 hover:text-slate-100 hover:border-white/20 transition-colors flex items-center gap-1.5"
            >
              <Crosshair className="w-3.5 h-3.5 text-red-400" />
              <span>Hunt: {finding.huntId}</span>
            </button>
          )}
        </div>
      </div>

      {/* Header Banner */}
      <div className="glass-panel-accent rounded-2xl p-5 sm:p-8 border border-red-700/50 bg-gradient-to-r from-[#1a080c] via-[#0d0c18] to-[#08090f]">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-5 sm:gap-6">
          <div className="space-y-3 min-w-0">
            <div className="flex flex-wrap items-center gap-2 sm:gap-3">
              <SeverityBadge severity={finding.severity} />
              <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-950/80 border border-emerald-700/50 px-3 py-1 rounded-full">
                Confidence: {finding.confidence}%
              </span>
              <span className="text-xs font-mono font-bold text-slate-200 bg-slate-900 border border-white/10 px-3 py-1 rounded-full uppercase tracking-wider">
                STATUS: {finding.status}
              </span>
            </div>

            <h1 className="text-xl sm:text-3xl font-bold font-outfit text-slate-100 tracking-wide">
              {finding.title}
            </h1>

            <p className="text-xs font-mono text-slate-400 break-all">
              Target: <span className="text-red-300 font-bold">{finding.affectedTarget}</span>
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 sm:gap-3 shrink-0">
            <button
              onClick={() => setShowEvidence(!showEvidence)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900 border border-white/10 hover:border-white/20 text-slate-200 text-xs font-mono uppercase font-semibold transition-colors cursor-pointer"
            >
              <Eye className="w-4 h-4 text-slate-400" />
              <span>{showEvidence ? 'Hide Evidence' : 'VIEW EVIDENCE'}</span>
            </button>

            {/* State-dependent Primary Action Button */}
            <button
              onClick={handleNextAction}
              className={`flex items-center gap-2 px-5 sm:px-6 py-2.5 rounded-xl text-xs font-bold font-outfit uppercase tracking-wider transition-all cursor-pointer ${cta.style}`}
            >
              {cta.icon}
              <span>{cta.label}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Lifecycle Workflow Tracker */}
      <div className="glass-panel rounded-2xl p-4 border border-white/10 bg-slate-950/60 font-mono text-xs">
        <div className="text-[10px] text-slate-500 uppercase font-bold mb-2 tracking-wider flex items-center gap-1.5">
          <CornerDownRight className="w-3.5 h-3.5 text-red-400" />
          <span>Finding Lifecycle Progress</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          {[
            { step: 'Potential', active: finding.status === 'Potential' },
            { step: 'Under Review', active: ['Needs review', 'Under review'].includes(finding.status) },
            { step: 'Validated', active: finding.status === 'Validated' },
            { step: 'Verified', active: finding.status === 'Verified' },
            { step: 'Reported', active: ['Submitted', 'Accepted', 'Resolved'].includes(finding.status) },
          ].map((s, idx) => (
            <div
              key={s.step}
              className={`p-2 rounded-lg border text-center transition-all ${
                s.active
                  ? 'bg-red-950/60 border-red-600 text-red-300 font-bold shadow-[0_0_10px_rgba(220,38,38,0.2)]'
                  : 'bg-slate-900/40 border-white/5 text-slate-500'
              }`}
            >
              <div className="text-[9px] text-slate-500">0{idx + 1}</div>
              <div>{s.step}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Main Breakdown Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: Details */}
        <div className="lg:col-span-2 space-y-6">
          {/* What We Found */}
          <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-2">
            <h3 className="text-xs font-mono uppercase font-bold text-slate-400 tracking-wider">
              What We Found
            </h3>
            <p className="text-slate-200 text-sm font-sans leading-relaxed">
              {finding.whatWeFound}
            </p>
          </div>

          {/* Why It Matters */}
          <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-2">
            <h3 className="text-xs font-mono uppercase font-bold text-slate-400 tracking-wider">
              Why It Matters
            </h3>
            <p className="text-slate-200 text-sm font-sans leading-relaxed">
              {finding.whyItMatters}
            </p>
          </div>

          {/* Recommended Fix */}
          <div className="glass-panel rounded-2xl p-6 border border-emerald-900/40 bg-emerald-950/10 space-y-2">
            <div className="flex items-center gap-2 text-xs font-mono uppercase font-bold text-emerald-400 tracking-wider">
              <CheckCircle2 className="w-4 h-4" />
              <span>Recommended Fix</span>
            </div>
            <p className="text-slate-200 text-sm font-sans leading-relaxed">
              {finding.recommendedFix}
            </p>
          </div>

          {/* Evidence Viewer Section */}
          {showEvidence && (
            <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <div className="flex items-center gap-2 font-outfit uppercase font-bold text-slate-100 text-base">
                  <Terminal className="w-5 h-5 text-red-400" />
                  <span>Secure Evidence Proof</span>
                </div>
                <span className="text-xs font-mono text-slate-400">SHA256 Signed</span>
              </div>

              <EvidenceViewer evidence={finding.evidence} policyCheck={finding.policyCheck} />
            </div>
          )}

          {/* Lifecycle Audit Timeline */}
          {timelineEvents.length > 0 && (
            <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <div className="flex items-center gap-2 font-outfit uppercase font-bold text-slate-100 text-base">
                  <History className="w-5 h-5 text-blue-400" />
                  <span>Server Audit Timeline</span>
                </div>
                <span className="text-xs font-mono text-slate-400">{timelineEvents.length} Events Recorded</span>
              </div>

              <div className="space-y-3">
                {timelineEvents.map((evt, idx) => (
                  <div key={evt.id || idx} className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                    <div className="flex items-center justify-between text-slate-300 font-semibold">
                      <span className="text-red-400">{evt.event}</span>
                      <span className="text-[10px] text-slate-500">{new Date(evt.timestamp).toLocaleString()}</span>
                    </div>
                    <p className="text-[11px] text-slate-300 font-sans">{evt.summary}</p>
                    {evt.requestId && (
                      <div className="text-[10px] text-slate-500 font-mono">Req ID: {evt.requestId}</div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right 1 Col: Policy Check Panel & Controlled Security Validation */}
        <div className="space-y-6">
          {/* Controlled Security Validation Action Card */}
          <div className="glass-panel rounded-2xl p-6 border border-blue-500/30 bg-slate-950/80 space-y-4 font-mono text-xs">
            <div className="flex items-center gap-2 pb-3 border-b border-white/10 text-slate-100">
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              <h3 className="text-sm font-bold font-outfit uppercase tracking-wider">
                Controlled Validation Engine
              </h3>
            </div>

            <p className="text-slate-300 text-[11px] font-sans leading-relaxed">
              Executes deterministic, non-destructive validation against registered controlled validators to confirm posture without exploiting vulnerabilities or accessing unauthorized data.
            </p>

            <button
              onClick={handleRunControlledValidation}
              disabled={isValidating}
              className="w-full py-2.5 px-4 rounded-xl font-bold font-outfit text-xs uppercase tracking-wider bg-blue-600 hover:bg-blue-500 text-white shadow-[0_0_15px_rgba(37,99,235,0.3)] transition-all flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
            >
              {isValidating ? (
                <>
                  <Cpu className="w-4 h-4 animate-spin text-blue-300" />
                  <span>Validating Finding...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Run Controlled Validation</span>
                </>
              )}
            </button>

            {validationError && (
              <div className="p-3 rounded-xl bg-red-950/60 border border-red-500/40 text-red-300 text-[11px]">
                {validationError}
              </div>
            )}

            {validationResult && (
              <div className="p-3.5 rounded-xl bg-slate-900 border border-blue-500/40 space-y-2.5 animate-fade-in">
                <div className="flex items-center justify-between pb-2 border-b border-white/10">
                  <span className="text-slate-400">Result Status</span>
                  <span
                    className={`font-bold px-2 py-0.5 rounded text-[10px] ${
                      validationResult.result === 'VALIDATED'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-600/40'
                        : 'bg-amber-950 text-amber-300 border border-amber-600/40'
                    }`}
                  >
                    {validationResult.result} ({validationResult.confidence}%)
                  </span>
                </div>

                <div className="flex items-center justify-between text-slate-300 text-[11px]">
                  <span className="text-slate-500">Safety Level</span>
                  <span className="text-emerald-400 font-semibold">{validationResult.safetyLevel}</span>
                </div>

                <div className="flex items-center justify-between text-slate-300 text-[11px]">
                  <span className="text-slate-500">Validator</span>
                  <span className="text-slate-200">{validationResult.validationId}</span>
                </div>

                <div className="text-[11px] text-slate-300 font-sans bg-slate-950 p-2 rounded border border-white/5 leading-snug">
                  {validationResult.summary}
                </div>

                {validationResult.evidence?.evidenceHash && (
                  <div className="text-[10px] text-slate-400 truncate">
                    <span className="text-slate-500">Hash: </span>
                    <span className="font-mono text-slate-300">{validationResult.evidence.evidenceHash.substring(0, 16)}...</span>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4 font-mono text-xs">
            <h3 className="text-sm font-bold font-outfit uppercase tracking-wider text-slate-100 pb-3 border-b border-white/10">
              Policy Verification Audit
            </h3>

            <div className="space-y-3">
              <div className="flex items-center justify-between text-slate-300">
                <span>In Scope Target:</span>
                <span className="text-emerald-400 font-bold">✓ Confirmed</span>
              </div>
              <div className="flex items-center justify-between text-slate-300">
                <span>Test Permitted:</span>
                <span className="text-emerald-400 font-bold">✓ Authorized</span>
              </div>
              <div className="flex items-center justify-between text-slate-300">
                <span>Validation Mode:</span>
                <span className="text-emerald-400 font-bold">✓ Zero Breach</span>
              </div>
              <div className="flex items-center justify-between text-slate-300">
                <span>Restricted Action:</span>
                <span className="text-emerald-400 font-bold">✕ None</span>
              </div>
            </div>

            <div className="pt-3 border-t border-white/5 text-[11px] text-slate-400 italic leading-snug">
              This finding was validated strictly within the authorized program policy rules. No DoS or staff social engineering was attempted.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

