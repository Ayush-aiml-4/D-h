import React, { useState, useEffect } from 'react';
import { Report, DisclosurePackage, DisclosureQualitySummary } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { ArrowLeft, Download, Send, Check, ShieldCheck, FileText, Calendar, User, Globe, AlertTriangle, CheckCircle2, XCircle, Copy, Code, Eye, RefreshCw } from 'lucide-react';
import { api } from '../api/client';

interface ReportDetailViewProps {
  report: Report;
  onBack: () => void;
  onPrepareDisclosure: (report: Report) => void;
  onShowToast: (title: string, msg?: string) => void;
}

export const ReportDetailView: React.FC<ReportDetailViewProps> = ({
  report,
  onBack,
  onPrepareDisclosure,
  onShowToast,
}) => {
  const [downloaded, setDownloaded] = useState(false);
  const [disclosurePkg, setDisclosurePkg] = useState<DisclosurePackage | null>(null);
  const [loadingDisclosure, setLoadingDisclosure] = useState(false);
  const [activeTab, setActiveTab] = useState<'report' | 'disclosure'>('report');
  const [exportFormat, setExportFormat] = useState<'markdown' | 'html' | 'text' | 'json'>('markdown');
  const [exportedText, setExportedText] = useState<string>('');
  const [copied, setCopied] = useState(false);

  const fetchOrCreateDisclosure = async () => {
    setLoadingDisclosure(true);
    try {
      const pkg = await api.createDisclosurePackage(report.findingId);
      setDisclosurePkg(pkg);
      setActiveTab('disclosure');
    } catch (err: any) {
      onShowToast('Disclosure Error', err.message || 'Failed to prepare disclosure package');
    } finally {
      setLoadingDisclosure(false);
    }
  };

  const handleTransition = async (targetStatus: string) => {
    if (!disclosurePkg) return;
    try {
      const updated = await api.transitionDisclosureStatus(disclosurePkg.id, targetStatus);
      setDisclosurePkg(updated);
      onShowToast('Status Updated', `Disclosure transitioned to ${updated.status}`);
    } catch (err: any) {
      onShowToast('Transition Failed', err.message);
    }
  };

  const handleApprove = async () => {
    if (!disclosurePkg) return;
    try {
      const updated = await api.approveDisclosurePackage(disclosurePkg.id);
      setDisclosurePkg(updated);
      onShowToast('Disclosure Approved', `Explicitly approved by researcher ${updated.approvedBy}`);
    } catch (err: any) {
      onShowToast('Approval Failed', err.message);
    }
  };

  const handleRecordSubmission = async () => {
    if (!disclosurePkg) return;
    try {
      const updated = await api.recordManualSubmission(disclosurePkg.id);
      setDisclosurePkg(updated);
      onShowToast('Submission Recorded', `Manual submission timestamp recorded at ${updated.submittedAt}`);
    } catch (err: any) {
      onShowToast('Submission Failed', err.message);
    }
  };

  useEffect(() => {
    if (disclosurePkg) {
      const url = api.getDisclosureExportUrl(disclosurePkg.id, exportFormat);
      fetch(url, { headers: { Authorization: 'Bearer mock-token:user-ayush-001:RESEARCHER:Ayush' } })
        .then((res) => res.text())
        .then(setExportedText)
        .catch(() => setExportedText(''));
    }
  }, [disclosurePkg, exportFormat]);

  const handleCopyExport = () => {
    navigator.clipboard.writeText(exportedText);
    setCopied(true);
    onShowToast('Copied to Clipboard', `Export format: ${exportFormat.toUpperCase()}`);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleExportMarkdown = () => {
    const mdContent = `# SECURITY RESEARCH REPORT: ${report.title}
**Target:** ${report.target}
**Severity:** ${report.severity}
**Researcher:** ${report.researcher}
**Program:** ${report.programName}
**Date:** ${report.createdAt}

## SUMMARY
${report.summary}

## IMPACT
${report.impact}

## TECHNICAL DETAILS
${report.technicalDetails}

\`\`\`http
${report.evidenceSnippet}
\`\`\`

## REPRODUCTION STEPS
${report.reproductionSteps.map((step, i) => `${i + 1}. ${step}`).join('\n')}

## RECOMMENDED FIX
${report.recommendedFix}

## TESTING POLICY & AUDIT
${report.testingPolicy}
`;

    const blob = new Blob([mdContent], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `DevilHunt_Report_${report.id}.md`;
    a.click();
    URL.revokeObjectURL(url);

    setDownloaded(true);
    onShowToast('Report Exported', `Saved DevilHunt_Report_${report.id}.md`);
    setTimeout(() => setDownloaded(false), 3000);
  };

  return (
    <div className="space-y-6 sm:space-y-8 animate-fade-in pb-12 max-w-5xl mx-auto">
      {/* Top Bar Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <button
          onClick={onBack}
          className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-slate-100 transition-colors self-start"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Reports
        </button>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3">
          <div className="flex items-center rounded-xl bg-slate-900 p-1 border border-white/10 font-mono text-xs">
            <button
              onClick={() => setActiveTab('report')}
              className={`px-2.5 sm:px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                activeTab === 'report' ? 'bg-slate-800 text-slate-100 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Research Report
            </button>
            <button
              onClick={fetchOrCreateDisclosure}
              className={`px-2.5 sm:px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'disclosure' ? 'bg-red-950 text-red-300 font-bold border border-red-700/50' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Send className="w-3.5 h-3.5 text-red-400" />
              <span>Disclosure Package</span>
            </button>
          </div>

          <button
            onClick={handleExportMarkdown}
            className="flex items-center gap-2 px-3.5 sm:px-4 py-2 rounded-xl bg-slate-900 border border-white/10 hover:border-white/20 text-slate-200 text-xs font-mono uppercase font-semibold transition-colors cursor-pointer"
          >
            {downloaded ? <Check className="w-4 h-4 text-emerald-400" /> : <Download className="w-4 h-4 text-slate-400" />}
            <span>Export Report</span>
          </button>
        </div>
      </div>

      {activeTab === 'disclosure' && disclosurePkg ? (
        <div className="space-y-6">
          {/* Disclosure Intelligence Header */}
          <div className="glass-panel-accent rounded-2xl p-5 sm:p-8 border border-red-700/50 bg-gradient-to-r from-[#18080a] via-[#0d0c18] to-[#08090f]">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-xs font-mono font-bold text-red-400 bg-red-950/80 border border-red-700/50 px-3 py-1 rounded-full uppercase tracking-wider">
                    DISCLOSURE PACKAGE
                  </span>
                  <span
                    className={`text-xs font-mono font-bold px-3 py-1 rounded-full uppercase tracking-wider ${
                      disclosurePkg.status === 'SUBMISSION_READY' || disclosurePkg.status === 'APPROVED'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-600/50'
                        : disclosurePkg.status === 'SUBMITTED'
                        ? 'bg-blue-950 text-blue-300 border border-blue-600/50'
                        : 'bg-amber-950 text-amber-300 border border-amber-600/50'
                    }`}
                  >
                    STATUS: {disclosurePkg.status}
                  </span>
                  <span className="text-xs font-mono font-bold text-slate-300 bg-slate-900 border border-white/10 px-3 py-1 rounded-full">
                    Scope: {disclosurePkg.scopeVerificationStatus}
                  </span>
                </div>

                <h1 className="text-2xl sm:text-3xl font-bold font-outfit text-slate-100 tracking-wide">
                  {disclosurePkg.title}
                </h1>

                <p className="text-xs font-mono text-slate-400">
                  Target Program: <span className="text-red-300 font-bold">{disclosurePkg.programName}</span> | Asset: <span className="text-slate-200">{disclosurePkg.affectedAsset}</span>
                </p>
              </div>

              {/* State Transitions & Approval Controls */}
              <div className="flex flex-col sm:flex-row items-center gap-3 shrink-0 font-mono text-xs">
                {disclosurePkg.status === 'DRAFT' && (
                  <button
                    onClick={() => handleTransition('UNDER_REVIEW')}
                    className="px-5 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-slate-100 font-bold uppercase transition-all shadow-[0_0_15px_rgba(217,119,6,0.3)] cursor-pointer"
                  >
                    Submit for Review
                  </button>
                )}

                {disclosurePkg.status === 'UNDER_REVIEW' && (
                  <button
                    onClick={() => handleTransition('READY_FOR_APPROVAL')}
                    className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-slate-100 font-bold uppercase transition-all shadow-[0_0_15px_rgba(37,99,235,0.3)] cursor-pointer"
                  >
                    Ready for Approval
                  </button>
                )}

                {(disclosurePkg.status === 'READY_FOR_APPROVAL' || disclosurePkg.status === 'UNDER_REVIEW') && (
                  <button
                    onClick={handleApprove}
                    disabled={!disclosurePkg.qualitySummary.overallPassed}
                    className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-500 hover:to-emerald-600 text-slate-100 font-bold uppercase tracking-wider transition-all disabled:opacity-50 cursor-pointer shadow-[0_0_20px_rgba(16,185,129,0.3)]"
                  >
                    Approve Disclosure
                  </button>
                )}

                {disclosurePkg.status === 'SUBMISSION_READY' && (
                  <button
                    onClick={handleRecordSubmission}
                    className="px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-slate-100 font-bold uppercase tracking-wider transition-all cursor-pointer shadow-[0_0_20px_rgba(37,99,235,0.3)]"
                  >
                    Record Submission
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Quality Gates Panel */}
          <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <div className="flex items-center gap-2 font-outfit uppercase font-bold text-slate-100 text-base">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span>Deterministic Quality Gates Assessment</span>
              </div>
              <span
                className={`px-3 py-1 rounded-full font-bold ${
                  disclosurePkg.qualitySummary.overallPassed
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-600/40'
                    : 'bg-red-950 text-red-300 border border-red-600/40'
                }`}
              >
                {disclosurePkg.qualitySummary.passedCount} / {disclosurePkg.qualitySummary.totalCount} Passed
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {disclosurePkg.qualitySummary.gates.map((g) => (
                <div
                  key={g.gateId}
                  className={`p-3 rounded-xl border flex items-start gap-3 ${
                    g.passed
                      ? 'bg-emerald-950/20 border-emerald-800/30 text-slate-200'
                      : 'bg-red-950/30 border-red-800/40 text-red-200'
                  }`}
                >
                  {g.passed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-0.5">
                    <div className="font-bold flex items-center justify-between">
                      <span>{g.name}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans">{g.description}</p>
                    {g.failureReason && (
                      <p className="text-[10px] text-red-300 font-mono italic">Reason: {g.failureReason}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Possible Duplicates Section */}
          {disclosurePkg.possibleDuplicates.length > 0 && (
            <div className="glass-panel rounded-2xl p-6 border border-amber-500/30 bg-amber-950/10 space-y-3 font-mono text-xs">
              <div className="flex items-center gap-2 text-amber-400 font-outfit uppercase font-bold text-sm">
                <AlertTriangle className="w-4 h-4" />
                <span>Duplicate Correlation Intelligence ({disclosurePkg.possibleDuplicates.length} Candidates)</span>
              </div>
              <p className="text-slate-300 text-[11px] font-sans">
                Potential related findings identified on same program. Duplicate status requires human review.
              </p>
              <div className="space-y-2">
                {disclosurePkg.possibleDuplicates.map((dup) => (
                  <div key={dup.findingId} className="p-3 rounded-xl bg-slate-900 border border-amber-500/20 flex items-center justify-between">
                    <div>
                      <span className="font-bold text-slate-200">{dup.title}</span>
                      <span className="text-slate-500 text-[10px] block font-mono">
                        {dup.findingId} | {dup.matchReason}
                      </span>
                    </div>
                    {dup.severity && <SeverityBadge severity={dup.severity as any} />}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Export Format Selector & Preview */}
          <div className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4 font-mono text-xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-white/10">
              <div className="flex items-center gap-2 font-outfit uppercase font-bold text-slate-100 text-base">
                <Code className="w-5 h-5 text-blue-400" />
                <span>Export Submission Package</span>
              </div>

              <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
                {(['markdown', 'html', 'text', 'json'] as const).map((fmt) => (
                  <button
                    key={fmt}
                    onClick={() => setExportFormat(fmt)}
                    className={`px-2.5 sm:px-3 py-1 rounded-lg uppercase text-[11px] font-bold cursor-pointer transition-colors ${
                      exportFormat === fmt
                        ? 'bg-blue-600 text-white'
                        : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-white/10'
                    }`}
                  >
                    {fmt}
                  </button>
                ))}

                <button
                  onClick={handleCopyExport}
                  className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold uppercase text-[11px] cursor-pointer transition-colors sm:ml-2"
                >
                  {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-[#07080e] border border-white/10 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-96 leading-relaxed">
              {exportedText || 'Generating export payload...'}
            </div>
          </div>
        </div>
      ) : (
        /* Regular Report Detail View */
        <div className="glass-panel rounded-2xl p-5 sm:p-8 md:p-12 border border-white/15 shadow-2xl space-y-6 sm:space-y-8 bg-[#0b0d14] text-slate-100 relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-red-600 via-red-500 to-amber-500" />

          <div className="space-y-4 pb-6 border-b border-white/10">
            <div className="flex flex-wrap items-center justify-between gap-3 font-mono text-xs text-slate-400">
              <span className="uppercase text-red-400 font-bold">DEVILHUNT CONFIDENTIAL REPORT</span>
              <span>Document ID: {report.id}</span>
            </div>

            <h1 className="text-2xl md:text-3xl font-extrabold font-outfit tracking-wide text-slate-100">
              {report.title}
            </h1>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 rounded-xl bg-slate-950/80 border border-white/5 font-mono text-xs">
              <div>
                <span className="text-slate-500 uppercase text-[10px] block">Severity</span>
                <div className="mt-1"><SeverityBadge severity={report.severity} /></div>
              </div>
              <div>
                <span className="text-slate-500 uppercase text-[10px] block">Program</span>
                <span className="text-slate-200 font-semibold block mt-1">{report.programName}</span>
              </div>
              <div>
                <span className="text-slate-500 uppercase text-[10px] block">Target</span>
                <span className="text-red-300 font-semibold block mt-1">{report.target}</span>
              </div>
              <div>
                <span className="text-slate-500 uppercase text-[10px] block">Researcher</span>
                <span className="text-slate-200 font-semibold block mt-1">{report.researcher}</span>
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <h2 className="text-sm font-mono uppercase font-bold text-slate-400 tracking-wider">
              1. Executive Summary
            </h2>
            <p className="text-slate-200 text-sm font-sans leading-relaxed">
              {report.summary}
            </p>
          </div>

          <div className="space-y-2">
            <h2 className="text-sm font-mono uppercase font-bold text-slate-400 tracking-wider">
              2. Vulnerability Impact
            </h2>
            <p className="text-slate-200 text-sm font-sans leading-relaxed">
              {report.impact}
            </p>
          </div>

          <div className="space-y-3">
            <h2 className="text-sm font-mono uppercase font-bold text-slate-400 tracking-wider">
              3. Technical Proof & HTTP Evidence
            </h2>
            <p className="text-slate-300 text-sm font-sans leading-relaxed">
              {report.technicalDetails}
            </p>
            <div className="p-4 rounded-xl bg-[#07080e] border border-white/10 font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {report.evidenceSnippet}
            </div>
          </div>

          <div className="space-y-3">
            <h2 className="text-sm font-mono uppercase font-bold text-slate-400 tracking-wider">
              4. Step-by-Step Reproduction Guide
            </h2>
            <ol className="space-y-2 font-mono text-xs text-slate-300">
              {report.reproductionSteps.map((step, idx) => (
                <li key={idx} className="p-3 rounded-lg bg-slate-950 border border-white/5 flex items-start gap-3">
                  <span className="text-red-400 font-bold">0{idx + 1}.</span>
                  <span className="leading-relaxed">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          <div className="space-y-2 p-5 rounded-xl bg-emerald-950/20 border border-emerald-900/40">
            <h2 className="text-xs font-mono uppercase font-bold text-emerald-400 tracking-wider">
              5. Recommended Remediation
            </h2>
            <p className="text-slate-200 text-sm font-sans leading-relaxed">
              {report.recommendedFix}
            </p>
          </div>

          <div className="pt-6 border-t border-white/10 space-y-6 font-mono text-xs">
            <div className="flex items-center gap-2 text-slate-400">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Authorized Testing Policy Audit: Verified 0 rule breaches</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

