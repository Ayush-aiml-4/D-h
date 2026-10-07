import React, { useState, useEffect } from 'react';
import { OperatorEngagementConsoleView } from './OperatorEngagementConsoleView';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  Unlock,
  Radio,
  FileCheck,
  Activity,
  Server,
  UserCheck,
  FileText,
  Clock,
  Play,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Key,
  Database,
  ArrowRight,
  RefreshCw,
  Search,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import {
  EngagementProgramProfile,
  EngagementReadinessEvaluation,
  ReadinessDimensionState,
  OverallReadinessStatus,
  EngagementAuditEntry,
  ProxyConnectionStatus,
  ResearchAccount,
} from '../types/engagement.ts';
import {
  listEngagementProfiles,
  createProgramDraft,
  importProgramPolicy,
  setProgramScopeAssets,
  validateProgramRules,
  submitResearcherReview,
  grantHumanOnboardingApproval,
  grantActiveTestingAuthorization,
  getEngagementProfile,
} from '../services/engagement/engagementService.ts';
import {
  evaluateOperationalReadiness,
} from '../services/engagement/operationalReadinessService.ts';
import {
  getProxyBoundaryConfig,
  configureExternalProxy,
  resetProxyConfig,
  checkProxyHealth,
} from '../services/engagement/proxyBoundaryService.ts';
import {
  getResearchAccounts,
  registerResearchAccount,
} from '../services/engagement/researchAccountService.ts';
import {
  startPassiveResearchSession,
  executePassiveObservation,
  getEngagementAuditLog,
} from '../services/engagement/passiveResearchService.ts';

export const OperationalReadinessView: React.FC = () => {
  const [profiles, setProfiles] = useState<EngagementProgramProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string>('');
  const [evaluation, setEvaluation] = useState<EngagementReadinessEvaluation | null>(null);
  const [auditLog, setAuditLog] = useState<EngagementAuditEntry[]>([]);
  const [accounts, setAccounts] = useState<ResearchAccount[]>([]);
  const [proxyConfig, setProxyConfig] = useState(getProxyBoundaryConfig());

  // Approval modal / inputs
  const [operatorToken, setOperatorToken] = useState('LEAD-SEC-9942');
  const [reviewNotes, setReviewNotes] = useState('All program policy rules and fail-closed scope boundaries verified.');
  const [approvalConfirmed, setApprovalConfirmed] = useState(false);
  const [activeReason, setActiveReason] = useState('Manual verification of candidate endpoint with zero mutation');

  // New Account Input
  const [accountSymbol, setAccountSymbol] = useState('ACCOUNT_B');
  const [accountTier, setAccountTier] = useState('MERCHANT');
  const [accountError, setAccountError] = useState('');

  // Proxy Input
  const [proxyHost, setProxyHost] = useState('127.0.0.1');
  const [proxyPort, setProxyPort] = useState(8080);
  const [proxyMsg, setProxyMsg] = useState('');

  // Passive observation simulation
  const [passivePath, setPassivePath] = useState('/api/v1/health');
  const [passiveMethod, setPassiveMethod] = useState<'GET' | 'HEAD' | 'OPTIONS'>('GET');
  const [passiveLog, setPassiveLog] = useState<string[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);

  // Initialize a demo program if none exist
  useEffect(() => {
    let progs = listEngagementProfiles();
    if (progs.length === 0) {
      // Create primary authorized engagement profile
      const demo = createProgramDraft({
        id: 'prog-first-bounty',
        name: 'NexusPay Global Security Program',
        handle: 'nexuspay-bounty',
        platform: 'HackerOne',
        policyUrl: 'https://hackerone.com/nexuspay',
        bountyStatus: 'BOUNTY',
        rewardCeiling: '$10,000',
        creator: 'lead-researcher',
      });

      // Advance through first stages
      importProgramPolicy(
        demo.id,
        {
          allowedVulnerabilityClasses: [
            'CWE-284: Improper Access Control',
            'CWE-862: Missing Authorization',
            'CWE-79: Cross-Site Scripting (Reflected)',
            'CWE-918: Server-Side Request Forgery',
          ],
          requestLimits: {
            numericLimitSpecified: true,
            rateLimitPerSecond: 10,
            maxConcurrentRequests: 3,
            totalSessionBudget: 100,
            burstTolerance: 10,
          },
        },
        'lead-researcher'
      );

      setProgramScopeAssets(
        demo.id,
        [
          {
            id: 'asset-1',
            targetPattern: 'api.nexuspay.dev',
            assetType: 'API_ENDPOINT',
            bountyEligible: true,
            maxSeverity: 'CRITICAL',
            description: 'Core REST API for NexusPay payment gateway',
          },
          {
            id: 'asset-2',
            targetPattern: '*.nexuspay.dev',
            assetType: 'WILDCARD',
            bountyEligible: true,
            maxSeverity: 'HIGH',
            description: 'Authenticated merchant portals',
            allowWildcardSubdomains: true,
          },
        ],
        [
          {
            id: 'oos-1',
            targetPattern: 'internal.nexuspay.dev',
            assetType: 'DOMAIN',
            reason: 'Corporate Intranet and VPN endpoints strictly out-of-scope',
          },
          {
            id: 'oos-2',
            targetPattern: 'admin.nexuspay.dev',
            assetType: 'DOMAIN',
            reason: 'Third-party hosted administrative service',
          },
        ],
        'lead-researcher'
      );

      validateProgramRules(demo.id, 'lead-researcher');

      // Register research account
      registerResearchAccount({
        symbolicIdentifier: 'ACCOUNT_A',
        tier: 'CUSTOMER',
        programId: demo.id,
        label: 'Buyer test account for order authorization testing',
      });

      progs = listEngagementProfiles();
    }

    setProfiles(progs);
    if (!selectedProfileId && progs.length > 0) {
      setSelectedProfileId(progs[0].id);
    }
  }, []);

  // Update evaluation whenever selected profile changes
  useEffect(() => {
    if (selectedProfileId) {
      const profile = getEngagementProfile(selectedProfileId);
      if (profile) {
        const evalResult = evaluateOperationalReadiness(profile);
        setEvaluation(evalResult);
        setAccounts(getResearchAccounts(profile.id));
        setAuditLog(getEngagementAuditLog(profile.id));
      }
    }
  }, [selectedProfileId, proxyConfig]);

  const refreshState = () => {
    if (selectedProfileId) {
      const profile = getEngagementProfile(selectedProfileId);
      if (profile) {
        setEvaluation(evaluateOperationalReadiness(profile));
        setAccounts(getResearchAccounts(profile.id));
        setAuditLog(getEngagementAuditLog(profile.id));
        setProxyConfig(getProxyBoundaryConfig());
      }
    }
  };

  const handleAdvanceResearcherReview = () => {
    if (!selectedProfileId) return;
    try {
      submitResearcherReview(selectedProfileId, 'lead-researcher', reviewNotes);
      refreshState();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleGrantHumanApproval = () => {
    if (!selectedProfileId) return;
    try {
      grantHumanOnboardingApproval(selectedProfileId, 'SECURITY_LEAD', operatorToken, approvalConfirmed);
      refreshState();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleAuthorizeActive = () => {
    if (!selectedProfileId) return;
    try {
      grantActiveTestingAuthorization(selectedProfileId, operatorToken, activeReason);
      refreshState();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleConfigureProxy = () => {
    try {
      const conf = configureExternalProxy({
        proxyHost,
        proxyPort,
        proxyProtocol: 'http',
        enabled: true,
      });
      setProxyConfig(conf);
      setProxyMsg(`Proxy configured: ${conf.proxyHost}:${conf.proxyPort}`);
      refreshState();
    } catch (err: any) {
      setProxyMsg(`Error: ${err.message}`);
    }
  };

  const handleResetProxy = () => {
    resetProxyConfig();
    setProxyConfig(getProxyBoundaryConfig());
    setProxyMsg('Proxy reset to BURP_CONFIGURATION_NOT_AVAILABLE');
    refreshState();
  };

  const handleAddAccount = () => {
    if (!selectedProfileId) return;
    setAccountError('');
    try {
      registerResearchAccount({
        symbolicIdentifier: accountSymbol,
        tier: accountTier,
        programId: selectedProfileId,
        label: `Research account for tier ${accountTier}`,
      });
      setAccountSymbol('ACCOUNT_C');
      refreshState();
    } catch (err: any) {
      setAccountError(err.message);
    }
  };

  const handleStartPassiveSession = () => {
    if (!selectedProfileId) return;
    const profile = getEngagementProfile(selectedProfileId);
    if (!profile) return;

    try {
      const target = profile.inScopeAssets[0]?.targetPattern || 'api.nexuspay.dev';
      const session = startPassiveResearchSession({
        programProfile: profile,
        targetAsset: target,
        maxBudget: 25,
      });
      setSessionId(session.sessionId);
      setPassiveLog((prev) => [
        `[${new Date().toLocaleTimeString()}] Passive session '${session.sessionId}' started on '${target}' (Budget: 25 requests)`,
        ...prev,
      ]);
      refreshState();
    } catch (err: any) {
      setPassiveLog((prev) => [`[${new Date().toLocaleTimeString()}] ERROR: ${err.message}`, ...prev]);
    }
  };

  const handleExecutePassiveRequest = () => {
    if (!sessionId || !selectedProfileId) return;
    const profile = getEngagementProfile(selectedProfileId);
    if (!profile) return;

    try {
      const res = executePassiveObservation({
        sessionId,
        profile,
        method: passiveMethod,
        path: passivePath,
        mockResponseStatus: 200,
        mockBodySnippet: '{"ok":true,"inspection":"passive_scan_evidence"}',
      });

      setPassiveLog((prev) => [
        `[${new Date().toLocaleTimeString()}] ${passiveMethod} ${res.evidence.url} -> Status ${res.evidence.responseStatus} | SHA256: ${res.evidence.evidenceHash.slice(0, 16)}... | Rem Budget: ${res.sessionRemainingBudget}`,
        ...prev,
      ]);
      refreshState();
    } catch (err: any) {
      setPassiveLog((prev) => [`[${new Date().toLocaleTimeString()}] BLOCKED: ${err.message}`, ...prev]);
      refreshState();
    }
  };

  const selectedProfile = profiles.find((p) => p.id === selectedProfileId);

  // Status badge styling helper
  const renderStatusBadge = (status: ReadinessDimensionState | OverallReadinessStatus) => {
    switch (status) {
      case 'READY':
      case 'READY_FOR_PASSIVE_TESTING':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" />
            {status}
          </span>
        );
      case 'READY_WITH_RESTRICTIONS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5" />
            READY WITH RESTRICTIONS
          </span>
        );
      case 'BLOCKED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-md bg-red-500/10 text-red-400 border border-red-500/30">
            <XCircle className="w-3.5 h-3.5" />
            BLOCKED
          </span>
        );
      case 'REVIEW_REQUIRED':
      case 'AWAITING_APPROVAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-md bg-yellow-500/10 text-yellow-300 border border-yellow-500/30">
            <Clock className="w-3.5 h-3.5" />
            {status}
          </span>
        );
      case 'NOT_CONFIGURED':
      case 'MISSING':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-md bg-zinc-800 text-zinc-400 border border-zinc-700">
            <HelpCircle className="w-3.5 h-3.5" />
            {status}
          </span>
        );
    }
  };

  return (
    <div className="p-0 sm:p-4 md:p-6 space-y-6 max-w-7xl mx-auto text-zinc-200">
      {/* Mission #0019 Operator Engagement Console */}
      <OperatorEngagementConsoleView />

      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-zinc-800">
        <div>
          <div className="flex items-start sm:items-center gap-3">
            <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 shrink-0">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-lg sm:text-xl font-bold tracking-tight text-white flex items-center gap-2">
                Operational Readiness & Governance Dashboard
              </h1>
              <p className="text-xs text-zinc-400">
                Program-agnostic fail-closed readiness audit, proxy boundaries, research accounts, and passive-first gating.
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {evaluation && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono text-zinc-500">OVERALL READINESS:</span>
              {renderStatusBadge(evaluation.overallReadiness)}
            </div>
          )}
          <button
            onClick={refreshState}
            className="p-2 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 transition-colors"
            title="Refresh Evaluation"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Program Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 bg-zinc-900/60 p-4 rounded-lg border border-zinc-800">
        <label className="text-xs font-mono uppercase tracking-wider text-zinc-400 shrink-0">Selected Program:</label>
        <select
          value={selectedProfileId}
          onChange={(e) => setSelectedProfileId(e.target.value)}
          className="w-full sm:w-auto bg-zinc-800 border border-zinc-700 rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-red-500"
        >
          {profiles.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.platform}) — Stage: {p.onboardingStage}
            </option>
          ))}
        </select>
        {selectedProfile && (
          <span className="text-xs text-zinc-500 font-mono">
            Platform: <strong className="text-zinc-300">{selectedProfile.platform}</strong> | Reward Ceiling:{' '}
            <strong className="text-emerald-400">{selectedProfile.rewardCeiling}</strong>
          </span>
        )}
      </div>

      {/* 10 Operational Readiness Dimensions Matrix */}
      {evaluation && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold tracking-wide text-zinc-300 uppercase">
              10 Governance Dimensions Status
            </h2>
            <span className="text-xs text-zinc-500">Evaluated deterministically in local memory</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
            {Object.entries(evaluation.dimensions).map(([key, dim]) => (
              <div
                key={key}
                className="p-3.5 rounded-lg bg-zinc-900/70 border border-zinc-800/80 flex flex-col justify-between hover:border-zinc-700 transition-colors"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-xs font-mono font-medium text-zinc-400">{dim.name}</span>
                    {renderStatusBadge(dim.status)}
                  </div>
                  <p className="text-xs text-zinc-300 line-clamp-2" title={dim.reason}>
                    {dim.reason}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Onboarding Lifecycle Workflow Stepper */}
      {selectedProfile && (
        <div className="p-4 rounded-lg bg-zinc-900/50 border border-zinc-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-zinc-200 uppercase tracking-wide flex items-center gap-2">
              <Activity className="w-4 h-4 text-red-400" />
              Controlled Onboarding Lifecycle Workflow
            </h3>
            <span className="text-xs font-mono text-zinc-400">
              Current Stage: <strong className="text-white">{selectedProfile.onboardingStage}</strong>
            </span>
          </div>

          {/* Stepper bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2 text-xs font-mono">
            {[
              'PROGRAM_DRAFT',
              'POLICY_IMPORTED',
              'SCOPE_VALIDATED',
              'RULES_VALIDATED',
              'RESEARCHER_REVIEW',
              'HUMAN_APPROVAL',
              'READY_FOR_PASSIVE_TESTING',
            ].map((st, i) => {
              const stages = [
                'PROGRAM_DRAFT',
                'POLICY_IMPORTED',
                'SCOPE_VALIDATED',
                'RULES_VALIDATED',
                'RESEARCHER_REVIEW',
                'HUMAN_APPROVAL',
                'READY_FOR_PASSIVE_TESTING',
                'ACTIVE_TESTING_AUTHORIZED',
              ];
              const currentIndex = stages.indexOf(selectedProfile.onboardingStage);
              const stepIndex = stages.indexOf(st);
              const isPast = currentIndex > stepIndex;
              const isCurrent = currentIndex === stepIndex;

              return (
                <div
                  key={st}
                  className={`p-2 rounded border text-center transition-all ${
                    isPast
                      ? 'bg-emerald-950/30 border-emerald-600/40 text-emerald-400'
                      : isCurrent
                      ? 'bg-amber-950/30 border-amber-500/50 text-amber-300 font-bold'
                      : 'bg-zinc-900 border-zinc-800 text-zinc-600'
                  }`}
                >
                  <div className="text-[10px] text-zinc-500 mb-0.5">STEP {i + 1}</div>
                  <div className="truncate" title={st}>
                    {st.replace(/_/g, ' ')}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Workflow Interactive Gating Actions */}
          <div className="pt-2 flex flex-wrap items-center gap-3">
            {selectedProfile.onboardingStage === 'RULES_VALIDATED' && (
              <div className="flex items-center gap-2 bg-zinc-800/80 p-2 rounded border border-zinc-700 text-xs w-full sm:w-auto">
                <input
                  type="text"
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  placeholder="Researcher review notes..."
                  className="bg-zinc-900 px-2 py-1 rounded text-white border border-zinc-700 text-xs"
                />
                <button
                  onClick={handleAdvanceResearcherReview}
                  className="px-3 py-1 bg-amber-600 hover:bg-amber-500 text-white rounded font-medium text-xs flex items-center gap-1"
                >
                  Submit Researcher Review <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            {selectedProfile.onboardingStage === 'RESEARCHER_REVIEW' && (
              <div className="flex flex-wrap items-center gap-3 bg-zinc-800/80 p-2 rounded border border-zinc-700 text-xs w-full">
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="confirmCheck"
                    checked={approvalConfirmed}
                    onChange={(e) => setApprovalConfirmed(e.target.checked)}
                    className="rounded text-red-500 focus:ring-0"
                  />
                  <label htmlFor="confirmCheck" className="text-zinc-300">
                    I confirm fail-closed scope, symbolic accounts, and zero unauthorized traffic.
                  </label>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-zinc-400 font-mono">Token:</span>
                  <input
                    type="text"
                    value={operatorToken}
                    onChange={(e) => setOperatorToken(e.target.value)}
                    className="bg-zinc-900 px-2 py-1 rounded text-white border border-zinc-700 text-xs font-mono"
                  />
                  <button
                    onClick={handleGrantHumanApproval}
                    disabled={!approvalConfirmed}
                    className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded font-medium text-xs flex items-center gap-1"
                  >
                    Grant Human Approval <CheckCircle2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}

            {selectedProfile.onboardingStage === 'READY_FOR_PASSIVE_TESTING' && (
              <div className="flex flex-wrap items-center justify-between gap-3 bg-emerald-950/20 p-2.5 rounded border border-emerald-800/40 text-xs w-full">
                <div className="flex items-center gap-2 text-emerald-400 font-medium">
                  <ShieldCheck className="w-4 h-4 shrink-0" />
                  <span>Program is authorized for PASSIVE RESEARCH. Active testing remains locked.</span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center gap-2 w-full sm:w-auto">
                  <input
                    type="text"
                    value={activeReason}
                    onChange={(e) => setActiveReason(e.target.value)}
                    placeholder="Active authorization rationale..."
                    className="bg-zinc-900 px-2 py-1.5 rounded text-white border border-zinc-700 text-xs w-full sm:w-64"
                  />
                  <button
                    onClick={handleAuthorizeActive}
                    className="px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded font-medium text-xs flex items-center justify-center gap-1 shrink-0"
                    title="Unlock active capabilities with human token"
                  >
                    <Unlock className="w-3.5 h-3.5" /> Authorize Active Testing
                  </button>
                </div>
              </div>
            )}

            {selectedProfile.onboardingStage === 'ACTIVE_TESTING_AUTHORIZED' && (
              <div className="flex items-center gap-2 bg-red-950/20 p-2.5 rounded border border-red-800/40 text-xs text-red-400 w-full font-mono">
                <AlertTriangle className="w-4 h-4" />
                ACTIVE TESTING AUTHORIZED: Subject to rate limits, zero-value transactions, and human approval for state-changing ops.
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3-Column Workspace: Proxy Boundary | Research Accounts | Passive Research Runner */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Column 1: Burp / External Proxy Integration Boundary */}
        <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-zinc-200 uppercase tracking-wide flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Proxy Integration Boundary
            </h3>
            {renderStatusBadge(proxyConfig.status)}
          </div>

          <p className="text-xs text-zinc-400">
            External proxy integration boundary. Does NOT fabricate fake Burp configs.
          </p>

          <div className="bg-zinc-950 p-3 rounded border border-zinc-800/80 font-mono text-xs space-y-1.5">
            <div>
              <span className="text-zinc-500">STATUS:</span>{' '}
              <span className={proxyConfig.status === 'CONNECTED' || proxyConfig.status === 'CONFIGURED' ? 'text-emerald-400' : 'text-zinc-400'}>
                {proxyConfig.status}
              </span>
            </div>
            <div>
              <span className="text-zinc-500">HOST:</span> <span className="text-zinc-300">{proxyConfig.proxyHost || 'None (Direct)'}</span>
            </div>
            <div>
              <span className="text-zinc-500">PORT:</span> <span className="text-zinc-300">{proxyConfig.proxyPort || 'None'}</span>
            </div>
            <div>
              <span className="text-zinc-500">CA CERT REF:</span> <span className="text-zinc-400">{proxyConfig.caCertificateRef || 'None'}</span>
            </div>
          </div>

          {/* Proxy Inputs */}
          <div className="space-y-2 pt-2 border-t border-zinc-800 text-xs">
            <div className="grid grid-cols-3 gap-2">
              <div className="col-span-2">
                <label className="text-zinc-400 block mb-1">Host:</label>
                <input
                  type="text"
                  value={proxyHost}
                  onChange={(e) => setProxyHost(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 px-2 py-1 rounded text-white font-mono"
                />
              </div>
              <div>
                <label className="text-zinc-400 block mb-1">Port:</label>
                <input
                  type="number"
                  value={proxyPort}
                  onChange={(e) => setProxyPort(Number(e.target.value))}
                  className="w-full bg-zinc-800 border border-zinc-700 px-2 py-1 rounded text-white font-mono"
                />
              </div>
            </div>

            <div className="flex gap-2 pt-1">
              <button
                onClick={handleConfigureProxy}
                className="flex-1 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-600 rounded font-medium text-xs"
              >
                Set External Proxy
              </button>
              <button
                onClick={handleResetProxy}
                className="px-2.5 py-1.5 bg-zinc-900 hover:bg-zinc-800 text-zinc-400 border border-zinc-700 rounded text-xs"
                title="Reset to BURP_CONFIGURATION_NOT_AVAILABLE"
              >
                Reset
              </button>
            </div>
            {proxyMsg && <p className="text-[11px] text-zinc-400">{proxyMsg}</p>}
          </div>
        </div>

        {/* Column 2: Research Account Model */}
        <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-zinc-200 uppercase tracking-wide flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-emerald-400" />
              Symbolic Research Accounts
            </h3>
            <span className="text-xs font-mono text-zinc-400">{accounts.length} Registered</span>
          </div>

          <p className="text-xs text-zinc-400">
            Reference-only account model (ACCOUNT_A, ACCOUNT_B). Never stores raw passwords, JWTs, or session cookies.
          </p>

          <div className="space-y-2 max-h-44 overflow-y-auto pr-1">
            {accounts.map((acc) => (
              <div
                key={acc.id}
                className="p-2.5 rounded bg-zinc-950 border border-zinc-800/80 flex items-center justify-between text-xs font-mono"
              >
                <div>
                  <span className="text-emerald-400 font-bold">{acc.symbolicIdentifier}</span>
                  <span className="text-zinc-500 ml-2">[{acc.tier}]</span>
                  <div className="text-[11px] text-zinc-400">{acc.label}</div>
                </div>
                <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 text-[10px] border border-emerald-800/50">
                  SAFE REF
                </span>
              </div>
            ))}
          </div>

          {/* Add Account Input */}
          <div className="space-y-2 pt-2 border-t border-zinc-800 text-xs">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-zinc-400 block mb-1">Symbolic Identifier:</label>
                <input
                  type="text"
                  value={accountSymbol}
                  onChange={(e) => setAccountSymbol(e.target.value)}
                  placeholder="e.g. ACCOUNT_B"
                  className="w-full bg-zinc-800 border border-zinc-700 px-2 py-1 rounded text-white font-mono"
                />
              </div>
              <div>
                <label className="text-zinc-400 block mb-1">Tier / Role:</label>
                <input
                  type="text"
                  value={accountTier}
                  onChange={(e) => setAccountTier(e.target.value)}
                  placeholder="e.g. BUYER, SELLER"
                  className="w-full bg-zinc-800 border border-zinc-700 px-2 py-1 rounded text-white font-mono"
                />
              </div>
            </div>

            <button
              onClick={handleAddAccount}
              className="w-full py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-600 rounded font-medium text-xs flex items-center justify-center gap-1.5"
            >
              <Key className="w-3.5 h-3.5 text-zinc-400" /> Register Symbolic Reference
            </button>
            {accountError && <p className="text-[11px] text-red-400">{accountError}</p>}
          </div>
        </div>

        {/* Column 3: Passive-First Research Session & Sandbox */}
        <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-zinc-200 uppercase tracking-wide flex items-center gap-2">
              <Radio className="w-4 h-4 text-amber-400" />
              Passive Research Mode
            </h3>
            {sessionId ? (
              <span className="text-xs font-mono text-emerald-400">ACTIVE SESSION</span>
            ) : (
              <span className="text-xs font-mono text-zinc-500">IDLE</span>
            )}
          </div>

          <p className="text-xs text-zinc-400">
            Safe non-state-changing observations (GET/HEAD/OPTIONS). State changes (POST/PUT/DELETE) fail immediately.
          </p>

          {!sessionId ? (
            <button
              onClick={handleStartPassiveSession}
              disabled={evaluation?.passiveModeStatus !== 'READY'}
              className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white rounded font-medium text-xs flex items-center justify-center gap-2"
            >
              <Play className="w-3.5 h-3.5" /> Start Passive Research Session
            </button>
          ) : (
            <div className="space-y-2 text-xs">
              <div className="grid grid-cols-3 gap-2">
                <div>
                  <label className="text-zinc-400 block mb-1">Method:</label>
                  <select
                    value={passiveMethod}
                    onChange={(e) => setPassiveMethod(e.target.value as any)}
                    className="w-full bg-zinc-800 border border-zinc-700 px-2 py-1 rounded text-white font-mono text-xs"
                  >
                    <option value="GET">GET (Safe)</option>
                    <option value="HEAD">HEAD (Safe)</option>
                    <option value="OPTIONS">OPTIONS (Safe)</option>
                  </select>
                </div>
                <div className="col-span-2">
                  <label className="text-zinc-400 block mb-1">Path:</label>
                  <input
                    type="text"
                    value={passivePath}
                    onChange={(e) => setPassivePath(e.target.value)}
                    className="w-full bg-zinc-800 border border-zinc-700 px-2 py-1 rounded text-white font-mono text-xs"
                  />
                </div>
              </div>

              <button
                onClick={handleExecutePassiveRequest}
                className="w-full py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-600 rounded font-medium text-xs flex items-center justify-center gap-1.5"
              >
                Execute Safe Observation
              </button>
            </div>
          )}

          {/* Passive observation log */}
          <div className="bg-zinc-950 p-2.5 rounded border border-zinc-800/80 font-mono text-[11px] h-32 overflow-y-auto space-y-1 text-zinc-400">
            {passiveLog.length === 0 ? (
              <div className="text-zinc-600 italic">No passive observations executed in this session.</div>
            ) : (
              passiveLog.map((log, idx) => <div key={idx}>{log}</div>)
            )}
          </div>
        </div>
      </div>

      {/* Audit Trails & Evidence Provenance Table */}
      <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-zinc-200 uppercase tracking-wide flex items-center gap-2">
            <FileText className="w-4 h-4 text-indigo-400" />
            Audit Trails & Evidence Provenance Log
          </h3>
          <span className="text-xs font-mono text-zinc-400">{auditLog.length} Audit Events</span>
        </div>

        <div className="overflow-x-auto max-h-56">
          <table className="w-full text-left font-mono text-xs text-zinc-300">
            <thead className="bg-zinc-950 text-zinc-500 uppercase text-[10px] tracking-wider border-b border-zinc-800">
              <tr>
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3">Mode</th>
                <th className="py-2 px-3">Action</th>
                <th className="py-2 px-3">Target Asset</th>
                <th className="py-2 px-3">Decision</th>
                <th className="py-2 px-3">Evidence SHA-256</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {auditLog.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-4 text-center text-zinc-500 italic">
                    No audit records registered yet.
                  </td>
                </tr>
              ) : (
                auditLog.slice(-10).reverse().map((entry) => (
                  <tr key={entry.id} className="hover:bg-zinc-800/40">
                    <td className="py-2 px-3 text-zinc-500">{new Date(entry.timestamp).toLocaleTimeString()}</td>
                    <td className="py-2 px-3">
                      <span className={entry.researchMode === 'PASSIVE' ? 'text-amber-400' : 'text-red-400'}>
                        {entry.researchMode}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-zinc-200">{entry.action}</td>
                    <td className="py-2 px-3 text-zinc-400 truncate max-w-xs">{entry.targetAsset}</td>
                    <td className="py-2 px-3">
                      <span
                        className={
                          entry.policyEvaluationResult === 'ALLOW'
                            ? 'text-emerald-400'
                            : entry.policyEvaluationResult === 'BLOCK'
                            ? 'text-red-400'
                            : 'text-amber-400'
                        }
                      >
                        {entry.policyEvaluationResult}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-zinc-500 truncate max-w-[120px]" title={entry.evidenceHash}>
                      {entry.evidenceHash === 'none' ? 'none' : entry.evidenceHash.slice(0, 12) + '...'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
