/**
 * Mission #0019 — Operator Engagement Console
 * Import → Review → Dual Confirm → Preflight → Supervised Session → STOP
 * Never fabricates scope/auth/credentials. Never auto-enables live mode.
 */
import React, { useCallback, useMemo, useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Import,
  Users,
  Play,
  Square,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Lock,
  Radio,
  FileSearch,
  Eye,
} from 'lucide-react';
import {
  importRealProgram,
  getImportedProgram,
  getImportOnboardingStage,
  submitDualConfirmation,
  getConfirmation,
  startSupervisedCollection,
  supervisedPassiveRequest,
  emergencyStop,
  supervisedSafetyStatus,
  runPassivePreflight,
  isActiveTestingLocked,
  type RealProgramProfile,
  type DualConfirmationRecord,
  type PassiveSession,
} from '../services/passiveResearch/index.ts';
import { getTimeline } from '../services/passiveIntelligence/researchTimeline.ts';
import { listEvidence } from '../services/passiveIntelligence/evidenceStore.ts';

type ModeLabel = 'FIXTURE' | 'LIVE_SUPERVISED' | 'BLOCKED' | 'READY';

const emptyForm = {
  programId: '',
  programName: '',
  platform: 'HackerOne' as const,
  policyVersion: '',
  scopeVersion: '',
  authorizationReference: '',
  authorizationStatus: 'AUTHORIZED' as const,
  allowedAssets: '',
  excludedAssets: '',
  requestBudget: '20',
  proxyRequirement: false,
  proxyEndpoint: '',
  researcherReferences: '',
};

function fieldStatus(ok: boolean, missing: boolean): 'VALID' | 'MISSING' | 'BLOCKED' {
  if (missing) return 'MISSING';
  return ok ? 'VALID' : 'BLOCKED';
}

function StatusPill({ status }: { status: string }) {
  const color =
    status === 'VALID' || status === 'PASS' || status === 'READY' || status === 'FIXTURE'
      ? 'border-emerald-600/40 text-emerald-400 bg-emerald-950/40'
      : status === 'LIVE_SUPERVISED'
        ? 'border-amber-500/50 text-amber-300 bg-amber-950/40'
        : 'border-red-600/40 text-red-400 bg-red-950/40';
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${color}`}>
      {status}
    </span>
  );
}

export const OperatorEngagementConsoleView: React.FC = () => {
  const [form, setForm] = useState({ ...emptyForm });
  const [importErrors, setImportErrors] = useState<string[]>([]);
  const [importWarnings, setImportWarnings] = useState<string[]>([]);
  const [profile, setProfile] = useState<RealProgramProfile | null>(null);
  const [primaryApprover, setPrimaryApprover] = useState('');
  const [secondaryApprover, setSecondaryApprover] = useState('');
  const [supervisedLiveEnabled, setSupervisedLiveEnabled] = useState(false);
  const [confirmation, setConfirmation] = useState<DualConfirmationRecord | null>(null);
  const [confirmErrors, setConfirmErrors] = useState<string[]>([]);
  const [session, setSession] = useState<PassiveSession | null>(null);
  const [mode, setMode] = useState<ModeLabel>('BLOCKED');
  const [sessionLog, setSessionLog] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [targetsText, setTargetsText] = useState('');

  const stage = profile ? getImportOnboardingStage(profile.programId) : null;
  const safety = profile ? supervisedSafetyStatus(profile.programId) : null;

  const preflight = useMemo(() => {
    if (!profile) return null;
    const targets = (targetsText || profile.allowedAssets.map((a) => `https://${a}/`).join('\n'))
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    return runPassivePreflight({
      programId: profile.programId,
      targets,
      proxyAvailable: !profile.proxyRequirement || !!profile.proxyEndpoint,
    });
  }, [profile, targetsText, confirmation]);

  const handleImport = () => {
    setImportErrors([]);
    setImportWarnings([]);
    const allowedAssets = form.allowedAssets
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const excludedAssets = form.excludedAssets
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const researcherAccountReferences = form.researcherReferences
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    const result = importRealProgram({
      programId: form.programId.trim(),
      programName: form.programName.trim(),
      platform: form.platform,
      authorizationStatus: form.authorizationStatus,
      authorizationReference: form.authorizationReference.trim() || null,
      policyVersion: form.policyVersion.trim(),
      scopeVersion: form.scopeVersion.trim(),
      allowedAssets,
      excludedAssets,
      requestBudget: Number(form.requestBudget) || 0,
      researcherAccountReferences,
      proxyRequirement: form.proxyRequirement,
      proxyEndpoint: form.proxyEndpoint.trim() || null,
    });

    if (!result.ok) {
      setImportErrors(result.errors);
      setProfile(null);
      setMode('BLOCKED');
      return;
    }
    setImportWarnings(result.warnings);
    setProfile(result.profile!);
    setTargetsText(result.profile!.allowedAssets.map((a) => `https://${a}/`).join('\n'));
    setMode('READY');
    setConfirmation(null);
    setSession(null);
  };

  const handleDualConfirm = () => {
    if (!profile) return;
    setConfirmErrors([]);
    const targets = targetsText
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    const result = submitDualConfirmation({
      programId: profile.programId,
      targets,
      primaryApproverRef: primaryApprover.trim(),
      secondaryApproverRef: secondaryApprover.trim(),
      supervisedLiveEnabled,
      proxyAvailable: !profile.proxyRequirement || !!profile.proxyEndpoint,
    });
    if (!result.ok) {
      setConfirmErrors(result.errors);
      return;
    }
    setConfirmation(result.confirmation);
    setMode(result.confirmation.supervisedLiveEnabled ? 'READY' : 'FIXTURE');
  };

  const handleStartSession = async () => {
    if (!profile || !confirmation) return;
    setBusy(true);
    try {
      const started = startSupervisedCollection({
        confirmationId: confirmation.confirmationId,
        programId: profile.programId,
        targets: confirmation.manifest.targets,
        proxyAvailable: !profile.proxyRequirement || !!profile.proxyEndpoint,
      });
      if (!started.ok) {
        setSessionLog((l) => [...l, `BLOCKED: ${started.errors.join(', ')}`]);
        setMode('BLOCKED');
        return;
      }
      setSession(started.session);
      setMode(started.mode === 'LIVE_SUPERVISED' ? 'LIVE_SUPERVISED' : 'FIXTURE');
      setSessionLog((l) => [
        ...l,
        `SESSION ${started.session.sessionId} started in ${started.mode} mode (no automatic live traffic)`,
      ]);
    } finally {
      setBusy(false);
    }
  };

  const handleFixtureProbe = async () => {
    if (!session || !confirmation || !profile) return;
    setBusy(true);
    try {
      const target = confirmation.manifest.targets[0];
      const res = await supervisedPassiveRequest({
        sessionId: session.sessionId,
        confirmationId: confirmation.confirmationId,
        target,
        method: 'GET',
        mode: 'FIXTURE',
        fixtureResponse: {
          status: 200,
          headers: { 'content-type': 'text/html', server: 'fixture' },
          body: '<html>FIXTURE_MODE_NO_LIVE_TRAFFIC</html>',
        },
      });
      const refreshed = getImportedProgram(profile.programId);
      setSessionLog((l) => [
        ...l,
        res.ok
          ? `FIXTURE GET ${target} ok liveNetwork=${res.liveNetwork} obs=${res.observations?.length || 0}`
          : `BLOCKED: ${res.error}`,
      ]);
    } finally {
      setBusy(false);
    }
  };

  const handleStop = () => {
    if (!session) return;
    const stopped = emergencyStop(session.sessionId, 'OPERATOR_STOP_SESSION');
    if (stopped) {
      setSession({ ...stopped });
      setSessionLog((l) => [...l, `STOP SESSION → ${stopped.state}`]);
      setMode('BLOCKED');
    }
  };

  const timeline = session ? getTimeline(session.researchCaseId) : [];
  const evidence = session ? listEvidence(session.researchCaseId) : [];

  return (
    <div className="space-y-6 sm:space-y-8 animate-fade-in pb-8 sm:pb-16 max-w-6xl mx-auto">
      {/* Mode banner */}
      <div
        className={`rounded-2xl p-4 border flex flex-col sm:flex-row sm:items-center justify-between gap-3 sm:gap-4 ${
          mode === 'LIVE_SUPERVISED'
            ? 'border-amber-500/50 bg-amber-950/30'
            : mode === 'FIXTURE'
              ? 'border-emerald-600/40 bg-emerald-950/20'
              : mode === 'READY'
                ? 'border-blue-500/40 bg-blue-950/20'
                : 'border-red-600/40 bg-red-950/20'
        }`}
      >
        <div className="flex items-start sm:items-center gap-3">
          <Radio className={`w-5 h-5 shrink-0 mt-0.5 sm:mt-0 ${mode === 'LIVE_SUPERVISED' ? 'text-amber-400 animate-pulse' : 'text-slate-300'}`} />
          <div>
            <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider">Traffic mode (unambiguous)</div>
            <div className="text-sm sm:text-lg font-outfit font-bold uppercase tracking-wider">
              {mode === 'FIXTURE' && 'FIXTURE MODE — NO LIVE NETWORK TRAFFIC'}
              {mode === 'LIVE_SUPERVISED' && 'LIVE SUPERVISED MODE — REAL NETWORK ENABLED'}
              {mode === 'BLOCKED' && 'BLOCKED — SESSION / GATES NOT READY'}
              {mode === 'READY' && 'READY — AWAITING SESSION START (STILL FIXTURE UNLESS LIVE GATES PASS)'}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Lock className="w-4 h-4 text-red-400" />
          <span className="text-xs font-mono text-red-300">ACTIVE TESTING LOCKED</span>
        </div>
      </div>

      {/* A. Program Import */}
      <section className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
        <div className="flex items-center gap-2">
          <Import className="w-5 h-5 text-red-400" />
          <h2 className="font-outfit font-bold uppercase tracking-wider text-slate-100">A. Program Import</h2>
        </div>
        <p className="text-xs text-slate-400">
          Operator-supplied data only. DevilHunt will not invent HackerOne scope, authorization, or credentials.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {(
            [
              ['programId', 'Program ID'],
              ['programName', 'Program name'],
              ['policyVersion', 'Policy version'],
              ['scopeVersion', 'Scope version'],
              ['authorizationReference', 'Authorization reference'],
              ['requestBudget', 'Request budget'],
            ] as const
          ).map(([key, label]) => (
            <label key={key} className="text-xs space-y-1">
              <span className="text-slate-400 font-mono uppercase">{label}</span>
              <input
                className="w-full bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-100"
                value={(form as any)[key]}
                onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
                placeholder={label}
              />
            </label>
          ))}
          <label className="text-xs space-y-1 md:col-span-2">
            <span className="text-slate-400 font-mono uppercase">In-scope assets (hosts, one per line)</span>
            <textarea
              className="w-full bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-100 font-mono min-h-[72px]"
              value={form.allowedAssets}
              onChange={(e) => setForm((f) => ({ ...f, allowedAssets: e.target.value }))}
              placeholder="app.example.com"
            />
          </label>
          <label className="text-xs space-y-1 md:col-span-2">
            <span className="text-slate-400 font-mono uppercase">Exclusions</span>
            <textarea
              className="w-full bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-100 font-mono min-h-[56px]"
              value={form.excludedAssets}
              onChange={(e) => setForm((f) => ({ ...f, excludedAssets: e.target.value }))}
            />
          </label>
          <label className="text-xs space-y-1 md:col-span-2">
            <span className="text-slate-400 font-mono uppercase">Researcher references (no passwords/JWTs/API keys)</span>
            <textarea
              className="w-full bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-sm text-slate-100 font-mono min-h-[56px]"
              value={form.researcherReferences}
              onChange={(e) => setForm((f) => ({ ...f, researcherReferences: e.target.value }))}
            />
          </label>
          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={form.proxyRequirement}
              onChange={(e) => setForm((f) => ({ ...f, proxyRequirement: e.target.checked }))}
            />
            Proxy required
          </label>
          <label className="text-xs space-y-1">
            <span className="text-slate-400 font-mono uppercase">Proxy endpoint</span>
            <input
              className="w-full bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-sm"
              value={form.proxyEndpoint}
              onChange={(e) => setForm((f) => ({ ...f, proxyEndpoint: e.target.value }))}
            />
          </label>
        </div>
        {importErrors.length > 0 && (
          <div className="text-xs text-red-300 font-mono space-y-1 border border-red-700/40 rounded-lg p-3 bg-red-950/30">
            {importErrors.map((e) => (
              <div key={e}>• {e}</div>
            ))}
          </div>
        )}
        {importWarnings.length > 0 && (
          <div className="text-xs text-amber-300 font-mono space-y-1">{importWarnings.map((w) => <div key={w}>• {w}</div>)}</div>
        )}
        <button
          type="button"
          onClick={handleImport}
          className="px-4 py-2 rounded-xl bg-gradient-to-r from-red-600 to-red-700 text-xs font-outfit font-bold uppercase tracking-wider"
        >
          Import Program (operator-supplied)
        </button>
      </section>

      {/* B. Program Review */}
      {profile && (
        <section className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
          <div className="flex items-center gap-2">
            <Eye className="w-5 h-5 text-red-400" />
            <h2 className="font-outfit font-bold uppercase tracking-wider">B. Program Review</h2>
            <StatusPill status={stage || 'UNKNOWN'} />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10 space-y-1">
              <div className="text-slate-500 font-mono">PROGRAM</div>
              <div className="text-slate-100 font-bold">{profile.programName}</div>
              <div className="text-slate-400 font-mono">{profile.programId}</div>
              <StatusPill status={fieldStatus(!!profile.programId, !profile.programId)} />
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10 space-y-1">
              <div className="text-slate-500 font-mono">AUTHORIZATION</div>
              <div>{profile.authorizationStatus}</div>
              <div className="font-mono text-slate-400">{profile.authorizationReference || '—'}</div>
              <StatusPill
                status={fieldStatus(
                  profile.authorizationStatus === 'AUTHORIZED' && !!profile.authorizationReference,
                  !profile.authorizationReference
                )}
              />
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10 space-y-1">
              <div className="text-slate-500 font-mono">IN-SCOPE</div>
              <ul className="font-mono text-emerald-300">{profile.allowedAssets.map((a) => <li key={a}>{a}</li>)}</ul>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10 space-y-1">
              <div className="text-slate-500 font-mono">EXCLUSIONS</div>
              <ul className="font-mono text-red-300">
                {profile.excludedAssets.length ? profile.excludedAssets.map((a) => <li key={a}>{a}</li>) : <li>—</li>}
              </ul>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10">
              <div className="text-slate-500 font-mono">METHODS</div>
              <div className="font-mono">{profile.allowedMethods.join(', ')}</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10">
              <div className="text-slate-500 font-mono">BUDGET</div>
              <div className="font-mono">{profile.requestBudget} requests</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10">
              <div className="text-slate-500 font-mono">PROXY</div>
              <div>{profile.proxyRequirement ? profile.proxyEndpoint || 'REQUIRED (missing endpoint)' : 'Not required'}</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10">
              <div className="text-slate-500 font-mono">RESEARCHER REFS</div>
              <ul className="font-mono">{profile.researcherAccountReferences.map((r) => <li key={r}>{r}</li>)}</ul>
            </div>
          </div>
          {safety && (
            <div className="flex flex-wrap gap-2">
              {Object.entries(safety).map(([k, v]) => (
                <StatusPill key={k} status={`${k.toUpperCase()}:${v}`} />
              ))}
            </div>
          )}
        </section>
      )}

      {/* C. Dual Confirmation */}
      {profile && (
        <section className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
          <div className="flex items-center gap-2">
            <Users className="w-5 h-5 text-red-400" />
            <h2 className="font-outfit font-bold uppercase tracking-wider">C. Dual Confirmation</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-xs space-y-1">
              <span className="text-slate-400 font-mono">PRIMARY APPROVER</span>
              <input
                className="w-full bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-sm"
                value={primaryApprover}
                onChange={(e) => setPrimaryApprover(e.target.value)}
              />
            </label>
            <label className="text-xs space-y-1">
              <span className="text-slate-400 font-mono">SECONDARY APPROVER</span>
              <input
                className="w-full bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-sm"
                value={secondaryApprover}
                onChange={(e) => setSecondaryApprover(e.target.value)}
              />
            </label>
          </div>
          <label className="flex items-center gap-2 text-xs text-amber-200">
            <input
              type="checkbox"
              checked={supervisedLiveEnabled}
              onChange={(e) => setSupervisedLiveEnabled(e.target.checked)}
            />
            supervisedLiveEnabled = true (still requires DEVILHUNT_ALLOW_LIVE_PASSIVE env for real traffic)
          </label>
          <label className="text-xs space-y-1 block">
            <span className="text-slate-400 font-mono">TARGETS</span>
            <textarea
              className="w-full bg-slate-950 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono min-h-[64px]"
              value={targetsText}
              onChange={(e) => setTargetsText(e.target.value)}
            />
          </label>
          {confirmErrors.length > 0 && (
            <div className="text-xs text-red-300 font-mono">{confirmErrors.map((e) => <div key={e}>• {e}</div>)}</div>
          )}
          <button
            type="button"
            onClick={handleDualConfirm}
            className="px-4 py-2 rounded-xl border border-white/15 bg-slate-900 text-xs font-outfit font-bold uppercase"
          >
            Submit Dual Confirmation
          </button>
          {confirmation && (
            <div className="text-xs font-mono space-y-1 p-3 rounded-xl bg-slate-950 border border-emerald-700/30">
              <div>confirmationId: {confirmation.confirmationId}</div>
              <div>primary: {confirmation.primaryApproverRef}</div>
              <div>secondary: {confirmation.secondaryApproverRef}</div>
              <div>supervisedLiveEnabled: {String(confirmation.supervisedLiveEnabled)}</div>
              <div className="text-slate-400">{confirmation.manifest.explicitStatement}</div>
            </div>
          )}
        </section>
      )}

      {/* D. Preflight */}
      {preflight && (
        <section className="glass-panel rounded-2xl p-6 border border-white/10 space-y-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-red-400" />
            <h2 className="font-outfit font-bold uppercase tracking-wider">D. Preflight</h2>
            <StatusPill status={preflight.status} />
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs">
            {Object.entries(preflight.checks).map(([k, v]) => (
              <div key={k} className="flex items-center gap-2 p-2 rounded-lg bg-slate-950 border border-white/5">
                {v === 'PASS' ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <XCircle className="w-3.5 h-3.5 text-red-400" />}
                <span className="font-mono">{k}</span>
                <StatusPill status={v} />
              </div>
            ))}
            <div className="flex items-center gap-2 p-2 rounded-lg bg-slate-950 border border-white/5">
              <Lock className="w-3.5 h-3.5 text-red-400" />
              <span className="font-mono">activeTesting</span>
              <StatusPill status="LOCKED" />
            </div>
            <div className="flex items-center gap-2 p-2 rounded-lg bg-slate-950 border border-white/5">
              <span className="font-mono">liveEnv</span>
              <StatusPill status={process.env.DEVILHUNT_ALLOW_LIVE_PASSIVE === 'true' ? 'LIVE_FLAG_SET' : 'FIXTURE'} />
            </div>
          </div>
          {preflight.reasons.length > 0 && (
            <div className="text-xs text-red-300 font-mono">{preflight.reasons.map((r) => <div key={r}>• {r}</div>)}</div>
          )}
        </section>
      )}

      {/* E + F Session Console + STOP */}
      <section className="glass-panel rounded-2xl p-6 border border-white/10 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-red-400" />
            <h2 className="font-outfit font-bold uppercase tracking-wider">E. Session Console</h2>
          </div>
          <button
            type="button"
            onClick={handleStop}
            disabled={!session || session.state === 'CANCELLED'}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-red-700 hover:bg-red-600 disabled:opacity-40 text-sm font-outfit font-bold uppercase tracking-wider shadow-[0_0_20px_rgba(220,38,38,0.35)]"
          >
            <Square className="w-4 h-4" />
            STOP SESSION
          </button>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={!confirmation || busy || preflight?.status !== 'READY'}
            onClick={handleStartSession}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-100 text-slate-900 text-xs font-bold uppercase disabled:opacity-40"
          >
            <Play className="w-3.5 h-3.5" />
            Start Supervised Session
          </button>
          <button
            type="button"
            disabled={!session || session.state === 'CANCELLED' || busy}
            onClick={handleFixtureProbe}
            className="px-4 py-2 rounded-xl border border-white/15 text-xs font-bold uppercase disabled:opacity-40"
          >
            Run FIXTURE probe (no live traffic)
          </button>
        </div>

        {session && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10">
              <div className="text-slate-500 font-mono">STATUS</div>
              <div className="font-bold">{session.state}</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10">
              <div className="text-slate-500 font-mono">MODE</div>
              <div className="font-bold">{mode}</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10">
              <div className="text-slate-500 font-mono">BUDGET</div>
              <div className="font-bold">
                {session.budgetUsed} / {session.budgetMax}
              </div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-white/10">
              <div className="text-slate-500 font-mono">OBSERVATIONS</div>
              <div className="font-bold">{session.observations.length}</div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-3 rounded-xl bg-slate-950 border border-white/10 max-h-40 overflow-auto font-mono">
            <div className="text-slate-500 mb-1">SESSION LOG</div>
            {sessionLog.length ? sessionLog.map((l, i) => <div key={i}>{l}</div>) : <div className="text-slate-600">—</div>}
          </div>
          <div className="p-3 rounded-xl bg-slate-950 border border-white/10 max-h-40 overflow-auto font-mono">
            <div className="text-slate-500 mb-1">AUDIT / TIMELINE ({timeline.length})</div>
            {timeline.slice(-12).map((e) => (
              <div key={e.id}>
                {e.type} {e.target || ''}
              </div>
            ))}
          </div>
        </div>
        <div className="text-xs font-mono text-slate-400">Evidence artifacts: {evidence.length} · Active testing: {isActiveTestingLocked() ? 'LOCKED' : 'UNLOCKED'}</div>
      </section>
    </div>
  );
};
