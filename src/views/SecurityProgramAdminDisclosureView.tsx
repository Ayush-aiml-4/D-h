/**
 * OPTIONAL ADMIN-only disclosure transition UI.
 * Separate from read-only SecurityProgramOpsView.
 * Server enforces ADMIN; client role check is UX only, not authorization.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Lock, RefreshCw, Shield } from 'lucide-react';
import { api } from '../api/client.ts';

const ADMIN_DISCLOSURE_BG_URL =
  'https://res.cloudinary.com/r67amuba/image/upload/v1791398953/Moonlit_Cloud_Vortex.png';

/** Conservative targets from known FSM — server remains authoritative */
const FSM_TARGETS = [
  'triaged',
  'validated',
  'remediation',
  'fix_verified',
  'disclosure_decision',
  'closed',
] as const;

const LIFECYCLE = [
  'reported',
  'triaged',
  'validated',
  'remediation',
  'fix_verified',
  'disclosure_decision',
  'closed',
] as const;

interface ReportRow {
  report_id: string;
  asset: string;
  disclosure_status?: string;
  validity?: string;
  scope_result?: string;
}

export function SecurityProgramAdminDisclosureView() {
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [target, setTarget] = useState<string>('triaged');
  const [allowedNext, setAllowedNext] = useState<string[]>([...FSM_TARGETS]);
  const [loading, setLoading] = useState(false);
  const [acting, setActing] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [httpHint, setHttpHint] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setHttpHint(null);
    try {
      const data = await api.securityProgram.listReports();
      const list = (data?.reports || []) as ReportRow[];
      setReports(list);
      if (!selectedId && list[0]?.report_id) setSelectedId(list[0].report_id);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      if (/401|unauthor/i.test(msg)) setHttpHint('401 — authentication required (server-enforced)');
      else if (/403|forbid/i.test(msg)) setHttpHint('403 — ADMIN required for mutations (server-enforced)');
      else setHttpHint('API error');
      setReports([]);
    }
    setLoading(false);
  }, [selectedId]);

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    void (async () => {
      try {
        const meta = await api.securityProgram.getDisclosureTransitions(selectedId);
        const next = Array.isArray(meta?.allowedNextStates) ? meta.allowedNextStates : [];
        setAllowedNext(next.length ? next : []);
        if (next.length && !next.includes(target)) setTarget(next[0]);
      } catch {
        // fall back to conservative static list; server still validates
        setAllowedNext([...FSM_TARGETS]);
      }
    })();
  }, [selectedId]);


  const selected = useMemo(
    () => reports.find((r) => r.report_id === selectedId) || null,
    [reports, selectedId]
  );

  const submit = async () => {
    if (!selectedId || !target) return;
    setActing(true);
    setMessage(null);
    setError(null);
    setHttpHint(null);
    try {
      const res = await api.securityProgram.disclosureTransition(selectedId, target);
      if (res?.accepted) {
        setMessage(`Transition accepted: ${res.before} → ${res.after}`);
        await load();
      } else {
        setMessage(`Rejected: ${res?.reason || 'INVALID_TRANSITION'} (state unchanged on server)`);
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      if (/401/i.test(msg)) setHttpHint('401 — unauthenticated');
      else if (/403/i.test(msg)) setHttpHint('403 — not ADMIN (client cannot bypass)');
      else if (/404/i.test(msg)) setHttpHint('404 — report not found');
      else if (/409/i.test(msg)) setHttpHint('409 — FSM rejected transition');
    }
    setActing(false);
  };

  return (
    <div className="animate-fade-in pb-6 max-w-7xl mx-auto w-full text-slate-100">
      {/* Defined Admin Disclosure Workspace Container — Subtle Border + Scoped Moonlit Cloud Vortex Background */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-700/65 bg-[#060911] p-5 sm:p-6 lg:p-8 min-h-[calc(100vh-8.5rem)] flex flex-col justify-between shadow-[0_24px_60px_-15px_rgba(0,0,0,0.92),inset_0_1px_0_0_rgba(148,163,184,0.16)] ring-1 ring-inset ring-cyan-400/10">
        {/* Layer 1: Moonlit Cloud Vortex Image — Scoped strictly to Admin Disclosure Main Workspace, preserving aspect ratio */}
        <img
          src={ADMIN_DISCLOSURE_BG_URL}
          alt=""
          aria-hidden="true"
          className="absolute inset-0 w-full h-full object-cover object-[center_28%] opacity-80 brightness-[0.84] contrast-[1.12] saturate-[1.08] pointer-events-none select-none"
        />

        {/* Layer 2: Controlled Dark Navy/Black Translucent Overlay */}
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-[#050811]/58 pointer-events-none"
        />

        {/* Layer 3: Localized Left-Center Scrim & Edge Vignette so Moon & Cloud Vortex remain visible around panels without competing with text */}
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-gradient-to-r from-[#060912]/75 via-[#060a14]/35 to-[#060912]/45 pointer-events-none"
        />
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-gradient-to-b from-[#060912]/60 via-transparent to-[#05070e]/75 pointer-events-none"
        />

        {/* Subtle Top Identity Hairline Accent */}
        <div
          aria-hidden="true"
          className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-red-500/35 to-transparent pointer-events-none"
        />

        {/* Foreground Admin Disclosure Content */}
        <div className="relative z-10 max-w-5xl w-full mx-auto space-y-5">
          {/* Header / Description Panel */}
          <div className="rounded-xl border border-slate-700/60 bg-[#090d18]/82 backdrop-blur-md p-5 sm:p-6 shadow-sm">
            <div className="flex items-start gap-3.5">
              <div className="w-10 h-10 rounded-xl bg-amber-950/70 border border-amber-700/50 flex items-center justify-center shrink-0 mt-0.5">
                <Lock className="w-5 h-5 text-amber-400" />
              </div>
              <div className="space-y-1.5">
                <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-red-950/70 border border-red-500/30 text-[10px] font-mono font-semibold text-red-400 uppercase tracking-wider">
                  <span>Internal Governance Control</span>
                </div>
                <h1 className="text-xl sm:text-2xl font-bold font-outfit uppercase tracking-wider text-slate-100">
                  ADMIN Disclosure Transitions
                </h1>
                <p className="text-sm text-slate-300 leading-relaxed">
                  Optional internal control. Authorization is enforced on the server. A client-side role check is{' '}
                  <strong className="text-amber-300 font-semibold">not</strong> authorization.
                </p>
                <p className="text-xs text-slate-400">
                  Read-only Program Ops dashboard remains separate and does not mutate disclosure state.
                </p>
              </div>
            </div>
          </div>

          {/* Status & Feedback Alerts */}
          {loading && (
            <div className="rounded-xl border border-slate-700/60 bg-[#090d18]/80 px-4 py-3 text-sm text-slate-300 font-mono">
              Loading reports…
            </div>
          )}
          {error && (
            <div className="rounded-xl border border-amber-500/45 bg-amber-950/55 backdrop-blur-md p-4 text-sm text-amber-100 shadow-sm">
              <div className="flex gap-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-medium">{error}</div>
                  {httpHint && <div className="text-xs text-amber-200/85 font-mono mt-1">{httpHint}</div>}
                </div>
              </div>
            </div>
          )}
          {message && (
            <div className="rounded-xl border border-emerald-500/40 bg-emerald-950/55 backdrop-blur-md p-4 text-sm text-emerald-100 shadow-sm">
              {message}
            </div>
          )}

          {/* Balanced Two-Column Grid: State Transition Flow + Report Transition Controls */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
            {/* State Transition Flow Panel (5 Cols) */}
            <div className="lg:col-span-5 rounded-xl border border-slate-700/60 bg-[#090d18]/84 backdrop-blur-md p-5 flex flex-col justify-between shadow-[0_12px_32px_-8px_rgba(0,0,0,0.75)]">
              <div className="space-y-3.5">
                <div className="flex items-center justify-between pb-2.5 border-b border-white/10">
                  <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-200">
                    Disclosure State Sequence
                  </h2>
                  <span className="text-[10px] font-mono text-slate-400 uppercase">Authoritative FSM</span>
                </div>

                <div className="rounded-lg border border-slate-800/80 bg-[#060911]/85 p-3.5 text-xs text-slate-300 font-mono space-y-1.5">
                  {LIFECYCLE.map((s, i) => {
                    const isCurrent = selected?.disclosure_status === s;
                    const isSelectedTarget = target === s;
                    return (
                      <div
                        key={s}
                        className={`flex items-center justify-between px-2.5 py-1.5 rounded-md border transition-colors ${
                          isCurrent
                            ? 'bg-emerald-950/50 border-emerald-700/50 text-emerald-300 font-bold'
                            : isSelectedTarget
                            ? 'bg-red-950/45 border-red-700/45 text-red-200'
                            : 'bg-slate-900/40 border-white/5 text-slate-300'
                        }`}
                      >
                        <span>
                          {i > 0 ? '↓ ' : ''}
                          {s}
                        </span>
                        {isCurrent && (
                          <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-emerald-900/60 text-emerald-300">
                            Current
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              <p className="text-xs text-slate-400 pt-3.5 mt-3.5 border-t border-white/10 normal-case font-sans leading-relaxed">
                Not every state can transition to every other state. The disclosure FSM remains authoritative.
              </p>
            </div>

            {/* Report Transition Controls Panel (7 Cols) */}
            <div className="lg:col-span-7 rounded-xl border border-slate-700/60 bg-[#090d18]/84 backdrop-blur-md p-5 flex flex-col justify-between space-y-4 shadow-[0_12px_32px_-8px_rgba(0,0,0,0.75)]">
              <div className="space-y-4">
                <div className="flex items-center justify-between pb-2.5 border-b border-white/10">
                  <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-200">
                    Report Transition Controls
                  </h2>
                  <span className="text-[10px] font-mono text-amber-400/90 uppercase">Server-Validated</span>
                </div>

                <label className="block text-xs font-mono uppercase tracking-wider text-slate-300">
                  Report
                  <select
                    className="mt-1.5 w-full rounded-xl bg-[#060810] border border-slate-700/80 focus:border-red-500/60 focus:outline-none px-3.5 py-2.5 text-sm font-sans text-slate-100 transition-colors"
                    value={selectedId}
                    onChange={(e) => setSelectedId(e.target.value)}
                  >
                    <option value="">— select —</option>
                    {reports.map((r) => (
                      <option key={r.report_id} value={r.report_id}>
                        {r.report_id} · {r.disclosure_status || '?'} · {r.asset}
                      </option>
                    ))}
                  </select>
                </label>

                {selected ? (
                  <div className="rounded-xl border border-white/10 bg-[#060911]/85 p-3.5 text-xs text-slate-300 space-y-1.5 font-mono">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Current disclosure:</span>
                      <span className="text-emerald-400 font-semibold">{selected.disclosure_status || '—'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Scope / Validity:</span>
                      <span className="text-slate-200">
                        {selected.scope_result || '—'} · {selected.validity || '—'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-sans pt-1 border-t border-white/5">
                      Evidence contents are not shown in this control.
                    </div>
                  </div>
                ) : (
                  <div className="rounded-xl border border-white/5 bg-[#060911]/60 p-3.5 text-xs text-slate-400 font-sans">
                    Select an indexed report above to inspect its current disclosure status and request an authorized state transition.
                  </div>
                )}

                <label className="block text-xs font-mono uppercase tracking-wider text-slate-300">
                  Target state (FSM allowlist in UI; server re-validates)
                  <select
                    className="mt-1.5 w-full rounded-xl bg-[#060810] border border-slate-700/80 focus:border-red-500/60 focus:outline-none px-3.5 py-2.5 text-sm font-mono text-slate-100 transition-colors"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  >
                    {(allowedNext.length ? allowedNext : FSM_TARGETS).map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </label>
              </div>

              <div className="pt-3.5 border-t border-white/10 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  disabled={!selectedId || acting}
                  onClick={() => void submit()}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 disabled:border-slate-700/50 disabled:shadow-none disabled:cursor-not-allowed text-white text-xs font-bold font-outfit uppercase tracking-wider border border-red-400/30 shadow-[0_6px_20px_-4px_rgba(220,38,38,0.4)] transition-all cursor-pointer"
                >
                  <Shield className="w-4 h-4" />
                  {acting ? 'Submitting…' : 'Request transition'}
                </button>
                <button
                  type="button"
                  onClick={() => void load()}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900/90 hover:bg-slate-800 border border-slate-700/70 hover:border-slate-500/70 text-slate-200 text-xs font-bold font-outfit uppercase tracking-wider transition-colors cursor-pointer"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-red-400' : 'text-slate-400'}`} />
                  Refresh
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Subtle Workspace Footer Status Bar */}
        <div className="relative z-10 max-w-5xl w-full mx-auto mt-8 pt-3.5 border-t border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-amber-400" />
            <span>
              {reports.length} {reports.length === 1 ? 'Report' : 'Reports'} Available • Server-Enforced ADMIN Gate
            </span>
          </div>
          <span className="text-slate-400/80 uppercase">FSM Authority: Active</span>
        </div>
      </div>
    </div>
  );
}

export default SecurityProgramAdminDisclosureView;
