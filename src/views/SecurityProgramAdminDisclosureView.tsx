/**
 * OPTIONAL ADMIN-only disclosure transition UI.
 * Separate from read-only SecurityProgramOpsView.
 * Server enforces ADMIN; client role check is UX only, not authorization.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Lock, RefreshCw, Shield } from 'lucide-react';
import { api } from '../api/client.ts';

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
    <div className="p-6 max-w-3xl mx-auto space-y-6 text-slate-100">
      <div className="flex items-start gap-3">
        <Lock className="w-6 h-6 text-amber-400 mt-1" />
        <div>
          <h1 className="text-xl font-semibold">ADMIN Disclosure Transitions</h1>
          <p className="text-sm text-slate-400 mt-1">
            Optional internal control. Authorization is enforced on the server. A client-side role check is{' '}
            <strong className="text-amber-200">not</strong> authorization.
          </p>
          <p className="text-xs text-slate-500 mt-2">
            Read-only Program Ops dashboard remains separate and does not mutate disclosure state.
          </p>
        </div>
      </div>

      <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4 text-xs text-slate-400 font-mono space-y-1">
        {LIFECYCLE.map((s, i) => (
          <div key={s}>
            {i > 0 ? '↓ ' : ''}
            {s}
          </div>
        ))}
        <p className="text-slate-500 pt-2 normal-case font-sans">
          Not every state can transition to every other state. The disclosure FSM remains authoritative.
        </p>
      </div>

      {loading && <p className="text-sm text-slate-400">Loading reports…</p>}
      {error && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-100">
          <div className="flex gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <div>
              <div>{error}</div>
              {httpHint && <div className="text-xs mt-1 opacity-80">{httpHint}</div>}
            </div>
          </div>
        </div>
      )}
      {message && (
        <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/30 p-3 text-sm text-cyan-100">{message}</div>
      )}

      <div className="space-y-3 rounded-xl border border-slate-700 bg-slate-900/60 p-4">
        <label className="block text-sm text-slate-300">
          Report
          <select
            className="mt-1 w-full rounded-lg bg-slate-950 border border-slate-600 px-3 py-2 text-sm"
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

        {selected && (
          <div className="text-xs text-slate-400 space-y-1">
            <div>
              Current disclosure: <span className="text-slate-200">{selected.disclosure_status || '—'}</span>
            </div>
            <div>
              Scope: <span className="text-slate-200">{selected.scope_result || '—'}</span> · Validity:{' '}
              <span className="text-slate-200">{selected.validity || '—'}</span>
            </div>
            <div className="text-slate-500">Evidence contents are not shown in this control.</div>
          </div>
        )}

        <label className="block text-sm text-slate-300">
          Target state (FSM allowlist in UI; server re-validates)
          <select
            className="mt-1 w-full rounded-lg bg-slate-950 border border-slate-600 px-3 py-2 text-sm"
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

        <div className="flex gap-2">
          <button
            type="button"
            disabled={!selectedId || acting}
            onClick={() => void submit()}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-amber-600/90 hover:bg-amber-500 disabled:opacity-40 text-sm font-medium"
          >
            <Shield className="w-4 h-4" />
            {acting ? 'Submitting…' : 'Request transition'}
          </button>
          <button
            type="button"
            onClick={() => void load()}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>
    </div>
  );
}

export default SecurityProgramAdminDisclosureView;
