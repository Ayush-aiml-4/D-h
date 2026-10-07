/**
 * INTERNAL read-only Security Program operations dashboard.
 * Uses shared authenticated api client. Launch readiness is derived only.
 * Optional report pagination uses GET /reports query params (server-bounded).
 */
import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, ChevronLeft, ChevronRight, RefreshCw, Shield } from 'lucide-react';
import { api } from '../api/client.ts';

interface DashboardSnap {
  programStatus?: string;
  launchReadiness?: string;
  blockers?: string[];
  reports?: { total?: number; open?: number; validityDistribution?: Record<string, number> };
  scope?: { distribution?: Record<string, number>; pendingSpecialAuthorization?: number };
  triage?: { duplicates?: number; systemicFindings?: number };
  bounty?: { status?: string; model?: string };
  q4AssetCount?: number;
  remediation?: Record<string, number>;
  disclosure?: Record<string, number>;
}

interface ReportMeta {
  report_id: string;
  asset: string;
  scope_result?: string;
  validity?: string;
  severity?: string | null;
  disclosure_status?: string;
  remediation_status?: string;
}

const PAGE_SIZE = 10;

export function SecurityProgramOpsView() {
  const [snap, setSnap] = useState<DashboardSnap | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [httpHint, setHttpHint] = useState<string | null>(null);

  const [page, setPage] = useState(1);
  const [pageSize] = useState(PAGE_SIZE);
  const [validityFilter, setValidityFilter] = useState('');
  const [scopeFilter, setScopeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [disclosureFilter, setDisclosureFilter] = useState('');
  const [remediationFilter, setRemediationFilter] = useState('');
  const [reportRows, setReportRows] = useState<ReportMeta[]>([]);
  const [reportTotal, setReportTotal] = useState(0);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [reportsError, setReportsError] = useState<string | null>(null);

  const [auditPage, setAuditPage] = useState(1);
  const [auditActionFilter, setAuditActionFilter] = useState('');
  const [auditReportIdFilter, setAuditReportIdFilter] = useState('');
  const [auditRows, setAuditRows] = useState<{ action?: string; detail?: string; at?: string }[]>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditsLoading, setAuditsLoading] = useState(false);
  const [auditsError, setAuditsError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setHttpHint(null);
    try {
      const data = (await api.securityProgram.getDashboard()) as DashboardSnap;
      setSnap(data);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // Preserve last successful snapshot so a refresh failure does not wipe the UI
      setError(msg);
      if (/401|unauthor/i.test(msg)) setHttpHint('401 — authentication required');
      else if (/403|forbid/i.test(msg)) setHttpHint('403 — insufficient role');
      else setHttpHint('API unavailable or network error');
    }
    setLoading(false);
  }, []);

  const loadReports = useCallback(async () => {
    setReportsLoading(true);
    setReportsError(null);
    try {
      const data = await api.securityProgram.listReports({
        page,
        pageSize,
        validity: validityFilter || undefined,
        scopeResult: scopeFilter || undefined,
        severity: severityFilter || undefined,
        disclosureStatus: disclosureFilter || undefined,
        remediationStatus: remediationFilter || undefined,
      });
      setReportRows((data?.reports || []) as ReportMeta[]);
      const total = typeof data?.count === 'number' ? data.count : (data?.reports || []).length;
      setReportTotal(total);
      // Sync page with server (clamps when filters shrink the result set)
      if (typeof data?.page === 'number' && data.page >= 1 && data.page !== page) {
        setPage(data.page);
      } else {
        const maxPage = Math.max(1, Math.ceil(total / pageSize) || 1);
        if (page > maxPage) setPage(maxPage);
      }
    } catch (e) {
      // Keep previous page visible; surface error without blanking the table
      setReportsError(e instanceof Error ? e.message : String(e));
    }
    setReportsLoading(false);
  }, [page, pageSize, validityFilter, scopeFilter, severityFilter, disclosureFilter, remediationFilter]);

  const loadAudits = useCallback(async () => {
    setAuditsLoading(true);
    setAuditsError(null);
    try {
      const data = await api.securityProgram.listAudits({
        page: auditPage,
        pageSize,
        action: auditActionFilter || undefined,
        reportId: auditReportIdFilter || undefined,
      });
      setAuditRows((data?.events || []) as { action?: string; detail?: string; at?: string }[]);
      const total = typeof data?.count === 'number' ? data.count : (data?.events || []).length;
      setAuditTotal(total);
      if (typeof data?.page === 'number' && data.page >= 1 && data.page !== auditPage) {
        setAuditPage(data.page);
      } else {
        const maxPage = Math.max(1, Math.ceil(total / pageSize) || 1);
        if (auditPage > maxPage) setAuditPage(maxPage);
      }
    } catch (e) {
      setAuditsError(e instanceof Error ? e.message : String(e));
    }
    setAuditsLoading(false);
  }, [auditPage, pageSize, auditActionFilter, auditReportIdFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    void loadReports();
  }, [loadReports]);

  useEffect(() => {
    void loadAudits();
  }, [loadAudits]);

  const blocked = (snap?.launchReadiness || 'BLOCKED') !== 'READY';
  const empty = snap && (snap.reports?.total ?? 0) === 0;
  const totalPages = Math.max(1, Math.ceil(reportTotal / pageSize) || 1);

  return (
    <div className="p-0 sm:p-4 md:p-6 max-w-5xl mx-auto space-y-6 text-slate-100">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 sm:gap-4">
        <div className="flex items-center gap-3">
          <Shield className="w-7 h-7 text-cyan-400 shrink-0" />
          <div>
            <h1 className="text-lg sm:text-xl font-semibold">Security Program Ops</h1>
            <p className="text-xs sm:text-sm text-slate-400">
              Internal operational view — not a public bounty page
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => {
            void load();
            void loadReports();
            void loadAudits();
          }}
          className="inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm self-start sm:self-auto"
        >
          <RefreshCw className={`w-4 h-4 ${loading || reportsLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {loading && !snap && (
        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4 text-sm text-slate-400">
          Loading operational snapshot…
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-100 space-y-1">
          <div>{error}</div>
          {httpHint && <div className="text-xs text-amber-200/80">{httpHint}</div>}
        </div>
      )}

      <div
        className={`rounded-xl border p-5 ${
          blocked ? 'border-rose-500/50 bg-rose-950/40' : 'border-emerald-500/40 bg-emerald-950/30'
        }`}
      >
        <div className="flex items-start gap-3">
          <AlertTriangle className={`w-6 h-6 ${blocked ? 'text-rose-400' : 'text-emerald-400'}`} />
          <div>
            <div className="text-lg font-semibold">
              PUBLIC LAUNCH: {snap?.launchReadiness || 'BLOCKED'}
            </div>
            <p className="text-sm text-slate-300 mt-1">
              Primary blocker when empty:{' '}
              <strong>Q4 — ZERO CONFIRMED AUTHORIZED ASSETS</strong>
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Status is <span className="text-cyan-300">DERIVED</span> from configuration — not editable here.
              Identity/rewards fields remain <span className="text-amber-300">PENDING</span> until owner input.
            </p>
            <ul className="mt-2 text-sm text-slate-400 list-disc list-inside">
              {(snap?.blockers || ['Q4_authorizedAssets_empty']).map((b) => (
                <li key={b}>{b}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {empty && (
        <div className="rounded-lg border border-slate-700 bg-slate-900/40 p-3 text-sm text-slate-400">
          No operational reports in the current store (empty state).
        </div>
      )}

      <div className="grid md:grid-cols-2 gap-4">
        <Panel title="Reports">
          <Row label="Total" value={String(snap?.reports?.total ?? 0)} />
          <Row label="Open" value={String(snap?.reports?.open ?? 0)} />
          <Dist title="Validity" data={snap?.reports?.validityDistribution} />
        </Panel>
        <Panel title="Scope">
          <Dist title="Decisions" data={snap?.scope?.distribution} />
          <Row
            label="Pending special auth"
            value={String(snap?.scope?.pendingSpecialAuthorization ?? 0)}
          />
          <Row label="Q4 asset count (CONFIRMED list size)" value={String(snap?.q4AssetCount ?? 0)} />
        </Panel>
        <Panel title="Triage">
          <Row label="Exact duplicates" value={String(snap?.triage?.duplicates ?? 0)} />
          <Row label="Systemic candidates" value={String(snap?.triage?.systemicFindings ?? 0)} />
        </Panel>
        <Panel title="Bounty (OPTIONAL until Q30)">
          <p className="text-sm text-amber-200/90 break-words">
            {snap?.bounty?.status || 'DEFERRED — PROGRAM REWARD MODEL NOT CONFIGURED'}
          </p>
          <Row label="Model" value={String(snap?.bounty?.model ?? 'PENDING')} />
        </Panel>
        <Panel title="Remediation">
          <Dist title="Status" data={snap?.remediation} />
        </Panel>
        <Panel title="Disclosure">
          <Dist title="Status" data={snap?.disclosure} />
        </Panel>
      </div>

      {/* Read-only report list with server-side pagination */}
      <div className="rounded-xl border border-slate-700/80 bg-slate-900/60 p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-cyan-300 tracking-wide uppercase">
            Report list (read-only)
          </h2>
          <div className="flex flex-wrap gap-2 text-xs">
            <select
              className="rounded bg-slate-950 border border-slate-600 px-2 py-1"
              value={validityFilter}
              onChange={(e) => {
                setPage(1);
                setValidityFilter(e.target.value);
              }}
            >
              <option value="">Validity: all</option>
              <option value="valid">valid</option>
              <option value="informative">informative</option>
              <option value="duplicate">duplicate</option>
              <option value="n_a">n_a</option>
              <option value="pending_clarification">pending_clarification</option>
            </select>
            <select
              className="rounded bg-slate-950 border border-slate-600 px-2 py-1"
              value={scopeFilter}
              onChange={(e) => {
                setPage(1);
                setScopeFilter(e.target.value);
              }}
            >
              <option value="">Scope: all</option>
              <option value="IN_SCOPE">IN_SCOPE</option>
              <option value="OUT_OF_SCOPE">OUT_OF_SCOPE</option>
              <option value="PENDING_SPECIAL_AUTH">PENDING_SPECIAL_AUTH</option>
            </select>
            <select
              className="rounded bg-slate-950 border border-slate-600 px-2 py-1"
              value={severityFilter}
              onChange={(e) => {
                setPage(1);
                setSeverityFilter(e.target.value);
              }}
            >
              <option value="">Severity: all</option>
              <option value="NOT_SCORED">NOT_SCORED</option>
              <option value="pending_cvss">pending_cvss</option>
            </select>
            <select
              className="rounded bg-slate-950 border border-slate-600 px-2 py-1"
              value={disclosureFilter}
              onChange={(e) => {
                setPage(1);
                setDisclosureFilter(e.target.value);
              }}
            >
              <option value="">Disclosure: all</option>
              <option value="reported">reported</option>
              <option value="triaged">triaged</option>
              <option value="validated">validated</option>
              <option value="remediation">remediation</option>
              <option value="fix_verified">fix_verified</option>
              <option value="disclosure_decision">disclosure_decision</option>
              <option value="closed">closed</option>
            </select>
            <select
              className="rounded bg-slate-950 border border-slate-600 px-2 py-1"
              value={remediationFilter}
              onChange={(e) => {
                setPage(1);
                setRemediationFilter(e.target.value);
              }}
            >
              <option value="">Remediation: all</option>
              <option value="none">none</option>
              <option value="assigned">assigned</option>
              <option value="in_progress">in_progress</option>
              <option value="fixed">fixed</option>
              <option value="verified">verified</option>
            </select>
          </div>
        </div>

        {reportsError && (
          <p className="text-sm text-amber-200">{reportsError}</p>
        )}
        {reportsLoading && <p className="text-xs text-slate-500">Loading page…</p>}

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="text-slate-500 border-b border-slate-700">
              <tr>
                <th className="py-2 pr-2">ID</th>
                <th className="py-2 pr-2">Asset</th>
                <th className="py-2 pr-2">Scope</th>
                <th className="py-2 pr-2">Validity</th>
                <th className="py-2 pr-2">Disclosure</th>
              </tr>
            </thead>
            <tbody>
              {reportRows.length === 0 && !reportsLoading ? (
                <tr>
                  <td colSpan={5} className="py-3 text-slate-500">
                    No reports on this page
                  </td>
                </tr>
              ) : (
                reportRows.map((r) => (
                  <tr key={r.report_id} className="border-b border-slate-800/80">
                    <td className="py-2 pr-2 font-mono">{r.report_id}</td>
                    <td className="py-2 pr-2 max-w-[12rem] truncate" title={r.asset}>
                      {r.asset}
                    </td>
                    <td className="py-2 pr-2">{r.scope_result || '—'}</td>
                    <td className="py-2 pr-2">{r.validity || '—'}</td>
                    <td className="py-2 pr-2">{r.disclosure_status || '—'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between gap-2 text-sm">
          <span className="text-slate-500 text-xs">
            Page {page} of {totalPages} · {reportTotal} total · pageSize {pageSize} (server max 100)
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={page <= 1 || reportsLoading}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 disabled:opacity-40 text-xs"
            >
              <ChevronLeft className="w-3 h-3" /> Prev
            </button>
            <button
              type="button"
              disabled={page >= totalPages || reportsLoading}
              onClick={() => setPage((p) => p + 1)}
              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 disabled:opacity-40 text-xs"
            >
              Next <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>
        <p className="text-[11px] text-slate-600">
          Read-only list. No disclosure mutations here — use Admin Disclosure if authorized on the server.
        </p>
      </div>

      {/* Read-only audit list with server-side pagination */}
      <div className="rounded-xl border border-slate-700/80 bg-slate-900/60 p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-cyan-300 tracking-wide uppercase">
            Audit events (read-only)
          </h2>
          <div className="flex flex-wrap gap-2 items-center">
            <select
              className="rounded bg-slate-950 border border-slate-600 px-2 py-1 text-xs"
              value={auditActionFilter}
              onChange={(e) => {
                setAuditPage(1);
                setAuditActionFilter(e.target.value);
              }}
            >
              <option value="">Action: all</option>
              <option value="SCOPE">SCOPE</option>
              <option value="SAFETY_OK">SAFETY_OK</option>
              <option value="SAFETY_STOP">SAFETY_STOP</option>
              <option value="DUPLICATE">DUPLICATE</option>
              <option value="VALIDITY_OK">VALIDITY_OK</option>
              <option value="DISCLOSURE_TRANSITION">DISCLOSURE_TRANSITION</option>
              <option value="DISCLOSURE_REJECTED">DISCLOSURE_REJECTED</option>
              <option value="BOUNTY">BOUNTY</option>
            </select>
            <input
              type="text"
              placeholder="Filter by reportId"
              className="rounded bg-slate-950 border border-slate-600 px-2 py-1 text-xs w-40"
              value={auditReportIdFilter}
              onChange={(e) => {
                setAuditPage(1);
                setAuditReportIdFilter(e.target.value.slice(0, 200));
              }}
            />
          </div>
        </div>
        {auditsError && <p className="text-sm text-amber-200">{auditsError}</p>}
        {auditsLoading && <p className="text-xs text-slate-500">Loading audits…</p>}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="text-slate-500 border-b border-slate-700">
              <tr>
                <th className="py-2 pr-2">When</th>
                <th className="py-2 pr-2">Action</th>
                <th className="py-2 pr-2">Detail</th>
              </tr>
            </thead>
            <tbody>
              {auditRows.length === 0 && !auditsLoading ? (
                <tr>
                  <td colSpan={3} className="py-3 text-slate-500">
                    No audit events on this page
                  </td>
                </tr>
              ) : (
                auditRows.map((a, i) => (
                  <tr key={`${a.at || ''}-${a.action || ''}-${i}`} className="border-b border-slate-800/80">
                    <td className="py-2 pr-2 font-mono whitespace-nowrap">{a.at || '—'}</td>
                    <td className="py-2 pr-2">{a.action || '—'}</td>
                    <td className="py-2 pr-2 max-w-[20rem] truncate" title={a.detail || ''}>
                      {a.detail || '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between gap-2 text-sm">
          <span className="text-slate-500 text-xs">
            Page {auditPage} of {Math.max(1, Math.ceil(auditTotal / pageSize) || 1)} · {auditTotal} total
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={auditPage <= 1 || auditsLoading}
              onClick={() => setAuditPage((p) => Math.max(1, p - 1))}
              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 disabled:opacity-40 text-xs"
            >
              <ChevronLeft className="w-3 h-3" /> Prev
            </button>
            <button
              type="button"
              disabled={auditPage >= Math.max(1, Math.ceil(auditTotal / pageSize) || 1) || auditsLoading}
              onClick={() => setAuditPage((p) => p + 1)}
              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 disabled:opacity-40 text-xs"
            >
              Next <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>
        <p className="text-[11px] text-slate-600">
          Metadata only — no secrets, tokens, or evidence payloads.
        </p>
      </div>
    </div>
  );
}

function Panel(props: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-slate-700/80 bg-slate-900/60 p-4 space-y-2">
      <h2 className="text-sm font-semibold text-cyan-300 tracking-wide uppercase">{props.title}</h2>
      {props.children}
    </div>
  );
}

function Row(props: { label: string; value: string }) {
  return (
    <div className="flex justify-between text-sm text-slate-300">
      <span>{props.label}</span>
      <span className="font-mono text-slate-100">{props.value}</span>
    </div>
  );
}

function Dist(props: { title: string; data?: Record<string, number> }) {
  const entries = Object.entries(props.data || {});
  if (!entries.length) return <p className="text-xs text-slate-500">{props.title}: none</p>;
  return (
    <div className="space-y-1">
      <p className="text-xs text-slate-500">{props.title}</p>
      {entries.map(([k, v]) => (
        <Row key={k} label={k} value={String(v)} />
      ))}
    </div>
  );
}

export default SecurityProgramOpsView;
