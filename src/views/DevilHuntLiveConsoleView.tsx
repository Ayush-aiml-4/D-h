/**
 * Devil Hunt live operator console — real controls, no fake traffic.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  Play,
  Pause,
  Square,
  RotateCcw,
  Download,
  Trash2,
  Shield,
  AlertTriangle,
  Radio,
  Terminal,
  Activity,
} from 'lucide-react';

const API = '/api/v1/devil-hunt';
const AUTH = 'Bearer mock-token:user-ayush-001:ADMIN:Ayush';

const LIVE_CONSOLE_BG_URL =
  'https://res.cloudinary.com/r67amuba/image/upload/v1791398955/Crimson_Moon_Over_Misty_Islands.png';

async function dhFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      Authorization: AUTH,
      ...(opts?.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || data?.message || `HTTP ${res.status}`);
  return data;
}

function downloadBlob(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function DevilHuntLiveConsoleView() {
  const [state, setState] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedReq, setSelectedReq] = useState<any>(null);
  const [ingestForm, setIngestForm] = useState({
    method: 'GET',
    host: 'supplier.meesho.com',
    path: '/api/example',
    category: 'PROFILE',
    status: '200',
    queryParamNames: '',
    bodyKeys: '',
  });

  const refresh = useCallback(async () => {
    try {
      const data = await dhFetch('/state');
      setState(data.state);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 2000);
    return () => clearInterval(t);
  }, [refresh]);

  const run = async (fn: () => Promise<any>) => {
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const exportFile = async (kind: 'json' | 'csv' | 'md') => {
    const res = await fetch(`${API}/export/${kind}`, {
      headers: { Authorization: AUTH },
    });
    const text = await res.text();
    const names = { json: 'devil-hunt-export.json', csv: 'devil-hunt-export.csv', md: 'devil-hunt-report.md' };
    const types = {
      json: 'application/json',
      csv: 'text/csv',
      md: 'text/markdown',
    };
    downloadBlob(names[kind], text, types[kind]);
    await refresh();
  };

  const statusColor =
    state?.status === 'RUNNING'
      ? 'text-emerald-400'
      : state?.status === 'WAITING_APPROVAL'
        ? 'text-amber-400'
        : state?.status === 'PAUSED'
          ? 'text-yellow-400'
          : state?.status === 'STOPPED'
            ? 'text-rose-400'
            : 'text-slate-400';

  const statusBadgeClasses =
    state?.status === 'RUNNING'
      ? 'bg-emerald-950/70 border-emerald-700/50 text-emerald-300'
      : state?.status === 'WAITING_APPROVAL'
        ? 'bg-amber-950/70 border-amber-700/50 text-amber-300'
        : state?.status === 'PAUSED'
          ? 'bg-yellow-950/70 border-yellow-700/50 text-yellow-300'
          : state?.status === 'STOPPED'
            ? 'bg-rose-950/70 border-rose-700/50 text-rose-300'
            : 'bg-slate-900/80 border-slate-700/60 text-slate-300';

  return (
    <div className="animate-fade-in pb-6 max-w-7xl mx-auto w-full text-slate-100">
      {/* Defined DevilHunt Live Workspace Container — Subtle Border + Scoped Crimson Moon Landscape Background */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-700/65 bg-[#09060a] p-4 sm:p-5 lg:p-6 shadow-[0_24px_60px_-15px_rgba(0,0,0,0.92),inset_0_1px_0_0_rgba(148,163,184,0.16)] ring-1 ring-inset ring-red-500/15 space-y-4">
        {/* Layer 1: Crimson Moon Over Misty Islands Image — Scoped strictly to DevilHunt Live Workspace, preserving aspect ratio */}
        <img
          src={LIVE_CONSOLE_BG_URL}
          alt=""
          aria-hidden="true"
          className="absolute inset-0 w-full h-full object-cover object-[center_42%] opacity-80 brightness-[0.84] contrast-[1.12] saturate-[1.08] pointer-events-none select-none"
        />

        {/* Layer 2: Dark Navy/Black Translucent Surface Overlay */}
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-[#07060c]/60 pointer-events-none"
        />

        {/* Layer 3: Subtle Crimson/Dark Vignette & Depth Gradients */}
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-gradient-to-b from-[#08060c]/70 via-[#08060c]/30 to-[#06050a]/78 pointer-events-none"
        />

        {/* Subtle Top Identity Hairline Accent */}
        <div
          aria-hidden="true"
          className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-red-500/40 to-transparent pointer-events-none"
        />

        {/* Foreground Live Console UI */}
        <div className="relative z-10 space-y-4">
          {/* Compact Page Header & Session Identifier */}
          <div className="rounded-xl border border-slate-700/60 bg-[#090b14]/82 backdrop-blur-md px-4 py-3.5 sm:px-5 sm:py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-sm">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-red-950/75 border border-red-700/50 flex items-center justify-center shrink-0">
                <Shield className="w-4 h-4 text-red-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-lg sm:text-xl font-black font-outfit uppercase tracking-wider text-slate-100">
                    DEVIL HUNT LIVE
                  </h1>
                  <span className={`px-2 py-0.5 rounded-full border text-[10px] font-mono font-bold uppercase ${statusBadgeClasses}`}>
                    ● {state?.status || 'IDLE'}
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-sans">
                  Live security research console — no fabricated findings
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2.5 self-start sm:self-center">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#060912]/90 border border-cyan-500/30 text-xs font-mono">
                <span className="text-slate-400 uppercase text-[10px]">LIVE SESSION</span>
                <span className="text-cyan-300 font-bold">HUNT #{state?.huntId || '—'}</span>
              </div>
            </div>
          </div>

          {error && (
            <div className="rounded-xl border border-amber-500/45 bg-amber-950/60 backdrop-blur-md px-4 py-3 text-sm text-amber-100 flex items-center gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Top Live Status Panel — Target/Scope/Mode/Traffic + Live Telemetry Counters */}
          <div className="rounded-xl border border-slate-700/60 bg-[#090b14]/84 backdrop-blur-md p-4 sm:p-5 space-y-4 shadow-[0_12px_32px_-8px_rgba(0,0,0,0.75)]">
            {/* Row 1: Primary Session Context */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 font-mono text-xs">
              <div className="rounded-lg border border-white/10 bg-[#060810]/85 p-3">
                <span className="text-[10px] text-slate-400 uppercase block mb-1">TARGET</span>
                <span className="text-slate-100 font-bold truncate block">{state?.target || '—'}</span>
              </div>
              <div className="rounded-lg border border-white/10 bg-[#060810]/85 p-3">
                <span className="text-[10px] text-slate-400 uppercase block mb-1">SCOPE</span>
                <span className="text-emerald-400 font-bold truncate block">{state?.scope || '—'}</span>
              </div>
              <div className="rounded-lg border border-white/10 bg-[#060810]/85 p-3">
                <span className="text-[10px] text-slate-400 uppercase block mb-1">MODE</span>
                <span className="text-cyan-300 font-bold truncate block">{state?.mode || '—'}</span>
              </div>
              <div className="rounded-lg border border-white/10 bg-[#060810]/85 p-3">
                <span className="text-[10px] text-slate-400 uppercase block mb-1">STATUS</span>
                <span className={`font-bold truncate block ${statusColor}`}>● {state?.status || 'IDLE'}</span>
              </div>
              <div className="col-span-2 sm:col-span-1 rounded-lg border border-white/10 bg-[#060810]/85 p-3">
                <span className="text-[10px] text-slate-400 uppercase block mb-1">TRAFFIC SOURCE</span>
                <span className="text-amber-300 font-bold truncate block">{state?.trafficSource || 'NOT_CONNECTED'}</span>
              </div>
            </div>

            {/* Row 2: Live Telemetry Counters */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 pt-3 border-t border-white/10 font-mono">
              <div className="flex items-center justify-between rounded-lg bg-[#060810]/70 border border-white/5 px-3 py-2">
                <span className="text-[11px] text-slate-400 uppercase">REQUESTS</span>
                <span className="text-sm font-bold text-slate-100">{state?.requests ?? 0}</span>
              </div>
              <div className="flex items-center justify-between rounded-lg bg-[#060810]/70 border border-white/5 px-3 py-2">
                <span className="text-[11px] text-slate-400 uppercase">ENDPOINTS</span>
                <span className="text-sm font-bold text-slate-100">{state?.endpoints ?? 0}</span>
              </div>
              <div className="flex items-center justify-between rounded-lg bg-[#060810]/70 border border-white/5 px-3 py-2">
                <span className="text-[11px] text-slate-400 uppercase">HYPOTHESES</span>
                <span className="text-sm font-bold text-slate-100">{state?.hypotheses ?? 0}</span>
              </div>
              <div className="flex items-center justify-between rounded-lg bg-[#060810]/70 border border-white/5 px-3 py-2">
                <span className="text-[11px] text-slate-400 uppercase">TESTS</span>
                <span className="text-sm font-bold text-slate-100">{state?.tests ?? 0}</span>
              </div>
              <div className="col-span-2 sm:col-span-1 flex items-center justify-between rounded-lg bg-red-950/30 border border-red-800/35 px-3 py-2">
                <span className="text-[11px] text-red-300 uppercase">FINDINGS</span>
                <span className="text-sm font-bold text-red-300">{state?.findings ?? 0}</span>
              </div>
            </div>
          </div>

          {/* Action Controls Bar — Logically Grouped (Session | Validation | Export | Utility) */}
          <div className="rounded-xl border border-slate-700/60 bg-[#090b14]/84 backdrop-blur-md p-3 sm:p-3.5 sm:px-4 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex flex-col sm:flex-row sm:flex-wrap sm:items-center gap-2.5 sm:gap-3">
              {/* SESSION GROUP */}
              <div className="flex flex-wrap items-center gap-1.5 sm:pr-3 sm:border-r sm:border-white/10 pb-2 sm:pb-0 border-b border-white/10 sm:border-b-0">
                <span className="text-[10px] font-mono uppercase text-slate-400 mr-1 w-full sm:w-auto">Session</span>
                <Btn
                  primary
                  onClick={() => run(() => dhFetch('/start', { method: 'POST', body: '{}' }))}
                  icon={<Play className="w-3.5 h-3.5" />}
                >
                  START HUNT
                </Btn>
                <Btn
                  onClick={() => run(() => dhFetch('/pause', { method: 'POST', body: '{}' }))}
                  icon={<Pause className="w-3.5 h-3.5" />}
                >
                  PAUSE
                </Btn>
                <Btn
                  onClick={() => run(() => dhFetch('/resume', { method: 'POST', body: '{}' }))}
                  icon={<RotateCcw className="w-3.5 h-3.5" />}
                >
                  RESUME
                </Btn>
                <Btn
                  danger
                  onClick={() => run(() => dhFetch('/stop', { method: 'POST', body: '{}' }))}
                  icon={<Square className="w-3.5 h-3.5" />}
                >
                  STOP
                </Btn>
              </div>

              {/* VALIDATION GROUP */}
              <div className="flex flex-wrap items-center gap-1.5 sm:pr-3 sm:border-r sm:border-white/10 pb-2 sm:pb-0 border-b border-white/10 sm:border-b-0">
                <span className="text-[10px] font-mono uppercase text-slate-400 mr-1 w-full sm:w-auto">Validation</span>
                <Btn onClick={() => run(() => dhFetch('/approve', { method: 'POST', body: '{}' }))}>
                  APPROVE TEST
                </Btn>
                <Btn onClick={() => run(() => dhFetch('/reject', { method: 'POST', body: '{}' }))}>
                  REJECT TEST
                </Btn>
              </div>

              {/* EXPORT GROUP */}
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] font-mono uppercase text-slate-400 mr-1 w-full sm:w-auto">Export</span>
                <Btn onClick={() => exportFile('json')} icon={<Download className="w-3.5 h-3.5" />}>
                  JSON
                </Btn>
                <Btn onClick={() => exportFile('csv')} icon={<Download className="w-3.5 h-3.5" />}>
                  CSV
                </Btn>
                <Btn onClick={() => exportFile('md')} icon={<Download className="w-3.5 h-3.5" />}>
                  MD
                </Btn>
              </div>
            </div>

            {/* UTILITY GROUP */}
            <div className="flex items-center justify-end gap-1.5 pt-2 lg:pt-0 border-t border-white/10 lg:border-t-0">
              <Btn
                onClick={() => run(() => dhFetch('/clear-view', { method: 'POST', body: '{}' }))}
                icon={<Trash2 className="w-3.5 h-3.5" />}
              >
                CLEAR VIEW
              </Btn>
            </div>
          </div>

          {/* Human Gate Alert */}
          {state?.pendingApproval && (
            <div className="rounded-xl border border-amber-500/50 bg-amber-950/65 backdrop-blur-md p-4 space-y-2.5 shadow-sm">
              <div className="flex items-center gap-2 text-amber-200 font-semibold text-sm font-mono uppercase">
                <AlertTriangle className="w-4 h-4 text-amber-400" /> HUMAN APPROVAL REQUIRED
              </div>
              <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-2 text-xs font-mono text-slate-200 bg-[#060810]/70 p-3 rounded-lg border border-amber-500/20">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Proposed action</span>
                  <span>{state.pendingApproval.action}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Target</span>
                  <span>{state.pendingApproval.target}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Method</span>
                  <span>{state.pendingApproval.method}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Reason</span>
                  <span>{state.pendingApproval.reason}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Risk</span>
                  <span className="text-amber-300 font-bold">{state.pendingApproval.risk}</span>
                </div>
              </div>
              <div className="flex gap-2 pt-1">
                <Btn primary onClick={() => run(() => dhFetch('/approve', { method: 'POST', body: '{}' }))}>
                  APPROVE
                </Btn>
                <Btn danger onClick={() => run(() => dhFetch('/reject', { method: 'POST', body: '{}' }))}>
                  REJECT
                </Btn>
              </div>
            </div>
          )}

          {/* Compact Manual Traffic Ingest Panel */}
          <div className="rounded-xl border border-slate-700/60 bg-[#090b14]/84 backdrop-blur-md p-4 sm:p-5 space-y-3.5 shadow-[0_12px_32px_-8px_rgba(0,0,0,0.75)]">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-white/10">
              <div>
                <h2 className="text-xs sm:text-sm font-bold font-outfit uppercase tracking-wider text-slate-100">
                  MANUAL TRAFFIC INGEST
                </h2>
                <p className="text-xs text-slate-400">
                  Paste sanitized observations only. Secrets are not accepted by design (names only for params).
                </p>
              </div>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-950/60 border border-amber-700/45 text-amber-300 text-[10px] font-mono font-semibold uppercase shrink-0">
                <Radio className="w-3 h-3" />
                PROXY / CDP NOT CONNECTED
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-3 text-xs font-mono">
              <label className="lg:col-span-2 block text-slate-300">
                <span className="text-[10px] uppercase text-slate-400">method</span>
                <input
                  className="mt-1 w-full rounded-lg bg-[#060810] border border-slate-700/80 focus:border-red-500/60 focus:outline-none px-2.5 py-1.5 text-slate-100"
                  value={ingestForm.method}
                  onChange={(e) => setIngestForm({ ...ingestForm, method: e.target.value })}
                />
              </label>

              <label className="lg:col-span-5 block text-slate-300">
                <span className="text-[10px] uppercase text-slate-400">host</span>
                <input
                  className="mt-1 w-full rounded-lg bg-[#060810] border border-slate-700/80 focus:border-red-500/60 focus:outline-none px-2.5 py-1.5 text-slate-100"
                  value={ingestForm.host}
                  onChange={(e) => setIngestForm({ ...ingestForm, host: e.target.value })}
                />
              </label>

              <label className="lg:col-span-5 block text-slate-300">
                <span className="text-[10px] uppercase text-slate-400">path</span>
                <input
                  className="mt-1 w-full rounded-lg bg-[#060810] border border-slate-700/80 focus:border-red-500/60 focus:outline-none px-2.5 py-1.5 text-slate-100"
                  value={ingestForm.path}
                  onChange={(e) => setIngestForm({ ...ingestForm, path: e.target.value })}
                />
              </label>

              <label className="lg:col-span-3 block text-slate-300">
                <span className="text-[10px] uppercase text-slate-400">category</span>
                <input
                  className="mt-1 w-full rounded-lg bg-[#060810] border border-slate-700/80 focus:border-red-500/60 focus:outline-none px-2.5 py-1.5 text-slate-100"
                  value={ingestForm.category}
                  onChange={(e) => setIngestForm({ ...ingestForm, category: e.target.value })}
                />
              </label>

              <label className="lg:col-span-2 block text-slate-300">
                <span className="text-[10px] uppercase text-slate-400">status</span>
                <input
                  className="mt-1 w-full rounded-lg bg-[#060810] border border-slate-700/80 focus:border-red-500/60 focus:outline-none px-2.5 py-1.5 text-slate-100"
                  value={ingestForm.status}
                  onChange={(e) => setIngestForm({ ...ingestForm, status: e.target.value })}
                />
              </label>

              <label className="lg:col-span-4 block text-slate-300">
                <span className="text-[10px] uppercase text-slate-400">queryParamNames</span>
                <input
                  placeholder="id, page, sort"
                  className="mt-1 w-full rounded-lg bg-[#060810] border border-slate-700/80 focus:border-red-500/60 focus:outline-none px-2.5 py-1.5 text-slate-100 placeholder:text-slate-600"
                  value={ingestForm.queryParamNames}
                  onChange={(e) => setIngestForm({ ...ingestForm, queryParamNames: e.target.value })}
                />
              </label>

              <label className="lg:col-span-3 block text-slate-300">
                <span className="text-[10px] uppercase text-slate-400">bodyKeys</span>
                <input
                  placeholder="userId, role"
                  className="mt-1 w-full rounded-lg bg-[#060810] border border-slate-700/80 focus:border-red-500/60 focus:outline-none px-2.5 py-1.5 text-slate-100 placeholder:text-slate-600"
                  value={ingestForm.bodyKeys}
                  onChange={(e) => setIngestForm({ ...ingestForm, bodyKeys: e.target.value })}
                />
              </label>
            </div>

            <div className="pt-1 flex justify-end">
              <Btn
                primary
                onClick={() =>
                  run(() =>
                    dhFetch('/ingest', {
                      method: 'POST',
                      body: JSON.stringify({
                        method: ingestForm.method,
                        host: ingestForm.host,
                        path: ingestForm.path,
                        category: ingestForm.category,
                        status: Number(ingestForm.status) || null,
                        queryParamNames: ingestForm.queryParamNames
                          .split(',')
                          .map((s) => s.trim())
                          .filter(Boolean),
                        bodyKeys: ingestForm.bodyKeys
                          .split(',')
                          .map((s) => s.trim())
                          .filter(Boolean),
                        authState: 'OWN_ACCOUNT',
                        responseStructure: 'redacted',
                      }),
                    })
                  )
                }
              >
                INGEST OBSERVATION
              </Btn>
            </div>
          </div>

          {/* Balanced Two-Column Monitoring Area: Live Event Stream + Request Inspector */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-stretch">
            {/* Live Event Stream */}
            <div className="rounded-xl border border-slate-700/65 bg-[#070911]/88 backdrop-blur-md p-4 flex flex-col justify-between min-h-[260px] max-h-96 shadow-[0_12px_32px_-8px_rgba(0,0,0,0.75)]">
              <div className="flex items-center justify-between pb-2.5 mb-2.5 border-b border-white/10">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <h2 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                    LIVE EVENT STREAM
                  </h2>
                </div>
                <span className="text-[10px] font-mono text-cyan-400 uppercase flex items-center gap-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                  {(state?.events || []).length} Events
                </span>
              </div>

              <div className="flex-1 overflow-y-auto space-y-1.5 font-mono text-xs pr-1">
                {(state?.events || [])
                  .slice()
                  .reverse()
                  .map((e: any) => (
                    <div
                      key={e.id}
                      className="rounded-lg bg-[#05070d]/90 border border-slate-800/80 px-2.5 py-1.5 flex items-start gap-2"
                    >
                      <span className="text-slate-500 shrink-0">[{e.ts?.slice(11, 19)}]</span>
                      <span className="text-cyan-400 font-semibold shrink-0">{e.kind}</span>
                      <span className="text-slate-200 break-words">{e.message}</span>
                    </div>
                  ))}
                {!state?.events?.length && (
                  <div className="h-full min-h-[160px] flex flex-col items-center justify-center text-center p-4 rounded-lg border border-dashed border-slate-800 bg-[#05070d]/50">
                    <span className="text-xs font-mono text-slate-400">No events yet — press START HUNT</span>
                    <span className="text-[11px] text-slate-500 mt-1">
                      Session telemetry and state transitions will stream here in real time.
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Request Inspector */}
            <div className="rounded-xl border border-slate-700/65 bg-[#070911]/88 backdrop-blur-md p-4 flex flex-col justify-between min-h-[260px] max-h-96 shadow-[0_12px_32px_-8px_rgba(0,0,0,0.75)]">
              <div className="flex items-center justify-between pb-2.5 mb-2.5 border-b border-white/10">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-red-400" />
                  <h2 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                    REQUEST INSPECTOR
                  </h2>
                </div>
                <span className="text-[10px] font-mono text-slate-400 uppercase">
                  {(state?.capturedRequests || []).length} Captured
                </span>
              </div>

              <div className="flex-1 overflow-y-auto space-y-1.5 text-xs pr-1">
                {(state?.capturedRequests || [])
                  .slice()
                  .reverse()
                  .map((r: any) => (
                    <button
                      key={r.id}
                      type="button"
                      className={`block w-full text-left px-3 py-2 rounded-lg border transition-colors font-mono ${
                        selectedReq?.id === r.id
                          ? 'bg-red-950/45 border-red-600/50 text-slate-100'
                          : 'bg-[#05070d]/90 border-slate-800/80 hover:bg-slate-900 text-slate-200'
                      }`}
                      onClick={() => setSelectedReq(r)}
                    >
                      <span className="text-cyan-400 font-bold">{r.method}</span> {r.path}{' '}
                      <span className="text-slate-400 float-right">{r.status}</span>
                    </button>
                  ))}
                {!state?.capturedRequests?.length && (
                  <div className="h-full min-h-[160px] flex flex-col items-center justify-center text-center p-4 rounded-lg border border-dashed border-slate-800 bg-[#05070d]/50">
                    <span className="text-xs font-mono text-slate-300">
                      Awaiting sanitized traffic...
                    </span>
                    <span className="text-[11px] text-slate-500 mt-1">
                      No captured requests — ingest sanitized traffic
                    </span>
                  </div>
                )}

                {selectedReq && (
                  <pre className="mt-2.5 p-3 rounded-lg bg-[#04060b] border border-slate-800 text-[10px] font-mono text-slate-300 whitespace-pre-wrap">
                    {JSON.stringify(selectedReq, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Btn(props: {
  children: React.ReactNode;
  onClick: () => void;
  icon?: React.ReactNode;
  danger?: boolean;
  primary?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-outfit font-bold uppercase tracking-wider border transition-colors cursor-pointer ${
        props.primary
          ? 'bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white border-red-400/30 shadow-[0_4px_14px_rgba(220,38,38,0.35)]'
          : props.danger
            ? 'bg-rose-950/85 hover:bg-rose-900 text-rose-200 border-rose-700/60'
            : 'bg-slate-900/90 hover:bg-slate-800 text-slate-200 border-slate-700/70 hover:border-slate-500/70'
      }`}
    >
      {props.icon}
      {props.children}
    </button>
  );
}

export default DevilHuntLiveConsoleView;
