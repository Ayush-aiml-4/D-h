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
} from 'lucide-react';

const API = '/api/v1/devil-hunt';
const AUTH = 'Bearer mock-token:user-ayush-001:ADMIN:Ayush';

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

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4 text-slate-100">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-7 h-7 text-rose-400" />
          <div>
            <h1 className="text-xl font-semibold tracking-wide">DEVIL HUNT</h1>
            <p className="text-xs text-slate-500">Live research console — no fabricated findings</p>
          </div>
        </div>
        <span className="font-mono text-sm text-cyan-300">HUNT #{state?.huntId || '—'}</span>
      </div>

      {error && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-100">
          {error}
        </div>
      )}

      {/* Status panel */}
      <div className="rounded-xl border border-slate-700 bg-slate-900/80 p-4 font-mono text-sm space-y-1">
        <div className="flex justify-between">
          <span className="text-slate-500">TARGET</span>
          <span>{state?.target || '—'}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">SCOPE</span>
          <span>{state?.scope || '—'}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">MODE</span>
          <span>{state?.mode || '—'}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">STATUS</span>
          <span className={statusColor}>● {state?.status || 'IDLE'}</span>
        </div>
        <div className="flex justify-between border-t border-slate-700 pt-2 mt-2">
          <span className="text-slate-500">REQUESTS</span>
          <span>{state?.requests ?? 0}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">ENDPOINTS</span>
          <span>{state?.endpoints ?? 0}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">HYPOTHESES</span>
          <span>{state?.hypotheses ?? 0}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">TESTS</span>
          <span>{state?.tests ?? 0}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">FINDINGS</span>
          <span>{state?.findings ?? 0}</span>
        </div>
        <div className="flex justify-between border-t border-slate-700 pt-2 mt-2">
          <span className="text-slate-500">TRAFFIC SOURCE</span>
          <span className="text-amber-300">{state?.trafficSource || 'NOT_CONNECTED'}</span>
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-2">
        <Btn onClick={() => run(() => dhFetch('/start', { method: 'POST', body: '{}' }))} icon={<Play className="w-3 h-3" />}>
          START HUNT
        </Btn>
        <Btn onClick={() => run(() => dhFetch('/pause', { method: 'POST', body: '{}' }))} icon={<Pause className="w-3 h-3" />}>
          PAUSE
        </Btn>
        <Btn onClick={() => run(() => dhFetch('/resume', { method: 'POST', body: '{}' }))} icon={<RotateCcw className="w-3 h-3" />}>
          RESUME
        </Btn>
        <Btn danger onClick={() => run(() => dhFetch('/stop', { method: 'POST', body: '{}' }))} icon={<Square className="w-3 h-3" />}>
          STOP
        </Btn>
        <Btn onClick={() => run(() => dhFetch('/approve', { method: 'POST', body: '{}' }))}>APPROVE TEST</Btn>
        <Btn onClick={() => run(() => dhFetch('/reject', { method: 'POST', body: '{}' }))}>REJECT TEST</Btn>
        <Btn onClick={() => exportFile('json')} icon={<Download className="w-3 h-3" />}>
          JSON
        </Btn>
        <Btn onClick={() => exportFile('csv')} icon={<Download className="w-3 h-3" />}>
          CSV
        </Btn>
        <Btn onClick={() => exportFile('md')} icon={<Download className="w-3 h-3" />}>
          MD
        </Btn>
        <Btn onClick={() => run(() => dhFetch('/clear-view', { method: 'POST', body: '{}' }))} icon={<Trash2 className="w-3 h-3" />}>
          CLEAR VIEW
        </Btn>
      </div>

      {/* Human gate */}
      {state?.pendingApproval && (
        <div className="rounded-xl border border-amber-500/50 bg-amber-950/40 p-4 space-y-2">
          <div className="flex items-center gap-2 text-amber-200 font-semibold">
            <AlertTriangle className="w-5 h-5" /> HUMAN APPROVAL REQUIRED
          </div>
          <div className="text-sm space-y-1 text-slate-300">
            <div>
              <span className="text-slate-500">Proposed action:</span> {state.pendingApproval.action}
            </div>
            <div>
              <span className="text-slate-500">Target:</span> {state.pendingApproval.target}
            </div>
            <div>
              <span className="text-slate-500">Method:</span> {state.pendingApproval.method}
            </div>
            <div>
              <span className="text-slate-500">Reason:</span> {state.pendingApproval.reason}
            </div>
            <div>
              <span className="text-slate-500">Risk:</span> {state.pendingApproval.risk}
            </div>
          </div>
          <div className="flex gap-2 pt-2">
            <Btn onClick={() => run(() => dhFetch('/approve', { method: 'POST', body: '{}' }))}>APPROVE</Btn>
            <Btn danger onClick={() => run(() => dhFetch('/reject', { method: 'POST', body: '{}' }))}>
              REJECT
            </Btn>
          </div>
        </div>
      )}

      {/* Manual ingest — explicit not-connected traffic path */}
      <div className="rounded-xl border border-slate-700 bg-slate-900/60 p-4 space-y-3">
        <h2 className="text-sm font-semibold text-cyan-300 uppercase tracking-wide">
          Manual traffic ingest (proxy/CDP not connected)
        </h2>
        <p className="text-xs text-slate-500">
          Paste sanitized observations only. Secrets are not accepted by design (names only for params).
        </p>
        <div className="grid md:grid-cols-3 gap-2 text-xs">
          {(['method', 'host', 'path', 'category', 'status', 'queryParamNames', 'bodyKeys'] as const).map((k) => (
            <label key={k} className="block text-slate-400">
              {k}
              <input
                className="mt-1 w-full rounded bg-slate-950 border border-slate-600 px-2 py-1 text-slate-200"
                value={(ingestForm as any)[k]}
                onChange={(e) => setIngestForm({ ...ingestForm, [k]: e.target.value })}
              />
            </label>
          ))}
        </div>
        <Btn
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

      <div className="grid md:grid-cols-2 gap-4">
        {/* Event stream */}
        <div className="rounded-xl border border-slate-700 bg-slate-950/80 p-3 max-h-96 overflow-y-auto">
          <h2 className="text-xs font-semibold text-slate-400 uppercase mb-2">Live event stream</h2>
          <div className="space-y-1 font-mono text-[11px]">
            {(state?.events || [])
              .slice()
              .reverse()
              .map((e: any) => (
                <div key={e.id} className="border-b border-slate-800/80 py-1">
                  <span className="text-slate-600">[{e.ts?.slice(11, 19)}]</span>{' '}
                  <span className="text-cyan-500">{e.kind}</span> {e.message}
                </div>
              ))}
            {!state?.events?.length && <p className="text-slate-600">No events yet — press START HUNT</p>}
          </div>
        </div>

        {/* Request inspector list */}
        <div className="rounded-xl border border-slate-700 bg-slate-950/80 p-3 max-h-96 overflow-y-auto">
          <h2 className="text-xs font-semibold text-slate-400 uppercase mb-2">Request inspector</h2>
          <div className="space-y-1 text-xs">
            {(state?.capturedRequests || [])
              .slice()
              .reverse()
              .map((r: any) => (
                <button
                  key={r.id}
                  type="button"
                  className="block w-full text-left px-2 py-1 rounded hover:bg-slate-800 font-mono"
                  onClick={() => setSelectedReq(r)}
                >
                  {r.method} {r.path} <span className="text-slate-500">{r.status}</span>
                </button>
              ))}
            {!state?.capturedRequests?.length && (
              <p className="text-slate-600">No captured requests — ingest sanitized traffic</p>
            )}
          </div>
          {selectedReq && (
            <pre className="mt-3 text-[10px] text-slate-400 whitespace-pre-wrap border-t border-slate-800 pt-2">
              {JSON.stringify(selectedReq, null, 2)}
            </pre>
          )}
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
}) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium ${
        props.danger ? 'bg-rose-700/80 hover:bg-rose-600' : 'bg-slate-800 hover:bg-slate-700'
      }`}
    >
      {props.icon}
      {props.children}
    </button>
  );
}

export default DevilHuntLiveConsoleView;
