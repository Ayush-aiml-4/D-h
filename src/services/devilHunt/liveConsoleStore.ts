/**
 * Devil Hunt live research console — in-memory + JSON file persistence.
 * No fake traffic. No secrets in events/exports.
 */
import fs from 'fs';
import path from 'path';

export type HuntStatus = 'IDLE' | 'RUNNING' | 'PAUSED' | 'STOPPED' | 'WAITING_APPROVAL';
export type HuntMode = 'OBSERVE' | 'VALIDATE';

export interface HuntEvent {
  id: string;
  ts: string;
  kind: 'SYSTEM' | 'SCOPE' | 'TRAFFIC' | 'ANALYZER' | 'HYPOTHESIS' | 'APPROVAL' | 'TEST' | 'BLOCK' | 'EXPORT' | 'CONTROL';
  message: string;
  meta?: Record<string, string | number | boolean | null>;
}

export interface CapturedRequest {
  id: string;
  ts: string;
  method: string;
  host: string;
  path: string;
  queryParamNames: string[];
  bodyKeys: string[];
  status: number | null;
  responseHeaderNames: string[];
  responseStructure: string;
  category: string;
  authState: string;
}

export interface Hypothesis {
  id: string;
  endpoint: string;
  parameter?: string;
  reason: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  status: 'OPEN' | 'APPROVED' | 'REJECTED' | 'TESTED' | 'CLOSED';
}

export interface PendingApproval {
  id: string;
  action: string;
  target: string;
  method: string;
  reason: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  createdAt: string;
}

export interface DevilHuntState {
  huntId: string;
  target: string;
  scope: 'CONFIRMED' | 'UNCONFIRMED' | 'BLOCKED';
  mode: HuntMode;
  status: HuntStatus;
  trafficSource: 'NOT_CONNECTED' | 'MANUAL_INGEST' | 'PROXY' | 'CDP';
  requests: number;
  endpoints: number;
  hypotheses: number;
  tests: number;
  findings: number;
  events: HuntEvent[];
  capturedRequests: CapturedRequest[];
  hypothesisList: Hypothesis[];
  pendingApproval: PendingApproval | null;
  endpointSet: string[];
  allowedHosts: string[];
}

const DATA_DIR = path.join(process.cwd(), 'data');
const STORE_FILE = path.join(DATA_DIR, 'devil-hunt-console.json');

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function defaultState(): DevilHuntState {
  return {
    huntId: '003',
    target: 'supplier.meesho.com',
    scope: 'CONFIRMED',
    mode: 'OBSERVE',
    status: 'IDLE',
    trafficSource: 'NOT_CONNECTED',
    requests: 0,
    endpoints: 0,
    hypotheses: 0,
    tests: 0,
    findings: 0,
    events: [],
    capturedRequests: [],
    hypothesisList: [],
    pendingApproval: null,
    endpointSet: [],
    allowedHosts: [
      'supplier.meesho.com',
      'www.meesho.com',
      'affiliate.meesho.com',
      'admin.meeshosupply.com',
      'prod.meeshoapi.com',
      'www.valmo.in',
      'superstoreapp.meesho.com',
      'investor.meesho.com',
      'meesho.io',
    ],
  };
}

let state: DevilHuntState = defaultState();

function persist() {
  try {
    ensureDir();
    fs.writeFileSync(STORE_FILE, JSON.stringify(state, null, 2), 'utf8');
  } catch {
    /* best-effort */
  }
}

function load() {
  try {
    if (fs.existsSync(STORE_FILE)) {
      const raw = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
      state = { ...defaultState(), ...raw };
    }
  } catch {
    state = defaultState();
  }
}

load();

function pushEvent(
  kind: HuntEvent['kind'],
  message: string,
  meta?: HuntEvent['meta']
) {
  const ev: HuntEvent = {
    id: `ev_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    ts: new Date().toISOString(),
    kind,
    message,
    meta,
  };
  state.events.push(ev);
  if (state.events.length > 2000) state.events = state.events.slice(-2000);
  persist();
  return ev;
}

export function getDevilHuntState(): DevilHuntState {
  return structuredClone(state);
}

export function startHunt(opts?: { huntId?: string; target?: string }) {
  if (opts?.huntId) state.huntId = opts.huntId;
  if (opts?.target) {
    const host = opts.target.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
    if (!state.allowedHosts.includes(host)) {
      pushEvent('BLOCK', `OUT_OF_SCOPE_BLOCKED: ${host}`);
      return { ok: false, error: 'OUT_OF_SCOPE_BLOCKED', state: getDevilHuntState() };
    }
    state.target = host;
  }
  state.status = 'RUNNING';
  state.mode = 'OBSERVE';
  state.scope = 'CONFIRMED';
  pushEvent('SYSTEM', `Hunt #${state.huntId} started`);
  pushEvent('SCOPE', `${state.target} confirmed in allowlist`);
  pushEvent('SYSTEM', 'TRAFFIC SOURCE: NOT CONNECTED — use manual ingest or connect proxy/CDP');
  persist();
  return { ok: true, state: getDevilHuntState() };
}

export function pauseHunt() {
  if (state.status === 'STOPPED') return { ok: false, error: 'STOPPED', state: getDevilHuntState() };
  state.status = 'PAUSED';
  pushEvent('CONTROL', 'Hunt paused — no new active actions');
  persist();
  return { ok: true, state: getDevilHuntState() };
}

export function resumeHunt() {
  if (state.status === 'STOPPED') return { ok: false, error: 'STOPPED', state: getDevilHuntState() };
  if (state.pendingApproval) {
    state.status = 'WAITING_APPROVAL';
  } else {
    state.status = 'RUNNING';
  }
  pushEvent('CONTROL', 'Hunt resumed');
  persist();
  return { ok: true, state: getDevilHuntState() };
}

export function stopHunt() {
  state.status = 'STOPPED';
  state.pendingApproval = null;
  pushEvent('CONTROL', 'Hunt STOPPED — further actions blocked until START');
  persist();
  return { ok: true, state: getDevilHuntState() };
}

export function clearView() {
  state.events = [];
  pushEvent('SYSTEM', 'Event view cleared (persisted requests/hypotheses retained)');
  persist();
  return { ok: true, state: getDevilHuntState() };
}

function scopeCheck(host: string): boolean {
  const h = host.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  if (h !== state.target.toLowerCase() && !state.allowedHosts.includes(h)) return false;
  // Hard: active hunt only allows selected target for traffic attribution
  return h === state.target.toLowerCase();
}

export function ingestRequest(input: {
  method: string;
  host: string;
  path: string;
  queryParamNames?: string[];
  bodyKeys?: string[];
  status?: number | null;
  responseHeaderNames?: string[];
  responseStructure?: string;
  category?: string;
  authState?: string;
}) {
  if (state.status === 'STOPPED') {
    return { ok: false, error: 'HUNT_STOPPED', state: getDevilHuntState() };
  }
  if (state.status === 'PAUSED') {
    return { ok: false, error: 'HUNT_PAUSED', state: getDevilHuntState() };
  }
  if (state.status === 'IDLE') {
    return { ok: false, error: 'HUNT_NOT_STARTED', state: getDevilHuntState() };
  }

  const host = (input.host || '').replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  if (!scopeCheck(host)) {
    pushEvent('BLOCK', `OUT_OF_SCOPE_BLOCKED host=${host}`);
    persist();
    return { ok: false, error: 'OUT_OF_SCOPE_BLOCKED', state: getDevilHuntState() };
  }

  const req: CapturedRequest = {
    id: `req_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    ts: new Date().toISOString(),
    method: (input.method || 'GET').toUpperCase().slice(0, 16),
    host,
    path: (input.path || '/').slice(0, 512),
    queryParamNames: (input.queryParamNames || []).map(String).slice(0, 40),
    bodyKeys: (input.bodyKeys || []).map(String).slice(0, 40),
    status: input.status ?? null,
    responseHeaderNames: (input.responseHeaderNames || []).map(String).slice(0, 40),
    responseStructure: (input.responseStructure || 'unknown').slice(0, 200),
    category: (input.category || 'OTHER').slice(0, 64),
    authState: (input.authState || 'UNKNOWN').slice(0, 64),
  };

  state.capturedRequests.push(req);
  state.requests = state.capturedRequests.length;
  const epKey = `${req.method} ${req.path}`;
  if (!state.endpointSet.includes(epKey)) {
    state.endpointSet.push(epKey);
    state.endpoints = state.endpointSet.length;
  }

  pushEvent('TRAFFIC', `${req.method} ${req.path} ${req.status ?? ''} ${req.category}`.trim(), {
    method: req.method,
    path: req.path,
    status: req.status,
  });

  // Analyzer: flag object-like param names as hypothesis candidates only (not findings)
  const idLike = [...req.queryParamNames, ...req.bodyKeys].find((p) =>
    /id$|Id$|ID$|resource|order|address|user|account/i.test(p)
  );
  if (idLike && state.status === 'RUNNING') {
    pushEvent('ANALYZER', `Resource identifier name detected: ${idLike}`);
    const hypId = `hyp_${Date.now()}`;
    const hyp: Hypothesis = {
      id: hypId,
      endpoint: epKey,
      parameter: idLike,
      reason: 'Client-visible object parameter name — not a finding; authorization boundary candidate only',
      risk: 'LOW',
      status: 'OPEN',
    };
    state.hypothesisList.push(hyp);
    state.hypotheses = state.hypothesisList.length;
    pushEvent('HYPOTHESIS', `Authorization boundary candidate on ${epKey} param=${idLike}`);

    state.pendingApproval = {
      id: `apr_${Date.now()}`,
      action: 'Propose minimal own-account authorization review (no ID substitution)',
      target: `${host}${req.path}`,
      method: req.method,
      reason: hyp.reason,
      risk: 'LOW',
      createdAt: new Date().toISOString(),
    };
    state.status = 'WAITING_APPROVAL';
    pushEvent('APPROVAL', 'WAITING FOR HUMAN APPROVAL', { approvalId: state.pendingApproval.id });
  }

  state.trafficSource = 'MANUAL_INGEST';
  persist();
  return { ok: true, request: req, state: getDevilHuntState() };
}

export function approveTest() {
  if (!state.pendingApproval) {
    return { ok: false, error: 'NO_PENDING_APPROVAL', state: getDevilHuntState() };
  }
  if (state.status === 'STOPPED') {
    return { ok: false, error: 'HUNT_STOPPED', state: getDevilHuntState() };
  }
  const apr = state.pendingApproval;
  pushEvent('APPROVAL', `APPROVED: ${apr.action}`, { approvalId: apr.id });
  // Record test slot without generating fake exploit traffic
  state.tests += 1;
  pushEvent(
    'TEST',
    'Approval recorded — no automated cross-account test executed (operator must validate manually under policy)'
  );
  state.pendingApproval = null;
  state.status = 'RUNNING';
  state.mode = 'VALIDATE';
  persist();
  return { ok: true, state: getDevilHuntState() };
}

export function rejectTest() {
  if (!state.pendingApproval) {
    return { ok: false, error: 'NO_PENDING_APPROVAL', state: getDevilHuntState() };
  }
  pushEvent('APPROVAL', `REJECTED: ${state.pendingApproval.action}`, {
    approvalId: state.pendingApproval.id,
  });
  state.pendingApproval = null;
  if (state.status !== 'STOPPED') state.status = 'RUNNING';
  persist();
  return { ok: true, state: getDevilHuntState() };
}

export function exportJSON(): string {
  const payload = {
    hunt: state.huntId,
    target: state.target,
    scope: state.scope,
    mode: state.mode,
    status: state.status,
    trafficSource: state.trafficSource,
    counts: {
      requests: state.requests,
      endpoints: state.endpoints,
      hypotheses: state.hypotheses,
      tests: state.tests,
      findings: state.findings,
    },
    events: state.events,
    requests: state.capturedRequests,
    endpoints: state.endpointSet,
    hypotheses: state.hypothesisList,
    approvals: state.pendingApproval ? [state.pendingApproval] : [],
    tests: [],
    findings: [],
  };
  pushEvent('EXPORT', 'JSON export generated');
  return JSON.stringify(payload, null, 2);
}

export function exportCSV(): string {
  const rows = [['timestamp', 'method', 'host', 'path', 'status', 'category', 'hypothesis', 'action', 'result']];
  for (const r of state.capturedRequests) {
    rows.push([
      r.ts,
      r.method,
      r.host,
      r.path,
      String(r.status ?? ''),
      r.category,
      '',
      'INGEST',
      'OBSERVED',
    ]);
  }
  for (const e of state.events) {
    if (e.kind === 'HYPOTHESIS' || e.kind === 'APPROVAL' || e.kind === 'TEST') {
      rows.push([e.ts, '', '', '', '', e.kind, e.message.slice(0, 120), e.kind, '']);
    }
  }
  pushEvent('EXPORT', 'CSV export generated');
  return rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
}

export function exportMarkdown(): string {
  const lines = [
    `# Devil Hunt — Hunt #${state.huntId}`,
    '',
    `- **Target:** ${state.target}`,
    `- **Scope:** ${state.scope}`,
    `- **Mode:** ${state.mode}`,
    `- **Status:** ${state.status}`,
    `- **Traffic source:** ${state.trafficSource}`,
    `- **Requests:** ${state.requests}`,
    `- **Endpoints:** ${state.endpoints}`,
    `- **Hypotheses:** ${state.hypotheses}`,
    `- **Tests:** ${state.tests}`,
    `- **Findings:** ${state.findings} (none invented)`,
    '',
    '## Events',
    '',
  ];
  for (const e of state.events.slice(-100)) {
    lines.push(`- \`[${e.ts}]\` **${e.kind}** ${e.message}`);
  }
  lines.push('', '## Requests (redacted metadata only)', '');
  for (const r of state.capturedRequests) {
    lines.push(
      `- \`${r.method} ${r.host}${r.path}\` status=${r.status ?? 'n/a'} category=${r.category}`
    );
  }
  lines.push('', '## Note', '', 'No vulnerability claimed without demonstrated security impact.', '');
  pushEvent('EXPORT', 'Markdown export generated');
  return lines.join('\n');
}
