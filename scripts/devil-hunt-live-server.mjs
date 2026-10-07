/**
 * Devil Hunt Live Console + Phase 2 passive traffic bridge
 * Port 3000 — pure Node. No fake Meesho traffic.
 */
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import net from 'net';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const STORE_FILE = path.join(DATA_DIR, 'devil-hunt-console.json');
const PORT = Number(process.env.PORT || 3000);
const PROXY_PORT = Number(process.env.DH_PROXY_PORT || 8890);

function defaultState() {
  return {
    huntId: '003',
    target: 'supplier.meesho.com',
    scope: 'CONFIRMED',
    mode: 'OBSERVE',
    status: 'IDLE',
    sessionType: 'REAL', // REAL | DEMO
    trafficSource: 'NOT_CONNECTED',
    trafficConnection: 'DISCONNECTED',
    sensorConnection: 'DISCONNECTED',
    trafficState: 'WAITING',
    trafficEventsReceived: 0,
    trafficLastEvent: null,
    trafficError: null,
    // REAL hunt counters only
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
    outOfScopeDiscoveries: [],
    // Demo history retained separately — never mixed into real counters
    demo: {
      events: [],
      capturedRequests: [],
      hypotheses: [],
      requests: 0,
      endpoints: 0,
      tests: 0,
    },
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

let state = defaultState();
try {
  if (fs.existsSync(STORE_FILE)) {
    state = { ...defaultState(), ...JSON.parse(fs.readFileSync(STORE_FILE, 'utf8')) };
  }
} catch {}



function persist() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(STORE_FILE, JSON.stringify(state, null, 2));
  } catch {}
}

function pushEvent(kind, message, meta) {
  const ev = {
    id: `ev_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    ts: new Date().toISOString(),
    kind,
    message,
    meta: meta || undefined,
  };
  state.events.push(ev);
  if (state.events.length > 2000) state.events = state.events.slice(-2000);
  persist();
  return ev;
}

function sanitizeHost(h) {
  return String(h || '')
    .replace(/^https?:\/\//i, '')
    .split('/')[0]
    .split(':')[0]
    .toLowerCase();
}

function isDemoHost(host) {
  const h = String(host || '').replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase();
  return h === '127.0.0.1' || h === 'localhost';
}

function archiveDemoFromMixedState() {
  if (!state.demo) state.demo = { events: [], capturedRequests: [], hypotheses: [], requests: 0, endpoints: 0, tests: 0 };
  const all = state.capturedRequests || [];
  const demoReqs = all.filter((r) => isDemoHost(r.host));
  const realReqs = all.filter((r) => !isDemoHost(r.host) && sanitizeHost(r.host) === 'supplier.meesho.com');
  if (demoReqs.length) {
    state.demo.capturedRequests = (state.demo.capturedRequests || []).concat(demoReqs);
    state.demo.requests = state.demo.capturedRequests.length;
  }
  state.capturedRequests = realReqs;
  state.requests = realReqs.length;
  state.endpointSet = [...new Set(realReqs.map((r) => r.method + ' ' + r.path))];
  state.endpoints = state.endpointSet.length;
  state.hypothesisList = [];
  state.hypotheses = 0;
  state.tests = 0;
  state.findings = 0;
  state.pendingApproval = null;
  state.mode = 'OBSERVE';
  state.sessionType = 'REAL';
  state.target = 'supplier.meesho.com';
}

function resetRealHunt003() {
  archiveDemoFromMixedState();
  state.huntId = '003';
  state.target = 'supplier.meesho.com';
  state.scope = 'CONFIRMED';
  state.mode = 'OBSERVE';
  state.status = 'IDLE';
  state.sessionType = 'REAL';
  state.trafficSource = 'NOT_CONNECTED';
  state.trafficConnection = 'DISCONNECTED';
  state.sensorConnection = 'DISCONNECTED';
  state.trafficState = 'WAITING';
  state.connectedAt = null;
  state.trafficEventsReceived = 0;
  state.trafficLastEvent = null;
  state.trafficError = null;
  state.requests = 0;
  state.endpoints = 0;
  state.hypotheses = 0;
  state.tests = 0;
  state.findings = 0;
  state.events = [{
    id: 'ev_reset_' + Date.now(),
    ts: new Date().toISOString(),
    kind: 'SYSTEM',
    message: 'Hunt #003 REAL session ready — MODE OBSERVE — counters zeroed (demo archived separately)',
  }];
  state.capturedRequests = [];
  state.hypothesisList = [];
  state.pendingApproval = null;
  state.endpointSet = [];
  state.outOfScopeDiscoveries = [];
  persist();
}



function isTargetHost(host) {
  return sanitizeHost(host) === sanitizeHost(state.target);
}

function isAllowedHost(host) {
  const h = sanitizeHost(host);
  return state.allowedHosts.includes(h) || h === '127.0.0.1' || h === 'localhost';
}

/** Redact secret-like keys from name lists only (values never stored from bridge) */
function sanitizeParamNames(names) {
  const deny = /cookie|auth|token|password|otp|secret|session|authorization|api[_-]?key|bearer/i;
  return (names || []).map(String).filter((n) => !deny.test(n)).slice(0, 40);
}

function canIngestTraffic() {
  if (state.status === 'STOPPED') return { ok: false, error: 'HUNT_STOPPED' };
  if (state.status === 'PAUSED') return { ok: false, error: 'HUNT_PAUSED' };
  if (state.status === 'IDLE') return { ok: false, error: 'HUNT_NOT_STARTED' };
  if (state.trafficConnection !== 'CONNECTED' && state.trafficConnection !== 'CONNECTING') {
    return { ok: false, error: 'TRAFFIC_NOT_CONNECTED' };
  }
  return { ok: true };
}

function ingestTraffic(body, sourceLabel) {
  const gate = canIngestTraffic();
  // Allow CONNECTING → first event flips to CONNECTED
  if (!gate.ok && !(state.trafficConnection === 'CONNECTING' && state.status === 'RUNNING')) {
    if (state.status === 'IDLE') return { ok: false, error: 'HUNT_NOT_STARTED', state };
    if (state.status === 'STOPPED') return { ok: false, error: 'HUNT_STOPPED', state };
    if (state.status === 'PAUSED') return { ok: false, error: 'HUNT_PAUSED', state };
    return { ok: false, error: gate.error || 'TRAFFIC_NOT_CONNECTED', state };
  }

  const host = sanitizeHost(body.host);
  if (!host) return { ok: false, error: 'HOST_REQUIRED', state };

  // DEMO traffic: localhost only — never counts as real Hunt #003 research
  if (isDemoHost(host)) {
    if (!state.demo) state.demo = { events: [], capturedRequests: [], hypotheses: [], requests: 0, endpoints: 0, tests: 0 };
    const req = {
      id: `demo_${Date.now()}`,
      ts: new Date().toISOString(),
      method: String(body.method || 'GET').toUpperCase().slice(0, 16),
      host,
      path: String(body.path || '/').slice(0, 512),
      queryParamNames: sanitizeParamNames(body.queryParamNames),
      bodyKeys: sanitizeParamNames(body.bodyKeys),
      status: typeof body.status === 'number' ? body.status : null,
      category: String(body.category || 'DEMO').slice(0, 64),
      authState: 'DEMO',
      source: 'DEMO',
    };
    state.demo.capturedRequests.push(req);
    state.demo.requests = state.demo.capturedRequests.length;
    state.demo.events.push({
      id: `ev_demo_${Date.now()}`,
      ts: req.ts,
      kind: 'TRAFFIC',
      message: `[DEMO] ${req.method} ${req.host} ${req.path} ${req.status ?? ''}`,
    });
    // Surface in UI stream but tagged DEMO — do NOT increment real counters
    state.trafficEventsReceived = (state.trafficEventsReceived || 0) + 1;
    state.trafficLastEvent = req.ts;
    state.trafficState = 'RECEIVING';
    pushEvent('TRAFFIC', `[DEMO] ${req.method} ${req.host} ${req.path} STATUS ${req.status ?? 'n/a'} (not counted in REAL hunt)`);
    state.sessionType = state.sessionType === 'REAL' && state.requests === 0 ? 'REAL' : state.sessionType;
    persist();
    return { ok: true, request: req, source: 'DEMO', state };
  }

  if (!isTargetHost(host)) {
    const disc = { host, path: String(body.path || '/').slice(0, 200), ts: new Date().toISOString() };
    state.outOfScopeDiscoveries.push(disc);
    pushEvent('BLOCK', `OUT_OF_SCOPE_DISCOVERY host=${host} path=${disc.path}`);
    persist();
    return { ok: false, error: 'OUT_OF_SCOPE_DISCOVERY', discovery: disc, state };
  }

  state.sessionType = 'REAL';

  if (state.trafficConnection === 'CONNECTING') {
    state.trafficConnection = 'CONNECTED';
    state.trafficSource = sourceLabel || 'BROWSER_BRIDGE';
    state.trafficError = null;
    pushEvent('SYSTEM', `TRAFFIC CONNECTED via ${state.trafficSource}`);
  }

  const req = {
    id: `req_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    ts: new Date().toISOString(),
    method: String(body.method || 'GET').toUpperCase().slice(0, 16),
    host,
    path: String(body.path || '/').slice(0, 512),
    queryParamNames: sanitizeParamNames(body.queryParamNames),
    bodyKeys: sanitizeParamNames(body.bodyKeys),
    status: typeof body.status === 'number' ? body.status : null,
    responseHeaderNames: sanitizeParamNames(body.responseHeaderNames || []),
    responseStructure: String(body.responseStructure || body.contentType || 'unknown').slice(0, 200),
    category: String(body.category || 'OTHER').slice(0, 64),
    authState: String(body.authState || 'UNKNOWN').slice(0, 64),
    requestSize: typeof body.requestSize === 'number' ? body.requestSize : null,
    responseSize: typeof body.responseSize === 'number' ? body.responseSize : null,
    contentType: String(body.contentType || '').slice(0, 120),
  };

  state.capturedRequests.push(req);
  state.requests = state.capturedRequests.length;
  state.trafficEventsReceived += 1;
  state.trafficLastEvent = req.ts;
  state.trafficState = 'RECEIVING';
  if (state.sensorConnection === 'CONNECTED') state.trafficConnection = 'CONNECTED';

  const epKey = `${req.method} ${req.path}`;
  if (!state.endpointSet.includes(epKey)) {
    state.endpointSet.push(epKey);
    state.endpoints = state.endpointSet.length;
  }

  const paramStr = [...req.queryParamNames, ...req.bodyKeys].join(',') || 'none';
  pushEvent(
    'TRAFFIC',
    `${req.method} ${req.host} ${req.path} STATUS ${req.status ?? 'n/a'} CATEGORY ${req.category} PARAMETERS: ${paramStr}`
  );

  if (state.status !== 'PAUSED' && state.status !== 'STOPPED') {
    const idLike = [...req.queryParamNames, ...req.bodyKeys].find((p) =>
      /id$|Id$|ID$|resource|order|address|user|account/i.test(p)
    );
    if (idLike) {
      pushEvent('ANALYZER', `Resource identifier detected: ${idLike}`);
      state.hypothesisList.push({
        id: `hyp_${Date.now()}`,
        endpoint: epKey,
        parameter: idLike,
        reason: 'Object-level authorization boundary candidate (observation only)',
        risk: 'LOW',
        status: 'OPEN',
      });
      state.hypotheses = state.hypothesisList.length;
      pushEvent('HYPOTHESIS', `Signal on ${epKey} param=${idLike} — OBSERVATION ONLY`);
      if (!state.pendingApproval && state.status === 'RUNNING') {
        state.pendingApproval = {
          id: `apr_${Date.now()}`,
          action: 'PROPOSE TEST: own-account authorization review only (no ID substitution)',
          target: `${host}${req.path}`,
          method: req.method,
          reason: `Parameter ${idLike} observed in authenticated-looking flow — not a finding`,
          risk: 'LOW',
          createdAt: new Date().toISOString(),
        };
        state.status = 'WAITING_APPROVAL';
        pushEvent('APPROVAL', 'WAITING FOR HUMAN APPROVAL');
      }
    }
  }

  persist();
  return { ok: true, request: req, state };
}

function json(res, code, obj) {
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve) => {
    let d = '';
    req.on('data', (c) => {
      d += c;
      if (d.length > 1e6) d = d.slice(0, 1e6);
    });
    req.on('end', () => {
      try {
        resolve(d ? JSON.parse(d) : {});
      } catch {
        resolve({});
      }
    });
  });
}

function exportJSON() {
  return JSON.stringify(
    {
      hunt: state.huntId,
      target: state.target,
      scope: state.scope,
      trafficSource: state.trafficSource,
      trafficConnection: state.trafficConnection,
      events: state.events,
      requests: state.capturedRequests,
      endpoints: state.endpointSet,
      hypotheses: state.hypothesisList,
      outOfScopeDiscoveries: state.outOfScopeDiscoveries,
      approvals: state.pendingApproval ? [state.pendingApproval] : [],
      tests: [],
      findings: [],
    },
    null,
    2
  );
}

function exportCSV() {
  const rows = [['timestamp', 'method', 'host', 'path', 'status', 'category', 'hypothesis', 'action', 'result']];
  for (const r of state.capturedRequests) {
    rows.push([r.ts, r.method, r.host, r.path, String(r.status ?? ''), r.category, '', 'CAPTURE', 'OBSERVED']);
  }
  return rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
}

function exportMD() {
  const lines = [
    `# Devil Hunt #${state.huntId}`,
    `Target: ${state.target}`,
    `Traffic: ${state.trafficConnection} / ${state.trafficSource}`,
    `Findings: ${state.findings}`,
    '',
    '## Timeline',
  ];
  for (const e of state.events) {
    lines.push(`- \`[${e.ts}]\` **${e.kind}** ${e.message}`);
  }
  return lines.join('\n');
}

const HTML = fs.readFileSync
  ? null
  : null;

// Inline UI (Phase 2 connection panel)
const PAGE = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>Devil Hunt Live</title>
<style>
body{font-family:ui-monospace,monospace;background:#0b0f17;color:#e2e8f0;margin:0;padding:1.2rem}
h1{color:#fb7185;margin:0}.sub{color:#64748b;font-size:12px;margin-bottom:1rem}
.panel{border:1px solid #334155;background:#0f172a;border-radius:12px;padding:1rem;margin-bottom:1rem}
.row{display:flex;justify-content:space-between;padding:.15rem 0}.muted{color:#64748b}
.ok{color:#34d399}.warn{color:#fbbf24}.bad{color:#f87171}
.btn{background:#1e293b;border:1px solid #475569;color:#e2e8f0;border-radius:8px;padding:.4rem .7rem;margin:.15rem;cursor:pointer;font-size:12px}
.btn.danger{background:#7f1d1d}.btn:hover{filter:brightness(1.1)}
.stream{max-height:260px;overflow:auto;font-size:11px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
.gate{border-color:#b45309;background:#451a03}
a{color:#38bdf8}
</style></head><body>
<h1>DEVIL HUNT</h1>
<div class="sub">Phase 2 · Passive capture · No auto-attack · <a href="/demo" target="_blank">Open local demo page</a></div>
<div class="panel" id="status"></div>
<div>
<button class="btn" onclick="api('start')">START HUNT</button>
<button class="btn" onclick="api('pause')">PAUSE</button>
<button class="btn" onclick="api('resume')">RESUME</button>
<button class="btn danger" onclick="api('stop')">STOP</button>
<button class="btn" onclick="connect()">CONNECT BROWSER</button>
<button class="btn danger" onclick="disconnect()">DISCONNECT</button>
<button class="btn" onclick="api('approve')">APPROVE</button>
<button class="btn" onclick="api('reject')">REJECT</button>
<button class="btn" onclick="dl('json')">JSON</button>
<button class="btn" onclick="dl('csv')">CSV</button>
<button class="btn" onclick="dl('md')">MD</button>
</div>
<div id="gate"></div>
<div class="panel">
  <div class="muted">TRAFFIC SOURCE</div>
  <div id="conn"></div>
  <div class="muted" style="margin-top:8px;font-size:11px">
    Browser bridge: demo page or any page posting sanitized events to /api/devil-hunt/bridge<br/>
    Optional HTTP proxy: localhost:\${PROXY_PORT} (CONNECT tunnel for HTTPS targets — passive observe only)
  </div>
</div>
<div class="grid">
  <div class="panel stream" id="events"></div>
  <div class="panel stream" id="reqs"></div>
</div>
<script>
const base='/api/devil-hunt';
async function refresh(){
  const d=await (await fetch(base+'/state')).json(); const s=d.state;
  const sc=s.status==='RUNNING'?'ok':s.status==='WAITING_APPROVAL'?'warn':s.status==='STOPPED'?'bad':'muted';
  const scn=s.sensorConnection||s.trafficConnection;const tc=scn==='CONNECTED'?'ok':scn==='CONNECTING'?'warn':'bad';const ts=s.trafficState||'WAITING';const tsc=ts==='RECEIVING'?'ok':ts==='PAUSED'?'warn':'muted';
  document.getElementById('status').innerHTML=\`
    <div class="row"><span class="muted">TARGET</span><span>\${s.target}</span></div>
    <div class="row"><span class="muted">SCOPE</span><span>\${s.scope}</span></div>
    <div class="row"><span class="muted">MODE</span><span>\${s.mode}</span></div>
    <div class="row"><span class="muted">STATUS</span><span class="\${sc}">● \${s.status}</span></div>
    <div class="row"><span class="muted">REQUESTS</span><span>\${s.requests}</span></div>
    <div class="row"><span class="muted">ENDPOINTS</span><span>\${s.endpoints}</span></div>
    <div class="row"><span class="muted">HYPOTHESES</span><span>\${s.hypotheses}</span></div>
    <div class="row"><span class="muted">TESTS</span><span>\${s.tests}</span></div>
    <div class="row"><span class="muted">FINDINGS</span><span>\${s.findings}</span></div>
    <div class="row"><span class="muted">HUNT</span><span>#\${s.huntId}</span></div>
    <div class="row"><span class="muted">SESSION</span><span class="\${s.sessionType==='REAL'?'ok':'warn'}">\${s.sessionType==='REAL'?'REAL HUNT':'DEMO'}</span></div>
    <div class="row"><span class="muted">REAL TARGET</span><span>\${s.target}</span></div>
    <div class="row"><span class="muted">DEMO reqs (archived)</span><span>\${(s.demo&&s.demo.requests)||0}</span></div>\`;
  document.getElementById('conn').innerHTML=\`
    <div class="row"><span class="muted">Connection</span><span class="\${tc}">\${s.sensorConnection||s.trafficConnection}</span></div>
    <div class="row"><span class="muted">Source</span><span>\${s.trafficSource}</span></div>
    <div class="row"><span class="muted">Events received</span><span>\${s.trafficEventsReceived||0}</span></div>
    <div class="row"><span class="muted">Last event</span><span>\${s.trafficLastEvent||'—'}</span></div><div class="row"><span class="muted">Traffic</span><span class="\${tsc}">\${ts==='RECEIVING'?'RECEIVING':ts==='PAUSED'?'PAUSED':'WAITING FOR FIRST EVENT'}</span></div>
    <div class="row"><span class="muted">Error</span><span class="bad">\${s.trafficError||'none'}</span></div>\`;
  document.getElementById('events').innerHTML='<div class="muted">EVENT STREAM</div>'+(s.events||[]).slice().reverse().slice(0,80).map(e=>
    \`<div>[\${(e.ts||'').slice(11,19)}] <b>\${e.kind}</b> \${e.message}</div>\`).join('');
  document.getElementById('reqs').innerHTML='<div class="muted">CAPTURED</div>'+(s.capturedRequests||[]).slice().reverse().slice(0,40).map(r=>
    \`<div>\${r.method} \${r.path} \${r.status??''}</div>\`).join('')||'<div class="muted">none</div>';
  const g=document.getElementById('gate');
  if(s.pendingApproval){const p=s.pendingApproval;g.innerHTML=\`<div class="panel gate"><b>⚠ HUMAN APPROVAL</b><br/>\${p.action}<br/>\${p.target}<br/>Risk \${p.risk}<br/>
    <button class="btn" onclick="api('approve')">APPROVE</button>
    <button class="btn danger" onclick="api('reject')">REJECT</button></div>\`;}
  else g.innerHTML='';
}
async function api(a){await fetch(base+'/'+a,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});refresh();}
async function connect(){await fetch(base+'/traffic/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});refresh();}
async function disconnect(){await fetch(base+'/traffic/disconnect',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});refresh();}
function dl(k){window.open(base+'/export/'+k);}
refresh();setInterval(refresh,1500);
</script></body></html>`;

const DEMO = `<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>Devil Hunt Local Demo</title>
<style>body{font-family:system-ui;background:#111;color:#eee;padding:2rem}button{padding:.5rem 1rem;margin:.25rem}</style>
</head><body>
<h1>Local demo traffic (not Meesho)</h1>
<p>Generates harmless requests to this server and reports them through the browser bridge.</p>
<ol>
<li>On the console: START HUNT</li>
<li>CONNECT BROWSER</li>
<li>Click buttons below</li>
</ol>
<button id="b1">Demo GET /demo-api/profile?resourceId=1</button>
<button id="b2">Demo GET out-of-scope host (should BLOCK discovery)</button>
<pre id="log"></pre>
<script>
const log=(m)=>{document.getElementById('log').textContent+=m+'\\n'};
async function bridge(evt){
  const r=await fetch('/api/devil-hunt/bridge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(evt)});
  const j=await r.json(); log(JSON.stringify(j.ok?{ok:true,error:j.error}:{ok:false,error:j.error}));
}
document.getElementById('b1').onclick=async()=>{
  const res=await fetch('/demo-api/profile?resourceId=own-1');
  await bridge({
    method:'GET', host:'127.0.0.1', path:'/demo-api/profile', status:res.status,
    queryParamNames:['resourceId'], category:'PROFILE', authState:'OWN_ACCOUNT',
    contentType:'application/json', responseStructure:'json-object'
  });
};
document.getElementById('b2').onclick=async()=>{
  await bridge({
    method:'GET', host:'evil.example.test', path:'/x', status:200,
    queryParamNames:[], category:'OTHER'
  });
};
</script></body></html>`;

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    });
    return res.end();
  }
  const url = new URL(req.url || '/', `http://127.0.0.1:${PORT}`);
  const p = url.pathname;

  if (p === '/' || p === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(PAGE);
  }
  if (p === '/demo') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(DEMO);
  }
  if (p === '/demo-api/profile') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, demo: true, note: 'local only' }));
  }

  if (p === '/api/devil-hunt/state') return json(res, 200, { state });

  if (p === '/api/devil-hunt/reset-real' && req.method === 'POST') {
    resetRealHunt003();
    return json(res, 200, { ok: true, state });
  }
  if (p === '/api/devil-hunt/start' && req.method === 'POST') {
    const body = await readBody(req);
    if (body.target) {
      const host = sanitizeHost(body.target);
      if (!isAllowedHost(host) && host !== sanitizeHost(state.target)) {
        pushEvent('BLOCK', `OUT_OF_SCOPE_BLOCKED: ${host}`);
        return json(res, 400, { ok: false, error: 'OUT_OF_SCOPE_BLOCKED', state });
      }
      state.target = host || state.target;
    }
    state.status = 'RUNNING';
    state.mode = 'OBSERVE';
    state.scope = 'CONFIRMED';
    state.sessionType = 'REAL';
    // Never carry demo into real session counters on start
    if (state.requests && state.capturedRequests.some((r) => isDemoHost(r.host))) {
      archiveDemoFromMixedState();
    }
    pushEvent('SYSTEM', `Hunt #${state.huntId} REAL session started — MODE OBSERVE`);
    pushEvent('SCOPE', `${state.target} confirmed`);
    persist();
    return json(res, 200, { ok: true, state });
  }
  if (p === '/api/devil-hunt/pause' && req.method === 'POST') {
    state.status = 'PAUSED';
    pushEvent('CONTROL', 'Hunt paused');
    persist();
    return json(res, 200, { ok: true, state });
  }
  if (p === '/api/devil-hunt/resume' && req.method === 'POST') {
    if (state.status === 'STOPPED') return json(res, 400, { ok: false, error: 'STOPPED', state });
    state.status = state.pendingApproval ? 'WAITING_APPROVAL' : 'RUNNING';
    pushEvent('CONTROL', 'Hunt resumed');
    persist();
    return json(res, 200, { ok: true, state });
  }
  if (p === '/api/devil-hunt/stop' && req.method === 'POST') {
    state.status = 'STOPPED';
    state.pendingApproval = null;
    pushEvent('CONTROL', 'Hunt STOPPED');
    persist();
    return json(res, 200, { ok: true, state });
  }
  if (p === '/api/devil-hunt/traffic/connect' && req.method === 'POST') {
    if (state.status === 'STOPPED' || state.status === 'IDLE') {
      state.trafficError = 'Start hunt before connecting traffic';
      return json(res, 400, { ok: false, error: state.trafficError, state });
    }
    state.sensorConnection = 'CONNECTING';
    state.trafficConnection = 'CONNECTING';
    state.trafficState = 'WAITING';
    state.trafficError = null;
    state.trafficSource = 'BROWSER_EXTENSION';
    pushEvent('SYSTEM', 'Waiting for browser extension SENSOR_HELLO');
    persist();
    return json(res, 200, { ok: true, state });
  }
  if (p === '/api/devil-hunt/traffic/disconnect' && req.method === 'POST') {
    state.sensorConnection = 'DISCONNECTED';
    state.trafficConnection = 'DISCONNECTED';
    state.trafficState = 'WAITING';
    state.trafficSource = 'NOT_CONNECTED';
    pushEvent('SYSTEM', 'Browser extension sensor disconnected');
    persist();
    return json(res, 200, { ok: true, state });
  }
  if (p === '/api/devil-hunt/bridge' && req.method === 'POST') {
    const raw = await readBody(req);
    // Extension envelope: { source, version, type, event }
    const isEnvelope = raw && typeof raw === 'object' && (raw.event || raw.type);
    const evt = isEnvelope && raw.event ? raw.event : raw;
    const src = isEnvelope ? String(raw.source || 'browser-bridge') : 'BROWSER_BRIDGE';
    const etype = isEnvelope ? String(raw.type || 'NETWORK') : 'NETWORK';

    if (!evt || typeof evt !== 'object') {
      return json(res, 400, { accepted: false, ok: false, reason: 'MALFORMED_EVENT' });
    }
    if (String(evt.method || '').length > 16 || String(evt.path || '').length > 512) {
      return json(res, 400, { accepted: false, ok: false, reason: 'FIELD_TOO_LONG' });
    }

    // Sensor hello / connect ack — does not require hunt traffic connection first
    if (etype === 'SENSOR_HELLO' || String(evt.path || '') === '/__devil_hunt_sensor_hello') {
      if (state.status === 'IDLE' || state.status === 'STOPPED') {
        return json(res, 400, { accepted: false, ok: false, reason: 'HUNT_NOT_RUNNING', error: 'Start hunt first' });
      }
      // Handshake success = sensor CONNECTED (does NOT require traffic)
      state.sensorConnection = 'CONNECTED';
      state.trafficConnection = 'CONNECTED';
      state.trafficSource = 'BROWSER_EXTENSION';
      state.trafficError = null;
      state.connectedAt = new Date().toISOString();
      if (!state.trafficState || state.trafficEventsReceived === 0) {
        state.trafficState = 'WAITING';
      }
      pushEvent('SYSTEM', 'Browser extension sensor connected');
      persist();
      return json(res, 200, { accepted: true, ok: true, eventId: 'hello', state });
    }

    if (etype === 'SENSOR_DISCONNECT') {
      state.sensorConnection = 'DISCONNECTED';
      state.trafficConnection = 'DISCONNECTED';
      state.trafficState = 'WAITING';
      state.trafficSource = 'NOT_CONNECTED';
      pushEvent('SYSTEM', 'Browser extension sensor disconnected');
      persist();
      return json(res, 200, { accepted: true, ok: true, state });
    }

    if (etype === 'OUT_OF_SCOPE_DISCOVERY') {
      const host = sanitizeHost(evt.host);
      state.outOfScopeDiscoveries.push({ host, path: '/', ts: new Date().toISOString() });
      pushEvent('BLOCK', `OUT_OF_SCOPE_DISCOVERY host=${host}`);
      persist();
      return json(res, 200, { accepted: false, ok: false, reason: 'OUT_OF_SCOPE', state });
    }

    // Auto-arm traffic connection when extension streams and hunt is running
    if (state.status === 'RUNNING' || state.status === 'WAITING_APPROVAL') {
      if (state.trafficConnection === 'DISCONNECTED') {
        state.trafficConnection = 'CONNECTING';
        state.trafficSource = src.includes('extension') ? 'BROWSER_EXTENSION' : 'BROWSER_BRIDGE';
      }
    }

    // Local demo paths on 127.0.0.1
    if ((sanitizeHost(evt.host) === '127.0.0.1' || sanitizeHost(evt.host) === 'localhost') &&
        String(evt.path || '').startsWith('/demo-api')) {
      const prev = state.target;
      state.target = '127.0.0.1';
      const r = ingestTraffic(evt, 'BROWSER_EXTENSION');
      state.target = prev;
      persist();
      return json(res, r.ok ? 200 : 400, {
        accepted: !!r.ok,
        ok: r.ok,
        eventId: r.request?.id,
        reason: r.error,
        state: r.state,
      });
    }

    const r = ingestTraffic(evt, src.includes('extension') ? 'BROWSER_EXTENSION' : 'BROWSER_BRIDGE');
    return json(res, r.ok ? 200 : 400, {
      accepted: !!r.ok,
      ok: r.ok,
      eventId: r.request?.id,
      reason: r.error,
      state: r.state,
    });
  }
  if (p === '/api/devil-hunt/ingest' && req.method === 'POST') {
    const body = await readBody(req);
    if (state.trafficConnection === 'DISCONNECTED') {
      state.trafficConnection = 'CONNECTING';
      state.trafficSource = 'MANUAL_INGEST';
    }
    const r = ingestTraffic(body, state.trafficSource || 'MANUAL_INGEST');
    return json(res, r.ok ? 200 : 400, r);
  }
  if (p === '/api/devil-hunt/approve' && req.method === 'POST') {
    if (!state.pendingApproval) return json(res, 400, { ok: false, error: 'NO_PENDING_APPROVAL', state });
    const isDemoApproval = state.pendingApproval && /demo|127\.0\.0\.1|localhost/i.test(
      String(state.pendingApproval.target || '') + String(state.pendingApproval.reason || '')
    );
    if (isDemoApproval) {
      pushEvent('APPROVAL', '[DEMO] approval recorded — does NOT authorize real-target validation');
      if (state.demo) state.demo.tests = (state.demo.tests || 0) + 1;
      // Do NOT increment real tests; stay OBSERVE
      state.pendingApproval = null;
      state.status = 'RUNNING';
      state.mode = 'OBSERVE';
    } else {
      pushEvent('APPROVAL', 'APPROVED real-target validation slot — operator executes manually; no auto-exploit');
      state.tests += 1;
      state.pendingApproval = null;
      state.status = 'RUNNING';
      state.mode = 'VALIDATE';
    }
    persist();
    return json(res, 200, { ok: true, state });
  }
  if (p === '/api/devil-hunt/reject' && req.method === 'POST') {
    if (!state.pendingApproval) return json(res, 400, { ok: false, error: 'NO_PENDING_APPROVAL', state });
    pushEvent('APPROVAL', 'REJECTED');
    state.pendingApproval = null;
    if (state.status !== 'STOPPED') state.status = 'RUNNING';
    persist();
    return json(res, 200, { ok: true, state });
  }
  if (p === '/api/devil-hunt/export/json') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename="devil-hunt.json"' });
    return res.end(exportJSON());
  }
  if (p === '/api/devil-hunt/export/csv') {
    res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="devil-hunt.csv"' });
    return res.end(exportCSV());
  }
  if (p === '/api/devil-hunt/export/md') {
    res.writeHead(200, { 'Content-Type': 'text/markdown', 'Content-Disposition': 'attachment; filename="devil-hunt.md"' });
    return res.end(exportMD());
  }
  json(res, 404, { error: 'NOT_FOUND' });
});

// Minimal CONNECT proxy for HTTPS tunnel logging (host only, no body MITM without certs)
const proxyServer = net.createServer((client) => {
  client.once('data', (chunk) => {
    const text = chunk.toString();
    if (text.startsWith('CONNECT ')) {
      const hostPort = text.split(' ')[1] || '';
      const host = hostPort.split(':')[0].toLowerCase();
      if (state.trafficConnection === 'CONNECTED' || state.trafficConnection === 'CONNECTING') {
        if (isTargetHost(host)) {
          ingestTraffic({ method: 'CONNECT', host, path: '/', status: null, category: 'TUNNEL', authState: 'UNKNOWN' }, 'HTTP_PROXY');
        } else {
          pushEvent('BLOCK', `OUT_OF_SCOPE_DISCOVERY proxy CONNECT ${host}`);
          persist();
        }
      }
      // Blind tunnel if possible
      const port = Number(hostPort.split(':')[1] || 443);
      const upstream = net.connect(port, host, () => {
        client.write('HTTP/1.1 200 Connection Established\\r\\n\\r\\n');
        client.pipe(upstream);
        upstream.pipe(client);
      });
      upstream.on('error', () => client.end());
      client.on('error', () => upstream.end());
    } else {
      client.end();
    }
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`DEVIL_HUNT_LIVE http://127.0.0.1:${PORT}`);
  console.log(`DEVIL_HUNT_DEMO http://127.0.0.1:${PORT}/demo`);
  persist();
});

proxyServer.listen(PROXY_PORT, '127.0.0.1', () => {
  console.log(`DEVIL_HUNT_PROXY 127.0.0.1:${PROXY_PORT}`);
});
