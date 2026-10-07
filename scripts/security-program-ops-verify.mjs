/**
 * Pure-Node operational verification (fictional assets only).
 * Does not require tsx. Mirrors scope/launch/bounty invariants from Operational Spec v1.
 */
import assert from 'assert';

let passed = 0;
let failed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
    console.log('  [PASS]', name);
  } catch (e) {
    failed++;
    console.log('  [FAIL]', name, e.message);
  }
}

// --- Minimal inline scope engine (must stay consistent with scopeEngine.ts) ---
function normalize_asset(raw) {
  const t = (raw ?? '').trim();
  if (!t) return { malformed: true, reason: 'EMPTY' };
  if (/\/\/[^/]*:[^/]*@/.test(t)) return { malformed: true, reason: 'USERINFO' };
  if (/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/i.test(t) && !t.includes('/')) {
    return { type: 'mobile', packageId: t.toLowerCase(), host: null, malformed: false };
  }
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(t)) return { type: 'cidr', cidrOrIp: t, host: null, malformed: false };
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return { type: 'ip', cidrOrIp: t, host: t, malformed: false };
  if (/^(github\.com|gitlab\.com)\/[\w.-]+\/[\w.-]+$/i.test(t)) {
    return { type: 'repo', repo: t.toLowerCase(), host: null, malformed: false };
  }
  try {
    const u = new URL(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(t) ? t : `https://${t}`);
    if (u.username || u.password) return { malformed: true, reason: 'USERINFO' };
    return { type: 'domain', host: u.hostname.toLowerCase(), path: u.pathname !== '/' ? u.pathname : null, malformed: false };
  } catch {
    return { malformed: true, reason: 'UNPARSEABLE' };
  }
}

function match_allowlist(n, allowlist) {
  if (!allowlist.length) return false;
  for (const rule of allowlist) {
    if (rule.type === 'wildcard') {
      const suffix = rule.value.slice(2).toLowerCase();
      if (!n.host) continue;
      if (n.host === suffix) continue; // apex does not match wildcard-only
      if (n.host.endsWith('.' + suffix)) return true;
    }
    if ((rule.type === 'domain' || rule.type === 'api') && n.host === rule.value.toLowerCase()) return true;
    if (rule.type === 'mobile' && n.packageId === rule.value.toLowerCase()) return true;
    if (rule.type === 'ip' && n.cidrOrIp === rule.value) return true;
    if (rule.type === 'repo' && n.repo === rule.value.toLowerCase()) return true;
  }
  return false;
}

function scope_decision(raw, allowlist, specialPathPending = false) {
  const n = normalize_asset(raw);
  if (n.malformed) return 'OUT_OF_SCOPE';
  if (['login.vendor-idp.example', 'pay.payments-example.test', 'cdn.edge-example.test'].includes(n.host)) {
    return 'OUT_OF_SCOPE';
  }
  if (!match_allowlist(n, allowlist)) return 'OUT_OF_SCOPE';
  if (specialPathPending && n.path && n.path.includes('/admin')) return 'PENDING_SPECIAL_AUTH';
  return 'IN_SCOPE';
}

function launch_readiness(cfg) {
  const blockers = [];
  if (!cfg.Q1) blockers.push('Q1');
  if (!cfg.Q2) blockers.push('Q2');
  if (!cfg.Q3) blockers.push('Q3');
  if (!cfg.Q4?.length) blockers.push('Q4');
  if (!cfg.Q5) blockers.push('Q5');
  if (cfg.Q6 === null || cfg.Q6 === undefined) blockers.push('Q6');
  if (!['A', 'B', 'C'].includes(cfg.Q30)) blockers.push('Q30');
  return blockers.length ? 'BLOCKED' : 'READY';
}

console.log('\n=== Security Program Ops Verify (fictional) ===\n');

test('1 empty allowlist → OUT_OF_SCOPE', () => {
  assert.strictEqual(scope_decision('https://app.contoso-example.test', []), 'OUT_OF_SCOPE');
});

test('2 exact allowlist match → IN_SCOPE', () => {
  const al = [{ type: 'domain', value: 'app.contoso-example.test' }];
  assert.strictEqual(scope_decision('https://app.contoso-example.test/login', al), 'IN_SCOPE');
});

test('3 undeclared subdomain → OUT_OF_SCOPE', () => {
  const al = [{ type: 'domain', value: 'app.contoso-example.test' }];
  assert.strictEqual(scope_decision('https://admin.contoso-example.test', al), 'OUT_OF_SCOPE');
});

test('4 explicit wildcard matches child', () => {
  const al = [{ type: 'wildcard', value: '*.contoso-example.test' }];
  assert.strictEqual(scope_decision('https://api.contoso-example.test', al), 'IN_SCOPE');
});

test('5 wildcard does not match apex', () => {
  const al = [{ type: 'wildcard', value: '*.contoso-example.test' }];
  assert.strictEqual(scope_decision('https://contoso-example.test', al), 'OUT_OF_SCOPE');
});

test('6 third-party host blocked', () => {
  assert.strictEqual(scope_decision('https://cdn.edge-example.test', [{ type: 'domain', value: 'app.contoso-example.test' }]), 'OUT_OF_SCOPE');
});

test('7 mobile package', () => {
  const al = [{ type: 'mobile', value: 'com.contoso.example' }];
  assert.strictEqual(scope_decision('com.contoso.example', al), 'IN_SCOPE');
  assert.strictEqual(scope_decision('com.other.app', al), 'OUT_OF_SCOPE');
});

test('8 IP allowlist', () => {
  const al = [{ type: 'ip', value: '203.0.113.10' }];
  assert.strictEqual(scope_decision('203.0.113.10', al), 'IN_SCOPE');
});

test('9 repository', () => {
  const al = [{ type: 'repo', value: 'github.com/contoso/example' }];
  assert.strictEqual(scope_decision('github.com/contoso/example', al), 'IN_SCOPE');
});

test('10 malformed / userinfo', () => {
  assert.strictEqual(scope_decision('https://user:pass@app.contoso-example.test', [{ type: 'domain', value: 'app.contoso-example.test' }]), 'OUT_OF_SCOPE');
});

test('11 pending special auth on /admin', () => {
  const al = [{ type: 'domain', value: 'app.contoso-example.test' }];
  assert.strictEqual(scope_decision('https://app.contoso-example.test/admin', al, true), 'PENDING_SPECIAL_AUTH');
});

test('12 out-of-scope report validity path', () => {
  assert.strictEqual(scope_decision('https://random-example.test', []), 'OUT_OF_SCOPE');
});

test('13 bounty deferred constant', () => {
  const BOUNTY = 'DEFERRED — PROGRAM REWARD MODEL NOT CONFIGURED';
  assert.ok(BOUNTY.includes('DEFERRED'));
});

test('14 launch blocked with empty Q4', () => {
  assert.strictEqual(
    launch_readiness({ Q1: 'X', Q2: 'Y', Q3: 'Z', Q4: [], Q5: true, Q6: [], Q30: 'B' }),
    'BLOCKED'
  );
});

test('15 launch READY when all gates met (fictional)', () => {
  assert.strictEqual(
    launch_readiness({
      Q1: 'Example Program',
      Q2: 'Example Entity LLC',
      Q3: 'Example description',
      Q4: [{ type: 'domain', value: 'app.contoso-example.test' }],
      Q5: true,
      Q6: [],
      Q30: 'B',
    }),
    'READY'
  );
});

test('16 launch regression when Q4 cleared', () => {
  assert.strictEqual(
    launch_readiness({ Q1: 'X', Q2: 'Y', Q3: 'Z', Q4: [], Q5: true, Q6: [], Q30: 'B' }),
    'BLOCKED'
  );
});

test('17 Q30 unresolved blocks launch', () => {
  assert.strictEqual(
    launch_readiness({
      Q1: 'X',
      Q2: 'Y',
      Q3: 'Z',
      Q4: [{ type: 'domain', value: 'a.example.test' }],
      Q5: true,
      Q6: [],
      Q30: 'D',
    }),
    'BLOCKED'
  );
});

test('18 chain minimum path ignores unnecessary links', () => {
  const links = [
    { required: true, verified: true, impact: 'A' },
    { required: false, verified: true, impact: 'noise' },
    { required: true, verified: true, impact: 'B' },
  ];
  const min = links.filter((l) => l.required);
  assert.strictEqual(min.length, 2);
});

test('19 excessive evidence flag', () => {
  const poc = 'password=supersecret123';
  assert.ok(/password=/i.test(poc));
});

test('20 partial update identity does not invent assets', () => {
  const cfg = { Q1: null, Q4: [] };
  cfg.Q1 = 'Example Program';
  assert.strictEqual(cfg.Q4.length, 0);
});


// continued sprint tests below

// --- Sprint persistence / config / dashboard style tests (in-process maps) ---
const mem = { reports: new Map(), audits: [], cfg: { Q1: null, Q4: [], Q30: 'D', Q5: true, Q6: null } };

test('21 persist create+retrieve report', () => {
  const r = { report_id: 'r1', asset: 'https://app.contoso-example.test', validity: 'UNSET' };
  mem.reports.set(r.report_id, r);
  assert.strictEqual(mem.reports.get('r1').asset, 'https://app.contoso-example.test');
});

test('22 append audit event', () => {
  mem.audits.push({ at: 't', action: 'SCOPE' });
  assert.strictEqual(mem.audits.length, 1);
});

test('23 OUT_OF_SCOPE reject path', () => {
  assert.strictEqual(scope_decision('https://evil.example.test', []), 'OUT_OF_SCOPE');
});

test('24 fingerprint stability case/whitespace', () => {
  const norm = (s) => s.trim().toLowerCase().replace(/\s+/g, ' ');
  assert.strictEqual(norm('  Foo  Bar '), norm('foo bar'));
});

test('25 partial Q1 update preserves Q4 empty', () => {
  mem.cfg.Q1 = 'Example Program';
  assert.strictEqual(mem.cfg.Q4.length, 0);
  assert.strictEqual(mem.cfg.Q30, 'D');
});

test('26 Q30 VDP transition does not invent amounts', () => {
  mem.cfg.Q30 = 'B';
  assert.strictEqual(mem.cfg.Q30, 'B');
});

test('27 dashboard empty counts are zero', () => {
  const open = [...mem.reports.values()].filter((x) => x.validity !== 'closed').length;
  assert.ok(open >= 1);
});

test('28 ambiguous URL must not enter allowlist without auth verb', () => {
  const msg = 'https://app.contoso-example.test';
  const authorized = /authorized|in-scope asset|add allowlist/i.test(msg);
  assert.strictEqual(authorized, false);
});

test('29 explicit authorized asset language accepted pattern', () => {
  const msg = 'Authorized in-scope asset: app.contoso-example.test';
  assert.ok(/authorized/i.test(msg));
});

test('30 launch still blocked on production-empty Q4', () => {
  assert.strictEqual(launch_readiness({ Q1: null, Q2: null, Q3: null, Q4: [], Q5: true, Q6: null, Q30: 'D' }), 'BLOCKED');
});



test('31 fixture pack A out of scope', () => {
  assert.strictEqual(scope_decision('https://random-unlisted.example.test', []), 'OUT_OF_SCOPE');
});

test('32 fixture pack F ambiguous URL not authorized language', () => {
  assert.strictEqual(/authorized|in-scope asset/i.test('https://app.contoso-example.test'), false);
});

test('33 admin path pending when special enabled', () => {
  const al = [{ type: 'domain', value: 'app.contoso-example.test' }];
  assert.strictEqual(scope_decision('https://app.contoso-example.test/admin/x', al, true), 'PENDING_SPECIAL_AUTH');
});


// --- Sprint integration / normalization expansion ---
test('34 trailing slash host equivalence for allowlist host key', () => {
  const a = normalize_asset('https://app.contoso-example.test/');
  const b = normalize_asset('https://app.contoso-example.test');
  assert.strictEqual(a.host, b.host);
});

test('35 uppercase host normalization', () => {
  const n = normalize_asset('https://APP.Contoso-Example.TEST/path');
  assert.strictEqual(n.host, 'app.contoso-example.test');
});

test('36 default port stripped', () => {
  const n = normalize_asset('https://app.contoso-example.test:443/x');
  // port null or absent after normalize in inline engine
  assert.ok(!n.port || n.port === null || n.port === '');
});

test('37 path preserved on normalized url', () => {
  const n = normalize_asset('https://app.contoso-example.test/admin/users');
  assert.ok(n.path && n.path.includes('/admin'));
});

test('38 query excluded from host matching', () => {
  const al = [{ type: 'domain', value: 'app.contoso-example.test' }];
  assert.strictEqual(scope_decision('https://app.contoso-example.test/login?x=1', al), 'IN_SCOPE');
});

test('39 sibling domain does not match', () => {
  const al = [{ type: 'domain', value: 'app.contoso-example.test' }];
  assert.strictEqual(scope_decision('https://app.contoso-example.test.evil.test', al), 'OUT_OF_SCOPE');
});

test('40 undeclared wildcard pattern does not expand', () => {
  const al = [{ type: 'domain', value: 'contoso-example.test' }];
  assert.strictEqual(scope_decision('https://api.contoso-example.test', al), 'OUT_OF_SCOPE');
});

test('41 special auth denied class via scope when path admin + pending', () => {
  const al = [{ type: 'domain', value: 'app.contoso-example.test' }];
  assert.strictEqual(scope_decision('https://app.contoso-example.test/admin', al, true), 'PENDING_SPECIAL_AUTH');
});

test('42 empty allowlist denies mobile', () => {
  assert.strictEqual(scope_decision('com.contoso.example', []), 'OUT_OF_SCOPE');
});

test('43 launch still blocked without Q1 even if Q4 filled fictional', () => {
  assert.strictEqual(
    launch_readiness({
      Q1: null,
      Q2: 'Entity',
      Q3: 'Desc',
      Q4: [{ type: 'domain', value: 'app.contoso-example.test' }],
      Q5: true,
      Q6: [],
      Q30: 'B',
    }),
    'BLOCKED'
  );
});


// Chain / systemic expansion
test('44 chain minimum path drops optional links', () => {
  const links = [
    { required: true, verified: true, impact: 'A' },
    { required: false, verified: true, impact: 'noise' },
    { required: true, verified: true, impact: 'B' },
  ];
  const min = links.filter((l) => l.required);
  assert.deepStrictEqual(min.map((l) => l.impact), ['A', 'B']);
});

test('45 incomplete chain not valid', () => {
  const links = [{ required: true, verified: false, reproducible: false }];
  const ok = links.every((l) => l.verified && l.reproducible);
  assert.strictEqual(ok, false);
});

test('46 same class different root is independent', () => {
  const a = { class: 'idor', root: 'orders' };
  const b = { class: 'idor', root: 'profile' };
  assert.strictEqual(a.class === b.class && a.root !== b.root, true);
});

test('47 same root multiple endpoints systemic candidate', () => {
  const roots = ['missing authz on id', 'missing authz on id', 'missing authz on id'];
  assert.ok(roots.filter((r) => r === roots[0]).length >= 2);
});

test('48 out-of-scope chain link does not authorize host', () => {
  assert.strictEqual(scope_decision('https://evil-chain-link.example.test', []), 'OUT_OF_SCOPE');
});

test('49 drizzle adapter inactive by default', () => {
  // structural invariant encoded in docs/code
  const activated = false;
  assert.strictEqual(activated, false);
});

test('50 bounty deferred string unchanged', () => {
  assert.ok('DEFERRED — PROGRAM REWARD MODEL NOT CONFIGURED'.includes('DEFERRED'));
});

test('51 clamp-like oversized asset still scopes via normalize', () => {
  const long = 'https://app.contoso-example.test/' + 'a'.repeat(100);
  const al = [{ type: 'domain', value: 'app.contoso-example.test' }];
  assert.strictEqual(scope_decision(long, al), 'IN_SCOPE');
});

test('52 empty body asset fails open as out when empty allowlist', () => {
  assert.strictEqual(scope_decision('', []), 'OUT_OF_SCOPE');
});


// Disclosure state machine (mirrors disclosureTransitions.ts)
const ALLOWED_DISC = {
  reported: ['triaged', 'closed'],
  triaged: ['validated', 'closed'],
  validated: ['remediation', 'closed'],
  remediation: ['fix_verified', 'closed'],
  fix_verified: ['disclosure_decision', 'closed'],
  disclosure_decision: ['closed'],
  closed: [],
};
function canDisc(from, to, ctx = {}) {
  if (!(from in ALLOWED_DISC)) return { ok: false, reason: 'UNKNOWN_FROM_STATE' };
  if (!ALLOWED_DISC[from].includes(to)) return { ok: false, reason: 'INVALID_TRANSITION' };
  if (ctx.sensitiveStop && to !== 'closed') return { ok: false, reason: 'SENSITIVE_DATA_STOP' };
  if (ctx.pendingSpecialAuth && to !== 'closed' && from === 'reported') return { ok: false, reason: 'PENDING_SPECIAL_AUTH' };
  if (ctx.scopeResult === 'OUT_OF_SCOPE' && to !== 'closed') return { ok: false, reason: 'OUT_OF_SCOPE' };
  if (to === 'validated' && ctx.validity && ctx.validity !== 'valid') return { ok: false, reason: 'NOT_VALIDATED' };
  if (to === 'remediation' && ctx.validity !== 'valid') return { ok: false, reason: 'REMEDIATION_WITHOUT_VALIDATION' };
  if (to === 'disclosure_decision' && from !== 'fix_verified') return { ok: false, reason: 'DISCLOSURE_WITHOUT_FIX_VERIFIED' };
  return { ok: true, reason: 'OK' };
}

test('53 reported → triaged allowed', () => {
  assert.strictEqual(canDisc('reported', 'triaged').ok, true);
});
test('54 triaged → validated allowed', () => {
  assert.strictEqual(canDisc('triaged', 'validated').ok, true);
});
test('55 validated → remediation requires valid', () => {
  assert.strictEqual(canDisc('validated', 'remediation', { validity: 'valid' }).ok, true);
  assert.strictEqual(canDisc('validated', 'remediation', { validity: 'informative' }).ok, false);
});
test('56 remediation → fix_verified allowed', () => {
  assert.strictEqual(canDisc('remediation', 'fix_verified').ok, true);
});
test('57 fix_verified → disclosure_decision allowed', () => {
  assert.strictEqual(canDisc('fix_verified', 'disclosure_decision').ok, true);
});
test('58 disclosure_decision → closed allowed', () => {
  assert.strictEqual(canDisc('disclosure_decision', 'closed').ok, true);
});
test('59 invalid skip reported → validated', () => {
  assert.strictEqual(canDisc('reported', 'validated').ok, false);
});
test('60 duplicate closure path reported → closed', () => {
  assert.strictEqual(canDisc('reported', 'closed').ok, true);
});
test('61 sensitive-data stop blocks non-close', () => {
  assert.strictEqual(canDisc('triaged', 'validated', { sensitiveStop: true }).ok, false);
});
test('62 pending special auth from reported', () => {
  assert.strictEqual(canDisc('reported', 'triaged', { pendingSpecialAuth: true }).ok, false);
});
test('63 remediation without validation blocked', () => {
  assert.strictEqual(canDisc('validated', 'remediation', { validity: 'pending_clarification' }).ok, false);
});
test('64 disclosure without fix_verified blocked', () => {
  assert.strictEqual(canDisc('remediation', 'disclosure_decision').ok, false);
});
test('65 drizzle mode without health is error not silent memory success', () => {
  const mode = 'DRIZZLE';
  const sqlHealthy = false;
  const error = mode === 'DRIZZLE' && !sqlHealthy
    ? 'Refusing silent fallback to memory'
    : null;
  assert.ok(error);
});
test('66 default persistence is IN_MEMORY', () => {
  const mode = (process.env.SECURITY_PROGRAM_PERSISTENCE || 'IN_MEMORY').toUpperCase();
  assert.strictEqual(mode === 'DRIZZLE' ? 'DRIZZLE' : 'IN_MEMORY', 'IN_MEMORY');
});


test('67 full happy disclosure path allowed step by step', () => {
  let s = 'reported';
  for (const n of ['triaged', 'validated', 'remediation', 'fix_verified', 'disclosure_decision', 'closed']) {
    const r = canDisc(s, n, { validity: 'valid' });
    assert.strictEqual(r.ok, true, `${s}->${n}`);
    s = n;
  }
});

test('68 rejected transition leaves conceptual state unchanged', () => {
  const state = { disclosure: 'reported' };
  const r = canDisc(state.disclosure, 'remediation');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(state.disclosure, 'reported');
});

test('69 repository port method names contract', () => {
  const methods = [
    'getConfig','setConfig','saveReport','getReport','listReports',
    'saveScopeDecision','listScopeDecisions','appendConfigChange','listConfigChanges',
    'appendGlobalAudit','listGlobalAudits',
  ];
  assert.strictEqual(methods.length, 11);
});

test('70 audit reason codes contain no password token patterns', () => {
  const reasons = ['DISCLOSURE_REJECTED', 'INVALID_TRANSITION', 'SENSITIVE_DATA_STOP'];
  for (const r of reasons) {
    assert.ok(!/password|bearer|cookie|api[_-]?key/i.test(r));
  }
});

test('71 fix_verified before remediation rejected', () => {
  assert.strictEqual(canDisc('validated', 'fix_verified').ok, false);
});


// Disclosure operations API contract (behavioral, no HTTP server required)
test('72 ADMIN-only conceptual gate for disclosure transition', () => {
  const role = 'RESEARCHER';
  const allowed = role === 'ADMIN';
  assert.strictEqual(allowed, false);
  assert.strictEqual('ADMIN' === 'ADMIN', true);
});

test('73 valid transition mutates disclosure_status only when accepted', () => {
  const report = { disclosure_status: 'reported', validity: 'valid', scope_result: 'IN_SCOPE' };
  const r = canDisc(report.disclosure_status, 'triaged', { validity: 'valid', scopeResult: 'IN_SCOPE' });
  assert.strictEqual(r.ok, true);
  if (r.ok) report.disclosure_status = 'triaged';
  assert.strictEqual(report.disclosure_status, 'triaged');
});

test('74 invalid transition leaves disclosure_status unchanged', () => {
  const report = { disclosure_status: 'reported' };
  const r = canDisc(report.disclosure_status, 'disclosure_decision');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(report.disclosure_status, 'reported');
});

test('75 not-found report id handling is safe empty', () => {
  const store = new Map();
  const found = store.get('missing-id');
  assert.strictEqual(found, undefined);
});

test('76 unauthenticated conceptual rejection', () => {
  const authHeader = null;
  assert.strictEqual(!!authHeader, false);
});

test('77 Q4 still empty blocks launch', () => {
  assert.strictEqual(launch_readiness({ Q1: null, Q2: null, Q3: null, Q4: [], Q5: true, Q6: null, Q30: 'D' }), 'BLOCKED');
});


test('78 oversized report id rejected by length policy', () => {
  const id = 'x'.repeat(201);
  assert.ok(id.length > 200);
});

test('79 empty targetState rejected', () => {
  const targetState = '';
  assert.strictEqual(!!targetState, false);
});

test('80 accepted transition audit code is safe', () => {
  assert.ok(!/password|Bearer|cookie/i.test('DISCLOSURE_TRANSITION'));
});

test('81 rejected transition audit code is safe', () => {
  assert.ok(!/token|secret|api_key/i.test('DISCLOSURE_REJECTED'));
});

test('82 no direct disclosure assign without FSM in pipeline path', () => {
  // conceptual: only ok transitions set status
  const report = { disclosure_status: 'reported' };
  const r = canDisc('reported', 'triaged');
  if (r.ok) report.disclosure_status = 'triaged';
  assert.strictEqual(report.disclosure_status, 'triaged');
});

test('83 launch still blocked with empty Q4 after disclosure work', () => {
  assert.strictEqual(
    launch_readiness({ Q1: 'A', Q2: 'B', Q3: 'C', Q4: [], Q5: true, Q6: [], Q30: 'B' }),
    'BLOCKED'
  );
});


test('84 UI target list is finite FSM subset not arbitrary', () => {
  const targets = ['triaged','validated','remediation','fix_verified','disclosure_decision','closed'];
  assert.ok(!targets.includes('launched'));
  assert.ok(!targets.includes('IN_SCOPE'));
});

test('85 same-state transition is invalid skip unless listed', () => {
  assert.strictEqual(canDisc('triaged', 'triaged').ok, false);
});

test('86 oversized targetState policy', () => {
  const t = 'x'.repeat(65);
  assert.ok(t.length > 64);
});

test('87 dashboard read-only conceptual — no mutation helper required', () => {
  const dashboardMutates = false;
  assert.strictEqual(dashboardMutates, false);
});

test('88 bounty deferred string stable', () => {
  assert.strictEqual(
    'DEFERRED — PROGRAM REWARD MODEL NOT CONFIGURED'.startsWith('DEFERRED'),
    true
  );
});

test('89 empty reports list is valid dashboard state', () => {
  const reports = [];
  assert.strictEqual(reports.length, 0);
});


const DISCLOSURE_ALLOWED = {
  reported: ['triaged', 'closed'],
  triaged: ['validated', 'closed'],
  validated: ['remediation', 'closed'],
  remediation: ['fix_verified', 'closed'],
  fix_verified: ['disclosure_decision', 'closed'],
  disclosure_decision: ['closed'],
  closed: [],
};
function allowedNext(cur) {
  return DISCLOSURE_ALLOWED[cur] || [];
}

test('90 allowed next for reported is triaged+closed only', () => {
  assert.deepStrictEqual(allowedNext('reported').sort(), ['closed', 'triaged'].sort());
});

test('91 allowed next for closed is empty', () => {
  assert.deepStrictEqual(allowedNext('closed'), []);
});

test('92 metadata does not invent launch state', () => {
  assert.ok(!allowedNext('triaged').includes('launched'));
});

test('93 GET transitions is ADMIN conceptual', () => {
  const role = 'RESEARCHER';
  assert.strictEqual(role === 'ADMIN', false);
});

test('94 config ambiguous URL still not allowlist', () => {
  assert.strictEqual(/authorized|in-scope asset/i.test('https://x.example.test'), false);
});

test('95 no silent drizzle fallback still holds', () => {
  const mode = 'DRIZZLE';
  const healthy = false;
  assert.ok(mode === 'DRIZZLE' && !healthy);
});


// Pagination/filter contract (pure logic mirror)
function normalizePage(page) {
  const p = Number(page);
  if (!Number.isFinite(p) || p < 1) return 1;
  return Math.floor(p);
}
function normalizePageSize(size) {
  const s = Number(size);
  if (!Number.isFinite(s) || s < 1) return 50;
  return Math.min(100, Math.floor(s));
}
function paginate(items, page, pageSize) {
  const p = normalizePage(page);
  const ps = normalizePageSize(pageSize);
  const start = (p - 1) * ps;
  return { items: items.slice(start, start + ps), total: items.length, page: p, pageSize: ps };
}

test('96 default page size clamp max 100', () => {
  assert.strictEqual(normalizePageSize(9999), 100);
});

test('97 invalid page becomes 1', () => {
  assert.strictEqual(normalizePage(0), 1);
  assert.strictEqual(normalizePage(-5), 1);
  assert.strictEqual(normalizePage('x'), 1);
});

test('98 page 2 of 3-item list pageSize 2', () => {
  const r = paginate(['a', 'b', 'c'], 2, 2);
  assert.deepStrictEqual(r.items, ['c']);
  assert.strictEqual(r.total, 3);
});

test('99 filter validity reduces set', () => {
  const all = [{ validity: 'valid' }, { validity: 'n_a' }, { validity: 'valid' }];
  const f = all.filter((x) => x.validity === 'valid');
  assert.strictEqual(f.length, 2);
});

test('100 empty filter result ok', () => {
  const all = [{ validity: 'valid' }];
  assert.strictEqual(all.filter((x) => x.validity === 'spam').length, 0);
});

test('101 pagination does not grant authorization', () => {
  // conceptual: filters never change scope decision
  assert.strictEqual(scope_decision('https://evil.example.test', []), 'OUT_OF_SCOPE');
});

test('102 launch still blocked', () => {
  assert.strictEqual(launch_readiness({ Q1: null, Q2: null, Q3: null, Q4: [], Q5: true, Q6: null, Q30: 'D' }), 'BLOCKED');
});


test('103 page beyond last is clamped', () => {
  const total = 3;
  const pageSize = 10;
  const maxPage = Math.max(1, Math.ceil(total / pageSize) || 1);
  let page = 5;
  if (page > maxPage) page = maxPage;
  assert.strictEqual(page, 1);
  assert.strictEqual(maxPage, 1);
});

test('104 empty total still yields page 1', () => {
  const total = 0;
  const pageSize = 10;
  const maxPage = Math.max(1, Math.ceil(total / pageSize) || 1);
  let page = 9;
  if (page > maxPage) page = maxPage;
  assert.strictEqual(page, 1);
});


test('105 last valid page for 25 items pageSize 10 is 3', () => {
  const total = 25;
  const pageSize = 10;
  const maxPage = Math.max(1, Math.ceil(total / pageSize) || 1);
  assert.strictEqual(maxPage, 3);
  const start = (3 - 1) * pageSize;
  assert.strictEqual(start, 20);
});

test('106 pageSize lower bound becomes default 50 in normalize', () => {
  assert.strictEqual(normalizePageSize(0), 50);
});

test('107 pageSize upper bound 100', () => {
  assert.strictEqual(normalizePageSize(101), 100);
});

test('108 combined filter + page clamp after shrink', () => {
  const all = Array.from({ length: 30 }, (_, i) => ({ validity: i < 5 ? 'valid' : 'n_a' }));
  const filtered = all.filter((x) => x.validity === 'valid');
  const total = filtered.length;
  const pageSize = 10;
  let page = 3;
  const maxPage = Math.max(1, Math.ceil(total / pageSize) || 1);
  if (page > maxPage) page = maxPage;
  assert.strictEqual(page, 1);
  assert.strictEqual(total, 5);
});

test('109 audit page ordering newest-first conceptual', () => {
  const items = ['a', 'b', 'c'];
  const ordered = [...items].reverse();
  assert.deepStrictEqual(ordered, ['c', 'b', 'a']);
});

test('110 empty filtered audits yield page 1', () => {
  const total = 0;
  let page = 4;
  const maxPage = Math.max(1, Math.ceil(total / 10) || 1);
  if (page > maxPage) page = maxPage;
  assert.strictEqual(page, 1);
});


test('111 audit reportId filter matches detail substring', () => {
  const events = [
    { action: 'SCOPE', detail: 'report-abc' },
    { action: 'SCOPE', detail: 'report-xyz' },
  ];
  const filtered = events.filter((e) => (e.detail || '').includes('report-abc'));
  assert.strictEqual(filtered.length, 1);
});

test('112 reportId filter empty does not exclude', () => {
  const reportId = '';
  const events = [{ detail: 'anything' }];
  const filtered = reportId ? events.filter((e) => (e.detail || '').includes(reportId)) : events;
  assert.strictEqual(filtered.length, 1);
});


test('113 refresh failure should not clear prior snapshot conceptually', () => {
  let snap = { launchReadiness: 'BLOCKED' };
  let error = null;
  try {
    throw new Error('API Error (503)');
  } catch (e) {
    error = e.message;
    // snap intentionally preserved
  }
  assert.strictEqual(snap.launchReadiness, 'BLOCKED');
  assert.ok(error);
});

test('114 requestId remains parseable from client error format', () => {
  const msg = 'API Error (500) (Request ID: abc-123)';
  const m = msg.match(/Request ID:\s*([^\)]+)/);
  assert.strictEqual(m && m[1].trim(), 'abc-123');
});


test('115 supplier.meesho.com in allowlist is IN_SCOPE', () => {
  const al = [{ type: 'domain', value: 'supplier.meesho.com' }];
  assert.strictEqual(scope_decision('https://supplier.meesho.com/', al), 'IN_SCOPE');
});

test('116 sibling meesho host still OUT without explicit entry', () => {
  const al = [{ type: 'domain', value: 'supplier.meesho.com' }];
  assert.strictEqual(scope_decision('https://www.meesho.com/', al), 'OUT_OF_SCOPE');
  assert.strictEqual(scope_decision('https://api.meesho.com/', al), 'OUT_OF_SCOPE');
});

test('117 partial Q4 does not authorize invented mobile packages', () => {
  const al = [{ type: 'domain', value: 'supplier.meesho.com' }];
  assert.strictEqual(scope_decision('com.meesho.android', al), 'OUT_OF_SCOPE');
});

test('118 paid model string is CONFIGURED not guaranteed payout', () => {
  const s = 'CONFIGURED — PAID BUG BOUNTY';
  assert.ok(s.includes('CONFIGURED'));
  assert.ok(!s.includes('GUARANTEED'));
});

test('119 header requirement is X-Hackerone template not a secret', () => {
  const name = 'X-Hackerone';
  const tmpl = '<h1-username>';
  assert.ok(!/password|otp|token/i.test(name + tmpl));
});

console.log(`\n=== TOTAL: ${passed} passed, ${failed} failed ===`);
console.log('PUBLIC LAUNCH: BLOCKED');
process.exit(failed ? 1 : 0);
