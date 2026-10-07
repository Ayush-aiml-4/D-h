/**
 * LOCAL-ONLY synthetic application responses.
 * No real external traffic. Deterministic scenarios for Mission #0014/#0015.
 */

import { SyntheticScenario, NormalizedPassiveResponse } from './types.ts';

export const SYNTHETIC_PROGRAM_ID = 'DEVILHUNT_TEST_PROGRAM';
export const SYNTHETIC_BASE = 'https://app.synthetic-bounty.local';
export const SYNTHETIC_API = 'https://api.synthetic-bounty.local';
export const SYNTHETIC_STATIC = 'https://static.synthetic-bounty.local';

export const SYNTHETIC_SCENARIOS: SyntheticScenario[] = [
  {
    id: 'A_HEADERS',
    name: 'Missing security headers',
    path: '/',
    method: 'GET',
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      server: 'nginx/1.24.0',
    },
    body: '<html><head><title>Synthetic App</title></head><body><div id="root" data-reactroot>Welcome</div><script src="/static/app.js"></script></body></html>',
    expectedObservations: ['SECURITY_HEADER'],
  },
  {
    id: 'B_SOURCEMAP',
    name: 'Public source map exposure',
    path: '/static/app.js',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'application/javascript' },
    body: 'console.log("app");\n//# sourceMappingURL=/static/app.js.map\nfetch("/api/v1/profile");\naxios.get("/api/v1/products");\nconst loginUrl="/api/v1/login";',
    expectedObservations: ['SOURCE_MAP'],
  },
  {
    id: 'C_VERBOSE',
    name: 'Verbose error / stack trace',
    path: '/api/v1/config',
    method: 'GET',
    status: 500,
    headers: { 'content-type': 'application/json', 'x-powered-by': 'Express' },
    body: '{"error":"Internal","stack":"Error: boom\\n    at Handler (/var/www/app/server.js:42:11)\\n    at processTicks"}',
    expectedObservations: ['VERBOSE_ERROR', 'INFORMATION_DISCLOSURE'],
  },
  {
    id: 'D_CORS',
    name: 'Suspicious CORS configuration',
    path: '/api/v1/products',
    method: 'GET',
    status: 200,
    headers: {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    },
    body: '{"products":[{"id":1,"name":"Widget"}]}',
    expectedObservations: ['CORS_OBSERVATION'],
  },
  {
    id: 'E_INTERNAL_HOST',
    name: 'Internal hostname disclosure',
    path: '/dashboard',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '<html>Connected to ip-10-0-4-22.ec2.internal backend</html>',
    expectedObservations: ['INTERNAL_HOSTNAME'],
  },
  {
    id: 'F_JS_ENDPOINTS',
    name: 'Interesting API endpoints from JS',
    path: '/static/app.js.map',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: '{"version":3,"file":"app.js","sources":["src/api/client.ts"],"mappings":"AAAA"}',
    expectedObservations: ['SOURCE_MAP'],
  },
  {
    id: 'G_TECH',
    name: 'Technology fingerprint',
    path: '/login',
    method: 'GET',
    status: 200,
    headers: {
      'content-type': 'text/html',
      server: 'cloudflare',
      'cf-ray': '7a1b2c3d4e5f-SJC',
      'x-powered-by': 'Express',
    },
    body: '<html><script>window.__NEXT_DATA__={}</script><form>login</form></html>',
    expectedObservations: [],
  },
  {
    id: 'H_FALSE_POSITIVE_CORS',
    name: 'False-positive CORS signal (specific origin, no credentials)',
    path: '/api/v1/public',
    method: 'GET',
    status: 200,
    headers: {
      'content-type': 'application/json',
      'access-control-allow-origin': 'https://app.synthetic-bounty.local',
    },
    body: '{"ok":true}',
    expectedObservations: ['CORS_OBSERVATION'],
  },
  {
    id: 'I_DUPLICATE',
    name: 'Duplicate observation path (same headers page)',
    path: '/products',
    method: 'GET',
    status: 200,
    headers: { 'content-type': 'text/html', server: 'nginx/1.24.0' },
    body: '<html>products</html>',
    expectedObservations: ['SECURITY_HEADER'],
  },
  {
    id: 'J_SECRET_REDACT',
    name: 'Secret-containing response must be redacted',
    path: '/api/v1/profile',
    method: 'GET',
    status: 200,
    headers: {
      'content-type': 'application/json',
      authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaa.bbbb',
      'set-cookie': 'session=abc123; Path=/',
    },
    body: '{"user":"demo","api_key":"sk_live_SUPERSECRETKEY123456","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.cccc.dddd"}',
    expectedObservations: [],
  },
];

export function scenarioToResponse(
  scenario: SyntheticScenario,
  ctx: { researchCaseId: string; executionId: string; requestId: string }
): NormalizedPassiveResponse {
  const host =
    scenario.path.startsWith('/api')
      ? SYNTHETIC_API
      : scenario.path.startsWith('/static')
        ? SYNTHETIC_STATIC
        : SYNTHETIC_BASE;
  return {
    url: `${host}${scenario.path}`,
    method: scenario.method,
    status: scenario.status,
    headers: { ...scenario.headers },
    body: scenario.body,
    contentType: scenario.headers['content-type'] || 'text/plain',
    programId: SYNTHETIC_PROGRAM_ID,
    researchCaseId: ctx.researchCaseId,
    executionId: ctx.executionId,
    requestId: ctx.requestId,
    target: host,
    timestamp: new Date().toISOString(),
  };
}
