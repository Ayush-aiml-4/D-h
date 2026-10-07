import crypto from 'crypto';
import { SecurityObservation } from './types.ts';
import { redactSecretsFromText } from './secretRedaction.ts';

const STACK_TRACE = /at\s+[\w.<>$]+\s+\([^)]+:\d+:\d+\)|Traceback \(most recent call last\)|Exception in thread/i;
const INTERNAL_HOST = /\b(?:ip-|ec2-|internal|corp|intranet|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[a-z0-9.-]*/i;
const DEBUG_MODE = /\b(?:debug\s*=\s*true|development mode|stacktrace|whitelabel error page|django\.debug|flask\.debug)\b/i;
const SOURCEMAP = /sourceMappingURL|\.js\.map\b/i;
const SERVER_BANNER = /\b(?:Apache\/[\d.]+|nginx\/[\d.]+|Microsoft-IIS\/[\d.]+|Express)\b/i;
const INTERNAL_PATH = /\/(?:var\/www|home\/ubuntu|Users\/|C:\\\\|opt\/app|node_modules\/)/i;

export function analyzeInformationDisclosure(params: {
  url: string;
  headers: Record<string, string>;
  body: string;
  programId: string;
  researchCaseId: string;
  requestId: string;
  evidenceRef: string;
}): SecurityObservation[] {
  const observations: SecurityObservation[] = [];
  const ts = new Date().toISOString();
  const bodyRedacted = redactSecretsFromText(params.body || '');
  const body = bodyRedacted.text;
  const server = Object.entries(params.headers || {}).find(([k]) => k.toLowerCase() === 'server')?.[1] || '';

  const add = (
    kind: SecurityObservation['kind'],
    signal: SecurityObservation['signal'],
    title: string,
    observed: string,
    expected: string,
    relevance: string,
    confidence: SecurityObservation['confidence']
  ) => {
    observations.push({
      id: `obs-${crypto.randomBytes(5).toString('hex')}`,
      kind,
      signal,
      title,
      observedBehavior: observed.slice(0, 400),
      expectedBehavior: expected,
      securityRelevance: relevance,
      confidence,
      evidenceRef: params.evidenceRef,
      sourceUrl: params.url,
      programId: params.programId,
      researchCaseId: params.researchCaseId,
      requestId: params.requestId,
      timestamp: ts,
      redacted: bodyRedacted.redacted,
    });
  };

  if (STACK_TRACE.test(body)) {
    add(
      'VERBOSE_ERROR',
      'HIGH_SIGNAL',
      'Stack trace / verbose error observed',
      'Response body contains stack-trace-like content',
      'Production responses should not expose stack traces',
      'May disclose internal paths, frameworks, and logic',
      'HIGH'
    );
  }

  if (DEBUG_MODE.test(body)) {
    add(
      'INFORMATION_DISCLOSURE',
      'HIGH_SIGNAL',
      'Development / debug mode indicator',
      'Debug or development-mode markers present in body',
      'Production should disable debug mode',
      'Debug mode often amplifies information disclosure',
      'HIGH'
    );
  }

  const hostMatch = body.match(INTERNAL_HOST);
  if (hostMatch) {
    add(
      'INTERNAL_HOSTNAME',
      'MEDIUM_SIGNAL',
      'Internal hostname / IP pattern observed',
      `Matched indicator: ${hostMatch[0]}`,
      'External responses should not leak internal hostnames',
      'Internal infrastructure disclosure signal',
      'MEDIUM'
    );
  }

  if (SOURCEMAP.test(body) || SOURCEMAP.test(params.url)) {
    add(
      'SOURCE_MAP',
      'MEDIUM_SIGNAL',
      'Source map reference observed',
      'sourceMappingURL or .js.map reference present',
      'Production builds often omit public source maps',
      'Source maps can expose original source structure',
      'HIGH'
    );
  }

  if (INTERNAL_PATH.test(body)) {
    add(
      'INFORMATION_DISCLOSURE',
      'MEDIUM_SIGNAL',
      'Internal filesystem path pattern',
      'Body contains path-like internal filesystem indicators',
      'Avoid exposing absolute internal paths',
      'Path disclosure can aid further research',
      'MEDIUM'
    );
  }

  if (server && SERVER_BANNER.test(server)) {
    add(
      'INFORMATION_DISCLOSURE',
      'INFO',
      'Server banner observed',
      `Server: ${server}`,
      'Optional: minimize version banners',
      'Technology fingerprinting aid (informational)',
      'HIGH'
    );
  }

  return observations;
}
