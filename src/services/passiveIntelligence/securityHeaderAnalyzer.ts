/**
 * Deterministic Security Header Analyzer — observation only.
 * Missing headers are signals, NOT automatic vulnerabilities.
 */

import crypto from 'crypto';
import { SecurityObservation, SignalStrength, ConfidenceLevel } from './types.ts';

const SECURITY_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-frame-options',
  'x-xss-protection',
];

function normHeaders(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h || {})) {
    out[k.toLowerCase()] = String(v);
  }
  return out;
}

function signalForMissing(header: string): SignalStrength {
  if (header === 'content-security-policy' || header === 'strict-transport-security') return 'MEDIUM_SIGNAL';
  if (header === 'x-frame-options' || header === 'x-content-type-options') return 'LOW_SIGNAL';
  return 'INFO';
}

export function analyzeSecurityHeaders(params: {
  url: string;
  headers: Record<string, string>;
  programId: string;
  researchCaseId: string;
  requestId: string;
  evidenceRef: string;
}): SecurityObservation[] {
  const h = normHeaders(params.headers);
  const observations: SecurityObservation[] = [];
  const ts = new Date().toISOString();

  for (const header of SECURITY_HEADERS) {
    if (!h[header]) {
      const signal = signalForMissing(header);
      observations.push({
        id: `obs-${crypto.randomBytes(5).toString('hex')}`,
        kind: 'SECURITY_HEADER',
        signal,
        title: `Missing ${header}`,
        observedBehavior: `Response did not include ${header}`,
        expectedBehavior: `Modern security baselines typically include ${header}`,
        securityRelevance: 'Absence is an observable hardening gap; not automatically a vulnerability without context',
        confidence: signal === 'MEDIUM_SIGNAL' ? 'MEDIUM' : 'LOW',
        evidenceRef: params.evidenceRef,
        sourceUrl: params.url,
        programId: params.programId,
        researchCaseId: params.researchCaseId,
        requestId: params.requestId,
        timestamp: ts,
        redacted: false,
      });
    } else {
      // Present — informational observation of value
      observations.push({
        id: `obs-${crypto.randomBytes(5).toString('hex')}`,
        kind: 'SECURITY_HEADER',
        signal: 'INFO',
        title: `Present ${header}`,
        observedBehavior: `${header}: ${h[header].slice(0, 200)}`,
        expectedBehavior: 'Header present and parseable',
        securityRelevance: 'Observable security control present',
        confidence: 'HIGH',
        evidenceRef: params.evidenceRef,
        sourceUrl: params.url,
        programId: params.programId,
        researchCaseId: params.researchCaseId,
        requestId: params.requestId,
        timestamp: ts,
        redacted: false,
      });
    }
  }

  // Cookie attributes
  const setCookie = h['set-cookie'];
  if (setCookie) {
    const lower = setCookie.toLowerCase();
    const missingSecure = !lower.includes('secure');
    const missingHttpOnly = !lower.includes('httponly');
    if (missingSecure || missingHttpOnly) {
      observations.push({
        id: `obs-${crypto.randomBytes(5).toString('hex')}`,
        kind: 'SECURITY_HEADER',
        signal: 'MEDIUM_SIGNAL',
        title: 'Set-Cookie missing security attributes',
        observedBehavior: `Set-Cookie present; secure=${!missingSecure}, httpOnly=${!missingHttpOnly}`,
        expectedBehavior: 'Session cookies should include Secure and HttpOnly where applicable',
        securityRelevance: 'Cookie attribute hardening observation',
        confidence: 'MEDIUM',
        evidenceRef: params.evidenceRef,
        sourceUrl: params.url,
        programId: params.programId,
        researchCaseId: params.researchCaseId,
        requestId: params.requestId,
        timestamp: ts,
        redacted: true,
      });
    }
  }

  return observations;
}
