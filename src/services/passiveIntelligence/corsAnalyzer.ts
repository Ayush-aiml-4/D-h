/**
 * Passive CORS analysis — NO origin manipulation, NO crafted Origin requests.
 */

import crypto from 'crypto';
import { SecurityObservation } from './types.ts';

function normHeaders(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h || {})) out[k.toLowerCase()] = String(v);
  return out;
}

export function analyzeCorsPassive(params: {
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
  const acao = h['access-control-allow-origin'];
  const acac = h['access-control-allow-credentials'];

  if (!acao) return observations;

  if (acao.trim() === '*') {
    observations.push({
      id: `obs-${crypto.randomBytes(5).toString('hex')}`,
      kind: 'CORS_OBSERVATION',
      signal: acac && /true/i.test(acac) ? 'HIGH_SIGNAL' : 'MEDIUM_SIGNAL',
      title: 'CORS wildcard Access-Control-Allow-Origin',
      observedBehavior: `ACAO=*${acac ? `; ACAC=${acac}` : ''}`,
      expectedBehavior: 'Restrict ACAO to trusted origins; never combine * with credentials',
      securityRelevance: 'Wildcard CORS can expand browser-reachable data exposure',
      confidence: 'HIGH',
      evidenceRef: params.evidenceRef,
      sourceUrl: params.url,
      programId: params.programId,
      researchCaseId: params.researchCaseId,
      requestId: params.requestId,
      timestamp: ts,
      redacted: false,
    });
  } else if (acao.includes('null')) {
    observations.push({
      id: `obs-${crypto.randomBytes(5).toString('hex')}`,
      kind: 'CORS_OBSERVATION',
      signal: 'MEDIUM_SIGNAL',
      title: 'CORS ACAO null origin',
      observedBehavior: `ACAO=${acao}`,
      expectedBehavior: 'Avoid reflecting null origin',
      securityRelevance: 'Null origin reflection is a known CORS footgun',
      confidence: 'MEDIUM',
      evidenceRef: params.evidenceRef,
      sourceUrl: params.url,
      programId: params.programId,
      researchCaseId: params.researchCaseId,
      requestId: params.requestId,
      timestamp: ts,
      redacted: false,
    });
  } else {
    // Present specific origin — informational; do NOT claim reflection without active test
    observations.push({
      id: `obs-${crypto.randomBytes(5).toString('hex')}`,
      kind: 'CORS_OBSERVATION',
      signal: 'INFO',
      title: 'CORS ACAO specific origin observed',
      observedBehavior: `ACAO=${acao}${acac ? `; ACAC=${acac}` : ''}`,
      expectedBehavior: 'Specific origins are preferred over wildcards',
      securityRelevance: 'Passive observation only; reflection not verified',
      confidence: 'LOW',
      evidenceRef: params.evidenceRef,
      sourceUrl: params.url,
      programId: params.programId,
      researchCaseId: params.researchCaseId,
      requestId: params.requestId,
      timestamp: ts,
      redacted: false,
    });
  }

  return observations;
}
