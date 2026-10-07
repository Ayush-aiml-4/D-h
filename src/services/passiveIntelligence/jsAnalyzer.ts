/**
 * Bounded JavaScript / static-resource analysis — NO execution of downloaded JS.
 */

import crypto from 'crypto';
import { DiscoveryRecord, ConfidenceLevel } from './types.ts';
import { evaluateScope } from './scopeGuard.ts';

const PATH_PATTERNS = [
  /['"`](\/(?:api|v\d+|graphql|auth|login|oauth|ws|socket)[a-zA-Z0-9/_\-.]*)['"`]/g,
  /['"`]((?:https?:)?\/\/[a-zA-Z0-9._\-]+\/[a-zA-Z0-9/_\-.?=&]*)['"`]/g,
  /(?:fetch|axios|XMLHttpRequest|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
  /(?:url|endpoint|path|route|href|src)\s*[:=]\s*['"`]([^'"`]+)['"`]/gi,
  /(?:wss?:\/\/[a-zA-Z0-9._\-/]+)/gi,
  /\.map['"`]?/gi,
];

const AUTH_HINTS = /auth|login|oauth|token|session|signin|signup|password|credential/i;
const VERSION_HINTS = /\/v\d+\//i;
const SOURCEMAP_HINTS = /\.map$|sourceMappingURL/i;
const CONFIG_HINTS = /config|feature[_-]?flag|env|settings/i;

export function analyzeJavaScriptContent(params: {
  sourceUrl: string;
  body: string;
  programId: string;
  researchCaseId: string;
  evidenceRef: string;
}): DiscoveryRecord[] {
  const { sourceUrl, body, programId, researchCaseId, evidenceRef } = params;
  if (!body || body.length < 8) return [];

  const discoveries: DiscoveryRecord[] = [];
  const seen = new Set<string>();

  const push = (
    discoveryType: DiscoveryRecord['discoveryType'],
    value: string,
    confidence: ConfidenceLevel,
    methodHint?: string
  ) => {
    const key = `${discoveryType}:${value}:${methodHint || ''}`;
    if (seen.has(key)) return;
    seen.add(key);

    // Scope check on absolute URLs / host-bearing values
    let scopeAllowed = true;
    let scopeReason = 'PATH_RELATIVE_PENDING_HOST';
    if (/^https?:\/\//i.test(value) || value.includes('://')) {
      const scope = evaluateScope(programId, value);
      scopeAllowed = scope.allowed;
      scopeReason = scope.reason;
    }

    discoveries.push({
      id: `disc-${crypto.randomBytes(6).toString('hex')}`,
      discoveryType,
      sourceUrl,
      extractedValue: value.slice(0, 500),
      methodHint,
      confidence,
      evidenceRef,
      scopeAllowed,
      scopeReason,
      programId,
      researchCaseId,
      timestamp: new Date().toISOString(),
    });
  };

  // Path / API routes
  for (const re of PATH_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
      const raw = (m[1] || m[0] || '').trim();
      if (!raw || raw.length < 2) continue;
      if (raw.length > 300) continue;

      if (SOURCEMAP_HINTS.test(raw) || SOURCEMAP_HINTS.test(m[0])) {
        push('DISCOVERED_RESOURCE', raw, 'HIGH');
        continue;
      }
      if (CONFIG_HINTS.test(raw)) {
        push('DISCOVERED_CONFIGURATION', raw, 'MEDIUM');
        continue;
      }
      if (AUTH_HINTS.test(raw)) {
        push('DISCOVERED_ENDPOINT', raw, 'HIGH', 'UNKNOWN');
        continue;
      }
      if (VERSION_HINTS.test(raw) || raw.includes('/api/')) {
        push('DISCOVERED_ENDPOINT', raw, 'MEDIUM', 'UNKNOWN');
        continue;
      }
      if (raw.startsWith('ws://') || raw.startsWith('wss://')) {
        push('DISCOVERED_REFERENCE', raw, 'MEDIUM');
        continue;
      }
      if (raw.startsWith('/') || raw.startsWith('http')) {
        push('DISCOVERED_ENDPOINT', raw, 'LOW', 'UNKNOWN');
      }
    }
  }

  // sourceMappingURL comments
  const sm = body.match(/sourceMappingURL\s*=\s*(\S+)/gi);
  if (sm) {
    for (const line of sm) {
      const val = line.split('=')[1]?.trim();
      if (val) push('DISCOVERED_RESOURCE', val, 'HIGH');
    }
  }

  return discoveries;
}
