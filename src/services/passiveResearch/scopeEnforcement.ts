/**
 * Fail-closed scope enforcement for real/synthetic authorized programs.
 * Rejects prefix/suffix lookalikes, userinfo, homoglyphs, punycode confusion, unlisted assets.
 */

import { getProgramProfile } from './programProfileModel.ts';

export type ScopeDecisionCode =
  | 'IN_SCOPE'
  | 'OUT_OF_SCOPE'
  | 'EXCLUDED'
  | 'UNLISTED'
  | 'MALFORMED'
  | 'PREFIX_SPOOF'
  | 'SUFFIX_SPOOF'
  | 'USERINFO_CONFUSION'
  | 'HOMOGLYPH_SUSPECT'
  | 'PUNYCODE_SUSPECT'
  | 'AMBIGUOUS';

export interface ScopeCheckResult {
  allowed: boolean;
  code: ScopeDecisionCode;
  reason: string;
  host: string | null;
  normalizedUrl: string | null;
}

const HOMOGLYPH_CHARS = /[аеорсухіјАВЕКМНОРСТХ]/; // Cyrillic lookalikes

function extractHost(raw: string): { host: string | null; hasUserInfo: boolean; hasPunycode: boolean; malformed: boolean } {
  if (!raw || typeof raw !== 'string') return { host: null, hasUserInfo: false, hasPunycode: false, malformed: true };
  let t = raw.trim();
  if (!t) return { host: null, hasUserInfo: false, hasPunycode: false, malformed: true };

  try {
    if (!/^https?:\/\//i.test(t) && !t.includes('/')) {
      t = 'https://' + t;
    } else if (!/^https?:\/\//i.test(t) && t.startsWith('/')) {
      return { host: null, hasUserInfo: false, hasPunycode: false, malformed: true };
    } else if (!/^https?:\/\//i.test(t)) {
      t = 'https://' + t;
    }
    const u = new URL(t);
    if (u.username || u.password) {
      return { host: u.hostname.toLowerCase(), hasUserInfo: true, hasPunycode: /xn--/i.test(u.hostname), malformed: false };
    }
    return {
      host: u.hostname.toLowerCase(),
      hasUserInfo: false,
      hasPunycode: /xn--/i.test(u.hostname),
      malformed: false,
    };
  } catch {
    return { host: null, hasUserInfo: false, hasPunycode: false, malformed: true };
  }
}

function isExactOrSubdomain(host: string, asset: string): boolean {
  const a = asset.toLowerCase().replace(/^\*\./, '');
  if (host === a) return true;
  if (host.endsWith('.' + a)) return true;
  return false;
}

/** Prefix spoof: evil-app.synthetic-bounty.local vs app.synthetic-bounty.local listed — host must match exact/subdomain rules only */
function isPrefixSpoof(host: string, allowed: string[]): boolean {
  for (const asset of allowed) {
    const a = asset.toLowerCase().replace(/^\*\./, '');
    // e.g. host "notapp.synthetic-bounty.local" when asset is "app.synthetic-bounty.local"
    if (host !== a && !host.endsWith('.' + a) && host.includes(a)) {
      // contains asset string but is not valid subdomain — suspicious
      if (host.endsWith(a) && host.length > a.length && host[host.length - a.length - 1] !== '.') {
        return true;
      }
    }
  }
  return false;
}

export function checkTargetScope(programId: string, target: string): ScopeCheckResult {
  const profile = getProgramProfile(programId);
  if (!profile) {
    return { allowed: false, code: 'UNLISTED', reason: 'PROGRAM_NOT_FOUND', host: null, normalizedUrl: null };
  }

  const extracted = extractHost(target);
  if (extracted.malformed || !extracted.host) {
    return { allowed: false, code: 'MALFORMED', reason: 'MALFORMED_TARGET', host: null, normalizedUrl: null };
  }
  if (extracted.hasUserInfo) {
    return {
      allowed: false,
      code: 'USERINFO_CONFUSION',
      reason: 'USERINFO_NOT_ALLOWED',
      host: extracted.host,
      normalizedUrl: null,
    };
  }
  if (extracted.hasPunycode) {
    return {
      allowed: false,
      code: 'PUNYCODE_SUSPECT',
      reason: 'PUNYCODE_REQUIRES_MANUAL_REVIEW',
      host: extracted.host,
      normalizedUrl: null,
    };
  }
  if (HOMOGLYPH_CHARS.test(extracted.host)) {
    return {
      allowed: false,
      code: 'HOMOGLYPH_SUSPECT',
      reason: 'HOMOGLYPH_CHARACTERS_DETECTED',
      host: extracted.host,
      normalizedUrl: null,
    };
  }

  // Exclusions first
  for (const ex of profile.excludedAssets) {
    if (isExactOrSubdomain(extracted.host, ex)) {
      return {
        allowed: false,
        code: 'EXCLUDED',
        reason: `EXCLUDED_ASSET:${ex}`,
        host: extracted.host,
        normalizedUrl: null,
      };
    }
  }

  // Allowed
  for (const asset of profile.allowedAssets) {
    if (isExactOrSubdomain(extracted.host, asset)) {
      let normalized = target;
      try {
        if (!/^https?:\/\//i.test(target)) normalized = 'https://' + target;
        normalized = new URL(normalized).toString();
      } catch {
        /* keep */
      }
      return {
        allowed: true,
        code: 'IN_SCOPE',
        reason: `IN_SCOPE_ASSET:${asset}`,
        host: extracted.host,
        normalizedUrl: normalized,
      };
    }
  }

  // Prefix / suffix spoof heuristics
  if (isPrefixSpoof(extracted.host, profile.allowedAssets)) {
    return {
      allowed: false,
      code: 'PREFIX_SPOOF',
      reason: 'PREFIX_LOOKALIKE_DENIED',
      host: extracted.host,
      normalizedUrl: null,
    };
  }

  // Suffix spoof: app.synthetic-bounty.local.attacker.local
  for (const asset of profile.allowedAssets) {
    const a = asset.toLowerCase();
    if (extracted.host.includes(a) && !isExactOrSubdomain(extracted.host, a)) {
      return {
        allowed: false,
        code: 'SUFFIX_SPOOF',
        reason: 'SUFFIX_LOOKALIKE_DENIED',
        host: extracted.host,
        normalizedUrl: null,
      };
    }
  }

  return {
    allowed: false,
    code: 'UNLISTED',
    reason: 'FAIL_CLOSED_UNLISTED_ASSET',
    host: extracted.host,
    normalizedUrl: null,
  };
}

export const PASSIVE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
export const BLOCKED_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT', 'TRACE']);

export function checkMethodAllowed(method: string, programId?: string): { allowed: boolean; reason: string } {
  const m = (method || '').toUpperCase();
  if (BLOCKED_METHODS.has(m)) return { allowed: false, reason: 'METHOD_NOT_ALLOWED' };
  if (!PASSIVE_METHODS.has(m)) return { allowed: false, reason: 'METHOD_NOT_ALLOWED' };
  if (programId) {
    const profile = getProgramProfile(programId);
    if (profile && !profile.allowedMethods.includes(m as any)) {
      return { allowed: false, reason: 'METHOD_NOT_IN_PROGRAM_POLICY' };
    }
  }
  return { allowed: true, reason: 'METHOD_ALLOWED' };
}
