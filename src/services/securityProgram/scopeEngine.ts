/**
 * Deterministic Scope Decision Engine
 * Empty allowlist => every target OUT_OF_SCOPE
 */

import type { AllowlistEntry, ProgramConfig, SpecialAuthClass, SpecialAuthDecision } from './configModel.js';

export type ScopeResult = 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'PENDING_SPECIAL_AUTH';
export type AssetType = 'domain' | 'url' | 'api' | 'mobile' | 'ip' | 'cidr' | 'repo' | 'unknown';

export interface NormalizedAsset {
  type: AssetType;
  host: string | null;
  port: string | null;
  path: string | null;
  packageId: string | null;
  cidrOrIp: string | null;
  repo: string | null;
  raw: string;
  malformed: boolean;
  reason?: string;
}

export interface ScopeDecision {
  result: ScopeResult;
  reason: string;
  normalized: NormalizedAsset;
  matchedRuleId?: string;
  specialAuthClass?: SpecialAuthClass | 'none';
}

const DEFAULT_PORTS = new Set(['80', '443']);

export function normalize_asset(raw: string): NormalizedAsset {
  const base: NormalizedAsset = {
    type: 'unknown',
    host: null,
    port: null,
    path: null,
    packageId: null,
    cidrOrIp: null,
    repo: null,
    raw: (raw ?? '').trim(),
    malformed: false,
  };
  if (!base.raw) {
    return { ...base, malformed: true, reason: 'EMPTY' };
  }
  // userinfo
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/@]+@/.test(base.raw) || /^[^/@]+@[^/]+:/.test(base.raw)) {
    // URLs with user:pass@host
    try {
      const u = new URL(base.raw.includes('://') ? base.raw : `https://${base.raw}`);
      if (u.username || u.password) {
        return { ...base, malformed: true, reason: 'USERINFO' };
      }
    } catch {
      if (base.raw.includes('@') && base.raw.includes('://')) {
        return { ...base, malformed: true, reason: 'USERINFO' };
      }
    }
  }
  if (base.raw.includes('://') && /\/\/[^/]*:[^/]*@/.test(base.raw)) {
    return { ...base, malformed: true, reason: 'USERINFO' };
  }

  // Mobile package (com.example.app)
  if (/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/i.test(base.raw) && !base.raw.includes('/') && !base.raw.includes(':')) {
    return { ...base, type: 'mobile', packageId: base.raw.toLowerCase() };
  }

  // CIDR
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(base.raw)) {
    return { ...base, type: 'cidr', cidrOrIp: base.raw };
  }

  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(base.raw)) {
    return { ...base, type: 'ip', cidrOrIp: base.raw, host: base.raw };
  }

  // Repo host/org/repo
  if (/^(github\.com|gitlab\.com)\/[\w.-]+\/[\w.-]+$/i.test(base.raw)) {
    return { ...base, type: 'repo', repo: base.raw.toLowerCase() };
  }

  // URL or host
  try {
    const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(base.raw) ? base.raw : `https://${base.raw}`;
    const u = new URL(withScheme);
    if (u.username || u.password) {
      return { ...base, malformed: true, reason: 'USERINFO' };
    }
    let host = u.hostname.toLowerCase();
    let port = u.port || null;
    if (port && DEFAULT_PORTS.has(port)) port = null;
    const path = u.pathname && u.pathname !== '/' ? u.pathname : null;
    // path-only nonsense
    if (!host) {
      return { ...base, malformed: true, reason: 'NO_HOST' };
    }
    const type: AssetType = path ? 'url' : 'domain';
    return { ...base, type, host, port, path };
  } catch {
    // bare hostname
    const host = base.raw.toLowerCase().replace(/:\d+$/, '');
    if (/^[a-z0-9.-]+$/.test(host) && host.includes('.')) {
      return { ...base, type: 'domain', host };
    }
    return { ...base, malformed: true, reason: 'UNPARSEABLE' };
  }
}

function ipToInt(ip: string): number | null {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => n < 0 || n > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function ipInCidr(ip: string, cidr: string): boolean {
  const [base, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const ipN = ipToInt(ip);
  const baseN = ipToInt(base);
  if (ipN === null || baseN === null || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipN & mask) === (baseN & mask);
}

export function match_allowlist(
  normalized: NormalizedAsset,
  allowlist: AllowlistEntry[]
): { match: boolean; rule?: AllowlistEntry } {
  if (!allowlist.length) return { match: false };

  for (const rule of allowlist) {
    if (rule.type === 'wildcard') {
      const pattern = rule.value.toLowerCase();
      if (!pattern.startsWith('*.')) continue;
      const suffix = pattern.slice(2);
      if (!normalized.host) continue;
      // apex does not match wildcard-only rule
      if (normalized.host === suffix) continue;
      if (normalized.host.endsWith('.' + suffix) && normalized.host.length > suffix.length + 1) {
        return { match: true, rule };
      }
      continue;
    }
    if (rule.type === 'domain' || rule.type === 'api') {
      if (normalized.host && normalized.host === rule.value.toLowerCase()) {
        if (rule.pathPrefix && normalized.path && !normalized.path.startsWith(rule.pathPrefix)) continue;
        return { match: true, rule };
      }
    }
    if (rule.type === 'mobile' && normalized.packageId === rule.value.toLowerCase()) {
      return { match: true, rule };
    }
    if (rule.type === 'ip' && normalized.cidrOrIp === rule.value) {
      return { match: true, rule };
    }
    if (rule.type === 'cidr' && normalized.cidrOrIp) {
      const ip = normalized.type === 'cidr' ? normalized.cidrOrIp.split('/')[0] : normalized.cidrOrIp;
      if (ipInCidr(ip, rule.value)) return { match: true, rule };
    }
    if (rule.type === 'repo' && normalized.repo === rule.value.toLowerCase()) {
      return { match: true, rule };
    }
  }
  return { match: false };
}

/** Fictional catalog labels for classification only — not authorization */
const FICTIONAL_THIRD_PARTY_HINTS = [
  'login.vendor-idp.example',
  'pay.payments-example.test',
  'cdn.edge-example.test',
  'analytics.tracker-example.test',
];

export function check_third_party(
  normalized: NormalizedAsset,
  intentionalThirdParty: AllowlistEntry[] | null
): { blocked: boolean; reason?: string } {
  if (!normalized.host) return { blocked: false };
  const intentional = intentionalThirdParty ?? [];
  const isIntentional = intentional.some(
    (e) => e.value.toLowerCase() === normalized.host || (e.type === 'wildcard' && normalized.host!.endsWith(e.value.slice(1)))
  );
  if (isIntentional) return { blocked: false };
  if (FICTIONAL_THIRD_PARTY_HINTS.includes(normalized.host)) {
    return { blocked: true, reason: 'THIRD_PARTY' };
  }
  return { blocked: false };
}

function classifySpecialAuth(normalized: NormalizedAsset): SpecialAuthClass | 'none' {
  const path = (normalized.path || '').toLowerCase();
  if (path.includes('/admin') || path.includes('/internal')) return path.includes('/admin') ? 'admin' : 'internal';
  return 'none';
}

export function check_special_authorization(
  normalized: NormalizedAsset,
  matrix: Record<SpecialAuthClass, SpecialAuthDecision>
): { status: 'NOT_REQUIRED' | 'PENDING_SPECIAL_AUTH' | 'OUT_OF_SCOPE' | 'AUTHORIZED'; class: SpecialAuthClass | 'none' } {
  const cls = classifySpecialAuth(normalized);
  if (cls === 'none') return { status: 'NOT_REQUIRED', class: 'none' };
  const decision = matrix[cls] ?? 'PENDING';
  if (decision === 'PENDING' || decision === 'PRIOR_WRITTEN_AUTH') {
    return { status: 'PENDING_SPECIAL_AUTH', class: cls };
  }
  if (decision === 'OUT_OF_SCOPE') return { status: 'OUT_OF_SCOPE', class: cls };
  return { status: 'AUTHORIZED', class: cls };
}

export function return_scope_decision(raw: string, config: ProgramConfig): ScopeDecision {
  const normalized = normalize_asset(raw);
  if (normalized.malformed) {
    return { result: 'OUT_OF_SCOPE', reason: normalized.reason || 'MALFORMED', normalized };
  }
  // Path-only without host already malformed

  const tp = check_third_party(normalized, config.Q6_intentionalThirdPartyInScope);
  if (tp.blocked) {
    return { result: 'OUT_OF_SCOPE', reason: tp.reason || 'THIRD_PARTY', normalized };
  }

  const allowlist = [
    ...config.Q4_authorizedAssets,
    ...(config.Q6_intentionalThirdPartyInScope ?? []),
  ];
  const { match, rule } = match_allowlist(normalized, allowlist);
  if (!match) {
    return { result: 'OUT_OF_SCOPE', reason: 'NO_ALLOWLIST_ENTRY', normalized };
  }

  const special = check_special_authorization(normalized, config.Q7_Q14_specialAuth);
  if (special.status === 'PENDING_SPECIAL_AUTH') {
    return {
      result: 'PENDING_SPECIAL_AUTH',
      reason: 'SPECIAL_AUTH_PENDING',
      normalized,
      matchedRuleId: rule?.id,
      specialAuthClass: special.class,
    };
  }
  if (special.status === 'OUT_OF_SCOPE') {
    return {
      result: 'OUT_OF_SCOPE',
      reason: 'SPECIAL_AUTH_OUT_OF_SCOPE',
      normalized,
      matchedRuleId: rule?.id,
      specialAuthClass: special.class,
    };
  }
  return {
    result: 'IN_SCOPE',
    reason: 'ALLOWLIST_MATCH',
    normalized,
    matchedRuleId: rule?.id,
    specialAuthClass: special.class,
  };
}
