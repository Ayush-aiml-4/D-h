/**
 * Fail-closed scope guard for synthetic + real program assets.
 * Every discovered endpoint must pass scope before inventory acceptance.
 */

export interface ScopeProfile {
  programId: string;
  inScopeHosts: string[];
  outOfScopeHosts: string[];
}

const SYNTHETIC_DEFAULT: ScopeProfile = {
  programId: 'DEVILHUNT_TEST_PROGRAM',
  inScopeHosts: [
    'app.synthetic-bounty.local',
    'api.synthetic-bounty.local',
    'static.synthetic-bounty.local',
  ],
  outOfScopeHosts: [
    'admin.synthetic-bounty.local',
    'internal.synthetic-bounty.local',
    'synthetic-bounty.local.attacker.local',
    'fake-synthetic-bounty.local',
  ],
};

const profiles = new Map<string, ScopeProfile>([[SYNTHETIC_DEFAULT.programId, SYNTHETIC_DEFAULT]]);

export function registerScopeProfile(profile: ScopeProfile): void {
  profiles.set(profile.programId, profile);
}

export function getScopeProfile(programId: string): ScopeProfile | undefined {
  return profiles.get(programId);
}

export function getSyntheticScopeProfile(): ScopeProfile {
  return { ...SYNTHETIC_DEFAULT, inScopeHosts: [...SYNTHETIC_DEFAULT.inScopeHosts], outOfScopeHosts: [...SYNTHETIC_DEFAULT.outOfScopeHosts] };
}

function extractHost(target: string): string | null {
  if (!target || typeof target !== 'string') return null;
  let t = target.trim().toLowerCase();
  if (!t) return null;
  try {
    if (!t.startsWith('http://') && !t.startsWith('https://')) {
      // path-only or host-only
      if (t.startsWith('/')) return null;
      t = 'https://' + t;
    }
    const u = new URL(t);
    return u.hostname.toLowerCase();
  } catch {
    // bare hostname
    if (/^[a-z0-9.-]+$/.test(t.replace(/^https?:\/\//, ''))) {
      return t.replace(/^https?:\/\//, '').split('/')[0];
    }
    return null;
  }
}

export interface ScopeDecision {
  allowed: boolean;
  reason: string;
  host: string | null;
  decision: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'UNKNOWN' | 'MALFORMED';
}

export function evaluateScope(programId: string, target: string): ScopeDecision {
  const host = extractHost(target);
  if (!host) {
    return { allowed: false, reason: 'MALFORMED_TARGET', host: null, decision: 'MALFORMED' };
  }

  const profile = profiles.get(programId) || SYNTHETIC_DEFAULT;

  for (const o of profile.outOfScopeHosts) {
    if (host === o || host.endsWith('.' + o)) {
      return { allowed: false, reason: `OUT_OF_SCOPE_HOST:${o}`, host, decision: 'OUT_OF_SCOPE' };
    }
  }

  for (const i of profile.inScopeHosts) {
    if (host === i || host.endsWith('.' + i)) {
      return { allowed: true, reason: `IN_SCOPE_HOST:${i}`, host, decision: 'IN_SCOPE' };
    }
  }

  // Fail closed
  return { allowed: false, reason: 'FAIL_CLOSED_UNKNOWN_HOST', host, decision: 'UNKNOWN' };
}

export const SAFE_PASSIVE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function isSafePassiveMethod(method: string): boolean {
  return SAFE_PASSIVE_METHODS.has((method || '').toUpperCase());
}
