/**
 * PASSIVE_PREFLIGHT — no network traffic if preflight fails.
 */

import { getProgramProfile, isAuthorizedForPassive, getOnboardingState } from './programProfileModel.ts';
import { checkTargetScope, PASSIVE_METHODS } from './scopeEnforcement.ts';

export interface PreflightResult {
  status: 'READY' | 'BLOCKED';
  reasons: string[];
  checks: Record<string, 'PASS' | 'BLOCKED'>;
}

export function runPassivePreflight(params: {
  programId: string;
  targets: string[];
  proxyAvailable?: boolean;
  evidenceStorageAvailable?: boolean;
  auditStorageAvailable?: boolean;
}): PreflightResult {
  const reasons: string[] = [];
  const checks: Record<string, 'PASS' | 'BLOCKED'> = {};

  const profile = getProgramProfile(params.programId);
  if (!profile) {
    reasons.push('Program not found');
    checks.program = 'BLOCKED';
  } else {
    checks.program = 'PASS';
  }

  const auth = isAuthorizedForPassive(params.programId);
  if (!auth.ok) {
    reasons.push(`Authorization: ${auth.reason}`);
    checks.authorization = 'BLOCKED';
  } else {
    checks.authorization = 'PASS';
  }

  if (profile) {
    if (!profile.allowedAssets.length) {
      reasons.push('Scope empty');
      checks.scope = 'BLOCKED';
    } else {
      checks.scope = 'PASS';
    }

    // Ambiguity: empty policy version
    if (!profile.policyVersion) {
      reasons.push('Policy version missing');
      checks.policy = 'BLOCKED';
    } else {
      checks.policy = 'PASS';
    }

    if (profile.testingWindow) {
      const now = Date.now();
      const end = Date.parse(profile.testingWindow.end);
      if (!Number.isNaN(end) && now > end) {
        reasons.push('Testing window expired');
        checks.testingWindow = 'BLOCKED';
      } else {
        checks.testingWindow = 'PASS';
      }
    } else {
      checks.testingWindow = 'PASS';
    }

    if (profile.requestBudget <= 0) {
      reasons.push('Request budget invalid');
      checks.budget = 'BLOCKED';
    } else {
      checks.budget = 'PASS';
    }

    if (profile.proxyRequirement && !params.proxyAvailable) {
      reasons.push('Proxy required but unavailable');
      checks.proxy = 'BLOCKED';
    } else {
      checks.proxy = 'PASS';
    }

    if (!profile.researcherAccountReferences.length) {
      reasons.push('No researcher account references');
      checks.credentials = 'BLOCKED';
    } else {
      // Ensure no raw secrets in references
      const dirty = profile.researcherAccountReferences.some((r) =>
        /eyJ|password=|Bearer\s+\S{20,}/i.test(r)
      );
      if (dirty) {
        reasons.push('Raw credentials detected in researcher references');
        checks.credentials = 'BLOCKED';
      } else {
        checks.credentials = 'PASS';
      }
    }

    const methodsOk = profile.allowedMethods.every((m) => PASSIVE_METHODS.has(m));
    if (!methodsOk || !profile.allowedMethods.length) {
      reasons.push('Passive methods not correctly configured');
      checks.passiveMethods = 'BLOCKED';
    } else {
      checks.passiveMethods = 'PASS';
    }
  }

  // Active testing always locked
  checks.activeTesting = 'PASS'; // locked = good

  for (const t of params.targets) {
    const scope = checkTargetScope(params.programId, t);
    if (!scope.allowed) {
      reasons.push(`Target blocked: ${t} (${scope.reason})`);
      checks[`target:${t}`] = 'BLOCKED';
    } else {
      checks[`target:${t}`] = 'PASS';
    }
  }

  if (params.evidenceStorageAvailable === false) {
    reasons.push('Evidence storage unavailable');
    checks.evidenceStorage = 'BLOCKED';
  } else {
    checks.evidenceStorage = 'PASS';
  }

  if (params.auditStorageAvailable === false) {
    reasons.push('Audit storage unavailable');
    checks.auditStorage = 'BLOCKED';
  } else {
    checks.auditStorage = 'PASS';
  }

  const status = reasons.length ? 'BLOCKED' : 'READY';
  return { status, reasons, checks };
}
