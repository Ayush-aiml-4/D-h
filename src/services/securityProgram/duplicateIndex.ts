/**
 * Deterministic duplicate / systemic fingerprints — no NLP.
 */

import { createHash } from 'crypto';
import type { SecurityReport } from './reportIntake.js';
import type { DuplicateStatus } from './reportIntake.js';

export function normalizeToken(s: string): string {
  return (s || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/\/+$/, '');
}

export function normalizeAssetKey(asset: string): string {
  let a = normalizeToken(asset);
  a = a.replace(/^https?:\/\//, '');
  a = a.replace(/:\d+/, ''); // strip ports
  return a;
}

export function fingerprintExact(r: Pick<SecurityReport, 'asset' | 'root_cause' | 'security_impact'>): string {
  const payload = [
    normalizeAssetKey(r.asset),
    normalizeToken(r.root_cause),
    normalizeToken(r.security_impact),
  ].join('|');
  return createHash('sha256').update(payload).digest('hex').slice(0, 32);
}

export function fingerprintRootCause(r: Pick<SecurityReport, 'root_cause' | 'vulnerability_class'>): string {
  const payload = [normalizeToken(r.root_cause), normalizeToken(r.vulnerability_class)].join('|');
  return createHash('sha256').update(payload).digest('hex').slice(0, 32);
}

export function classifyAgainstIndex(
  incoming: SecurityReport,
  existing: SecurityReport[]
): DuplicateStatus {
  if (!incoming.root_cause && !incoming.vulnerability_class) return 'NONE';

  const inExact = fingerprintExact(incoming);
  const inRoot = fingerprintRootCause(incoming);

  for (const e of existing) {
    if (e.report_id === incoming.report_id) continue;
    if (fingerprintExact(e) === inExact) return 'EXACT_DUPLICATE';
  }

  for (const e of existing) {
    if (e.report_id === incoming.report_id) continue;
    if (
      fingerprintRootCause(e) === inRoot &&
      normalizeAssetKey(e.asset) !== normalizeAssetKey(incoming.asset)
    ) {
      return 'SAME_ROOT_CAUSE';
    }
  }

  for (const e of existing) {
    if (e.report_id === incoming.report_id) continue;
    if (
      normalizeToken(e.vulnerability_class) === normalizeToken(incoming.vulnerability_class) &&
      normalizeToken(e.root_cause) !== normalizeToken(incoming.root_cause) &&
      e.vulnerability_class
    ) {
      return 'INDEPENDENT_ROOT_CAUSE';
    }
  }

  // Multiple endpoints same root on related assets
  const sameRootSameClass = existing.filter(
    (e) =>
      e.report_id !== incoming.report_id &&
      fingerprintRootCause(e) === inRoot &&
      normalizeToken(e.vulnerability_class) === normalizeToken(incoming.vulnerability_class)
  );
  if (sameRootSameClass.length >= 2) return 'SYSTEMIC';
  if (sameRootSameClass.length === 1) return 'MULTIPLE_ENDPOINT_INSTANCE';

  return 'NONE';
}
