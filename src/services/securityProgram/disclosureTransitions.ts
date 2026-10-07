/**
 * Disclosure / remediation state machine — deterministic allowed transitions.
 * Audit-friendly; no invented deadlines.
 */

export type DisclosureState =
  | 'reported'
  | 'triaged'
  | 'validated'
  | 'remediation'
  | 'fix_verified'
  | 'disclosure_decision'
  | 'closed';

export const DISCLOSURE_ALLOWED: Record<DisclosureState, DisclosureState[]> = {
  reported: ['triaged', 'closed'],
  triaged: ['validated', 'closed'],
  validated: ['remediation', 'closed'],
  remediation: ['fix_verified', 'closed'],
  fix_verified: ['disclosure_decision', 'closed'],
  disclosure_decision: ['closed'],
  closed: [],
};

export interface TransitionResult {
  ok: boolean;
  from: DisclosureState;
  to: DisclosureState;
  reason: string;
}

export function canTransitionDisclosure(from: string, to: string): TransitionResult {
  const f = from as DisclosureState;
  const t = to as DisclosureState;
  if (!(f in DISCLOSURE_ALLOWED)) {
    return { ok: false, from: f, to: t, reason: 'UNKNOWN_FROM_STATE' };
  }
  if (!DISCLOSURE_ALLOWED[f].includes(t)) {
    return { ok: false, from: f, to: t, reason: 'INVALID_TRANSITION' };
  }
  return { ok: true, from: f, to: t, reason: 'OK' };
}

/** Business rules for when transitions are meaningful */
export function validateTransitionContext(opts: {
  from: string;
  to: string;
  validity?: string;
  scopeResult?: string;
  sensitiveStop?: boolean;
  pendingSpecialAuth?: boolean;
}): TransitionResult {
  const base = canTransitionDisclosure(opts.from, opts.to);
  if (!base.ok) return base;

  if (opts.sensitiveStop && opts.to !== 'closed') {
    return { ...base, ok: false, reason: 'SENSITIVE_DATA_STOP' };
  }
  if (opts.pendingSpecialAuth && opts.to !== 'closed' && opts.from === 'reported') {
    return { ...base, ok: false, reason: 'PENDING_SPECIAL_AUTH' };
  }
  if (opts.scopeResult === 'OUT_OF_SCOPE' && opts.to !== 'closed') {
    return { ...base, ok: false, reason: 'OUT_OF_SCOPE' };
  }
  if (opts.to === 'validated' && opts.validity && opts.validity !== 'valid') {
    return { ...base, ok: false, reason: 'NOT_VALIDATED' };
  }
  if (opts.to === 'remediation' && opts.validity !== 'valid') {
    return { ...base, ok: false, reason: 'REMEDIATION_WITHOUT_VALIDATION' };
  }
  if (opts.to === 'disclosure_decision' && opts.from !== 'fix_verified') {
    return { ...base, ok: false, reason: 'DISCLOSURE_WITHOUT_FIX_VERIFIED' };
  }
  return base;
}

export function applyDisclosureTransition(
  current: string,
  next: string,
  ctx?: {
    validity?: string;
    scopeResult?: string;
    sensitiveStop?: boolean;
    pendingSpecialAuth?: boolean;
  }
): TransitionResult {
  return validateTransitionContext({
    from: current,
    to: next,
    ...ctx,
  });
}

export function getAllowedNextStates(current: string): string[] {
  const c = current as DisclosureState;
  if (!(c in DISCLOSURE_ALLOWED)) return [];
  return [...DISCLOSURE_ALLOWED[c]];
}
