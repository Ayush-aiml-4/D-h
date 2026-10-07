import { BOUNTY_STATUS_DEFERRED } from './configModel.js';
import type { ScopeResult } from './scopeEngine.js';

export type Validity =
  | 'valid'
  | 'informative'
  | 'duplicate'
  | 'n_a'
  | 'spam'
  | 'pending_clarification';

export type EvidenceClass =
  | 'MINIMAL_REPRODUCIBLE'
  | 'STRONG'
  | 'INSUFFICIENT'
  | 'EXCESSIVE';

export type DuplicateStatus =
  | 'NONE'
  | 'EXACT_DUPLICATE'
  | 'SAME_ROOT_CAUSE'
  | 'INDEPENDENT_ROOT_CAUSE'
  | 'MULTIPLE_ENDPOINT_INSTANCE'
  | 'SYSTEMIC'
  | 'ADDITIONAL_SECURITY_VALUE';

export interface AuditEvent {
  at: string;
  action: string;
  detail?: string;
}

export interface SecurityReport {
  report_id: string;
  program: string | null;
  researcher: string;
  submitted_at: string;
  asset: string;
  asset_type: string;
  endpoint?: string;
  scope_result: ScopeResult | 'UNSET';
  special_auth_status: string;
  vulnerability_class: string;
  root_cause: string;
  preconditions: string;
  reproduction_steps: string[];
  expected_behavior: string;
  actual_behavior: string;
  proof_of_concept: string;
  security_impact: string;
  attack_scenario: string;
  evidence: { kind: string; ref: string; redacted: boolean }[];
  cvss: { vector?: string; score?: number } | null;
  business_impact: string;
  severity: string | null;
  validity: Validity | 'UNSET';
  duplicate_status: DuplicateStatus;
  systemic_status: 'none' | 'candidate' | 'confirmed';
  bounty_status: string;
  remediation_owner: string | null;
  remediation_status: 'none' | 'assigned' | 'in_progress' | 'fixed' | 'verified';
  disclosure_status: string;
  notes: string;
  audit_trail: AuditEvent[];
}

export function createEmptyReport(partial: Partial<SecurityReport> & Pick<SecurityReport, 'report_id' | 'researcher' | 'asset'>): SecurityReport {
  return {
    program: null,
    submitted_at: new Date().toISOString(),
    asset_type: 'unknown',
    scope_result: 'UNSET',
    special_auth_status: 'not_required',
    vulnerability_class: '',
    root_cause: '',
    preconditions: '',
    reproduction_steps: [],
    expected_behavior: '',
    actual_behavior: '',
    proof_of_concept: '',
    security_impact: '',
    attack_scenario: '',
    evidence: [],
    cvss: null,
    business_impact: '',
    severity: null,
    validity: 'UNSET',
    duplicate_status: 'NONE',
    systemic_status: 'none',
    bounty_status: BOUNTY_STATUS_DEFERRED,
    remediation_owner: null,
    remediation_status: 'none',
    disclosure_status: 'reported',
    notes: '',
    audit_trail: [],
    ...partial,
  };
}

export interface QualityResult {
  ok: boolean;
  missing: string[];
  evidenceClass: EvidenceClass;
}

export function validateReportQuality(r: SecurityReport): QualityResult {
  const missing: string[] = [];
  if (!r.asset?.trim()) missing.push('asset');
  if (r.scope_result === 'UNSET') missing.push('scope_result');
  if (!r.reproduction_steps?.length) missing.push('reproduction_steps');
  if (!r.actual_behavior?.trim()) missing.push('observable_result');
  if (!r.security_impact?.trim()) missing.push('security_impact');
  if (!r.proof_of_concept?.trim() && !r.evidence?.length) missing.push('evidence_or_poc');
  if (!r.attack_scenario?.trim() && r.validity !== 'informative') missing.push('attack_scenario');
  // CVSS optional at intake but preferred
  if (!r.notes?.toLowerCase().includes('limitation') && !r.notes?.toLowerCase().includes('assumption')) {
    // soft — not hard fail
  }

  let evidenceClass: EvidenceClass = 'INSUFFICIENT';
  const hasSteps = r.reproduction_steps.length >= 1 && !!r.actual_behavior.trim();
  const hasImpact = !!r.security_impact.trim();
  const hasPoC = !!r.proof_of_concept.trim() || r.evidence.length > 0;
  const excessive =
    r.evidence.some((e) => !e.redacted && /password|cookie|ssn|secret/i.test(e.ref)) ||
    /Bearer\s+[A-Za-z0-9\-._~+/]+=*/.test(r.proof_of_concept);

  if (excessive) evidenceClass = 'EXCESSIVE';
  else if (hasSteps && hasImpact && hasPoC && r.evidence.length > 0) evidenceClass = 'STRONG';
  else if (hasSteps && hasImpact) evidenceClass = 'MINIMAL_REPRODUCIBLE';
  else evidenceClass = 'INSUFFICIENT';

  return { ok: missing.length === 0 && evidenceClass !== 'INSUFFICIENT', missing, evidenceClass };
}
