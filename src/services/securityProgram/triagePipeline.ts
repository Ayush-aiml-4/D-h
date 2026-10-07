import { BOUNTY_STATUS_DEFERRED, type ProgramConfig } from './configModel.js';
import { return_scope_decision } from './scopeEngine.js';
import {
  type SecurityReport,
  type Validity,
  type DuplicateStatus,
  validateReportQuality,
} from './reportIntake.js';
import { applyDisclosureTransition } from './disclosureTransitions.js';

export type TriageStage =
  | 'RECEIVED'
  | 'SCOPE'
  | 'SAFETY'
  | 'DUPLICATE'
  | 'VALIDITY'
  | 'IMPACT'
  | 'SEVERITY'
  | 'BOUNTY'
  | 'REMEDIATION'
  | 'DISCLOSURE'
  | 'CLOSED'
  | 'HELD';

export interface TriageResult {
  report: SecurityReport;
  stage: TriageStage;
  stopped: boolean;
  hold: boolean;
  messages: string[];
}

function appendAudit(r: SecurityReport, action: string, detail?: string) {
  r.audit_trail.push({ at: new Date().toISOString(), action, detail });
}

/** Detect sensitive real-user data markers in report text (heuristic for ops) */
export function containsSensitiveRealUserData(r: SecurityReport): boolean {
  const blob = [r.proof_of_concept, r.actual_behavior, r.notes, ...r.evidence.map((e) => e.ref)].join('\n');
  return /real user|production pii|ssn=|credit card \d{4}|password=[^r]/i.test(blob);
}

export function classifyDuplicate(
  incoming: SecurityReport,
  existing: SecurityReport[]
): DuplicateStatus {
  for (const e of existing) {
    if (
      e.asset === incoming.asset &&
      e.root_cause &&
      e.root_cause === incoming.root_cause &&
      e.security_impact === incoming.security_impact
    ) {
      return 'EXACT_DUPLICATE';
    }
    if (e.root_cause && e.root_cause === incoming.root_cause && e.asset !== incoming.asset) {
      return 'SAME_ROOT_CAUSE';
    }
    if (
      e.vulnerability_class &&
      e.vulnerability_class === incoming.vulnerability_class &&
      e.root_cause !== incoming.root_cause
    ) {
      return 'INDEPENDENT_ROOT_CAUSE';
    }
  }
  return 'NONE';
}

export interface ChainLink {
  finding: string;
  verified: boolean;
  required: boolean;
  reproducible: boolean;
  linkImpact: string;
}

export function analyzeChain(links: ChainLink[]): {
  combinedImpact: string;
  minimumPath: ChainLink[];
  unnecessary: ChainLink[];
  valid: boolean;
} {
  const required = links.filter((l) => l.required);
  const unnecessary = links.filter((l) => !l.required);
  const allVerified = required.every((l) => l.verified && l.reproducible);
  const combinedImpact = allVerified
    ? required.map((l) => l.linkImpact).filter(Boolean).join(' → ') || 'combined_demonstrated'
    : 'incomplete_chain';
  return {
    combinedImpact,
    minimumPath: required,
    unnecessary,
    valid: allVerified && required.length > 0,
  };
}

export function runTriagePipeline(
  report: SecurityReport,
  config: ProgramConfig,
  existingReports: SecurityReport[] = []
): TriageResult {
  const messages: string[] = [];
  let stage: TriageStage = 'RECEIVED';
  appendAudit(report, 'RECEIVED');

  // SCOPE
  stage = 'SCOPE';
  const scope = return_scope_decision(report.asset, config);
  report.scope_result = scope.result;
  report.special_auth_status =
    scope.result === 'PENDING_SPECIAL_AUTH' ? 'pending' : scope.specialAuthClass === 'none' ? 'not_required' : 'evaluated';
  appendAudit(report, 'SCOPE', `${scope.result}:${scope.reason}`);

  if (scope.result === 'OUT_OF_SCOPE') {
    report.validity = 'n_a';
    messages.push('OUT_OF_SCOPE stop');
    return { report, stage: 'CLOSED', stopped: true, hold: false, messages };
  }
  if (scope.result === 'PENDING_SPECIAL_AUTH') {
    messages.push('HOLD special authorization');
    return { report, stage: 'HELD', stopped: false, hold: true, messages };
  }

  // SAFETY
  stage = 'SAFETY';
  if (containsSensitiveRealUserData(report)) {
    messages.push('SENSITIVE_DATA stop expansion');
    appendAudit(report, 'SAFETY_STOP', 'sensitive_real_user_data');
    return { report, stage: 'HELD', stopped: true, hold: true, messages };
  }

  // DUPLICATE
  stage = 'DUPLICATE';
  const dup = classifyDuplicate(report, existingReports);
  report.duplicate_status = dup;
  if (dup === 'EXACT_DUPLICATE') {
    report.validity = 'duplicate';
    messages.push('EXACT_DUPLICATE');
    return { report, stage: 'CLOSED', stopped: true, hold: false, messages };
  }
  if (dup === 'SYSTEMIC' || dup === 'SAME_ROOT_CAUSE') {
    report.systemic_status = 'candidate';
  }

  // VALIDITY / quality
  stage = 'VALIDITY';
  const quality = validateReportQuality(report);
  if (quality.evidenceClass === 'EXCESSIVE') {
    messages.push('Request redaction — do not collect more sensitive data');
  }
  if (!quality.ok) {
    report.validity = 'pending_clarification';
    messages.push(`Insufficient: ${quality.missing.join(',')}`);
    return { report, stage: 'VALIDITY', stopped: false, hold: true, messages };
  }
  report.validity = 'valid';

  // IMPACT / SEVERITY placeholders (no bounty mapping)
  stage = 'IMPACT';
  appendAudit(report, 'IMPACT_RECORDED');
  stage = 'SEVERITY';
  if (!report.severity) report.severity = 'pending_cvss';

  // BOUNTY always deferred while Q30 not A/B/C paid/vdp resolved for payment
  stage = 'BOUNTY';
  report.bounty_status = BOUNTY_STATUS_DEFERRED;
  if (config.Q30_rewardModel === 'A_PAID' || config.Q30_rewardModel === 'C_SELECTED') {
    // still no amounts — eligibility evaluation can begin but amounts not invented
    report.bounty_status = 'ELIGIBILITY_REVIEW — AMOUNTS NOT CONFIGURED';
  } else if (config.Q30_rewardModel === 'B_VDP') {
    report.bounty_status = 'VDP — RECOGNITION_ONLY';
  }

  stage = 'REMEDIATION';
  report.remediation_status = report.remediation_status === 'none' ? 'assigned' : report.remediation_status;
  stage = 'DISCLOSURE';
  {
    const current = report.disclosure_status || 'reported';
    const result = applyDisclosureTransition(current, 'triaged', {
      validity: report.validity === 'UNSET' ? undefined : report.validity,
      scopeResult: report.scope_result === 'UNSET' ? undefined : report.scope_result,
    });
    if (result.ok) {
      report.disclosure_status = 'triaged';
      appendAudit(report, 'DISCLOSURE_TRANSITION', `${result.from}->${result.to}`);
    } else {
      appendAudit(report, 'DISCLOSURE_REJECTED', result.reason);
    }
  }
  messages.push('Validated path complete; disclosure pending owner rules');
  return { report, stage: 'DISCLOSURE', stopped: false, hold: false, messages };
}

export function applyIdorAttackComplexity(opts: {
  idsUnpredictable: boolean;
  reliableIdDiscoveryDemonstrated: boolean;
}): 'AC:H' | 'AC:L' {
  if (opts.idsUnpredictable && !opts.reliableIdDiscoveryDemonstrated) return 'AC:H';
  if (opts.reliableIdDiscoveryDemonstrated) return 'AC:L';
  return 'AC:H';
}
