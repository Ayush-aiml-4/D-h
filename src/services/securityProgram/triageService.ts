/**
 * Modular triage service — processSecurityReport entry point.
 */

import { BOUNTY_STATUS_DEFERRED, BOUNTY_STATUS_CONFIGURED_PAID } from './configModel.js';
import { return_scope_decision } from './scopeEngine.js';
import {
  createEmptyReport,
  validateReportQuality,
  type SecurityReport,
} from './reportIntake.js';
import { classifyAgainstIndex } from './duplicateIndex.js';
import {
  containsSensitiveRealUserData,
  type TriageResult,
} from './triagePipeline.js';
import {
  getProgramConfig,
  saveReport,
  listReports,
  saveScopeDecision,
  appendGlobalAudit,
} from './repository.js';
import { applyDisclosureTransition } from './disclosureTransitions.js';

export interface ProcessOptions {
  existingReports?: SecurityReport[];
}

function audit(report: SecurityReport, action: string, detail?: string) {
  report.audit_trail.push({ at: new Date().toISOString(), action, detail });
  appendGlobalAudit({ at: new Date().toISOString(), action, detail: detail || report.report_id });
}

export function stageScope(report: SecurityReport): SecurityReport {
  const config = getProgramConfig();
  const decision = return_scope_decision(report.asset, config);
  report.scope_result = decision.result;
  report.special_auth_status =
    decision.result === 'PENDING_SPECIAL_AUTH'
      ? 'pending'
      : decision.specialAuthClass === 'none'
        ? 'not_required'
        : 'evaluated';
  saveScopeDecision({
    id: `scope_${report.report_id}_${Date.now()}`,
    reportId: report.report_id,
    decision,
    createdAt: new Date().toISOString(),
  });
  audit(report, 'SCOPE', `${decision.result}:${decision.reason}`);
  return report;
}

export function stageSafety(report: SecurityReport): { report: SecurityReport; stop: boolean } {
  if (containsSensitiveRealUserData(report)) {
    audit(report, 'SAFETY_STOP', 'sensitive_real_user_data');
    return { report, stop: true };
  }
  audit(report, 'SAFETY_OK');
  return { report, stop: false };
}

export function stageDuplicate(report: SecurityReport, existing: SecurityReport[]): SecurityReport {
  const status = classifyAgainstIndex(report, existing);
  report.duplicate_status = status;
  if (status === 'SYSTEMIC' || status === 'SAME_ROOT_CAUSE' || status === 'MULTIPLE_ENDPOINT_INSTANCE') {
    report.systemic_status = 'candidate';
  }
  audit(report, 'DUPLICATE', status);
  return report;
}

export function stageValidity(report: SecurityReport): { report: SecurityReport; hold: boolean } {
  const q = validateReportQuality(report);
  if (q.evidenceClass === 'EXCESSIVE') {
    audit(report, 'EVIDENCE_EXCESSIVE', 'request_redaction');
  }
  if (report.scope_result === 'OUT_OF_SCOPE') {
    report.validity = 'n_a';
    return { report, hold: false };
  }
  if (!q.ok) {
    report.validity = 'pending_clarification';
    audit(report, 'VALIDITY_HOLD', q.missing.join(','));
    return { report, hold: true };
  }
  if (report.duplicate_status === 'EXACT_DUPLICATE') {
    report.validity = 'duplicate';
    return { report, hold: false };
  }
  report.validity = 'valid';
  audit(report, 'VALIDITY_OK');
  return { report, hold: false };
}


export function stageImpact(report: SecurityReport): SecurityReport {
  if (!report.security_impact?.trim()) {
    report.business_impact = report.business_impact || 'PENDING_ASSESSMENT';
  } else if (!report.business_impact?.trim()) {
    report.business_impact = 'PENDING_ASSESSMENT';
  }
  audit(report, 'IMPACT', report.business_impact);
  return report;
}

export function stageSeverity(report: SecurityReport): SecurityReport {
  if (!report.cvss || report.cvss.score == null) {
    report.severity = report.severity || 'NOT_SCORED';
  } else if (!report.severity) {
    report.severity = 'pending_cvss';
  }
  audit(report, 'SEVERITY', report.severity || 'NOT_SCORED');
  return report;
}

export function stageRemediation(report: SecurityReport): SecurityReport {
  if (report.validity === 'valid' && report.remediation_status === 'none') {
    report.remediation_status = 'assigned';
  }
  audit(report, 'REMEDIATION', report.remediation_status);
  return report;
}

export function stageDisclosure(report: SecurityReport): SecurityReport {
  const current = report.disclosure_status || 'reported';
  // Initial pipeline only advances reported → triaged when in-scope and not held
  const target = current === 'reported' ? 'triaged' : current;
  if (target === current) {
    audit(report, 'DISCLOSURE_NOOP', current);
    return report;
  }
  const result = applyDisclosureTransition(current, target, {
    validity: report.validity,
    scopeResult: report.scope_result,
    sensitiveStop: false,
    pendingSpecialAuth: report.scope_result === 'PENDING_SPECIAL_AUTH',
  });
  if (!result.ok) {
    audit(report, 'DISCLOSURE_REJECTED', result.reason);
    return report; // state unchanged
  }
  report.disclosure_status = target;
  audit(report, 'DISCLOSURE_TRANSITION', `${result.from}->${result.to}`);
  return report;
}

/** Explicit guarded transition API for later stages (remediation/fix/disclosure). */
export function transitionReportDisclosure(
  report: SecurityReport,
  next: string,
  opts?: { sensitiveStop?: boolean }
): { report: SecurityReport; accepted: boolean; reason: string } {
  const current = report.disclosure_status || 'reported';
  const result = applyDisclosureTransition(current, next, {
    validity: report.validity === 'UNSET' ? undefined : report.validity,
    scopeResult: report.scope_result === 'UNSET' ? undefined : report.scope_result,
    sensitiveStop: opts?.sensitiveStop,
    pendingSpecialAuth: report.scope_result === 'PENDING_SPECIAL_AUTH',
  });
  if (!result.ok) {
    audit(report, 'DISCLOSURE_REJECTED', result.reason);
    return { report, accepted: false, reason: result.reason };
  }
  report.disclosure_status = next;
  audit(report, 'DISCLOSURE_TRANSITION', `${result.from}->${result.to}`);
  return { report, accepted: true, reason: result.reason };
}

export function stageBounty(report: SecurityReport): SecurityReport {
  const cfg = getProgramConfig();
  if (cfg.Q30_rewardModel === 'B_VDP') {
    report.bounty_status = 'VDP — RECOGNITION_ONLY';
  } else if (cfg.Q30_rewardModel === 'A_PAID') {
    report.bounty_status = BOUNTY_STATUS_CONFIGURED_PAID + ' — ELIGIBILITY_REVIEW_REQUIRED';
  } else if (cfg.Q30_rewardModel === 'C_SELECTED') {
    report.bounty_status = 'ELIGIBILITY_REVIEW — AMOUNTS NOT CONFIGURED';
  } else {
    report.bounty_status = BOUNTY_STATUS_DEFERRED;
  }
  audit(report, 'BOUNTY', report.bounty_status);
  return report;
}

/**
 * Full pipeline entry point.
 */
export function processSecurityReport(
  input: Partial<SecurityReport> & Pick<SecurityReport, 'report_id' | 'researcher' | 'asset'>,
  options: ProcessOptions = {}
): TriageResult {
  let report = createEmptyReport(input);
  const messages: string[] = [];
  const existing = options.existingReports ?? listReports().filter((r) => r.report_id !== report.report_id);

  report = stageScope(report);
  if (report.scope_result === 'OUT_OF_SCOPE') {
    report.validity = 'n_a';
    messages.push('OUT_OF_SCOPE');
    saveReport(report);
    return { report, stage: 'CLOSED', stopped: true, hold: false, messages };
  }
  if (report.scope_result === 'PENDING_SPECIAL_AUTH') {
    messages.push('PENDING_SPECIAL_AUTH');
    saveReport(report);
    return { report, stage: 'HELD', stopped: false, hold: true, messages };
  }

  const safety = stageSafety(report);
  report = safety.report;
  if (safety.stop) {
    messages.push('SENSITIVE_DATA_STOP');
    saveReport(report);
    return { report, stage: 'HELD', stopped: true, hold: true, messages };
  }

  report = stageDuplicate(report, existing);
  if (report.duplicate_status === 'EXACT_DUPLICATE') {
    report.validity = 'duplicate';
    messages.push('EXACT_DUPLICATE');
    saveReport(report);
    return { report, stage: 'CLOSED', stopped: true, hold: false, messages };
  }

  const val = stageValidity(report);
  report = val.report;
  if (val.hold) {
    messages.push('CLARIFICATION');
    saveReport(report);
    return { report, stage: 'VALIDITY', stopped: false, hold: true, messages };
  }

  report = stageImpact(report);
  report = stageSeverity(report);
  report = stageBounty(report);
  report = stageRemediation(report);
  report = stageDisclosure(report);
  messages.push('PIPELINE_COMPLETE');
  saveReport(report);
  return { report, stage: 'DISCLOSURE', stopped: false, hold: false, messages };
}

/** API-facing scope gate helper */
export function enforceScopeForAsset(asset: string): {
  allowed: boolean;
  result: string;
  reason: string;
} {
  const decision = return_scope_decision(asset, getProgramConfig());
  saveScopeDecision({
    id: `api_scope_${Date.now()}`,
    decision,
    createdAt: new Date().toISOString(),
  });
  return {
    allowed: decision.result === 'IN_SCOPE',
    result: decision.result,
    reason: decision.reason,
  };
}
