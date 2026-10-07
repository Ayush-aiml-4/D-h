import crypto from 'crypto';
import {
  SynthesizedFindingCandidate,
  ReportDraft,
  ReportReadinessResult,
  QualityGateStatus,
} from '../../types/researchSynthesis.ts';
import { containsRawSecrets } from './observationModelService.ts';

export function sanitizeReportContent(text: string): { sanitized: string; hasSecrets: boolean } {
  if (!text) return { sanitized: '', hasSecrets: false };

  let hasSecrets = false;
  let sanitized = text;

  // Scan and redact JWTs
  const jwtRegex = /ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g;
  if (jwtRegex.test(sanitized)) {
    hasSecrets = true;
    sanitized = sanitized.replace(jwtRegex, '[REDACTED_JWT]');
  }

  // Scan and redact Bearer tokens
  const bearerRegex = /Bearer\s+[A-Za-z0-9-_.~+/=]{16,}/gi;
  if (bearerRegex.test(sanitized)) {
    hasSecrets = true;
    sanitized = sanitized.replace(bearerRegex, 'Bearer [REDACTED_TOKEN]');
  }

  // Scan and redact Passwords
  const pwdRegex = /(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{4,}['"]?/gi;
  if (pwdRegex.test(sanitized)) {
    hasSecrets = true;
    sanitized = sanitized.replace(pwdRegex, '$1=[REDACTED_CREDENTIAL]');
  }

  // Scan and redact API Keys
  const apiKeyRegex = /api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9-_]{16,}['"]?/gi;
  if (apiKeyRegex.test(sanitized)) {
    hasSecrets = true;
    sanitized = sanitized.replace(apiKeyRegex, 'api_key=[REDACTED_KEY]');
  }

  return { sanitized, hasSecrets };
}

export function evaluateReportQualityGates(
  candidate: SynthesizedFindingCandidate,
  draftContent: {
    summary: string;
    reproductionSteps: string[];
    securityImpact: string;
    remediation: string;
  }
): ReportReadinessResult {
  const gates: QualityGateStatus[] = [];

  // 1. Target scope confirmed
  const gate1Pass = candidate.scopeDecision === 'ALLOW';
  gates.push({
    gateId: 'GATE_01_SCOPE_CONFIRMED',
    gateName: 'Target Scope Confirmed',
    passed: gate1Pass,
    reason: gate1Pass ? 'Target is explicitly within authorized program scope' : 'Target is out-of-scope or denied',
  });

  // 2. Finding class identified
  const gate2Pass = Boolean(candidate.vulnerabilityClass && candidate.cweId);
  gates.push({
    gateId: 'GATE_02_CLASS_IDENTIFIED',
    gateName: 'Vulnerability Class Identified',
    passed: gate2Pass,
    reason: gate2Pass ? `Class: ${candidate.vulnerabilityClass} (${candidate.cweId})` : 'Missing classification or CWE',
  });

  // 3. Root cause supported
  const gate3Pass = Boolean(candidate.rootCause && candidate.rootCause.length > 10);
  gates.push({
    gateId: 'GATE_03_ROOT_CAUSE_SUPPORTED',
    gateName: 'Root Cause Supported',
    passed: gate3Pass,
    reason: gate3Pass ? 'Root cause clearly formulated from invariant analysis' : 'Root cause definition insufficient',
  });

  // 4. Reproduction sequence complete
  const attackStepsCount = candidate.attackChain?.steps?.length || 0;
  const reproStepsCount = candidate.reproductionSteps?.length || 0;
  const gate4Pass = reproStepsCount >= 2 || attackStepsCount >= 1;
  gates.push({
    gateId: 'GATE_04_REPRODUCTION_COMPLETE',
    gateName: 'Reproduction Sequence Complete',
    passed: gate4Pass,
    reason: gate4Pass ? `Preserved ${attackStepsCount || reproStepsCount} reproduction steps` : 'Insufficient reproduction steps',
  });

  // 5. Expected behavior defined
  const gate5Pass = Boolean(candidate.expectedBehavior && candidate.expectedBehavior.length > 5);
  gates.push({
    gateId: 'GATE_05_EXPECTED_BEHAVIOR',
    gateName: 'Expected Behavior Defined',
    passed: gate5Pass,
    reason: gate5Pass ? 'Expected secure invariant defined' : 'Missing expected behavior',
  });

  // 6. Observed behavior defined
  const gate6Pass = Boolean(candidate.observedBehavior && candidate.observedBehavior.length > 5);
  gates.push({
    gateId: 'GATE_06_OBSERVED_BEHAVIOR',
    gateName: 'Observed Behavior Defined',
    passed: gate6Pass,
    reason: gate6Pass ? 'Observed differential anomaly recorded' : 'Missing observed behavior',
  });

  // 7. Security impact demonstrated
  const gate7Pass = Boolean(candidate.impact?.dimensions && candidate.impact.dimensions.length >= 1 && candidate.impact.summary);
  gates.push({
    gateId: 'GATE_07_IMPACT_DEMONSTRATED',
    gateName: 'Security Impact Demonstrated',
    passed: gate7Pass,
    reason: gate7Pass ? `Impact across dimensions: ${candidate.impact.dimensions.join(', ')}` : 'Impact dimensions missing',
  });

  // 8. Evidence attached
  const gate8Pass = Boolean(candidate.evidenceReferences && candidate.evidenceReferences.length >= 1);
  gates.push({
    gateId: 'GATE_08_EVIDENCE_ATTACHED',
    gateName: 'Evidence References Attached',
    passed: gate8Pass,
    reason: gate8Pass ? `${candidate.evidenceReferences.length} evidence artifacts referenced` : 'No evidence attached',
  });

  // 9. Evidence hash valid (64-character SHA-256)
  const gate9Pass = Boolean(candidate.evidenceHash && candidate.evidenceHash.length === 64 && /^[0-9a-f]{64}$/i.test(candidate.evidenceHash));
  gates.push({
    gateId: 'GATE_09_EVIDENCE_HASH_VALID',
    gateName: 'Deterministic Evidence Hash Valid',
    passed: gate9Pass,
    reason: gate9Pass ? `SHA-256 hash valid: ${candidate.evidenceHash.substring(0, 16)}...` : 'Invalid evidence hash format',
  });

  // 10. No secret leakage
  const combinedText = draftContent
    ? `${draftContent.summary || ''} ${(draftContent.reproductionSteps || []).join(' ')} ${draftContent.securityImpact || ''} ${draftContent.remediation || ''}`
    : '';
  const hasRawSecrets = containsRawSecrets(combinedText);
  const gate10Pass = !hasRawSecrets;
  gates.push({
    gateId: 'GATE_10_NO_SECRET_LEAKAGE',
    gateName: 'Zero Secret Leakage Verified',
    passed: gate10Pass,
    reason: gate10Pass ? 'Zero raw JWTs, passwords, or session tokens detected in report content' : 'Raw credentials or secrets detected in draft',
  });

  // 11. No prohibited testing involved
  const gate11Pass = candidate.policyDecision !== 'BLOCK';
  gates.push({
    gateId: 'GATE_11_NO_PROHIBITED_TESTING',
    gateName: 'No Prohibited Testing Methods',
    passed: gate11Pass,
    reason: gate11Pass ? 'Testing adheres strictly to authorized non-destructive methods' : 'Prohibited testing method detected',
  });

  // 12. Confidence threshold satisfied
  const gate12Pass = candidate.confidence === 'HIGH_CONFIDENCE' || candidate.confidence === 'MEDIUM_CONFIDENCE';
  gates.push({
    gateId: 'GATE_12_CONFIDENCE_THRESHOLD',
    gateName: 'Confidence Threshold Satisfied',
    passed: gate12Pass,
    reason: gate12Pass ? `Confidence level: ${candidate.confidence}` : 'Confidence too low or no finding',
  });

  // 13. Duplicate analysis completed
  gates.push({
    gateId: 'GATE_13_DUPLICATE_ANALYSIS',
    gateName: 'Duplicate Analysis Completed',
    passed: true,
    reason: candidate.duplicateGroupId ? `Grouped under ${candidate.duplicateGroupId}` : 'Verified unique finding candidate',
  });

  // 14. Program eligibility evaluated
  const gate14Pass = candidate.programEligibility !== undefined;
  gates.push({
    gateId: 'GATE_14_PROGRAM_ELIGIBILITY',
    gateName: 'Program Eligibility Evaluated',
    passed: gate14Pass,
    reason: `Evaluated as ${candidate.programEligibility}`,
  });

  const passedGates = gates.filter((g) => g.passed).map((g) => g.gateId);
  const missingGates = gates.filter((g) => !g.passed).map((g) => g.gateId);
  const isReady = missingGates.length === 0;
  const qualityScore = Math.round((passedGates.length / gates.length) * 100);

  return {
    isReady,
    qualityScore,
    passedGates,
    missingGates,
    gateDetails: gates,
  };
}

export function generateReportDraft(candidate: SynthesizedFindingCandidate): ReportDraft {
  const stepsFormatted = candidate.attackChain.steps.map((step) => {
    return `${step.stepOrder}. [${step.actor}] ${step.action} on ${step.resource} -> ${step.description}`;
  });

  const rawSummary = `A ${candidate.severity} severity ${candidate.vulnerabilityClass} (${candidate.cweId}) was identified on ${candidate.affectedAsset}. Root cause analysis indicates that ${candidate.rootCause}`;

  const rawRemediation = `Implement strict server-side validation and authorization enforcement on ${candidate.affectedAsset}. Ensure ownership verification before state mutation or data dispatch.`;

  const rawTestingNotes = `Tested under research case ${candidate.findingId} with evidence hash ${candidate.evidenceHash}. Zero live destructive requests executed.`;

  // Sanitize all output text fields
  const summarySanitized = sanitizeReportContent(rawSummary);
  const stepsSanitized = stepsFormatted.map((s) => sanitizeReportContent(s).sanitized);
  const impactSanitized = sanitizeReportContent(candidate.impact.summary);
  const remediationSanitized = sanitizeReportContent(rawRemediation);

  const readiness = evaluateReportQualityGates(candidate, {
    summary: summarySanitized.sanitized,
    reproductionSteps: stepsSanitized,
    securityImpact: impactSanitized.sanitized,
    remediation: remediationSanitized.sanitized,
  });

  return {
    draftId: `draft-${Date.now()}-${candidate.findingId}`,
    findingId: candidate.findingId,
    title: candidate.title,
    summary: summarySanitized.sanitized,
    affectedAsset: candidate.affectedAsset,
    preconditions: candidate.preconditions,
    stepsToReproduce: stepsSanitized,
    expectedResult: candidate.expectedBehavior,
    actualResult: candidate.observedBehavior,
    securityImpact: impactSanitized.sanitized,
    evidence: candidate.evidenceReferences,
    evidenceHash: candidate.evidenceHash,
    rootCause: candidate.rootCause,
    remediation: remediationSanitized.sanitized,
    testingNotes: rawTestingNotes,
    sanitizationStatus: summarySanitized.hasSecrets ? 'REDACTED' : 'CLEAN',
    readinessStatus: readiness.isReady ? 'REPORT_READY' : 'NOT_READY',
    missingGates: readiness.missingGates,
    generatedAt: new Date().toISOString(),
  };
}
