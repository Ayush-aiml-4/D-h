import {
  ClientSideImpactDimension,
  StoredXssImpactScope,
  ClientSideImpactAnalysis,
  ConfidenceRating,
  DataFlowTrace,
  BrowserExecutionEvidence,
  XssVulnerabilityType,
  ClientSideContextType,
} from '../../types/clientSideResearch.ts';
import { SeverityLevel } from '../../types.ts';

export function evaluateClientSideImpact(input: {
  vulnerabilityType: XssVulnerabilityType;
  isVulnerable: boolean;
  context: ClientSideContextType;
  storedScope?: StoredXssImpactScope;
  evidence?: BrowserExecutionEvidence;
  dataFlow: DataFlowTrace;
}): ClientSideImpactAnalysis {
  if (!input.isVulnerable) {
    return {
      dimensions: [],
      severity: 'Low',
      summary: 'No client-side security impact observed.',
      hasSufficientEvidence: Boolean(input.evidence),
    };
  }

  const dimensions: ClientSideImpactDimension[] = ['CODE_EXECUTION', 'CONTENT_INTEGRITY'];

  let severity: SeverityLevel = 'Medium';

  if (input.vulnerabilityType === 'STORED_XSS') {
    dimensions.push('DATA_INTEGRITY');
    if (input.storedScope === 'CROSS_USER' || input.storedScope === 'PRIVILEGED_USER_CONTEXT') {
      dimensions.push('CROSS_USER_IMPACT', 'SESSION_IMPACT', 'ACCOUNT_IMPACT');
      severity = 'High';
    } else {
      severity = 'Medium';
    }
  } else if (input.vulnerabilityType === 'REFLECTED_XSS' || input.vulnerabilityType === 'DOM_XSS') {
    if (input.context === 'JAVASCRIPT_CODE' || input.context === 'HTML_TEXT') {
      severity = 'Medium';
    }
  }

  const summary = `${input.vulnerabilityType} allows arbitrary JavaScript code execution in ${input.context} context with ${severity} severity (${dimensions.join(', ')}).`;

  return {
    dimensions,
    storedScope: input.storedScope,
    severity,
    summary,
    hasSufficientEvidence: Boolean(input.evidence && input.evidence.evidenceHash),
  };
}

export function evaluateClientSideConfidence(input: {
  isVulnerable: boolean;
  sourceIdentified: boolean;
  dataFlowEstablished: boolean;
  unsafeSinkOrContextEstablished: boolean;
  executionEvidenceEstablished: boolean;
  impactEstablished: boolean;
  isDeterministic: boolean;
}): { confidence: ConfidenceRating; reasoning: string } {
  if (!input.isVulnerable) {
    return {
      confidence: 'NO_FINDING',
      reasoning: 'Zero client-side injection vulnerability confirmed by defensive controls and safe context.',
    };
  }

  const allSixEstablished =
    input.sourceIdentified &&
    input.dataFlowEstablished &&
    input.unsafeSinkOrContextEstablished &&
    input.executionEvidenceEstablished &&
    input.impactEstablished &&
    input.isDeterministic;

  if (allSixEstablished) {
    return {
      confidence: 'HIGH_CONFIDENCE',
      reasoning: 'High confidence established across all 6 criteria: verified source, tainted data flow, unsafe sink/context, deterministic browser execution evidence, verified impact, and reproducible fixture.',
    };
  }

  if (input.dataFlowEstablished && (input.executionEvidenceEstablished || input.unsafeSinkOrContextEstablished)) {
    return {
      confidence: 'MEDIUM_CONFIDENCE',
      reasoning: 'Medium confidence established: partial data flow or execution evidence observed.',
    };
  }

  return {
    confidence: 'LOW_CONFIDENCE',
    reasoning: 'Low confidence: insufficient evidence or ambiguous execution context.',
  };
}

export function isClientSideFalsePositive(input: {
  isReflected: boolean;
  isNeutralized: boolean;
  isDangerousSink: boolean;
  isExecutableContext: boolean;
  isTrustedConstant: boolean;
  hasExecutionEvidence: boolean;
}): boolean {
  // 1. Reflected safely or neutralized
  if (input.isNeutralized) return true;

  // 2. Safe sink or safe text context without execution breakout
  if (!input.isDangerousSink && !input.isExecutableContext) return true;

  // 3. Dangerous sink receiving trusted constant
  if (input.isDangerousSink && input.isTrustedConstant) return true;

  // 4. No execution evidence and no executable context
  if (!input.hasExecutionEvidence && !input.isExecutableContext) return true;

  return false;
}
