import {
  DestinationClass,
  InteractionObservation,
  DestinationPolicyDecision,
  SSRFImpact,
  SSRFConfidence,
} from '../../types/serverInteractionResearch.ts';

export interface SSRFDifferentialEvaluation {
  hasAnomaly: boolean;
  anomalyType?: 'UNAUTHORIZED_SERVER_INTERACTION' | 'FORBIDDEN_DESTINATION_REACHED' | 'METADATA_DISCLOSURE';
  isFalsePositive: boolean;
  suppressionReason?: string;
  impact: SSRFImpact;
  confidence: SSRFConfidence;
  explanation: string;
}

export function evaluateSSRFDifferential(params: {
  intendedDestinationClass: DestinationClass;
  policyDecision: DestinationPolicyDecision;
  serverSideInteractions: InteractionObservation[];
  responseStatus?: number;
  responseBodySnippet?: string;
  isInputReflectedOnly?: boolean;
}): SSRFDifferentialEvaluation {
  const {
    intendedDestinationClass,
    policyDecision,
    serverSideInteractions,
    responseStatus,
    responseBodySnippet,
    isInputReflectedOnly,
  } = params;

  // 1. False positive check: Input reflected only in response, no server-side interaction occurred
  if (serverSideInteractions.length === 0) {
    if (isInputReflectedOnly) {
      return {
        hasAnomaly: false,
        isFalsePositive: true,
        suppressionReason: 'URL string is reflected in response markup/body without server-side outbound interaction',
        impact: 'NONE',
        confidence: 'NO_FINDING',
        explanation: 'Harmless URL reflection: No outbound network request initiated by the server.',
      };
    }

    if (policyDecision.decision === 'DENY' || policyDecision.decision === 'BLOCK') {
      return {
        hasAnomaly: false,
        isFalsePositive: false,
        suppressionReason: 'Server-side component safely rejected forbidden destination',
        impact: 'NONE',
        confidence: 'NO_FINDING',
        explanation: `Secure defense enforced: ${policyDecision.reason}`,
      };
    }

    return {
      hasAnomaly: false,
      isFalsePositive: false,
      impact: 'NONE',
      confidence: 'NO_FINDING',
      explanation: 'No outbound server-side interactions recorded.',
    };
  }

  // 2. Correlated server-side interactions occurred
  const forbiddenInteractions = serverSideInteractions.filter(
    obs =>
      obs.destinationClass === 'PRIVATE_RFC1918' ||
      obs.destinationClass === 'LOOPBACK' ||
      obs.destinationClass === 'LINK_LOCAL' ||
      obs.destinationClass === 'METADATA'
  );

  if (forbiddenInteractions.length > 0) {
    const hasMetadata = forbiddenInteractions.some(obs => obs.destinationClass === 'METADATA');
    const hasSensitiveService = forbiddenInteractions.some(
      obs => obs.bodySnippet?.includes('AWS_SECRET') || obs.bodySnippet?.includes('instance-id') || obs.bodySnippet?.includes('root:x:')
    );

    let impact: SSRFImpact = 'INTERNAL_RESOURCE_ACCESS';
    if (hasMetadata || hasSensitiveService) {
      impact = 'SENSITIVE_SERVICE_ACCESS';
    } else if (intendedDestinationClass === 'PRIVATE_RFC1918' || intendedDestinationClass === 'LOOPBACK') {
      impact = 'NETWORK_BOUNDARY_CROSSING';
    }

    return {
      hasAnomaly: true,
      anomalyType: hasMetadata ? 'METADATA_DISCLOSURE' : 'FORBIDDEN_DESTINATION_REACHED',
      isFalsePositive: false,
      impact,
      confidence: 'HIGH_CONFIDENCE',
      explanation: `Server initiated ${forbiddenInteractions.length} outbound request(s) to forbidden destination class (${forbiddenInteractions[0].destinationClass})`,
    };
  }

  // 3. Server reached safe / public / controlled fixture
  if (intendedDestinationClass === 'PUBLIC_EXTERNAL' || intendedDestinationClass === 'CONTROLLED_FIXTURE') {
    return {
      hasAnomaly: false,
      isFalsePositive: false,
      impact: 'SERVER_SIDE_REQUEST_ONLY',
      confidence: 'OBSERVATION',
      explanation: 'Server-side request reached legitimate public/fixture destination as intended.',
    };
  }

  return {
    hasAnomaly: false,
    isFalsePositive: false,
    impact: 'NONE',
    confidence: 'NO_FINDING',
    explanation: 'Standard request behavior without boundary violations.',
  };
}
