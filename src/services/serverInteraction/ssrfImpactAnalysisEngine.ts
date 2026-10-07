import { SeverityLevel } from '../../types.ts';
import {
  DestinationClass,
  SSRFImpact,
  SSRFConfidence,
  SSRFFindingCandidate,
  ServerInteractionEvidence,
  ParsedUrl,
  ResolutionResult,
  RedirectHop,
  DestinationPolicyDecision,
  InteractionObservation,
} from '../../types/serverInteractionResearch.ts';
import { computeEvidenceHash } from '../evidenceService.ts';

export function classifySSRFImpact(
  destinationClass: DestinationClass,
  observations: InteractionObservation[],
  responseSnippet?: string
): { impact: SSRFImpact; severity: SeverityLevel } {
  if (observations.length === 0) {
    return { impact: 'NONE', severity: 'Low' };
  }

  const isMetadata =
    destinationClass === 'METADATA' ||
    observations.some(o => o.destinationClass === 'METADATA');

  const isPrivate =
    destinationClass === 'PRIVATE_RFC1918' ||
    destinationClass === 'LOOPBACK' ||
    destinationClass === 'LINK_LOCAL' ||
    observations.some(
      o =>
        o.destinationClass === 'PRIVATE_RFC1918' ||
        o.destinationClass === 'LOOPBACK' ||
        o.destinationClass === 'LINK_LOCAL'
    );

  const containsCredentials =
    (responseSnippet &&
      (responseSnippet.includes('AWS_SECRET_ACCESS_KEY') ||
        responseSnippet.includes('security-credentials') ||
        responseSnippet.includes('access_token') ||
        responseSnippet.includes('private_key'))) ||
    observations.some(o => o.bodySnippet?.includes('AWS_SECRET_ACCESS_KEY'));

  if (isMetadata && containsCredentials) {
    return { impact: 'CREDENTIAL_ACCESS_INDICATOR', severity: 'Critical' };
  }

  if (isMetadata) {
    return { impact: 'SENSITIVE_SERVICE_ACCESS', severity: 'Critical' };
  }

  if (isPrivate) {
    return { impact: 'NETWORK_BOUNDARY_CROSSING', severity: 'High' };
  }

  return { impact: 'SERVER_SIDE_REQUEST_ONLY', severity: 'Low' };
}

export function calculateSSRFConfidence(params: {
  hasServerSideInteraction: boolean;
  isControlledDestination: boolean;
  isForbiddenDestination: boolean;
  isCorrelated: boolean;
  isReproducible: boolean;
}): SSRFConfidence {
  const {
    hasServerSideInteraction,
    isControlledDestination,
    isForbiddenDestination,
    isCorrelated,
    isReproducible,
  } = params;

  if (!hasServerSideInteraction) {
    return 'NO_FINDING';
  }

  if (
    hasServerSideInteraction &&
    isControlledDestination &&
    isForbiddenDestination &&
    isCorrelated &&
    isReproducible
  ) {
    return 'HIGH_CONFIDENCE';
  }

  if (hasServerSideInteraction && isForbiddenDestination) {
    return 'MEDIUM_CONFIDENCE';
  }

  if (hasServerSideInteraction && !isForbiddenDestination) {
    return 'OBSERVATION';
  }

  return 'LOW_CONFIDENCE';
}

export function createSSRFFindingCandidate(params: {
  researchCaseId: string;
  executionId: string;
  requestId: string;
  target: string;
  targetEndpoint: string;
  inputParameter: string;
  suppliedUrl: string;
  parsedUrl: ParsedUrl;
  resolution: ResolutionResult;
  redirectChain: RedirectHop[];
  policyDecision: DestinationPolicyDecision;
  observations: InteractionObservation[];
  responseSnippet?: string;
  capabilityId?: string;
}): SSRFFindingCandidate {
  const {
    researchCaseId,
    executionId,
    requestId,
    target,
    targetEndpoint,
    inputParameter,
    suppliedUrl,
    parsedUrl,
    resolution,
    redirectChain,
    policyDecision,
    observations,
    responseSnippet,
    capabilityId = 'active-server-interaction-ssrf',
  } = params;

  const { impact, severity } = classifySSRFImpact(
    resolution.destinationClass,
    observations,
    responseSnippet
  );

  const confidence = calculateSSRFConfidence({
    hasServerSideInteraction: observations.length > 0,
    isControlledDestination: true,
    isForbiddenDestination:
      resolution.destinationClass === 'PRIVATE_RFC1918' ||
      resolution.destinationClass === 'LOOPBACK' ||
      resolution.destinationClass === 'LINK_LOCAL' ||
      resolution.destinationClass === 'METADATA',
    isCorrelated: observations.some(o => o.isCorrelated),
    isReproducible: true,
  });

  const vulnerabilityType =
    resolution.destinationClass === 'METADATA'
      ? 'SSRF_CLOUD_METADATA_EXPOSURE'
      : resolution.destinationClass === 'LOOPBACK'
      ? 'SSRF_LOOPBACK_SERVICE_ACCESS'
      : 'SSRF_INTERNAL_NETWORK_INTERACTION';

  const reproductionSteps = [
    `1. Identify server-side URL consumption endpoint: ${targetEndpoint} accepting parameter '${inputParameter}'.`,
    `2. Supply destination target: '${suppliedUrl}' (resolving to ${resolution.ipAddress}, destination class: ${resolution.destinationClass}).`,
    `3. Send request to application server and observe outbound interaction or response.`,
    `4. Verify server-side network component initiated ${observations.length} outbound connection(s) to forbidden address (${resolution.ipAddress}).`,
  ];

  const remediation =
    'Enforce a strict server-side URL validation and network egress policy. Canonicalize and parse all user-supplied URLs against an allowlist of permitted protocols (HTTP/HTTPS only). Resolve hostnames and validate the resolved IP addresses against RFC 1918 private subnets, loopback ranges (127.0.0.0/8), link-local ranges (169.254.0.0/16), and cloud metadata services before establishing socket connections. Validate every hop in HTTP redirect chains.';

  const evidenceSummary = {
    researchCaseId,
    executionId,
    requestId,
    target,
    targetEndpoint,
    inputParameter,
    suppliedUrl,
    canonicalUrl: parsedUrl.canonicalUrl,
    resolvedIp: resolution.ipAddress,
    destinationClass: resolution.destinationClass,
    totalRedirectHops: redirectChain.length,
    recordedInteractionsCount: observations.length,
    impact,
    confidence,
  };

  const evidenceHash = computeEvidenceHash(evidenceSummary, capabilityId, target);

  return {
    candidateId: `cand-ssrf-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    title: `[${vulnerabilityType}] Server-Side Request Forgery via ${inputParameter} on ${targetEndpoint}`,
    target,
    vulnerabilityType,
    cweId: 'CWE-918',
    severity,
    confidence,
    impact,
    destinationClass: resolution.destinationClass,
    reproductionSteps,
    remediation,
    evidenceSummary,
    evidenceHash,
    createdAt: new Date().toISOString(),
  };
}
