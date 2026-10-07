import {
  ResearchObservation,
  AttackChainStep,
  AttackChain,
} from '../../types/researchSynthesis.ts';

export interface CrossEngineChainLink {
  sourceEngine: string;
  targetEngine: string;
  isCompatible: boolean;
  synthesizedVulnerabilityClass: string;
  rootCause: string;
  cweId: string;
}

export function evaluateCrossEngineChain(
  obsA: ResearchObservation,
  obsB: ResearchObservation
): CrossEngineChainLink | null {
  const engineA = obsA.provenance.engine;
  const engineB = obsB.provenance.engine;

  // 1. Authentication (#0005) -> Authorization (#0004)
  if (
    (engineA === 'AUTHENTICATION_0005' && engineB === 'AUTHORIZATION_0004') ||
    (engineA === 'AUTHORIZATION_0004' && engineB === 'AUTHENTICATION_0005')
  ) {
    return {
      sourceEngine: engineA,
      targetEngine: engineB,
      isCompatible: true,
      synthesizedVulnerabilityClass: 'AUTHENTICATION_BYPASS_LEADING_TO_BOLA',
      rootCause: 'Improper authentication context propagation leading to unauthorized resource access across tenants.',
      cweId: 'CWE-287',
    };
  }

  // 2. Authorization (#0004) -> Workflow (#0006)
  if (
    (engineA === 'AUTHORIZATION_0004' && engineB === 'WORKFLOW_0006') ||
    (engineA === 'WORKFLOW_0006' && engineB === 'AUTHORIZATION_0004')
  ) {
    return {
      sourceEngine: engineA,
      targetEngine: engineB,
      isCompatible: true,
      synthesizedVulnerabilityClass: 'UNAUTHORIZED_WORKFLOW_STATE_MUTATION',
      rootCause: 'Missing role authorization on critical workflow state transitions allowing cross-account lifecycle manipulation.',
      cweId: 'CWE-639',
    };
  }

  // 3. Authentication (#0005) -> Workflow (#0006)
  if (
    (engineA === 'AUTHENTICATION_0005' && engineB === 'WORKFLOW_0006') ||
    (engineA === 'WORKFLOW_0006' && engineB === 'AUTHENTICATION_0005')
  ) {
    return {
      sourceEngine: engineA,
      targetEngine: engineB,
      isCompatible: true,
      synthesizedVulnerabilityClass: 'UNAUTHENTICATED_BUSINESS_FLOW_BYPASS',
      rootCause: 'Unauthenticated actor can directly invoke protected state transitions in business workflows.',
      cweId: 'CWE-306',
    };
  }

  // 4. Input / Injection (#0005) -> Authorization (#0004)
  if (
    (obsA.observationType === 'SQL_INJECTION_DIFFERENTIAL' || obsB.observationType === 'SQL_INJECTION_DIFFERENTIAL') &&
    (obsA.observationType === 'CROSS_ACCOUNT_ACCESS' || obsB.observationType === 'CROSS_ACCOUNT_ACCESS')
  ) {
    return {
      sourceEngine: engineA,
      targetEngine: engineB,
      isCompatible: true,
      synthesizedVulnerabilityClass: 'INJECTION_DRIVEN_AUTHORIZATION_BYPASS',
      rootCause: 'SQL/Parameter injection in resource lookup query compromises ownership boundaries.',
      cweId: 'CWE-89',
    };
  }

  // 5. Server Interaction / SSRF (#0007) -> Input / Internal Access (#0005 / #0004)
  if (
    engineA === 'SERVER_INTERACTION_0007' ||
    engineB === 'SERVER_INTERACTION_0007'
  ) {
    return {
      sourceEngine: engineA,
      targetEngine: engineB,
      isCompatible: true,
      synthesizedVulnerabilityClass: 'SERVER_SIDE_REQUEST_FORGERY_INTERNAL_PIVOT',
      rootCause: 'Server-side request forgery allows access to internal loopback or cloud metadata services.',
      cweId: 'CWE-918',
    };
  }

  return null;
}
