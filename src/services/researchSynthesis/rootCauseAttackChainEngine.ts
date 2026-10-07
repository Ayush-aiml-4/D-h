import {
  ResearchObservation,
  AttackChain,
  AttackChainStep,
} from '../../types/researchSynthesis.ts';
import { evaluateCrossEngineChain } from './crossEngineAdapters.ts';

export interface RootCauseSynthesis {
  rootCause: string;
  vulnerabilityClass: string;
  cweId: string;
  attackChain: AttackChain;
  primaryObservation: ResearchObservation;
  correlatedObservations: ResearchObservation[];
}

export function synthesizeRootCauseAndChain(
  observations: ResearchObservation[]
): RootCauseSynthesis {
  if (!observations || observations.length === 0) {
    throw new Error('Cannot synthesize root cause from empty observation list');
  }

  // Sort observations deterministically by provenance step or timestamp
  const sorted = [...observations].sort((a, b) => {
    const stepA = a.provenance.stepNumber ?? 0;
    const stepB = b.provenance.stepNumber ?? 0;
    if (stepA !== stepB) return stepA - stepB;
    return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
  });

  const primaryObs = sorted[0];
  const chainSteps: AttackChainStep[] = [];

  sorted.forEach((obs, idx) => {
    const stepOrder = idx + 1;
    const actor = obs.actorContext.accountIdentifier || obs.actorContext.researcherId || 'Standard Actor';
    const role = obs.actorContext.accountRole || 'STANDARD_USER';
    const resource = obs.resourceIdentifier || obs.target || 'Target System';

    let action = `Executes ${obs.capability}`;
    let description = obs.observedBehavior;

    if (obs.observationType === 'AUTHN_BYPASS' || obs.observationType === 'UNAUTHENTICATED_ACCESS') {
      action = 'Bypasses authentication checkpoint';
      description = `Actor (${actor}) accesses protected endpoint without valid credentials: ${obs.observedBehavior}`;
    } else if (obs.observationType === 'CROSS_ACCOUNT_ACCESS' || obs.observationType === 'AUTHZ_BOUNDARY_WEAKNESS') {
      action = 'Accesses unauthorized tenant resource (BOLA)';
      description = `Actor (${actor}) in role ${role} accesses resource ${resource} belonging to another tenant`;
    } else if (obs.observationType === 'FORBIDDEN_WORKFLOW_TRANSITION') {
      action = 'Forces unauthorized workflow state transition';
      description = `Workflow state mutation invoked out-of-order or without sufficient privilege: ${obs.observedBehavior}`;
    } else if (obs.observationType === 'OUTBOUND_SSRF_INTERACTION' || obs.observationType === 'BLIND_INTERACTION_RECEIVED') {
      action = 'Triggers server-side outbound interaction';
      description = `Target server issues HTTP interaction to restricted internal/metadata destination: ${obs.observedBehavior}`;
    } else if (obs.observationType === 'SQL_INJECTION_DIFFERENTIAL') {
      action = 'Injects structured query payload';
      description = `Database behavior differential confirms arbitrary SQL query injection`;
    }

    chainSteps.push({
      stepOrder,
      actor: `${actor} [${role}]`,
      action,
      resource,
      initialState: idx === 0 ? 'AUTHENTICATED_SESSION' : `STEP_${idx}_COMPLETED`,
      resultingState: `STATE_ANOMALY_STEP_${stepOrder}`,
      authorizationContext: role,
      evidenceRef: obs.evidenceReferences[0] || `ev-synthetic-${obs.observationId}`,
      description,
    });
  });

  // Evaluate cross-engine link if multiple observations exist
  let rootCause: string = primaryObs.observedBehavior;
  let vulnerabilityClass: string = primaryObs.observationType;
  let cweId: string = 'CWE-200';

  if (sorted.length > 1) {
    const crossLink = evaluateCrossEngineChain(sorted[0], sorted[sorted.length - 1]);
    if (crossLink) {
      rootCause = crossLink.rootCause;
      vulnerabilityClass = crossLink.synthesizedVulnerabilityClass;
      cweId = crossLink.cweId;
    } else {
      rootCause = `Multi-step sequence allows unauthorized outcome: ${sorted.map((s) => s.observedBehavior).join(' -> ')}`;
      vulnerabilityClass = `CHAINED_${primaryObs.observationType}`;
    }
  } else {
    // Single observation root cause resolution
    switch (primaryObs.observationType) {
      case 'CROSS_ACCOUNT_ACCESS':
      case 'AUTHZ_BOUNDARY_WEAKNESS':
        rootCause = 'Broken Object Level Authorization (BOLA) on resource access controller.';
        vulnerabilityClass = 'BROKEN_OBJECT_LEVEL_AUTHORIZATION';
        cweId = 'CWE-639';
        break;
      case 'AUTHN_BYPASS':
      case 'UNAUTHENTICATED_ACCESS':
        rootCause = 'Missing authentication verification on protected resource route.';
        vulnerabilityClass = 'BROKEN_AUTHENTICATION';
        cweId = 'CWE-306';
        break;
      case 'FORBIDDEN_WORKFLOW_TRANSITION':
      case 'BUSINESS_INVARIANT_VIOLATION':
        rootCause = 'Missing business logic invariant validation during state transitions.';
        vulnerabilityClass = 'BUSINESS_LOGIC_STATE_BYPASS';
        cweId = 'CWE-840';
        break;
      case 'OUTBOUND_SSRF_INTERACTION':
      case 'METADATA_ACCESS_ATTEMPT':
        rootCause = 'Unrestricted outbound URL fetching allows requests to internal network or cloud metadata.';
        vulnerabilityClass = 'SERVER_SIDE_REQUEST_FORGERY';
        cweId = 'CWE-918';
        break;
      case 'SQL_INJECTION_DIFFERENTIAL':
        rootCause = 'Improper neutralization of special elements used in an SQL command.';
        vulnerabilityClass = 'SQL_INJECTION';
        cweId = 'CWE-89';
        break;
      case 'XSS_HTML_EXECUTION':
        rootCause = 'Improper neutralization of input during web page generation.';
        vulnerabilityClass = 'CROSS_SITE_SCRIPTING';
        cweId = 'CWE-79';
        break;
      case 'PATH_TRAVERSAL_READ':
        rootCause = 'Improper limitation of a pathname to a restricted directory.';
        vulnerabilityClass = 'PATH_TRAVERSAL';
        cweId = 'CWE-22';
        break;
      default:
        rootCause = primaryObs.observedBehavior;
        vulnerabilityClass = primaryObs.observationType;
        cweId = 'CWE-699';
    }
  }

  const attackChain: AttackChain = {
    chainId: `chain-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    steps: chainSteps,
    summary: `${chainSteps.length}-step execution path demonstrating ${vulnerabilityClass}`,
    entryPoint: chainSteps[0]?.action || 'Initial request',
    terminalImpact: chainSteps[chainSteps.length - 1]?.description || 'Impact achieved',
  };

  return {
    rootCause,
    vulnerabilityClass,
    cweId,
    attackChain,
    primaryObservation: primaryObs,
    correlatedObservations: sorted,
  };
}
