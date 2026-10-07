import { ResearchObservation, ObservationType, ActorContext } from '../../types/researchSynthesis.ts';
import { BadRequestError } from '../../utils/errors.ts';

const RAW_SECRET_PATTERNS = [
  /ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/, // JWT
  /(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{4,}/i,
  /bearer\s+[A-Za-z0-9-_.~+/=]{16,}/i,
  /sessionid\s*[:=]\s*['"]?[A-Za-z0-9-_]{16,}/i,
  /api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9-_]{16,}/i,
  /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PRIVATE)\s+KEY-----/i,
];

export function containsRawSecrets(value: string): boolean {
  if (!value || typeof value !== 'string') return false;
  return RAW_SECRET_PATTERNS.some((pattern) => pattern.test(value));
}

export function validateNoRawSecretsInObject(obj: Record<string, any>, path = ''): void {
  for (const [key, val] of Object.entries(obj)) {
    const currentPath = path ? `${path}.${key}` : key;
    if (typeof val === 'string') {
      if (containsRawSecrets(val)) {
        throw new BadRequestError(`Security violation: Raw credentials or secrets detected at '${currentPath}'. Use indirect credential references.`);
      }
    } else if (val && typeof val === 'object' && !Array.isArray(val)) {
      validateNoRawSecretsInObject(val, currentPath);
    } else if (Array.isArray(val)) {
      val.forEach((item, index) => {
        if (typeof item === 'string' && containsRawSecrets(item)) {
          throw new BadRequestError(`Security violation: Raw credentials or secrets detected at '${currentPath}[${index}]'.`);
        } else if (item && typeof item === 'object') {
          validateNoRawSecretsInObject(item, `${currentPath}[${index}]`);
        }
      });
    }
  }
}

export function createObservation(input: {
  observationId?: string;
  researchCaseId: string;
  executionId?: string;
  requestId?: string;
  programId: string;
  target: string;
  asset: string;
  capability?: string;
  actorContext: ActorContext;
  observationType: ObservationType;
  expectedBehavior: string;
  observedBehavior: string;
  impactIndicators?: string[];
  evidenceReferences?: string[];
  confidence?: 'HIGH_CONFIDENCE' | 'MEDIUM_CONFIDENCE' | 'LOW_CONFIDENCE' | 'NO_FINDING';
  provenance: {
    engine: 'AUTHORIZATION_0004' | 'AUTHENTICATION_0005' | 'WORKFLOW_0006' | 'SERVER_INTERACTION_0007' | 'SYNTHESIS_0008' | 'MANUAL';
    fixtureId?: string;
    stepNumber?: number;
    hypothesisId?: string;
  };
  resourceIdentifier?: string;
  workflowId?: string;
  metadata?: Record<string, any>;
}): ResearchObservation {
  if (!input.researchCaseId) throw new BadRequestError('Observation requires researchCaseId');
  if (!input.programId) throw new BadRequestError('Observation requires programId');
  if (!input.target) throw new BadRequestError('Observation requires target');
  if (!input.asset) throw new BadRequestError('Observation requires asset');
  if (!input.observationType) throw new BadRequestError('Observation requires observationType');
  if (!input.expectedBehavior) throw new BadRequestError('Observation requires expectedBehavior');
  if (!input.observedBehavior) throw new BadRequestError('Observation requires observedBehavior');

  // Strict secret check across actor context, behaviors, and metadata
  validateNoRawSecretsInObject(input.actorContext, 'actorContext');
  if (containsRawSecrets(input.expectedBehavior)) {
    throw new BadRequestError('Expected behavior contains raw secret pattern');
  }
  if (containsRawSecrets(input.observedBehavior)) {
    throw new BadRequestError('Observed behavior contains raw secret pattern');
  }
  if (input.metadata) {
    validateNoRawSecretsInObject(input.metadata, 'metadata');
  }

  const observationId = input.observationId || `obs-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  const executionId = input.executionId || `exec-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const requestId = input.requestId || `req-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

  return {
    observationId,
    researchCaseId: input.researchCaseId.trim(),
    executionId,
    requestId,
    programId: input.programId.trim(),
    target: input.target.trim(),
    asset: input.asset.trim(),
    capability: input.capability || 'SYNTHESIS_CORRELATION',
    actorContext: {
      researcherId: input.actorContext.researcherId || 'researcher-anon',
      accountIdentifier: input.actorContext.accountIdentifier,
      accountRole: input.actorContext.accountRole || 'STANDARD_USER',
      indirectCredentialRef: input.actorContext.indirectCredentialRef,
      sessionIdentifier: input.actorContext.sessionIdentifier,
    },
    timestamp: new Date().toISOString(),
    observationType: input.observationType,
    expectedBehavior: input.expectedBehavior.trim(),
    observedBehavior: input.observedBehavior.trim(),
    impactIndicators: input.impactIndicators || [],
    evidenceReferences: input.evidenceReferences || [],
    confidence: input.confidence || 'MEDIUM_CONFIDENCE',
    provenance: {
      engine: input.provenance.engine,
      fixtureId: input.provenance.fixtureId,
      stepNumber: input.provenance.stepNumber,
      hypothesisId: input.provenance.hypothesisId,
    },
    resourceIdentifier: input.resourceIdentifier,
    workflowId: input.workflowId,
    metadata: input.metadata || {},
  };
}

export function normalizeObservation(raw: any): ResearchObservation {
  if (!raw || typeof raw !== 'object') {
    throw new BadRequestError('Invalid raw observation object');
  }

  return createObservation({
    observationId: raw.observationId || raw.id,
    researchCaseId: raw.researchCaseId || raw.caseId || 'case-default',
    executionId: raw.executionId,
    requestId: raw.requestId,
    programId: raw.programId || 'default-program',
    target: raw.target || 'unknown-target',
    asset: raw.asset || raw.target || 'unknown-asset',
    capability: raw.capability,
    actorContext: raw.actorContext || {
      researcherId: raw.researcherId || 'researcher-001',
      accountIdentifier: raw.accountIdentifier || raw.accountId,
      accountRole: raw.accountRole || raw.role,
      indirectCredentialRef: raw.indirectCredentialRef,
    },
    observationType: raw.observationType || raw.type || 'CUSTOM_OBSERVATION',
    expectedBehavior: raw.expectedBehavior || 'Expected secure boundary enforcement',
    observedBehavior: raw.observedBehavior || raw.description || 'Observed anomaly',
    impactIndicators: Array.isArray(raw.impactIndicators) ? raw.impactIndicators : [],
    evidenceReferences: Array.isArray(raw.evidenceReferences) ? raw.evidenceReferences : (raw.evidenceRef ? [raw.evidenceRef] : []),
    confidence: raw.confidence || 'MEDIUM_CONFIDENCE',
    provenance: raw.provenance || {
      engine: raw.engine || 'SYNTHESIS_0008',
      fixtureId: raw.fixtureId,
      stepNumber: raw.stepNumber,
      hypothesisId: raw.hypothesisId,
    },
    resourceIdentifier: raw.resourceIdentifier || raw.resourceId,
    workflowId: raw.workflowId,
    metadata: raw.metadata || {},
  });
}
