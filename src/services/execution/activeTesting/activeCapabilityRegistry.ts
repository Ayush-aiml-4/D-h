import { ActiveCapabilityDefinition, ActiveTestingAdapter } from './activeTestingTypes.ts';
import { NotFoundError, ConflictError } from '../../../utils/errors.ts';

export const CANONICAL_ACTIVE_CAPABILITIES: Record<string, ActiveCapabilityDefinition> = {
  'active-http-method-validation': {
    capabilityId: 'active-http-method-validation',
    canonicalName: 'HTTP Method Behavior & Verb Tampering Validation',
    category: 'Active Web Security Testing',
    description: 'Systematically validates server-side handling and access boundaries across HTTP verbs (GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, PATCH) to identify unexpected method overrides or configuration flaws.',
    authorizationTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    scopeRequired: true,
    policyRequirements: ['SCOPE_IN_SCOPE_REQUIRED', 'ACTIVE_TESTING_ALLOWED'],
    maximumRequestBudget: 8,
    maximumConcurrency: 2,
    timeout: 8000,
    maximumResponseSize: 1024 * 1024, // 1MB
    evidenceType: 'HTTP_VERB_TAMPERING_ANALYSIS',
    findingPromotionPolicy: 'MANUAL_REVIEW_ONLY',
    destructive: false,
    credentialInteraction: false,
    mutationLevel: 'CONTROLLED_BENIGN',
    supportedProtocols: ['http:', 'https:'],
    enabled: true,
  },

  'active-header-mutation-validation': {
    capabilityId: 'active-header-mutation-validation',
    canonicalName: 'Security Header Mutation & Reflection Validation',
    category: 'Active Web Security Testing',
    description: 'Applies controlled benign variations to request headers (e.g. Origin reflection probes, host header variations, custom accept representations) to detect unhandled reflections or insecure overrides.',
    authorizationTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    scopeRequired: true,
    policyRequirements: ['SCOPE_IN_SCOPE_REQUIRED', 'ACTIVE_TESTING_ALLOWED'],
    maximumRequestBudget: 6,
    maximumConcurrency: 2,
    timeout: 8000,
    maximumResponseSize: 1024 * 1024,
    evidenceType: 'HEADER_MUTATION_EVIDENCE',
    findingPromotionPolicy: 'MANUAL_REVIEW_ONLY',
    destructive: false,
    credentialInteraction: false,
    mutationLevel: 'CONTROLLED_BENIGN',
    supportedProtocols: ['http:', 'https:'],
    enabled: true,
  },

  'active-auth-boundary-observation': {
    capabilityId: 'active-auth-boundary-observation',
    canonicalName: 'Authorization Boundary & Access Differential Observation',
    category: 'Active Authorization Testing',
    description: 'Observes differential response behaviors between unauthenticated and test-bound request contexts to detect privilege leakage or improper 401/403 disclosure without attempting credential replay or cracking.',
    authorizationTier: 'APPROVAL_REQUIRED',
    approvalRequired: true,
    scopeRequired: true,
    policyRequirements: ['SCOPE_IN_SCOPE_REQUIRED', 'ACTIVE_TESTING_ALLOWED', 'EXPLICIT_RESEARCHER_APPROVAL_REQUIRED'],
    maximumRequestBudget: 5,
    maximumConcurrency: 1,
    timeout: 10000,
    maximumResponseSize: 1024 * 1024,
    evidenceType: 'AUTH_BOUNDARY_DIFFERENTIAL',
    findingPromotionPolicy: 'MANUAL_REVIEW_ONLY',
    destructive: false,
    credentialInteraction: false,
    mutationLevel: 'PAYLOAD_PROBE',
    supportedProtocols: ['http:', 'https:'],
    enabled: true,
  },

  'active-parameter-handling-validation': {
    capabilityId: 'active-parameter-handling-validation',
    canonicalName: 'Parameter Handling & Pollution Validation',
    category: 'Active Input Validation Testing',
    description: 'Validates server resilience against HTTP parameter pollution (HPP), duplicate query parameters, and benign type variations to detect unhandled exception traces or inconsistent parameter parsing.',
    authorizationTier: 'APPROVAL_REQUIRED',
    approvalRequired: true,
    scopeRequired: true,
    policyRequirements: ['SCOPE_IN_SCOPE_REQUIRED', 'ACTIVE_TESTING_ALLOWED', 'EXPLICIT_RESEARCHER_APPROVAL_REQUIRED'],
    maximumRequestBudget: 6,
    maximumConcurrency: 1,
    timeout: 8000,
    maximumResponseSize: 1024 * 1024,
    evidenceType: 'PARAMETER_HANDLING_EVIDENCE',
    findingPromotionPolicy: 'MANUAL_REVIEW_ONLY',
    destructive: false,
    credentialInteraction: false,
    mutationLevel: 'CONTROLLED_BENIGN',
    supportedProtocols: ['http:', 'https:'],
    enabled: true,
  },

  'active-redirect-policy-validation': {
    capabilityId: 'active-redirect-policy-validation',
    canonicalName: 'Redirect & Transport Security Policy Validation',
    category: 'Active Transport & Routing Security',
    description: 'Probes HTTP-to-HTTPS upgrade strictness, relative versus absolute redirect behavior, and protocol downgrade resistance on target endpoints without performing external crawling.',
    authorizationTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    scopeRequired: true,
    policyRequirements: ['SCOPE_IN_SCOPE_REQUIRED', 'ACTIVE_TESTING_ALLOWED'],
    maximumRequestBudget: 5,
    maximumConcurrency: 2,
    timeout: 8000,
    maximumResponseSize: 1024 * 1024,
    evidenceType: 'REDIRECT_POLICY_EVIDENCE',
    findingPromotionPolicy: 'MANUAL_REVIEW_ONLY',
    destructive: false,
    credentialInteraction: false,
    mutationLevel: 'CONTROLLED_BENIGN',
    supportedProtocols: ['http:', 'https:'],
    enabled: true,
  },

  'active-bola-idor-research': {
    capabilityId: 'active-bola-idor-research',
    canonicalName: 'Broken Object Level Authorization (BOLA/IDOR) Research',
    category: 'Active Authorization Testing',
    description: 'Executes controlled differential authorization testing across distinct account contexts to identify unauthorized cross-tenant object access without unrestricted enumeration.',
    authorizationTier: 'APPROVAL_REQUIRED',
    approvalRequired: true,
    scopeRequired: true,
    policyRequirements: ['SCOPE_IN_SCOPE_REQUIRED', 'ACTIVE_TESTING_ALLOWED', 'EXPLICIT_RESEARCHER_APPROVAL_REQUIRED'],
    maximumRequestBudget: 10,
    maximumConcurrency: 1,
    timeout: 10000,
    maximumResponseSize: 1024 * 1024,
    evidenceType: 'BOLA_DIFFERENTIAL_EVIDENCE',
    findingPromotionPolicy: 'MANUAL_REVIEW_ONLY',
    destructive: false,
    credentialInteraction: true,
    mutationLevel: 'CONTROLLED_BENIGN',
    supportedProtocols: ['http:', 'https:'],
    enabled: true,
  },

  'active-horizontal-auth-research': {
    capabilityId: 'active-horizontal-auth-research',
    canonicalName: 'Horizontal Peer Authorization Boundary Research',
    category: 'Active Authorization Testing',
    description: 'Compares response differentials between equivalent peer account contexts (Account A vs Account B) on sensitive target resources to detect horizontal authorization bypasses.',
    authorizationTier: 'APPROVAL_REQUIRED',
    approvalRequired: true,
    scopeRequired: true,
    policyRequirements: ['SCOPE_IN_SCOPE_REQUIRED', 'ACTIVE_TESTING_ALLOWED', 'EXPLICIT_RESEARCHER_APPROVAL_REQUIRED'],
    maximumRequestBudget: 10,
    maximumConcurrency: 1,
    timeout: 10000,
    maximumResponseSize: 1024 * 1024,
    evidenceType: 'HORIZONTAL_AUTH_EVIDENCE',
    findingPromotionPolicy: 'MANUAL_REVIEW_ONLY',
    destructive: false,
    credentialInteraction: true,
    mutationLevel: 'CONTROLLED_BENIGN',
    supportedProtocols: ['http:', 'https:'],
    enabled: true,
  },

  'active-vertical-auth-research': {
    capabilityId: 'active-vertical-auth-research',
    canonicalName: 'Vertical Privilege Escalation & Role Boundary Research',
    category: 'Active Authorization Testing',
    description: 'Evaluates role-based access control (RBAC) boundaries by testing unprivileged caller access against privileged administrative endpoints and operations.',
    authorizationTier: 'APPROVAL_REQUIRED',
    approvalRequired: true,
    scopeRequired: true,
    policyRequirements: ['SCOPE_IN_SCOPE_REQUIRED', 'ACTIVE_TESTING_ALLOWED', 'EXPLICIT_RESEARCHER_APPROVAL_REQUIRED'],
    maximumRequestBudget: 8,
    maximumConcurrency: 1,
    timeout: 10000,
    maximumResponseSize: 1024 * 1024,
    evidenceType: 'VERTICAL_ESCALATION_EVIDENCE',
    findingPromotionPolicy: 'MANUAL_REVIEW_ONLY',
    destructive: false,
    credentialInteraction: true,
    mutationLevel: 'CONTROLLED_BENIGN',
    supportedProtocols: ['http:', 'https:'],
    enabled: true,
  },

  'active-unauth-differential-research': {
    capabilityId: 'active-unauth-differential-research',
    canonicalName: 'Unauthenticated Access & Information Disclosure Research',
    category: 'Active Authorization Testing',
    description: 'Identifies non-public resources and sensitive data accessible without authentication, distinguishing intentionally public endpoints from authentication bypasses.',
    authorizationTier: 'LOW_RISK_ACTIVE',
    approvalRequired: false,
    scopeRequired: true,
    policyRequirements: ['SCOPE_IN_SCOPE_REQUIRED', 'ACTIVE_TESTING_ALLOWED'],
    maximumRequestBudget: 6,
    maximumConcurrency: 2,
    timeout: 8000,
    maximumResponseSize: 1024 * 1024,
    evidenceType: 'UNAUTHENTICATED_ACCESS_EVIDENCE',
    findingPromotionPolicy: 'MANUAL_REVIEW_ONLY',
    destructive: false,
    credentialInteraction: false,
    mutationLevel: 'CONTROLLED_BENIGN',
    supportedProtocols: ['http:', 'https:'],
    enabled: true,
  },

  'active-destructive-fuzzing-prohibited': {
    capabilityId: 'active-destructive-fuzzing-prohibited',
    canonicalName: 'Destructive Payload Injection & Arbitrary Fuzzing',
    category: 'Prohibited Testing',
    description: 'Unrestricted brute force, credential stuffing, and destructive payload testing are strictly prohibited by the DevilHunt safety policy architecture.',
    authorizationTier: 'RESTRICTED',
    approvalRequired: true,
    scopeRequired: true,
    policyRequirements: ['RESTRICTED_OPERATION_NEVER_PERMITTED'],
    maximumRequestBudget: 0,
    maximumConcurrency: 0,
    timeout: 0,
    maximumResponseSize: 0,
    evidenceType: 'PROHIBITED',
    findingPromotionPolicy: 'OBSERVATION_ONLY',
    destructive: true,
    credentialInteraction: true,
    mutationLevel: 'RESTRICTED',
    supportedProtocols: [],
    enabled: false,
  },
};

class ActiveAdapterRegistry {
  private adapters: Map<string, ActiveTestingAdapter> = new Map();

  public registerAdapter(adapter: ActiveTestingAdapter): void {
    const primaryId = adapter.capabilityId.trim().toLowerCase();
    this.adapters.set(primaryId, adapter);

    if (adapter.aliases) {
      for (const alias of adapter.aliases) {
        this.adapters.set(alias.trim().toLowerCase(), adapter);
      }
    }
  }

  public getAdapter(capabilityId: string): ActiveTestingAdapter | undefined {
    if (!capabilityId) return undefined;
    return this.adapters.get(capabilityId.trim().toLowerCase());
  }

  public listAdapters(): ActiveTestingAdapter[] {
    const seen = new Set<string>();
    const list: ActiveTestingAdapter[] = [];
    for (const adapter of this.adapters.values()) {
      if (!seen.has(adapter.capabilityId)) {
        seen.add(adapter.capabilityId);
        list.push(adapter);
      }
    }
    return list;
  }

  public isAdapterRegistered(capabilityId: string): boolean {
    if (!capabilityId) return false;
    return this.adapters.has(capabilityId.trim().toLowerCase());
  }

  public clearAdaptersForTesting(): void {
    this.adapters.clear();
  }
}

export const activeAdapterRegistry = new ActiveAdapterRegistry();

export function resolveActiveCapability(capabilityId: string): ActiveCapabilityDefinition {
  if (!capabilityId) {
    throw new NotFoundError('CAPABILITY_ID_REQUIRED: Active capability ID must be provided');
  }

  const def = CANONICAL_ACTIVE_CAPABILITIES[capabilityId.trim().toLowerCase()];
  if (!def) {
    throw new NotFoundError(`UNKNOWN_ACTIVE_CAPABILITY: Active capability '${capabilityId}' is not defined`);
  }

  return def;
}

export function resolveActiveAdapter(capabilityId: string): ActiveTestingAdapter {
  if (!capabilityId) {
    throw new NotFoundError('CAPABILITY_ID_REQUIRED: Capability ID must be provided');
  }

  const def = resolveActiveCapability(capabilityId);
  if (def.authorizationTier === 'RESTRICTED' || !def.enabled) {
    throw new ConflictError(`CAPABILITY_RESTRICTED: Capability '${capabilityId}' is restricted or disabled`);
  }

  const adapter = activeAdapterRegistry.getAdapter(capabilityId);
  if (!adapter) {
    throw new NotFoundError(
      `UNREGISTERED_ACTIVE_ADAPTER: No active testing adapter is registered for capability '${capabilityId}'`
    );
  }

  if (!adapter.enabled) {
    throw new ConflictError(
      `ADAPTER_DISABLED: Active adapter for capability '${capabilityId}' is currently disabled`
    );
  }

  return adapter;
}
