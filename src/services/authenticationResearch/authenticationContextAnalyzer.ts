import {
  AuthContext,
  AuthContextLabel,
  AccountRole,
  AuthState,
} from '../../types/authorizationResearch.ts';
import {
  AuthenticationState,
  SessionModel,
  SessionState,
} from '../../types/authenticationResearch.ts';

export interface CreateAuthContextParams {
  contextId?: string;
  contextLabel: AuthContextLabel;
  researcherId: string;
  programId: string;
  caseId: string;
  accountIdentifier: string;
  accountRole: AccountRole;
  authState?: AuthState;
  credentialReference: string; // Must match "cred-ref-*"
  sessionReference: string;    // Must match "sess-ref-*"
  authorizationScopes?: string[];
  expiresAt?: string;
  metadata?: Record<string, any>;
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * Validates credential and session references to strictly prohibit raw secrets or JWTs.
 */
export function validateCredentialReference(ref: string): void {
  if (!ref) {
    throw new ValidationError('Credential reference must not be empty.');
  }

  // Reject raw passwords or tokens
  const lower = ref.toLowerCase();
  if (
    lower.startsWith('eyj') || // Common JWT prefix
    lower.startsWith('bearer ') ||
    lower.includes('secret') ||
    lower.includes('password') ||
    lower.length > 80 // Reference identifiers should be short aliases
  ) {
    throw new ValidationError(
      `INVALID_CREDENTIAL_REFERENCE: Raw tokens, JWTs, and passwords are strictly prohibited. Use an indirect alias like 'cred-ref-user-a-01'.`
    );
  }

  if (!ref.startsWith('cred-ref-') && !ref.startsWith('session-ref-') && !ref.startsWith('sess-ref-') && ref !== 'none') {
    throw new ValidationError(
      `NON_COMPLIANT_REFERENCE_FORMAT: Reference must start with 'cred-ref-' or 'sess-ref-' (received '${ref}').`
    );
  }
}

/**
 * Creates and validates an AuthContext instance.
 */
export function createValidatedAuthContext(params: CreateAuthContextParams): AuthContext {
  const contextId = params.contextId || `ctx-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

  if (params.contextLabel !== 'UNAUTHENTICATED') {
    validateCredentialReference(params.credentialReference);
    validateCredentialReference(params.sessionReference);
  }

  return {
    contextId,
    contextLabel: params.contextLabel,
    researcherId: params.researcherId,
    programId: params.programId,
    caseId: params.caseId,
    accountIdentifier: params.accountIdentifier,
    accountRole: params.accountRole,
    authState: params.authState || (params.contextLabel === 'UNAUTHENTICATED' ? 'UNAUTHENTICATED' : 'AUTHENTICATED'),
    credentialReference: params.credentialReference,
    sessionReference: params.sessionReference,
    authorizationScopes: params.authorizationScopes || ['read', 'write'],
    expiresAt: params.expiresAt || new Date(Date.now() + 3600 * 1000).toISOString(),
    metadata: params.metadata || {},
  };
}

/**
 * Creates a SessionModel instance.
 */
export function createSessionModel(params: {
  sessionId?: string;
  sessionReference: string;
  accountIdentifier: string;
  accountRole?: string;
  state?: SessionState;
  credentialReference: string;
  ttlSeconds?: number;
  metadata?: Record<string, any>;
}): SessionModel {
  validateCredentialReference(params.credentialReference);
  validateCredentialReference(params.sessionReference);

  const now = new Date();
  const ttl = params.ttlSeconds !== undefined ? params.ttlSeconds : 3600;
  const expiresAt = new Date(now.getTime() + ttl * 1000).toISOString();

  return {
    sessionId: params.sessionId || `sess-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    sessionReference: params.sessionReference,
    accountIdentifier: params.accountIdentifier,
    accountRole: params.accountRole || 'STANDARD_USER',
    state: params.state || 'ACTIVE',
    createdAt: now.toISOString(),
    lastActiveAt: now.toISOString(),
    expiresAt,
    credentialReference: params.credentialReference,
    metadata: params.metadata || {},
  };
}

/**
 * Validates a session state transition.
 */
export function transitionSessionState(
  session: SessionModel,
  newState: SessionState
): SessionModel {
  const updated = { ...session, state: newState };
  if (newState === 'INVALIDATED' || newState === 'REVOKED') {
    updated.invalidatedAt = new Date().toISOString();
  }
  return updated;
}
