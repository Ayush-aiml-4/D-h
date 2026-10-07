import { AuthContext, AuthContextLabel, AccountRole, AuthState } from '../../types/authorizationResearch.ts';
import { BadRequestError } from '../../utils/errors.ts';

// Secret detection pattern - prevents accidental insertion of raw tokens or passwords
const RAW_SECRET_PATTERNS = [
  /^(ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,})/i, // JWT token
  /^bearer\s+/i,
  /^basic\s+/i,
  /^ghp_[a-zA-Z0-9]{36}/i,
  /^gho_[a-zA-Z0-9]{36}/i,
  /^xox[baprs]-[0-9a-zA-Z]{10,}/i,
  /^[A-Za-z0-9+/]{40,}={0,2}$/, // Base64 raw secret
  /password123/i,
  /secret/i,
];

export function validateCredentialReference(credRef: string): void {
  if (!credRef || typeof credRef !== 'string') {
    throw new BadRequestError('INVALID_CREDENTIAL_REFERENCE: Credential reference is required');
  }

  const clean = credRef.trim();

  // Ensure it is a reference identifier, not a raw credential
  for (const pattern of RAW_SECRET_PATTERNS) {
    if (pattern.test(clean)) {
      throw new BadRequestError(
        'SECRET_DETECTED_IN_CREDENTIAL_REFERENCE: Credential references must be symbolic identifiers (e.g. cred-ref-user-a-01), not raw credentials or tokens'
      );
    }
  }

  if (
    !clean.startsWith('cred-ref-') &&
    !clean.startsWith('anon-ref-') &&
    !clean.startsWith('ref-') &&
    !/^ACCOUNT_[A-Z0-9]+$/i.test(clean) &&
    !/^TEST_[A-Z0-9_]+$/i.test(clean) &&
    !/^RESEARCHER_[A-Z0-9_]+$/i.test(clean)
  ) {
    throw new BadRequestError(
      `INVALID_CREDENTIAL_REFERENCE_FORMAT: Credential reference '${clean}' must use standard reference prefix (e.g. cred-ref-* or ACCOUNT_A)`
    );
  }
}

export function validateAuthContext(context: AuthContext): void {
  if (!context.contextId) {
    throw new BadRequestError('INVALID_AUTH_CONTEXT: contextId is required');
  }
  if (!context.accountIdentifier) {
    throw new BadRequestError('INVALID_AUTH_CONTEXT: accountIdentifier is required');
  }
  if (!context.accountRole) {
    throw new BadRequestError('INVALID_AUTH_CONTEXT: accountRole is required');
  }
  if (!context.authState) {
    throw new BadRequestError('INVALID_AUTH_CONTEXT: authState is required');
  }

  // Validate credential reference format
  if (context.authState === 'AUTHENTICATED') {
    validateCredentialReference(context.credentialReference);
  }
}

export function isAuthContextExpired(context: AuthContext): boolean {
  if (!context.expiresAt) return false;
  return new Date(context.expiresAt).getTime() <= Date.now();
}

/**
 * Standard Auth Context Factory Templates
 */
export function createAccountAContext(params: {
  researcherId: string;
  programId: string;
  caseId: string;
  accountIdentifier?: string;
  scopes?: string[];
}): AuthContext {
  return {
    contextId: `ctx-acc-a-${Date.now()}`,
    contextLabel: 'ACCOUNT_A',
    researcherId: params.researcherId,
    programId: params.programId,
    caseId: params.caseId,
    accountIdentifier: params.accountIdentifier || 'acc-researcher-primary-01',
    accountRole: 'STANDARD_USER',
    authState: 'AUTHENTICATED',
    credentialReference: 'cred-ref-user-a-01',
    sessionReference: 'sess-ref-user-a-01',
    authorizationScopes: params.scopes || ['read:profile', 'read:orders', 'write:orders'],
    metadata: { label: 'Primary Test Account (Account A)' },
  };
}

export function createAccountBContext(params: {
  researcherId: string;
  programId: string;
  caseId: string;
  accountIdentifier?: string;
  scopes?: string[];
}): AuthContext {
  return {
    contextId: `ctx-acc-b-${Date.now()}`,
    contextLabel: 'ACCOUNT_B',
    researcherId: params.researcherId,
    programId: params.programId,
    caseId: params.caseId,
    accountIdentifier: params.accountIdentifier || 'acc-researcher-secondary-02',
    accountRole: 'STANDARD_USER',
    authState: 'AUTHENTICATED',
    credentialReference: 'cred-ref-user-b-02',
    sessionReference: 'sess-ref-user-b-02',
    authorizationScopes: params.scopes || ['read:profile', 'read:orders', 'write:orders'],
    metadata: { label: 'Secondary Peer Test Account (Account B)' },
  };
}

export function createPrivilegedUserContext(params: {
  researcherId: string;
  programId: string;
  caseId: string;
  accountIdentifier?: string;
  scopes?: string[];
}): AuthContext {
  return {
    contextId: `ctx-priv-${Date.now()}`,
    contextLabel: 'PRIVILEGED_USER',
    researcherId: params.researcherId,
    programId: params.programId,
    caseId: params.caseId,
    accountIdentifier: params.accountIdentifier || 'acc-privileged-admin-01',
    accountRole: 'ADMIN_USER',
    authState: 'AUTHENTICATED',
    credentialReference: 'cred-ref-admin-01',
    sessionReference: 'sess-ref-admin-01',
    authorizationScopes: params.scopes || ['admin:all', 'read:all', 'write:all'],
    metadata: { label: 'Privileged / Administrative Test Account' },
  };
}

export function createStandardUserContext(params: {
  researcherId: string;
  programId: string;
  caseId: string;
  accountIdentifier?: string;
  scopes?: string[];
}): AuthContext {
  return {
    contextId: `ctx-std-${Date.now()}`,
    contextLabel: 'STANDARD_USER',
    researcherId: params.researcherId,
    programId: params.programId,
    caseId: params.caseId,
    accountIdentifier: params.accountIdentifier || 'acc-standard-user-01',
    accountRole: 'STANDARD_USER',
    authState: 'AUTHENTICATED',
    credentialReference: 'cred-ref-std-01',
    sessionReference: 'sess-ref-std-01',
    authorizationScopes: params.scopes || ['read:own', 'write:own'],
    metadata: { label: 'Standard Low-Privilege Test Account' },
  };
}

export function createUnauthenticatedContext(params: {
  researcherId: string;
  programId: string;
  caseId: string;
}): AuthContext {
  return {
    contextId: `ctx-unauth-${Date.now()}`,
    contextLabel: 'UNAUTHENTICATED',
    researcherId: params.researcherId,
    programId: params.programId,
    caseId: params.caseId,
    accountIdentifier: 'anon-visitor',
    accountRole: 'UNAUTHENTICATED',
    authState: 'UNAUTHENTICATED',
    credentialReference: 'anon-ref-none',
    sessionReference: 'sess-ref-none',
    authorizationScopes: [],
    metadata: { label: 'Anonymous / Unauthenticated Visitor' },
  };
}
