/**
 * DEVILHUNT — Research Account Model Service
 * Enforces symbolic reference-only account architecture (ACCOUNT_A, ACCOUNT_B, etc.).
 * Strictly detects and rejects accidental credential insertion (passwords, JWTs, cookies, tokens).
 */

import { ResearchAccount } from '../../types/engagement.ts';
import { BadRequestError } from '../../utils/errors.ts';

// Comprehensive regex patterns for detecting accidental credential leaks
export const RAW_SECRET_PATTERNS = [
  // JWT tokens: 3 base64url segments
  /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/,
  /ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}/,
  // Bearer tokens
  /^bearer\s+[A-Za-z0-9_\-\.\=\+]+/i,
  // Hex/Base64 API keys or hashes
  /^[a-fA-F0-9]{32,64}$/,
  /^[A-Za-z0-9+/]{40,}={0,2}$/,
  // Common secret assignments or key formats
  /(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token)\s*[:=]\s*["']?[^\s"']+/i,
  // Private key blocks
  /-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PRIVATE)\s+KEY-----/i,
  // Cookie strings with session identifiers
  /(?:sessionid|jsessionid|phpsessid|connect\.sid|authtoken)=[^;\s]+/i,
  // AWS / Cloud tokens
  /AKIA[0-9A-Z]{16}/,
  /ghp_[0-9a-zA-Z]{36}/,
  /sk_live_[0-9a-zA-Z]{24}/,
];

// Valid symbolic reference formats: e.g. ACCOUNT_A, ACCOUNT_B, TEST_USER_1, cred-ref-user-a-01
export const VALID_SYMBOLIC_IDENTIFIER_REGEX =
  /^(ACCOUNT_[A-Z0-9]+|TEST_[A-Z0-9_]+|RESEARCHER_[A-Z0-9_]+|USER_[A-Z0-9_]+|cred-ref-[a-z0-9\-]+|ref-[a-z0-9\-]+)$/;

export interface CredentialDetectionResult {
  hasCredentialMaterial: boolean;
  detectedTypes: string[];
  safeSnippet: string;
}

/**
 * Scans any string, object, or header for raw secrets.
 */
export function detectCredentialMaterial(input: unknown): CredentialDetectionResult {
  if (input === null || input === undefined) {
    return { hasCredentialMaterial: false, detectedTypes: [], safeSnippet: '' };
  }

  const detected: string[] = [];
  const textToScan = typeof input === 'string' ? input : JSON.stringify(input);

  // 1. Check for JWT
  if (/ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}/.test(textToScan)) {
    detected.push('JWT_TOKEN');
  }

  // 2. Check for Bearer token
  if (/bearer\s+[A-Za-z0-9_\-\.\=\+]+/i.test(textToScan)) {
    detected.push('BEARER_TOKEN');
  }

  // 3. Check for private keys
  if (/-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PRIVATE)\s+KEY-----/i.test(textToScan)) {
    detected.push('PRIVATE_KEY');
  }

  // 4. Check for session cookies
  if (/(?:sessionid|jsessionid|phpsessid|connect\.sid|authtoken)\s*=\s*[^;\s]+/i.test(textToScan)) {
    detected.push('SESSION_COOKIE');
  }

  // 5. Check for raw passwords or secret assignments
  if (/(?:password|passwd|pwd|secret)\s*[:=]\s*["']?[^\s"',]{4,}/i.test(textToScan)) {
    detected.push('PASSWORD_OR_SECRET');
  }

  // 6. Check for cloud API keys
  if (/AKIA[0-9A-Z]{16}/.test(textToScan) || /ghp_[0-9a-zA-Z]{36}/.test(textToScan) || /sk_live_[0-9a-zA-Z]{24}/.test(textToScan)) {
    detected.push('API_KEY');
  }

  return {
    hasCredentialMaterial: detected.length > 0,
    detectedTypes: detected,
    safeSnippet: detected.length > 0 ? '[REDACTED_POTENTIAL_CREDENTIAL]' : textToScan.slice(0, 50),
  };
}

/**
 * Validates a symbolic account identifier.
 * Throws BadRequestError if it contains secrets or does not follow symbolic conventions.
 */
export function validateSymbolicAccountIdentifier(identifier: string): void {
  if (!identifier || typeof identifier !== 'string') {
    throw new BadRequestError('INVALID_ACCOUNT_IDENTIFIER: Identifier must be a non-empty string');
  }

  const trimmed = identifier.trim();

  // First verify no raw secret pattern is contained
  const detection = detectCredentialMaterial(trimmed);
  if (detection.hasCredentialMaterial) {
    throw new BadRequestError(
      `CREDENTIAL_INSERTION_BLOCKED: Raw secret detected in account identifier (${detection.detectedTypes.join(
        ', '
      )}). Only symbolic references (e.g. ACCOUNT_A, ACCOUNT_B) are allowed.`
    );
  }

  // Check against valid symbolic formats
  if (!VALID_SYMBOLIC_IDENTIFIER_REGEX.test(trimmed)) {
    throw new BadRequestError(
      `INVALID_SYMBOLIC_FORMAT: Account identifier '${trimmed}' must be symbolic (e.g. 'ACCOUNT_A', 'ACCOUNT_B', 'TEST_USER_1', or 'cred-ref-user-a')`
    );
  }
}

/**
 * Validates an account registration payload, ensuring no passwords or sensitive fields exist.
 */
export function validateAccountPayload(payload: {
  symbolicIdentifier: string;
  tier: string;
  programId: string;
  label: string;
  [key: string]: any;
}): void {
  // Disallow any forbidden keys
  const forbiddenKeys = ['password', 'pwd', 'secret', 'jwt', 'token', 'cookie', 'apiKey', 'authorization'];
  for (const key of Object.keys(payload)) {
    if (forbiddenKeys.some((f) => key.toLowerCase().includes(f))) {
      throw new BadRequestError(
        `FORBIDDEN_FIELD_IN_ACCOUNT_PAYLOAD: Field '${key}' is prohibited. Research accounts are symbolic references only.`
      );
    }
  }

  validateSymbolicAccountIdentifier(payload.symbolicIdentifier);

  if (!payload.tier || typeof payload.tier !== 'string') {
    throw new BadRequestError('INVALID_ACCOUNT_PAYLOAD: Tier is required');
  }

  if (!payload.programId || typeof payload.programId !== 'string') {
    throw new BadRequestError('INVALID_ACCOUNT_PAYLOAD: ProgramId is required');
  }

  // Deep scan the whole object
  const detection = detectCredentialMaterial(payload);
  if (detection.hasCredentialMaterial) {
    throw new BadRequestError(
      `CREDENTIAL_INSERTION_BLOCKED: Raw credentials detected in payload (${detection.detectedTypes.join(', ')})`
    );
  }
}

// In-Memory Account Registry for symbolic accounts
const researchAccountRegistry = new Map<string, ResearchAccount[]>();

export function registerResearchAccount(account: {
  symbolicIdentifier: string;
  tier: string;
  programId: string;
  label: string;
}): ResearchAccount {
  validateAccountPayload(account);

  const cleanProgramId = account.programId.toLowerCase().trim();
  const existing = researchAccountRegistry.get(cleanProgramId) || [];

  // Check for duplicates
  if (existing.some((a) => a.symbolicIdentifier === account.symbolicIdentifier)) {
    throw new BadRequestError(`ACCOUNT_ALREADY_EXISTS: Account '${account.symbolicIdentifier}' is already registered for program '${account.programId}'`);
  }

  const newAccount: ResearchAccount = {
    id: `acc-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    symbolicIdentifier: account.symbolicIdentifier.trim(),
    tier: account.tier.trim(),
    programId: cleanProgramId,
    label: account.label.trim(),
    createdAt: new Date().toISOString(),
    credentialSafetyVerified: true,
  };

  existing.push(newAccount);
  researchAccountRegistry.set(cleanProgramId, existing);
  return newAccount;
}

export function getResearchAccounts(programId: string): ResearchAccount[] {
  return researchAccountRegistry.get(programId.toLowerCase().trim()) || [];
}

export function clearResearchAccounts(programId?: string): void {
  if (programId) {
    researchAccountRegistry.delete(programId.toLowerCase().trim());
  } else {
    researchAccountRegistry.clear();
  }
}
