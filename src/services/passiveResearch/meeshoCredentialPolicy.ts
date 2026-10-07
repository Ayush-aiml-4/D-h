/**
 * Meesho credential policy — never persist or emit raw secrets.
 */

import { createRedactedTestAccountRef, type MeeshoTestAccountRef } from './meeshoProgramProfile.ts';

const SECRET_PATTERNS = [
  /password\s*[:=]\s*\S+/i,
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i,
  /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i,
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, // emails — redact from audit if operator pastes
];

export function containsForbiddenSecretMaterial(text: string): boolean {
  if (!text) return false;
  // Allow explicit redaction tokens
  if (text === 'REDACTED' || text === 'SECRET_REF') return false;
  return SECRET_PATTERNS.some((p) => p.test(text));
}

export function assertNoSecretsInPayload(payload: unknown, path = 'root'): void {
  if (typeof payload === 'string') {
    if (containsForbiddenSecretMaterial(payload) && payload !== 'REDACTED' && payload !== 'SECRET_REF') {
      // Allow HackerOne usernames that look like handles without @email
      if (payload.includes('@') || /password|Bearer |eyJ/i.test(payload)) {
        throw new Error(`SECRET_LEAK_REJECTED:${path}`);
      }
    }
  } else if (payload && typeof payload === 'object') {
    for (const [k, v] of Object.entries(payload as Record<string, unknown>)) {
      if (/password|secret|token|cookie|otp|phone/i.test(k) && typeof v === 'string') {
        if (v !== 'REDACTED' && v !== 'SECRET_REF' && v !== '') {
          throw new Error(`SECRET_LEAK_REJECTED:${path}.${k}`);
        }
      }
      assertNoSecretsInPayload(v, `${path}.${k}`);
    }
  }
}

export function supplierTestAccountTemplate(configured: boolean): MeeshoTestAccountRef {
  return createRedactedTestAccountRef({
    credentialType: 'SUPPLIER_TEST_ACCOUNT',
    accountPurpose: 'supplier.meesho.com authorized testing',
    asset: 'supplier.meesho.com',
    configured,
  });
}

/** Header requirement — value must come from operator; never invent username */
export function buildHackerOneHeader(hackerOneUsername: string | null | undefined): {
  ok: boolean;
  headerName: 'X-Hackerone';
  headerValue: string | null;
  reason?: string;
} {
  if (!hackerOneUsername || !hackerOneUsername.trim()) {
    return {
      ok: false,
      headerName: 'X-Hackerone',
      headerValue: null,
      reason: 'HACKERONE_IDENTITY_NOT_CONFIGURED',
    };
  }
  if (containsForbiddenSecretMaterial(hackerOneUsername) && hackerOneUsername.includes('@')) {
    // Disallow pasting full emails into header config path if it looks like secret material dump
    return {
      ok: false,
      headerName: 'X-Hackerone',
      headerValue: null,
      reason: 'HACKERONE_IDENTITY_INVALID_FORMAT',
    };
  }
  return {
    ok: true,
    headerName: 'X-Hackerone',
    headerValue: hackerOneUsername.trim(),
  };
}
