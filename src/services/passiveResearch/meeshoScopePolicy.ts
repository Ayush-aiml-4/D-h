/**
 * Meesho scope policy — fail closed. No invented domains.
 */

import { MEESHO_EXPLICIT_HOSTS, MEESHO_IN_SCOPE_ASSETS } from './meeshoProgramProfile.ts';

export type MeeshoScopeDecision =
  | 'IN_SCOPE_HOST'
  | 'IN_SCOPE_MOBILE_LABEL'
  | 'IN_SCOPE_WEB_LABEL_NEEDS_HOST_CLARIFICATION'
  | 'OUT_OF_SCOPE'
  | 'THIRD_PARTY'
  | 'INTERNAL_OR_ADMIN'
  | 'STAGING_UNLISTED'
  | 'UNKNOWN_FAIL_CLOSED'
  | 'MALFORMED';

export interface MeeshoScopeResult {
  decision: MeeshoScopeDecision;
  allowedForPassiveHttp: boolean;
  reason: string;
  host: string | null;
}

const THIRD_PARTY_HINTS = [
  'google-analytics',
  'googletagmanager',
  'facebook.com',
  'razorpay',
  'paytm',
  'stripe.com',
  'cloudflare',
  'zendesk',
  'freshdesk',
  'intercom',
  'segment.com',
  'sentry.io',
  'amazonaws.com',
  'googleapis.com',
];

const INTERNAL_HINTS = ['admin.', 'internal.', 'intranet.', 'corp.', 'employee.', 'staff.'];
const STAGING_HINTS = ['staging.', 'dev.', 'develop.', 'qa.', 'test.', 'sandbox.', 'uat.'];

function extractHost(raw: string): string | null {
  try {
    let t = raw.trim();
    if (!t) return null;
    if (!/^https?:\/\//i.test(t)) t = 'https://' + t;
    const u = new URL(t);
    if (u.username || u.password) return null; // userinfo → treat malformed/unsafe
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function classifyMeeshoAsset(target: string): MeeshoScopeResult {
  if (!target || typeof target !== 'string') {
    return { decision: 'MALFORMED', allowedForPassiveHttp: false, reason: 'EMPTY_TARGET', host: null };
  }

  const lower = target.trim().toLowerCase();

  // Mobile app labels (not HTTP hosts)
  for (const a of MEESHO_IN_SCOPE_ASSETS) {
    if (a.kind === 'MOBILE_APP' && (lower === a.label.toLowerCase() || lower === a.id)) {
      return {
        decision: 'IN_SCOPE_MOBILE_LABEL',
        allowedForPassiveHttp: false,
        reason: 'MOBILE_ASSET_STATIC_ANALYSIS_ONLY_NO_HTTP_DISPATCH',
        host: null,
      };
    }
  }

  if (lower === 'meesho web' || lower === 'meesho-web') {
    return {
      decision: 'IN_SCOPE_WEB_LABEL_NEEDS_HOST_CLARIFICATION',
      allowedForPassiveHttp: false,
      reason: 'REQUIRES_OPERATOR_CLARIFICATION_EXACT_WEB_HOSTS',
      host: null,
    };
  }

  const host = extractHost(target);
  if (!host) {
    return { decision: 'MALFORMED', allowedForPassiveHttp: false, reason: 'MALFORMED_OR_USERINFO', host: null };
  }

  // Explicit in-scope host
  if (MEESHO_EXPLICIT_HOSTS.some((h) => host === h || host.endsWith('.' + h))) {
    return {
      decision: 'IN_SCOPE_HOST',
      allowedForPassiveHttp: true,
      reason: 'EXPLICIT_POLICY_HOST',
      host,
    };
  }

  // Third-party
  if (THIRD_PARTY_HINTS.some((t) => host.includes(t))) {
    return {
      decision: 'THIRD_PARTY',
      allowedForPassiveHttp: false,
      reason: 'THIRD_PARTY_VENDOR_OUT_OF_SCOPE',
      host,
    };
  }

  // Internal/admin
  if (INTERNAL_HINTS.some((h) => host.startsWith(h) || host.includes(h))) {
    return {
      decision: 'INTERNAL_OR_ADMIN',
      allowedForPassiveHttp: false,
      reason: 'INTERNAL_OR_ADMIN_NOT_LISTED',
      host,
    };
  }

  // Staging unless explicitly listed (none of staging hosts listed in supplied policy)
  if (STAGING_HINTS.some((h) => host.startsWith(h) || host.includes(h))) {
    return {
      decision: 'STAGING_UNLISTED',
      allowedForPassiveHttp: false,
      reason: 'STAGING_NOT_EXPLICITLY_IN_SCOPE',
      host,
    };
  }

  // Do not assume meesho.com or other Meesho domains are in scope
  if (host.endsWith('meesho.com') && host !== 'supplier.meesho.com') {
    return {
      decision: 'UNKNOWN_FAIL_CLOSED',
      allowedForPassiveHttp: false,
      reason: 'MEESHO_DOMAIN_NOT_EXPLICITLY_LISTED_FAIL_CLOSED',
      host,
    };
  }

  return {
    decision: 'OUT_OF_SCOPE',
    allowedForPassiveHttp: false,
    reason: 'NOT_EXPLICITLY_LISTED',
    host,
  };
}
