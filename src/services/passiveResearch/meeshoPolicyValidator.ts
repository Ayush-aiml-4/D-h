/**
 * Meesho vulnerability / testing restriction / known-duplicate policy model.
 * Preserves explicit exclusions from the operator-supplied HackerOne policy.
 */

export type PolicyFindingClassStatus =
  | 'ELIGIBLE_IF_IMPACT_DEMONSTRATED'
  | 'EXCLUDED'
  | 'KNOWN_DUPLICATE'
  | 'REQUIRES_OPERATOR_CLARIFICATION'
  | 'MOBILE_STATIC_ONLY'
  | 'BLOCKED_TESTING_RESTRICTION';

export interface PolicyConstraint {
  id: string;
  title: string;
  status: PolicyFindingClassStatus;
  notes?: string;
}

/** Explicit exclusions / constrained classes from supplied Meesho policy */
export const MEESHO_EXPLICIT_EXCLUSIONS: PolicyConstraint[] = [
  { id: 'user-enum', title: 'Username/email enumeration', status: 'EXCLUDED' },
  { id: 'brute-rate', title: 'Brute force / rate limiting findings alone', status: 'EXCLUDED' },
  { id: 'clickjacking', title: 'Clickjacking', status: 'EXCLUDED' },
  { id: 'cache-deception', title: 'Cache deception', status: 'EXCLUDED' },
  { id: 'cache-poison-no-poc', title: 'Cache poisoning without valid PoC', status: 'EXCLUDED' },
  { id: 'csrf-unauth', title: 'CSRF on unauthenticated/login/logout actions', status: 'EXCLUDED' },
  { id: 'self-xss', title: 'Self-XSS / content spoofing / text injection without security impact', status: 'EXCLUDED' },
  { id: 'open-redirect', title: 'Open redirects without impactful chaining', status: 'EXCLUDED' },
  { id: 'stack-path', title: 'Stack traces / directory listings / path disclosure without demonstrated risk', status: 'EXCLUDED' },
  { id: 'dos', title: 'DoS / DDoS', status: 'EXCLUDED' },
  { id: 'headers-only', title: 'Security-header / hardening-only findings', status: 'EXCLUDED' },
  { id: 'scanner-only', title: 'Automated scanner-only findings', status: 'EXCLUDED' },
  { id: 'outdated-sw', title: 'Outdated / unsupported software issues', status: 'EXCLUDED' },
  { id: 'pinning', title: 'Missing certificate pinning / root detection / obfuscation', status: 'EXCLUDED' },
  { id: 'tls-url-data', title: 'Sensitive data in URLs/bodies protected by TLS', status: 'EXCLUDED' },
  { id: 'oauth-no-impact', title: 'OAuth / app secrets without demonstrated impact', status: 'EXCLUDED' },
  { id: 'device-data', title: 'Unencrypted device data without clear risk', status: 'EXCLUDED' },
  { id: 'physical', title: 'Physical-access vulnerabilities', status: 'EXCLUDED' },
  { id: 'email-auth', title: 'SPF/DKIM/DMARC without demonstrated spoofing impact', status: 'EXCLUDED' },
  { id: 'cve-no-poc', title: 'Known CVEs without valid PoC or low/medium impact only', status: 'EXCLUDED' },
  { id: 'theoretical', title: 'Theoretical / speculative vulnerabilities', status: 'EXCLUDED' },
  { id: 'banner', title: 'Service / banner fingerprinting', status: 'EXCLUDED' },
  { id: 'public-files', title: 'Publicly known files / directories', status: 'EXCLUDED' },
  { id: 'subtakeover-no-poc', title: 'Subdomain takeover without working PoC', status: 'EXCLUDED' },
  { id: 'gmaps-key', title: 'Google Maps API key exposure without demonstrated abuse', status: 'EXCLUDED' },
  { id: 'weak-password', title: 'Weak password policy without exploitable impact', status: 'EXCLUDED' },
  { id: 'ssrf-pingback', title: 'SSRF pingback without proper exploit PoC', status: 'EXCLUDED' },
  { id: 'cors-no-impact', title: 'CORS without significant impact', status: 'EXCLUDED' },
  { id: 'affiliate-collection-id', title: 'Collection ID enumeration in affiliate panel', status: 'EXCLUDED' },
  { id: 'account-deletion', title: 'Account deletion issues', status: 'EXCLUDED' },
];

/** Supplier panel additional constraints */
export const MEESHO_SUPPLIER_CONSTRAINTS: PolicyConstraint[] = [
  { id: 'supplier-idor-limited', title: 'IDOR with limited/no demonstrated impact (supplier)', status: 'EXCLUDED' },
  { id: 'supplier-ssrf-limited', title: 'SSRF with limited/no demonstrated impact (supplier)', status: 'EXCLUDED' },
  { id: 'supplier-upload-limited', title: 'File upload issues with limited/no demonstrated impact (supplier)', status: 'EXCLUDED' },
  { id: 'supplier-public-bucket', title: 'Public buckets without business-critical data (supplier)', status: 'EXCLUDED' },
  { id: 'supplier-mfa-absence', title: 'MFA/2FA absence alone (supplier)', status: 'EXCLUDED' },
  { id: 'supplier-rate-alone', title: 'Rate limiting alone (supplier)', status: 'EXCLUDED' },
  { id: 'supplier-cache-no-impact', title: 'Cache-related issues without real-world impact (supplier)', status: 'EXCLUDED' },
];

/** Known duplicates — must NOT be presented as discoveries */
export const MEESHO_KNOWN_DUPLICATES: PolicyConstraint[] = [
  {
    id: 'dup-html-injection-supplier-ticket',
    title: 'HTML injection in supplier ticketing module',
    status: 'KNOWN_DUPLICATE',
  },
  {
    id: 'dup-account-deletion-discount',
    title: 'Account deletion issues causing first-order discount misuse',
    status: 'KNOWN_DUPLICATE',
  },
  {
    id: 'dup-stored-xss-upload-supplier',
    title: 'Stored XSS via file upload on supplier.meesho.com',
    status: 'KNOWN_DUPLICATE',
  },
  {
    id: 'dup-bank-otp-supplier',
    title: 'Bank-details-update OTP bypass on supplier.meesho.com',
    status: 'KNOWN_DUPLICATE',
  },
  {
    id: 'dup-bank-upi-otp-mobile',
    title: 'My Bank & UPI OTP bypass on Meesho mobile apps',
    status: 'KNOWN_DUPLICATE',
  },
];

export const MEESHO_TESTING_RESTRICTIONS: PolicyConstraint[] = [
  { id: 'no-real-finance', title: 'Real financial transactions', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-real-users', title: 'Testing against real user accounts', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-real-user-data', title: 'Accessing real user data', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-change-security-settings', title: 'Changing passwords/emails/security settings', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-lock-accounts', title: 'Locking/suspending accounts', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-priv-esc-supplied', title: 'Privilege escalation against supplied accounts', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-share-creds', title: 'Sharing supplied credentials', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-prod-scanners', title: 'Production-impacting automated scanners', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-social-eng', title: 'Social engineering / phishing / vishing / smishing', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-ddos', title: 'DoS / DDoS', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-scrape', title: 'Automated scraping', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-model-inference', title: 'Model inference attacks', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-training-extract', title: 'Training-data extraction', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-prompt-inject', title: 'Prompt injection', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-reco-reverse', title: 'Algorithm/recommendation reverse engineering', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'no-outside-scope', title: 'Testing outside listed scope', status: 'BLOCKED_TESTING_RESTRICTION' },
  { id: 'mobile-dynamic', title: 'Mobile dynamic testing', status: 'BLOCKED_TESTING_RESTRICTION' },
];

export function classifyFindingTitle(title: string): PolicyConstraint | null {
  const t = title.toLowerCase();
  for (const d of MEESHO_KNOWN_DUPLICATES) {
    if (t.includes(d.title.toLowerCase().slice(0, 24)) || t.includes(d.id)) return d;
  }
  for (const e of [...MEESHO_EXPLICIT_EXCLUSIONS, ...MEESHO_SUPPLIER_CONSTRAINTS]) {
    const key = e.title.toLowerCase().split(' ')[0];
    if (t.includes(e.id) || (key.length > 4 && t.includes(key))) {
      // conservative match on id
      if (t.includes(e.id.replace(/-/g, ' ')) || t.includes(e.title.toLowerCase().slice(0, 20))) return e;
    }
  }
  return null;
}

export function isKnownDuplicate(title: string): boolean {
  const c = classifyFindingTitle(title);
  return c?.status === 'KNOWN_DUPLICATE';
}

export function mobileTestingPolicy(): {
  MOBILE_DYNAMIC_TESTING: 'BLOCKED';
  MOBILE_STATIC_ANALYSIS: 'POLICY_ALLOWED';
} {
  return {
    MOBILE_DYNAMIC_TESTING: 'BLOCKED',
    MOBILE_STATIC_ANALYSIS: 'POLICY_ALLOWED',
  };
}

export function publicDisclosurePolicy(): 'BLOCKED' {
  return 'BLOCKED';
}
