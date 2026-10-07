import { ParsedUrl } from '../../types/serverInteractionResearch.ts';

const ALLOWED_SCHEMES = new Set(['http', 'https']);

/**
 * Parses and canonicalizes a URL safely, enforcing strict scheme validation,
 * hostname normalization, port handling, and parser confusion defenses.
 */
export function parseCanonicalUrl(rawUrl: string): ParsedUrl {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      rawUrl: rawUrl || '',
      canonicalUrl: '',
      scheme: '',
      isValidScheme: false,
      hostname: '',
      canonicalHostname: '',
      port: 0,
      explicitPort: false,
      pathname: '/',
      search: '',
      hash: '',
      hasUserInfo: false,
      isValid: false,
      validationError: 'Empty or non-string URL provided',
    };
  }

  const trimmed = rawUrl.trim();

  // Check for dangerous control characters or null bytes
  if (/[\x00-\x1F\x7F]/.test(trimmed)) {
    return {
      rawUrl: trimmed,
      canonicalUrl: '',
      scheme: '',
      isValidScheme: false,
      hostname: '',
      canonicalHostname: '',
      port: 0,
      explicitPort: false,
      pathname: '/',
      search: '',
      hash: '',
      hasUserInfo: false,
      isValid: false,
      validationError: 'URL contains control characters or null bytes',
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch (err: any) {
    return {
      rawUrl: trimmed,
      canonicalUrl: '',
      scheme: '',
      isValidScheme: false,
      hostname: '',
      canonicalHostname: '',
      port: 0,
      explicitPort: false,
      pathname: '/',
      search: '',
      hash: '',
      hasUserInfo: false,
      isValid: false,
      validationError: `Malformed URL: ${err?.message || 'Invalid syntax'}`,
    };
  }

  const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
  const isValidScheme = ALLOWED_SCHEMES.has(scheme);

  if (!isValidScheme) {
    return {
      rawUrl: trimmed,
      canonicalUrl: '',
      scheme,
      isValidScheme: false,
      hostname: parsed.hostname,
      canonicalHostname: parsed.hostname.toLowerCase(),
      port: parsed.port ? parseInt(parsed.port, 10) : 0,
      explicitPort: !!parsed.port,
      pathname: parsed.pathname,
      search: parsed.search,
      hash: parsed.hash,
      username: parsed.username || undefined,
      password: parsed.password || undefined,
      hasUserInfo: !!(parsed.username || parsed.password),
      isValid: false,
      validationError: `Unsupported scheme: '${scheme}'. Only http and https are allowed.`,
    };
  }

  // Canonicalize hostname (strip trailing dots, lowercase)
  let canonicalHostname = parsed.hostname.toLowerCase();
  while (canonicalHostname.endsWith('.')) {
    canonicalHostname = canonicalHostname.slice(0, -1);
  }

  // Detect and handle IPv6 brackets
  const isIPv6 = canonicalHostname.startsWith('[') && canonicalHostname.endsWith(']');
  const cleanHostname = isIPv6 ? canonicalHostname.slice(1, -1) : canonicalHostname;

  const explicitPort = !!parsed.port;
  let port = parsed.port ? parseInt(parsed.port, 10) : 0;
  if (!port) {
    port = scheme === 'https' ? 443 : 80;
  }

  const hasUserInfo = !!(parsed.username || parsed.password);
  const pathname = parsed.pathname || '/';
  const search = parsed.search || '';
  const hash = parsed.hash || '';

  // Canonical URL construction (without userinfo in standard canonical representation)
  const portString =
    (scheme === 'http' && port === 80) || (scheme === 'https' && port === 443) ? '' : `:${port}`;

  const hostDisplay = isIPv6 ? `[${cleanHostname}]` : cleanHostname;
  const canonicalUrl = `${scheme}://${hostDisplay}${portString}${pathname}${search}${hash}`;

  return {
    rawUrl: trimmed,
    canonicalUrl,
    scheme,
    isValidScheme: true,
    hostname: parsed.hostname,
    canonicalHostname: cleanHostname,
    port,
    explicitPort,
    pathname,
    search,
    hash,
    username: parsed.username || undefined,
    password: parsed.password || undefined,
    hasUserInfo,
    isValid: true,
  };
}

/**
 * Evaluates whether two hostnames match exactly or under safe subdomain boundaries,
 * strictly preventing parser confusion like 'meesho.com.attacker.com' matching 'meesho.com'.
 */
export function isExactOrSubdomain(candidateHostname: string, baseDomain: string): boolean {
  if (!candidateHostname || !baseDomain) return false;

  let cand = candidateHostname.toLowerCase();
  while (cand.endsWith('.')) cand = cand.slice(0, -1);

  let base = baseDomain.toLowerCase();
  while (base.endsWith('.')) base = base.slice(0, -1);

  if (cand === base) {
    return true;
  }

  return cand.endsWith(`.${base}`);
}
