/**
 * Strong secret redaction before any persistence.
 * Never store passwords, JWTs, API keys, cookies, authorization headers, or private credentials.
 */

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g },
  { name: 'api_key', pattern: /(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9_\-]{12,})/gi },
  { name: 'bearer', pattern: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi },
  { name: 'password', pattern: /\b(?:password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{4,}['"]?/gi },
  { name: 'aws_key', pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'private_key', pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----/g },
  { name: 'cookie_header', pattern: /(?:^|\n)cookie\s*:\s*[^\n]+/gi },
  { name: 'set_cookie', pattern: /(?:^|\n)set-cookie\s*:\s*[^\n]+/gi },
  { name: 'authorization', pattern: /(?:^|\n)authorization\s*:\s*[^\n]+/gi },
];

const SENSITIVE_HEADER_KEYS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'proxy-authorization',
]);

export function redactSecretsFromText(input: string): { text: string; redacted: boolean } {
  if (!input) return { text: '', redacted: false };
  let text = input;
  let redacted = false;
  for (const { name, pattern } of SECRET_PATTERNS) {
    const next = text.replace(pattern, `[REDACTED_${name.toUpperCase()}]`);
    if (next !== text) redacted = true;
    text = next;
  }
  return { text, redacted };
}

export function redactHeaders(headers: Record<string, string>): {
  headers: Record<string, string>;
  redacted: boolean;
} {
  const out: Record<string, string> = {};
  let redacted = false;
  for (const [k, v] of Object.entries(headers || {})) {
    if (SENSITIVE_HEADER_KEYS.has(k.toLowerCase())) {
      out[k] = '[REDACTED]';
      redacted = true;
    } else {
      const r = redactSecretsFromText(String(v));
      out[k] = r.text;
      if (r.redacted) redacted = true;
    }
  }
  return { headers: out, redacted };
}
