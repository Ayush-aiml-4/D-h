import crypto from 'crypto';
import { SanitizedEvidence, FindingCandidate } from './types.ts';

// Secret redaction patterns
const SECRET_PATTERNS = [
  /(?:api[_-]?key|secret|token|password|auth|jwt|private[_-]?key|access[_-]?token)["']?\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{8,})["']?/gi,
  /bearer\s+([a-zA-Z0-9_\-\.]{12,})/gi,
  /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, // JWT
  /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi,
  /(?:AIzaSy|AKIA|ASIA|sq0atp-|sq0csp-|ghp_|gho_|glpat-)[a-zA-Z0-9_\-]{16,}/g,
];

/**
 * Redacts potential secrets from text or object recursively.
 * Replaces matching strings with [REDACTED:hash].
 */
export function sanitizeAndRedact(data: any): { sanitized: any; redactedSecrets: boolean } {
  let redacted = false;

  function redactString(str: string): string {
    let result = str;
    for (const pattern of SECRET_PATTERNS) {
      pattern.lastIndex = 0;
      result = result.replace(pattern, (match, ...args) => {
        redacted = true;
        const p1 = typeof args[0] === 'string' ? args[0] : undefined;
        const targetToHash = p1 || match;
        const hash = crypto.createHash('sha256').update(String(targetToHash)).digest('hex').substring(0, 8);
        if (p1) {
          return match.replace(p1, `[REDACTED:${hash}]`);
        }
        return `[REDACTED:${hash}]`;
      });
    }
    return result;
  }

  function walk(val: any): any {
    if (val === null || val === undefined) return val;
    if (typeof val === 'string') {
      return redactString(val);
    }
    if (Array.isArray(val)) {
      return val.map(walk);
    }
    if (typeof val === 'object') {
      const obj: Record<string, any> = {};
      for (const [k, v] of Object.entries(val)) {
        // Redact cookie / authorization headers directly if key suggests sensitive credential
        const lowerKey = k.toLowerCase();
        if (
          lowerKey === 'authorization' ||
          lowerKey === 'cookie' ||
          lowerKey === 'set-cookie' ||
          lowerKey.includes('secret') ||
          lowerKey.includes('password') ||
          lowerKey.includes('token') ||
          lowerKey.includes('key') ||
          lowerKey.includes('auth') ||
          lowerKey.includes('bearer')
        ) {
          if (typeof v === 'string') {
            redacted = true;
            const hash = crypto.createHash('sha256').update(v).digest('hex').substring(0, 8);
            obj[k] = `[REDACTED_CREDENTIAL:${hash}]`;
          } else {
            obj[k] = walk(v);
          }
        } else {
          obj[k] = walk(v);
        }
      }
      return obj;
    }
    return val;
  }

  const sanitized = walk(data);
  return { sanitized, redactedSecrets: redacted };
}

/**
 * Computes deterministic SHA-256 hash of evidence object.
 */
export function generateEvidenceHash(data: any): string {
  const jsonStr = JSON.stringify(data, Object.keys(data || {}).sort());
  return crypto.createHash('sha256').update(jsonStr).digest('hex');
}

/**
 * Generates deterministic correlation key for deduplication without secrets.
 */
export function generateCorrelationKey(
  programId: string,
  assetId: string,
  capabilityId: string,
  issueIdentifier: string
): string {
  const normProgram = (programId || 'global').trim().toLowerCase();
  const normAsset = (assetId || 'unknown').trim().toLowerCase();
  const normCap = (capabilityId || 'cap').trim().toLowerCase();
  const normIssue = (issueIdentifier || 'gen').trim().toLowerCase();

  const raw = `${normProgram}:${normAsset}:${normCap}:${normIssue}`;
  return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 32);
}

/**
 * Constructs a SanitizedEvidence record.
 */
export function createSanitizedEvidence(
  capabilityId: string,
  assetId: string,
  evidenceType: string,
  rawObservation: any,
  confidence: number
): SanitizedEvidence {
  const { sanitized, redactedSecrets } = sanitizeAndRedact(rawObservation);
  const evidenceHash = generateEvidenceHash(sanitized);
  const evidenceId = `ev-${capabilityId}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;

  return {
    evidenceId,
    capabilityId,
    assetId,
    observedAt: new Date().toISOString(),
    evidenceType,
    sanitizedObservation: sanitized,
    confidence,
    hash: evidenceHash,
    redactedSecrets,
  };
}

/**
 * Constructs a FindingCandidate object with status 'Potential'.
 */
export function createFindingCandidate(params: {
  programId: string;
  assetId: string;
  capabilityId: string;
  issueIdentifier: string;
  title: string;
  category: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  confidence: number;
  whatWeFound: string;
  whyItMatters: string;
  affectedTarget: string;
  recommendedFix: string;
  evidence: SanitizedEvidence;
}): FindingCandidate {
  const correlationKey = generateCorrelationKey(
    params.programId,
    params.assetId,
    params.capabilityId,
    params.issueIdentifier
  );

  return {
    correlationKey,
    title: params.title,
    category: params.category,
    severity: params.severity,
    confidence: params.confidence,
    status: 'Potential',
    whatWeFound: params.whatWeFound,
    whyItMatters: params.whyItMatters,
    affectedTarget: params.affectedTarget,
    recommendedFix: params.recommendedFix,
    evidence: params.evidence,
  };
}
