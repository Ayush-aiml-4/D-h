/**
 * DEVILHUNT — Scope Import & Fail-Closed Validation Engine
 * Enforces strict boundary checks, lookalike rejection, out-of-scope denial,
 * mobile app matching, and explicit wildcard authorization checks.
 * Fail-Closed: UNKNOWN = DENY, AMBIGUOUS = DENY, MISSING_SCOPE = DENY.
 */

import {
  EngagementAsset,
  EngagementExcludedAsset,
  EngagementProgramProfile,
  ScopeValidationDecision,
} from '../../types/engagement.ts';

// Homoglyphs and lookalike confusable patterns
const HOMOGLYPH_REGEX = /[а-яА-Я\u0400-\u04FF\u0370-\u03FF\u0100-\u017F\u0180-\u024F\uFF01-\uFF5E]/;

export interface RawScopeImportAsset {
  target: string;
  type: 'DOMAIN' | 'SUBDOMAIN' | 'WILDCARD' | 'URL' | 'API_ENDPOINT' | 'MOBILE_APP_ANDROID' | 'MOBILE_APP_IOS' | 'SERVICE' | 'OTHER';
  eligible?: boolean;
  maxSeverity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  description?: string;
  excluded?: boolean;
  exclusionReason?: string;
}

/**
 * Sanitizes and validates a raw input target string.
 */
export function sanitizeAndParseTarget(rawTarget: string): {
  isValid: boolean;
  raw: string;
  scheme: string;
  hostname: string;
  path: string;
  fullUrl?: string;
  isMobileId: boolean;
  hasUserInfo: boolean;
  isLookalike: boolean;
  error?: string;
} {
  if (!rawTarget || typeof rawTarget !== 'string' || rawTarget.trim().length === 0) {
    return {
      isValid: false,
      raw: '',
      scheme: '',
      hostname: '',
      path: '',
      isMobileId: false,
      hasUserInfo: false,
      isLookalike: false,
      error: 'EMPTY_TARGET',
    };
  }

  const trimmed = rawTarget.trim();

  // Reject control characters or null bytes
  if (/[\x00-\x1F\x7F]/.test(trimmed)) {
    return {
      isValid: false,
      raw: trimmed,
      scheme: '',
      hostname: '',
      path: '',
      isMobileId: false,
      hasUserInfo: false,
      isLookalike: false,
      error: 'CONTROL_CHARACTERS_DETECTED',
    };
  }

  // Check for homoglyphs / unicode confusables in target
  if (HOMOGLYPH_REGEX.test(trimmed) || /xn--/.test(trimmed)) {
    return {
      isValid: false,
      raw: trimmed,
      scheme: '',
      hostname: '',
      path: '',
      isMobileId: false,
      hasUserInfo: false,
      isLookalike: true,
      error: 'HOMOGLYPH_OR_PUNYCODE_LOOKALIKE_DETECTED',
    };
  }

  // Check for Mobile Application Identifiers:
  // Android: com.example.app, com.company.sub
  if (/^com\.[a-zA-Z0-9_\.]+[a-zA-Z0-9_]$/.test(trimmed)) {
    return {
      isValid: true,
      raw: trimmed,
      scheme: 'app',
      hostname: trimmed,
      path: '',
      isMobileId: true,
      hasUserInfo: false,
      isLookalike: false,
    };
  }

  // iOS App Store numeric ID (e.g. 1457958492 or id1457958492)
  if (/^(id)?[0-9]{8,12}$/.test(trimmed)) {
    return {
      isValid: true,
      raw: trimmed,
      scheme: 'app-store',
      hostname: trimmed,
      path: '',
      isMobileId: true,
      hasUserInfo: false,
      isLookalike: false,
    };
  }

  // Malformed scheme check e.g. malformed://target or file:// or gopher://
  if (trimmed.includes('://')) {
    const schemeMatch = trimmed.match(/^([a-zA-Z0-9_\-]+):\/\//);
    if (!schemeMatch || (schemeMatch[1] !== 'http' && schemeMatch[1] !== 'https')) {
      return {
        isValid: false,
        raw: trimmed,
        scheme: schemeMatch ? schemeMatch[1] : 'unknown',
        hostname: '',
        path: '',
        isMobileId: false,
        hasUserInfo: false,
        isLookalike: false,
        error: 'DISALLOWED_OR_MALFORMED_SCHEME',
      };
    }
  }

  // Userinfo Host Confusion check (user:pass@host)
  if (trimmed.includes('@')) {
    return {
      isValid: false,
      raw: trimmed,
      scheme: '',
      hostname: '',
      path: '',
      isMobileId: false,
      hasUserInfo: true,
      isLookalike: false,
      error: 'USERINFO_HOST_CONFUSION_REJECTED',
    };
  }

  // Construct URL for parsing
  try {
    let urlString = trimmed;
    if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
      urlString = 'https://' + urlString;
    }

    const parsed = new URL(urlString);
    const hostname = parsed.hostname.toLowerCase();

    // Check invalid hostname characters or double dots or empty
    if (
      !hostname ||
      hostname.includes('..') ||
      hostname.startsWith('.') ||
      hostname.endsWith('.') ||
      /[^\w\.\-]/.test(hostname)
    ) {
      return {
        isValid: false,
        raw: trimmed,
        scheme: parsed.protocol.replace(':', ''),
        hostname: '',
        path: '',
        isMobileId: false,
        hasUserInfo: false,
        isLookalike: false,
        error: 'INVALID_HOSTNAME_SYNTAX',
      };
    }

    return {
      isValid: true,
      raw: trimmed,
      scheme: parsed.protocol.replace(':', ''),
      hostname,
      path: parsed.pathname || '/',
      fullUrl: parsed.href,
      isMobileId: false,
      hasUserInfo: false,
      isLookalike: false,
    };
  } catch (err: any) {
    return {
      isValid: false,
      raw: trimmed,
      scheme: '',
      hostname: '',
      path: '',
      isMobileId: false,
      hasUserInfo: false,
      isLookalike: false,
      error: `URL_PARSER_EXCEPTION: ${err.message}`,
    };
  }
}

/**
 * Evaluates whether a target matches a specific asset pattern.
 * Strictly prevents prefix lookalikes (evil-target.com) and suffix lookalikes (target.com.attacker.com).
 */
export function matchTargetToAssetPattern(
  targetInfo: ReturnType<typeof sanitizeAndParseTarget>,
  assetPattern: string,
  assetType: string,
  allowWildcard: boolean = true
): boolean {
  if (!targetInfo.isValid) return false;

  const normalizedPattern = assetPattern.trim().toLowerCase();
  const rawTargetLower = targetInfo.raw.toLowerCase();
  const hostname = targetInfo.hostname.toLowerCase();

  // Mobile App Matching
  if (assetType === 'MOBILE_APP_ANDROID') {
    return rawTargetLower === normalizedPattern;
  }
  if (assetType === 'MOBILE_APP_IOS') {
    const cleanPattern = normalizedPattern.replace(/^id/, '');
    const cleanRaw = rawTargetLower.replace(/^id/, '');
    return cleanRaw === cleanPattern;
  }

  // Exact API_ENDPOINT matching
  if (assetType === 'API_ENDPOINT') {
    const cleanPattern = normalizedPattern.replace(/^https?:\/\//, '');
    const cleanFullUrl = (targetInfo.fullUrl || '').replace(/^https?:\/\//, '').toLowerCase();

    if (cleanPattern.includes('/')) {
      return cleanFullUrl.startsWith(cleanPattern);
    }
    return hostname === cleanPattern;
  }

  // Wildcard Matching: *.example.com
  if (normalizedPattern.startsWith('*.')) {
    if (!allowWildcard) return false; // Not explicitly authorized

    const baseDomain = normalizedPattern.slice(2);

    // Exact match to baseDomain
    if (hostname === baseDomain) return true;

    // Strict subdomain boundary match: must end with '.' + baseDomain
    // Example: api.example.com -> ends with .example.com (PASS)
    // Example: fake-example.com -> does not end with .example.com (FAIL)
    // Example: example.com.attacker.com -> does not end with .example.com (FAIL)
    if (hostname.endsWith('.' + baseDomain)) {
      return true;
    }
    return false;
  }

  // Exact Domain / Subdomain matching
  if (assetType === 'DOMAIN' || assetType === 'SUBDOMAIN') {
    const cleanPattern = normalizedPattern.replace(/^https?:\/\//, '').split('/')[0];
    return hostname === cleanPattern;
  }

  // Exact URL matching
  if (assetType === 'URL') {
    if (targetInfo.fullUrl) {
      const fullUrlLower = targetInfo.fullUrl.toLowerCase();
      if (fullUrlLower === normalizedPattern) return true;
      if (fullUrlLower.startsWith(normalizedPattern.endsWith('/') ? normalizedPattern : normalizedPattern + '/')) {
        return true;
      }
    }
    return false;
  }

  // Service / Other exact matching
  return rawTargetLower === normalizedPattern;
}

/**
 * Validates a target against an Engagement Program Profile with complete fail-closed semantics.
 */
export function validateTargetScope(
  rawTarget: string,
  profile: EngagementProgramProfile
): ScopeValidationDecision {
  const evaluatedAt = new Date().toISOString();

  // 1. Sanitize and parse
  const targetInfo = sanitizeAndParseTarget(rawTarget);

  if (!targetInfo.isValid) {
    return {
      allowed: false,
      decision: 'DENY',
      target: rawTarget,
      canonicalHostname: '',
      reason: `MALFORMED_OR_AMBIGUOUS_TARGET: ${targetInfo.error || 'Failed target validation'}`,
      lookalikeDetected: targetInfo.isLookalike,
      malformedDetected: true,
      outOfScopeDetected: false,
      evaluatedAt,
    };
  }

  // 2. Check Explicit Out-of-Scope Assets First (Highest Precedence)
  for (const excluded of profile.outOfScopeAssets) {
    if (matchTargetToAssetPattern(targetInfo, excluded.targetPattern, excluded.assetType, true)) {
      return {
        allowed: false,
        decision: 'DENY',
        target: rawTarget,
        canonicalHostname: targetInfo.hostname,
        matchedAsset: excluded,
        reason: `EXPLICIT_OUT_OF_SCOPE: Matched excluded asset '${excluded.targetPattern}' (${excluded.reason})`,
        lookalikeDetected: false,
        malformedDetected: false,
        outOfScopeDetected: true,
        evaluatedAt,
      };
    }
  }

  // 3. Check Explicit In-Scope Exact Assets
  for (const asset of profile.inScopeAssets) {
    const isWildcardPattern = asset.targetPattern.startsWith('*.');
    const allowWildcard = isWildcardPattern ? (asset.allowWildcardSubdomains ?? false) : false;

    if (matchTargetToAssetPattern(targetInfo, asset.targetPattern, asset.assetType, allowWildcard)) {
      return {
        allowed: true,
        decision: 'ALLOW',
        target: rawTarget,
        canonicalHostname: targetInfo.hostname,
        matchedAsset: asset,
        reason: `AUTHORIZED_IN_SCOPE: Matched asset '${asset.targetPattern}' [${asset.assetType}]`,
        lookalikeDetected: false,
        malformedDetected: false,
        outOfScopeDetected: false,
        evaluatedAt,
      };
    }
  }

  // 4. Fail Closed: Unlisted / Ambiguous / Unknown Target
  return {
    allowed: false,
    decision: 'DENY',
    target: rawTarget,
    canonicalHostname: targetInfo.hostname,
    reason: `UNLISTED_TARGET_DENIED: Host '${targetInfo.hostname || targetInfo.raw}' is not authorized in scope definition`,
    lookalikeDetected: false,
    malformedDetected: false,
    outOfScopeDetected: false,
    evaluatedAt,
  };
}

/**
 * Imports and constructs an Engagement Program Profile from raw definitions.
 */
export function importProgramScope(params: {
  programId: string;
  name: string;
  handle: string;
  platform: EngagementProgramProfile['platform'];
  policyUrl: string;
  assets: RawScopeImportAsset[];
}): { inScope: EngagementAsset[]; outOfScope: EngagementExcludedAsset[]; errors: string[] } {
  const inScope: EngagementAsset[] = [];
  const outOfScope: EngagementExcludedAsset[] = [];
  const errors: string[] = [];

  for (const [index, raw] of params.assets.entries()) {
    const parsed = sanitizeAndParseTarget(raw.target);
    if (!parsed.isValid && raw.type !== 'OTHER') {
      errors.push(`Asset #${index} '${raw.target}' failed validation: ${parsed.error}`);
      continue;
    }

    if (raw.excluded) {
      outOfScope.push({
        id: `oos-${index}-${Date.now()}`,
        targetPattern: raw.target.trim(),
        assetType: raw.type,
        reason: raw.exclusionReason || 'Explicitly excluded by program policy',
      });
    } else {
      inScope.push({
        id: `ins-${index}-${Date.now()}`,
        targetPattern: raw.target.trim(),
        assetType: raw.type,
        bountyEligible: raw.eligible ?? true,
        maxSeverity: raw.maxSeverity || 'CRITICAL',
        description: raw.description,
        allowWildcardSubdomains: raw.target.startsWith('*.'),
      });
    }
  }

  return { inScope, outOfScope, errors };
}
