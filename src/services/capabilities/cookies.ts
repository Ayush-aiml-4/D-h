import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult, CookieObservation } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const cookieSecurityAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-cookie-security-audit',
  aliases: ['COOKIE_SECURITY_ANALYSIS', 'Cookie Security & Flags Audit'],
  name: 'Cookie Security & Flags Audit',
  description: 'Audits HTTP cookie attributes for Secure, HttpOnly, and SameSite flags',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const rawHeaders = observationData.headers || {};

    let setCookieHeaders: string[] = [];
    for (const [k, v] of Object.entries(rawHeaders)) {
      if (k.toLowerCase() === 'set-cookie') {
        setCookieHeaders = Array.isArray(v) ? v : [String(v)];
        break;
      }
    }

    if (observationData.cookies && observationData.cookies.length > 0) {
      for (const c of observationData.cookies) {
        const flags = [];
        if (c.httpOnly) flags.push('HttpOnly');
        if (c.secure) flags.push('Secure');
        if (c.sameSite) flags.push(`SameSite=${c.sameSite}`);
        setCookieHeaders.push(`${c.name}=REDACTED; ${flags.join('; ')}`);
      }
    }

    const cookieAnalysis: Record<string, any>[] = [];
    const missingFlags: { cookieName: string; missing: string[] }[] = [];

    for (const rawCookie of setCookieHeaders) {
      const parts = rawCookie.split(';').map((p) => p.trim());
      const firstPart = parts[0] || '';
      const cookieName = firstPart.split('=')[0] || 'unknown';

      const isSecure = parts.some((p) => p.toLowerCase() === 'secure');
      const isHttpOnly = parts.some((p) => p.toLowerCase() === 'httponly');
      const sameSitePart = parts.find((p) => p.toLowerCase().startsWith('samesite='));
      const sameSiteVal = sameSitePart ? sameSitePart.split('=')[1] : null;

      const missing = [];
      if (!isSecure) missing.push('Secure');
      if (!isHttpOnly) missing.push('HttpOnly');
      if (!sameSiteVal) missing.push('SameSite');

      if (missing.length > 0) {
        missingFlags.push({ cookieName, missing });
      }

      cookieAnalysis.push({
        cookieName,
        isSecure,
        isHttpOnly,
        sameSite: sameSiteVal || 'Not Set',
        missingFlags: missing,
      });
    }

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      cookiesAnalyzedCount: setCookieHeaders.length,
      cookieDetails: cookieAnalysis,
      insecureCookiesCount: missingFlags.length,
    };

    const evidence = createSanitizedEvidence(
      'cap-cookie-security-audit',
      asset.id,
      'COOKIE_SECURITY_ANALYSIS',
      observation,
      95
    );

    const findingCandidates = [];

    for (const item of missingFlags) {
      if (item.missing.includes('Secure') || item.missing.includes('HttpOnly')) {
        findingCandidates.push(
          createFindingCandidate({
            programId,
            assetId: asset.id,
            capabilityId: 'cap-cookie-security-audit',
            issueIdentifier: `cookie-missing-flags-${item.cookieName}`,
            title: `Insecure Cookie Flags on '${item.cookieName}'`,
            category: 'Cookie Security',
            severity: 'Low',
            confidence: 90,
            whatWeFound: `Cookie '${item.cookieName}' is missing security flags: ${item.missing.join(', ')}.`,
            whyItMatters: 'Missing Secure allows transmission over unencrypted HTTP. Missing HttpOnly exposes session tokens to client-side XSS access.',
            affectedTarget: `${asset.hostname || 'target'} (Cookie: ${item.cookieName})`,
            recommendedFix: `Set 'Secure; HttpOnly; SameSite=Lax' on Set-Cookie directive for '${item.cookieName}'.`,
            evidence,
          })
        );
      }
    }

    return {
      capabilityId: 'cap-cookie-security-audit',
      capabilityName: 'Cookie Security & Flags Audit',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'Cookie security audit completed successfully',
    };
  },
};
