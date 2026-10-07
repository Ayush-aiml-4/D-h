import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const securityHeaderAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-http-header-analysis',
  aliases: ['SECURITY_HEADER_ANALYSIS', 'HTTP Security Headers Analysis'],
  name: 'HTTP Security Headers Analysis',
  description: 'Analyzes HTTP security headers for defense-in-depth posture',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const rawHeaders = observationData.headers || {};
    
    // Normalize header keys to lowercase
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(rawHeaders)) {
      headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
    }

    const missingHeaders: string[] = [];
    const recommendedHeaders = [
      'content-security-policy',
      'strict-transport-security',
      'x-content-type-options',
      'x-frame-options',
      'referrer-policy',
      'permissions-policy',
      'cross-origin-opener-policy',
      'cross-origin-resource-policy',
    ];

    for (const h of recommendedHeaders) {
      if (!headers[h]) {
        missingHeaders.push(h);
      }
    }

    const observation = {
      target: asset.hostname || asset.domain || observationData.target || 'target',
      analyzedHeadersCount: Object.keys(headers).length,
      missingSecurityHeadersCount: missingHeaders.length,
      missingHeaders,
      presentSecurityHeaders: Object.keys(headers).filter((h) => recommendedHeaders.includes(h)),
    };

    const evidence = createSanitizedEvidence(
      'cap-http-header-analysis',
      asset.id,
      'HTTP_HEADER_ANALYSIS',
      observation,
      95
    );

    const findingCandidates = [];

    if (missingHeaders.includes('x-content-type-options')) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-http-header-analysis',
          issueIdentifier: 'missing-x-content-type-options',
          title: 'Missing X-Content-Type-Options Security Header',
          category: 'Defense in Depth',
          severity: 'Low',
          confidence: 90,
          whatWeFound: `Target ${asset.hostname} does not include the 'X-Content-Type-Options: nosniff' header in HTTP responses.`,
          whyItMatters: 'MIME-sniffing allows browsers to interpret response bodies differently than declared, potentially leading to XSS vulnerabilities.',
          affectedTarget: asset.hostname || asset.domain || 'target',
          recommendedFix: "Set HTTP response header 'X-Content-Type-Options: nosniff' on all responses.",
          evidence,
        })
      );
    }

    if (missingHeaders.includes('x-frame-options') && missingHeaders.includes('content-security-policy')) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-http-header-analysis',
          issueIdentifier: 'missing-clickjacking-protection',
          title: 'Missing Clickjacking Defense Headers',
          category: 'Defense in Depth',
          severity: 'Medium',
          confidence: 85,
          whatWeFound: `Target ${asset.hostname} lacks both 'X-Frame-Options' and a CSP frame-ancestors directive.`,
          whyItMatters: 'Without framing restrictions, malicious sites can embed this web application in an iframe to perform clickjacking attacks.',
          affectedTarget: asset.hostname || asset.domain || 'target',
          recommendedFix: "Implement 'X-Frame-Options: DENY' or CSP 'frame-ancestors 'none'' or 'frame-ancestors 'self''.",
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-http-header-analysis',
      capabilityName: 'HTTP Security Headers Analysis',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'Header analysis executed successfully',
    };
  },
};
