import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const hstsAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-hsts-audit',
  aliases: ['HSTS_ANALYSIS', 'Strict Transport Security Audit'],
  name: 'Strict Transport Security Audit',
  description: 'Evaluates HTTP Strict Transport Security (HSTS) implementation',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const rawHeaders = observationData.headers || {};

    let hstsHeader = '';
    for (const [k, v] of Object.entries(rawHeaders)) {
      if (k.toLowerCase() === 'strict-transport-security') {
        hstsHeader = Array.isArray(v) ? v.join('; ') : String(v);
        break;
      }
    }

    let maxAge = 0;
    let includeSubDomains = false;
    let preload = false;

    if (hstsHeader) {
      const matchAge = hstsHeader.match(/max-age=(\d+)/i);
      if (matchAge) maxAge = parseInt(matchAge[1], 10);
      includeSubDomains = /includeSubDomains/i.test(hstsHeader);
      preload = /preload/i.test(hstsHeader);
    }

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      hasHsts: Boolean(hstsHeader),
      rawHsts: hstsHeader || null,
      maxAgeSeconds: maxAge,
      includeSubDomains,
      preload,
      isOneYearPlus: maxAge >= 31536000,
    };

    const evidence = createSanitizedEvidence(
      'cap-hsts-audit',
      asset.id,
      'HSTS_ANALYSIS',
      observation,
      95
    );

    const findingCandidates = [];

    if (!hstsHeader) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-hsts-audit',
          issueIdentifier: 'missing-hsts-header',
          title: 'Missing HTTP Strict Transport Security (HSTS) Header',
          category: 'Transport Security',
          severity: 'Low',
          confidence: 90,
          whatWeFound: `Target ${asset.hostname} does not serve a Strict-Transport-Security header over HTTPS responses.`,
          whyItMatters: 'Without HSTS, initial HTTP connections or downgrade redirects remain vulnerable to SSL stripping / Man-In-The-Middle attacks.',
          affectedTarget: asset.hostname || asset.domain || 'target',
          recommendedFix: "Serve 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS endpoints.",
          evidence,
        })
      );
    } else if (maxAge < 15768000) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-hsts-audit',
          issueIdentifier: 'short-hsts-max-age',
          title: 'HSTS Header Max-Age Is Too Short',
          category: 'Transport Security',
          severity: 'Low',
          confidence: 85,
          whatWeFound: `HSTS header max-age is ${maxAge} seconds (less than 6 months recommended duration).`,
          whyItMatters: 'Short HSTS max-age values leave users exposed to MITM downgrade attacks if they do not visit frequently.',
          affectedTarget: asset.hostname || asset.domain || 'target',
          recommendedFix: 'Increase HSTS max-age to at least 31536000 seconds (1 year).',
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-hsts-audit',
      capabilityName: 'Strict Transport Security Audit',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'HSTS audit completed successfully',
    };
  },
};
