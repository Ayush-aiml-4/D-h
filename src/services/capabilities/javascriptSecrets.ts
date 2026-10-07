import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const javascriptSecretAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-javascript-secret-exposure',
  aliases: ['JAVASCRIPT_SECRET_EXPOSURE', 'Client-Side JavaScript Secret Extraction'],
  name: 'Client-Side JavaScript Secret Extraction',
  description: 'Extracts embedded API keys, tokens, and credentials from client-side JS bundles',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const body = observationData.body || '';

    const secretMatches: { type: string; patternName: string }[] = [];

    const secretRules = [
      { name: 'AWS Access Key', pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/g },
      { name: 'Google API Key', pattern: /AIzaSy[a-zA-Z0-9_\-]{20,40}/g },
      { name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g },
      { name: 'GitHub Personal Access Token', pattern: /ghp_[a-zA-Z0-9]{36}/g },
      { name: 'Private Key Block', pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g },
      { name: 'Hardcoded Bearer Token', pattern: /["']Bearer\s+eyJ[a-zA-Z0-9_-]{10,}\.eyJ/g },
    ];

    for (const rule of secretRules) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(body)) {
        secretMatches.push({ type: 'Embedded Credential', patternName: rule.name });
      }
    }

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      path: observationData.path || '/',
      hasSecretExposure: secretMatches.length > 0,
      detectedSecretCategories: secretMatches,
    };

    const evidence = createSanitizedEvidence(
      'cap-javascript-secret-exposure',
      asset.id,
      'JAVASCRIPT_SECRET_EXPOSURE',
      {
        ...observation,
        sampleBody: body,
      },
      95
    );

    const findingCandidates = [];

    if (secretMatches.length > 0) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-javascript-secret-exposure',
          issueIdentifier: 'hardcoded-secrets-in-javascript',
          title: 'Hardcoded Secret / API Key Disclosed in Client-Side Code',
          category: 'Credential Exposure',
          severity: 'Critical',
          confidence: 95,
          whatWeFound: `Client-side script at path '${observationData.path}' contains hardcoded secrets (${secretMatches.map((s) => s.patternName).join(', ')}).`,
          whyItMatters: 'Exposed secret keys allow unauthenticated third parties to access backend services, impersonate systems, or extract sensitive data.',
          affectedTarget: `${asset.hostname || 'target'}${observationData.path}`,
          recommendedFix: 'Revoke compromised credentials immediately and move secret keys to secure server-side environment variables.',
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-javascript-secret-exposure',
      capabilityName: 'Client-Side JavaScript Secret Extraction',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'JavaScript secret analysis completed successfully',
    };
  },
};
