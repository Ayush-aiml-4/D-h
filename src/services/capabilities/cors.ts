import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const corsAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-cors-policy-audit',
  aliases: ['CORS_MISCONFIGURATION', 'CORS Misconfiguration Assessment'],
  name: 'CORS Misconfiguration Assessment',
  description: 'Detects unsafe Cross-Origin Resource Sharing (CORS) configurations',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const rawHeaders = observationData.headers || {};

    const getHeader = (name: string): string => {
      for (const [k, v] of Object.entries(rawHeaders)) {
        if (k.toLowerCase() === name.toLowerCase()) {
          return Array.isArray(v) ? v[0] : String(v);
        }
      }
      return '';
    };

    const allowOrigin = getHeader('access-control-allow-origin');
    const allowCredentials = getHeader('access-control-allow-credentials').toLowerCase() === 'true';

    let isMisconfigured = false;
    let issueType = '';

    if (allowOrigin === '*' && allowCredentials) {
      isMisconfigured = true;
      issueType = 'wildcard-origin-with-credentials';
    } else if (allowOrigin && allowOrigin !== '*' && allowOrigin !== 'null' && allowCredentials) {
      // Check if origin reflected arbitrary domain from observation metadata if provided
      if (
        observationData.metadata?.requestOrigin &&
        allowOrigin === observationData.metadata.requestOrigin &&
        !allowOrigin.includes(asset.domain || 'localhost')
      ) {
        isMisconfigured = true;
        issueType = 'arbitrary-reflected-origin-with-credentials';
      }
    } else if (allowOrigin === 'null' && allowCredentials) {
      isMisconfigured = true;
      issueType = 'null-origin-with-credentials';
    }

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      allowOrigin,
      allowCredentials,
      isMisconfigured,
      issueType: issueType || 'none',
    };

    const evidence = createSanitizedEvidence(
      'cap-cors-policy-audit',
      asset.id,
      'CORS_MISCONFIGURATION',
      observation,
      95
    );

    const findingCandidates = [];

    if (isMisconfigured) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-cors-policy-audit',
          issueIdentifier: `cors-${issueType}`,
          title: 'Unsafe Cross-Origin Resource Sharing (CORS) Policy',
          category: 'Access Control',
          severity: 'High',
          confidence: 90,
          whatWeFound: `CORS policy allows ${allowOrigin} with Access-Control-Allow-Credentials: true.`,
          whyItMatters: 'Unsafe CORS configurations with credentials allow malicious websites to make authenticated cross-origin requests and read sensitive response data.',
          affectedTarget: asset.hostname || asset.domain || 'target',
          recommendedFix: 'Whitelist explicit trusted origins and avoid reflecting arbitrary Origin headers or setting null/wildcard origins when credentials are enabled.',
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-cors-policy-audit',
      capabilityName: 'CORS Misconfiguration Assessment',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'CORS policy assessment completed successfully',
    };
  },
};
