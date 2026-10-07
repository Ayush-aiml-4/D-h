import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const tlsAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-tls-ssl-audit',
  aliases: ['TLS_CONFIGURATION_ANALYSIS', 'TLS / SSL Configuration Audit'],
  name: 'TLS / SSL Configuration Audit',
  description: 'Audits TLS protocol versions, cipher suites, and certificate validity metadata',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const tls = observationData.tls || {};

    const issues: string[] = [];

    if (tls.version && (tls.version.includes('TLSv1.0') || tls.version.includes('TLSv1.1') || tls.version.includes('SSL'))) {
      issues.push('deprecated-tls-protocol');
    }

    if (tls.validTo) {
      const expiry = new Date(tls.validTo).getTime();
      const now = Date.now();
      if (expiry < now) {
        issues.push('expired-certificate');
      } else if (expiry - now < 30 * 86400 * 1000) {
        issues.push('certificate-expiring-soon');
      }
    }

    if (tls.authorized === false) {
      issues.push('untrusted-certificate-authority');
    }

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      tlsVersion: tls.version || 'Unknown',
      cipher: tls.cipher || 'Unknown',
      validTo: tls.validTo || null,
      authorized: tls.authorized ?? true,
      issuesIdentified: issues,
    };

    const evidence = createSanitizedEvidence(
      'cap-tls-ssl-audit',
      asset.id,
      'TLS_CONFIGURATION_ANALYSIS',
      observation,
      90
    );

    const findingCandidates = [];

    if (issues.includes('deprecated-tls-protocol')) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-tls-ssl-audit',
          issueIdentifier: 'deprecated-tls-version',
          title: 'Deprecated TLS Protocol Version Enabled',
          category: 'Transport Security',
          severity: 'Medium',
          confidence: 95,
          whatWeFound: `TLS metadata indicates protocol version '${tls.version}' is active on ${asset.hostname}.`,
          whyItMatters: 'TLS 1.0 and 1.1 are deprecated protocols subject to known cryptographic weaknesses (BEAST, POODLE).',
          affectedTarget: asset.hostname || asset.domain || 'target',
          recommendedFix: 'Disable TLS 1.0/1.1 and mandate TLS 1.2 or TLS 1.3 with secure AEAD ciphers.',
          evidence,
        })
      );
    }

    if (issues.includes('expired-certificate')) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-tls-ssl-audit',
          issueIdentifier: 'expired-tls-certificate',
          title: 'Expired TLS / SSL Certificate',
          category: 'Transport Security',
          severity: 'High',
          confidence: 95,
          whatWeFound: `TLS certificate for ${asset.hostname} expired on ${tls.validTo}.`,
          whyItMatters: 'Expired certificates break browser TLS trust and expose users to interception risks.',
          affectedTarget: asset.hostname || asset.domain || 'target',
          recommendedFix: 'Renew and deploy a valid TLS certificate from a recognized Certificate Authority.',
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-tls-ssl-audit',
      capabilityName: 'TLS / SSL Configuration Audit',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'TLS configuration audit completed successfully',
    };
  },
};
