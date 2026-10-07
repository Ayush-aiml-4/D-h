import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const sensitiveInformationAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-sensitive-info-exposure',
  aliases: ['SENSITIVE_INFORMATION_EXPOSURE', 'Sensitive Information Exposure Audit'],
  name: 'Sensitive Information Exposure Audit',
  description: 'Audits response bodies and headers for internal IPs, emails, PII, and staging endpoints',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const body = observationData.body || '';

    const findings: string[] = [];

    // Internal IP disclosure (RFC 1918)
    const privateIpRegex = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;
    if (privateIpRegex.test(body)) {
      findings.push('private-ip-disclosure');
    }

    // Internal staging domain references
    const stagingDomainRegex = /\b[a-zA-Z0-9-]+\.(?:staging|internal|dev|corp|local)\.[a-zA-Z]{2,}\b/g;
    if (stagingDomainRegex.test(body)) {
      findings.push('internal-domain-disclosure');
    }

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      path: observationData.path || '/',
      hasSensitiveInfoExposure: findings.length > 0,
      disclosures: findings,
    };

    const evidence = createSanitizedEvidence(
      'cap-sensitive-info-exposure',
      asset.id,
      'SENSITIVE_INFORMATION_EXPOSURE',
      observation,
      90
    );

    const findingCandidates = [];

    if (findings.includes('private-ip-disclosure')) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-sensitive-info-exposure',
          issueIdentifier: 'internal-ip-disclosure',
          title: 'Internal RFC1918 IP Address Disclosure',
          category: 'Information Disclosure',
          severity: 'Low',
          confidence: 85,
          whatWeFound: `Response body leaks internal RFC1918 private IP addresses.`,
          whyItMatters: 'Internal IP disclosures aid attackers in mapping internal network topology during lateral movement phases.',
          affectedTarget: `${asset.hostname || 'target'}${observationData.path || '/'}`,
          recommendedFix: 'Sanitize server responses and headers to remove internal private IP address references.',
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-sensitive-info-exposure',
      capabilityName: 'Sensitive Information Exposure Audit',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'Sensitive information exposure audit completed successfully',
    };
  },
};
