import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const cspAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-csp-audit',
  aliases: ['CSP_ANALYSIS', 'Content Security Policy Audit'],
  name: 'Content Security Policy Audit',
  description: 'Evaluates CSP policy strength, directives, and potential bypass routes',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const rawHeaders = observationData.headers || {};

    let cspHeader = '';
    for (const [k, v] of Object.entries(rawHeaders)) {
      if (k.toLowerCase() === 'content-security-policy') {
        cspHeader = Array.isArray(v) ? v.join('; ') : String(v);
        break;
      }
    }

    const weaknesses: string[] = [];
    if (!cspHeader) {
      weaknesses.push('missing-csp');
    } else {
      if (cspHeader.includes("'unsafe-inline'")) weaknesses.push('unsafe-inline');
      if (cspHeader.includes("'unsafe-eval'")) weaknesses.push('unsafe-eval');
      if (cspHeader.includes('*') || cspHeader.includes('http:')) weaknesses.push('wildcard-or-insecure-scheme');
      if (!cspHeader.includes('default-src') && !cspHeader.includes('script-src')) {
        weaknesses.push('missing-script-src-fallback');
      }
    }

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      hasCsp: Boolean(cspHeader),
      rawCsp: cspHeader || null,
      identifiedWeaknesses: weaknesses,
    };

    const evidence = createSanitizedEvidence(
      'cap-csp-audit',
      asset.id,
      'CSP_ANALYSIS',
      observation,
      95
    );

    const findingCandidates = [];

    if (weaknesses.includes('missing-csp')) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-csp-audit',
          issueIdentifier: 'missing-csp-header',
          title: 'Missing Content-Security-Policy (CSP) Header',
          category: 'Defense in Depth',
          severity: 'Low',
          confidence: 90,
          whatWeFound: `Target ${asset.hostname} does not supply a Content-Security-Policy header.`,
          whyItMatters: 'A strong CSP significantly mitigates Cross-Site Scripting (XSS) and data injection attacks.',
          affectedTarget: asset.hostname || asset.domain || 'target',
          recommendedFix: 'Implement a strict CSP restricting script execution to trusted domains and nonces.',
          evidence,
        })
      );
    } else if (weaknesses.includes('unsafe-inline') || weaknesses.includes('unsafe-eval')) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-csp-audit',
          issueIdentifier: 'weak-csp-unsafe-directives',
          title: 'Content Security Policy Contains Unsafe Directives',
          category: 'Insecure Configuration',
          severity: 'Medium',
          confidence: 95,
          whatWeFound: `CSP header includes unsafe directives: ${weaknesses.filter((w) => w.startsWith('unsafe')).join(', ')}.`,
          whyItMatters: "'unsafe-inline' and 'unsafe-eval' allow execution of arbitrary inline scripts and dynamic eval code, neutralizing CSP XSS mitigations.",
          affectedTarget: asset.hostname || asset.domain || 'target',
          recommendedFix: "Refactor scripts to use nonces/hashes and remove 'unsafe-inline' and 'unsafe-eval'.",
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-csp-audit',
      capabilityName: 'Content Security Policy Audit',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'CSP audit completed successfully',
    };
  },
};
