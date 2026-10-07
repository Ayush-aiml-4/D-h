import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const cspValidator: ControlledValidator = {
  validationId: 'val-csp-audit',
  supportedCapability: 'cap-csp-audit',
  aliases: ['CSP_CONFIGURATION_VALIDATION', 'CSP_ANALYSIS'],
  validationType: 'CSP_CONFIGURATION_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'CSP_VALIDATION_EVIDENCE',
  description: 'Validates Content-Security-Policy directives for unsafe directives like unsafe-inline, unsafe-eval, or missing directives',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || (finding.evidence?.responseHeaders ? { headers: finding.evidence.responseHeaders } : {});
    const headers: Record<string, string> = {};

    const sourceHeaders = rawObs.headers || rawObs || {};
    for (const [k, v] of Object.entries(sourceHeaders)) {
      headers[k.toLowerCase()] = String(v);
    }

    const cspHeader = headers['content-security-policy'] || headers['content-security-policy-report-only'] || '';

    const issues: string[] = [];
    if (!cspHeader) {
      issues.push('Content-Security-Policy header is missing');
    } else {
      if (cspHeader.includes("'unsafe-inline'")) issues.push("CSP allows 'unsafe-inline' script execution");
      if (cspHeader.includes("'unsafe-eval'")) issues.push("CSP allows 'unsafe-eval' script execution");
      if (cspHeader.includes('*')) issues.push('CSP contains wildcard (*) directives');
      if (!cspHeader.includes('object-src')) issues.push("CSP lacks explicit 'object-src' directive");
    }

    const isValidated = issues.length > 0;
    const confidence = isValidated ? 95 : 15;
    const status: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: status,
      confidence,
      summary: isValidated
        ? `Confirmed CSP configuration issues: ${issues.join('; ')}`
        : 'CSP configuration has strong restrictive directives with no identified weaknesses.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        cspHeaderPresent: Boolean(cspHeader),
        identifiedIssues: issues,
        validationMethod: 'CONTROLLED_CSP_VERIFICATION',
      },
    };
  },
};
