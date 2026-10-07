import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const hstsValidator: ControlledValidator = {
  validationId: 'val-hsts-audit',
  supportedCapability: 'cap-hsts-audit',
  aliases: ['HSTS_CONFIGURATION_VALIDATION', 'HSTS_ANALYSIS'],
  validationType: 'HSTS_CONFIGURATION_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'HSTS_VALIDATION_EVIDENCE',
  description: 'Validates Strict-Transport-Security header presence, max-age threshold, and includeSubDomains directive',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || (finding.evidence?.responseHeaders ? { headers: finding.evidence.responseHeaders } : {});
    const headers: Record<string, string> = {};

    const sourceHeaders = rawObs.headers || rawObs || {};
    for (const [k, v] of Object.entries(sourceHeaders)) {
      headers[k.toLowerCase()] = String(v);
    }

    const hsts = headers['strict-transport-security'] || '';
    const issues: string[] = [];

    if (!hsts) {
      issues.push('Strict-Transport-Security header is missing');
    } else {
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 15768000) {
        issues.push(`HSTS max-age (${maxAge}s) is below recommended minimum (15768000s / 180 days)`);
      }
      if (!hsts.toLowerCase().includes('includesubdomains')) {
        issues.push('HSTS lacks includeSubDomains directive');
      }
    }

    const isValidated = issues.length > 0;
    const confidence = isValidated ? 95 : 10;
    const status: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: status,
      confidence,
      summary: isValidated
        ? `Confirmed HSTS configuration weaknesses: ${issues.join('; ')}`
        : 'HSTS is fully configured with adequate max-age and includeSubDomains.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        hstsPresent: Boolean(hsts),
        identifiedIssues: issues,
        validationMethod: 'CONTROLLED_HSTS_VERIFICATION',
      },
    };
  },
};
