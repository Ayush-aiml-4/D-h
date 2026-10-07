import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const securityHeadersValidator: ControlledValidator = {
  validationId: 'val-security-headers',
  supportedCapability: 'cap-http-header-analysis',
  aliases: ['SECURITY_HEADER_VALIDATION', 'SECURITY_HEADER_ANALYSIS'],
  validationType: 'SECURITY_HEADER_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'HEADER_VALIDATION_EVIDENCE',
  description: 'Validates controlled HTTP response metadata to confirm security header enforcement posture',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || (finding.evidence?.responseHeaders ? { headers: finding.evidence.responseHeaders } : {});
    const headers: Record<string, string> = {};

    const sourceHeaders = rawObs.headers || rawObs || {};
    for (const [k, v] of Object.entries(sourceHeaders)) {
      headers[k.toLowerCase()] = String(v);
    }

    const missingHeaders: string[] = [];
    const checkList = ['x-content-type-options', 'x-frame-options', 'content-security-policy', 'strict-transport-security', 'referrer-policy'];

    for (const h of checkList) {
      if (!headers[h]) {
        missingHeaders.push(h);
      }
    }

    const isValidated = missingHeaders.length > 0;
    const confidence = isValidated ? 95 : 10;
    const status: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: status,
      confidence,
      summary: isValidated
        ? `Confirmed ${missingHeaders.length} missing HTTP security headers: ${missingHeaders.join(', ')}`
        : 'All recommended security headers are actively enforced.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        missingHeaders,
        evaluatedHeaderCount: Object.keys(headers).length,
        validationMethod: 'CONTROLLED_HEADER_VERIFICATION',
      },
    };
  },
};
