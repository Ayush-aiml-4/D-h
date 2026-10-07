import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const corsValidator: ControlledValidator = {
  validationId: 'val-cors-misconfiguration',
  supportedCapability: 'cap-cors-misconfiguration',
  aliases: ['CORS_CONFIGURATION_VALIDATION', 'CORS_MISCONFIGURATION'],
  validationType: 'CORS_CONFIGURATION_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'CORS_VALIDATION_EVIDENCE',
  description: 'Validates CORS headers for unsafe wildcard (*), reflected origin, or Access-Control-Allow-Credentials combinations',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || (finding.evidence?.responseHeaders ? { headers: finding.evidence.responseHeaders } : {});
    const headers: Record<string, string> = {};

    const sourceHeaders = rawObs.headers || rawObs || {};
    for (const [k, v] of Object.entries(sourceHeaders)) {
      headers[k.toLowerCase()] = String(v);
    }

    const allowOrigin = headers['access-control-allow-origin'] || '';
    const allowCredentials = headers['access-control-allow-credentials'] || '';

    const issues: string[] = [];
    if (allowOrigin === '*' && allowCredentials === 'true') {
      issues.push('Invalid combination: Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true');
    } else if (allowOrigin === '*') {
      issues.push('Access-Control-Allow-Origin is set to wildcard (*)');
    } else if (rawObs.originReflected || allowOrigin === 'null') {
      issues.push('Access-Control-Allow-Origin reflects untrusted origin or null');
    }

    const isValidated = issues.length > 0;
    const confidence = isValidated ? 95 : 10;
    const status: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: status,
      confidence,
      summary: isValidated
        ? `Confirmed CORS misconfiguration: ${issues.join('; ')}`
        : 'CORS origin policies are properly restricted.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        allowOrigin,
        allowCredentials,
        issues,
        validationMethod: 'CONTROLLED_CORS_VERIFICATION',
      },
    };
  },
};
