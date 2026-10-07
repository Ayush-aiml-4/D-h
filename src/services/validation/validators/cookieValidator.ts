import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const cookieValidator: ControlledValidator = {
  validationId: 'val-cookie-security',
  supportedCapability: 'cap-cookie-security',
  aliases: ['COOKIE_ATTRIBUTE_VALIDATION', 'COOKIE_SECURITY_ANALYSIS'],
  validationType: 'COOKIE_ATTRIBUTE_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'COOKIE_VALIDATION_EVIDENCE',
  description: 'Validates cookie security flags (Secure, HttpOnly, SameSite) in Set-Cookie headers',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || (finding.evidence?.responseHeaders ? { headers: finding.evidence.responseHeaders } : {});
    const headers: Record<string, string> = {};

    const sourceHeaders = rawObs.headers || rawObs || {};
    for (const [k, v] of Object.entries(sourceHeaders)) {
      headers[k.toLowerCase()] = String(v);
    }

    const setCookie = headers['set-cookie'] || '';
    const issues: string[] = [];

    if (!setCookie) {
      // Check if observation explicitly provided cookie string
      const cookieStr = typeof rawObs.cookie === 'string' ? rawObs.cookie : '';
      if (!cookieStr) {
        issues.push('No Set-Cookie header or cookie attribute metadata present in response');
      } else {
        if (!cookieStr.toLowerCase().includes('secure')) issues.push('Cookie missing Secure attribute');
        if (!cookieStr.toLowerCase().includes('httponly')) issues.push('Cookie missing HttpOnly attribute');
        if (!cookieStr.toLowerCase().includes('samesite')) issues.push('Cookie missing SameSite attribute');
      }
    } else {
      const cookiesArr = Array.isArray(setCookie) ? setCookie : [setCookie];
      for (const cookie of cookiesArr) {
        const lower = cookie.toLowerCase();
        if (!lower.includes('secure')) issues.push('Set-Cookie missing Secure attribute');
        if (!lower.includes('httponly')) issues.push('Set-Cookie missing HttpOnly attribute');
        if (!lower.includes('samesite')) issues.push('Set-Cookie missing SameSite attribute');
      }
    }

    const isValidated = issues.length > 0;
    const confidence = isValidated ? 90 : 15;
    const status: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: status,
      confidence,
      summary: isValidated
        ? `Confirmed insecure cookie attribute flags: ${issues.join('; ')}`
        : 'All evaluated cookies include Secure, HttpOnly, and SameSite attributes.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        identifiedInsecurities: issues,
        validationMethod: 'CONTROLLED_COOKIE_VERIFICATION',
      },
    };
  },
};
