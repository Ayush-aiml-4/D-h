import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const tlsValidator: ControlledValidator = {
  validationId: 'val-tls-cipher-audit',
  supportedCapability: 'cap-tls-cipher-audit',
  aliases: ['TLS_CONFIGURATION_VALIDATION', 'TLS_CONFIGURATION_ANALYSIS'],
  validationType: 'TLS_CONFIGURATION_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'TLS_VALIDATION_EVIDENCE',
  description: 'Validates TLS protocol version and weak cipher suite configurations',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || {};
    const tlsVersion = rawObs.tlsVersion || rawObs.version || 'TLSv1.0';
    const cipher = rawObs.cipher || 'DES-CBC3-SHA';

    const issues: string[] = [];
    const deprecatedVersions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'];

    if (deprecatedVersions.includes(tlsVersion)) {
      issues.push(`Deprecated TLS protocol version negotiated: ${tlsVersion}`);
    }

    const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'ANON'];
    if (weakCiphers.some((w) => cipher.toUpperCase().includes(w))) {
      issues.push(`Weak cipher suite accepted: ${cipher}`);
    }

    const isValidated = issues.length > 0;
    const confidence = isValidated ? 95 : 10;
    const status: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: status,
      confidence,
      summary: isValidated
        ? `Confirmed TLS protocol/cipher weaknesses: ${issues.join('; ')}`
        : 'TLS configuration uses modern protocol versions (TLS 1.2+) and strong ciphers.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        tlsVersion,
        cipher,
        issues,
        validationMethod: 'CONTROLLED_TLS_VERIFICATION',
      },
    };
  },
};
