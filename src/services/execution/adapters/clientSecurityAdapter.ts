import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const clientSecurityAdapter: ExecutionAdapter = {
  capabilityId: 'cap-client-secrets-detection',
  aliases: [
    'CLIENT_SECRETS_DETECTION',
    'cap-subresource-integrity',
    'client-secrets-detection',
    'subresource-integrity',
  ],
  name: 'Client-Side Security & Subresource Integrity Adapter',
  description: 'Inspects HTML and JavaScript assets for unhashed high-entropy secret patterns (with mandatory redaction) and checks Subresource Integrity tags',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-cli-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const targetPath = (context.parameters?.path as string) || '/';

    const response = await client.request({
      method: 'GET',
      path: targetPath,
    });

    const body = typeof response.body === 'string' ? response.body : '';
    const scriptTagCount = (body.match(/<script/gi) || []).length;
    const sriScriptTagCount = (body.match(/<script[^>]+integrity=/gi) || []).length;

    // Pattern analysis (with strict redaction)
    const hasAwsPattern = /AKIA[0-9A-Z]{16}/.test(body);
    const hasGooglePattern = /AIza[0-9A-Za-z\-_]{35}/.test(body);
    const hasGithubPattern = /ghp_[0-9a-zA-Z]{36}/.test(body);

    const detectedPatterns: string[] = [];
    if (hasAwsPattern) detectedPatterns.push('AWS_KEY_PATTERN');
    if (hasGooglePattern) detectedPatterns.push('GOOGLE_API_KEY_PATTERN');
    if (hasGithubPattern) detectedPatterns.push('GITHUB_TOKEN_PATTERN');

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: response.statusCode,
      scriptTagCount,
      sriScriptTagCount,
      hasMissingSri: scriptTagCount > sriScriptTagCount,
      detectedSecretPatternsCount: detectedPatterns.length,
      detectedPatternTypes: detectedPatterns,
      redactedConfidence: detectedPatterns.length > 0 ? 'HIGH_ENTROPY_PATTERN_IDENTIFIED' : 'NONE',
      assessment: detectedPatterns.length > 0 ? 'SUSPECTED_STATIC_TOKEN' : 'CLEAN_CLIENT_SCRIPTS',
    };

    const correlationHash = crypto
      .createHash('sha256')
      .update(`${context.capabilityId}:${context.assetId}:${context.executionId}:${response.statusCode}`)
      .digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'CLIENT_SECURITY_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
