import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const securityTxtAdapter: ExecutionAdapter = {
  capabilityId: 'cap-security-txt-observation',
  aliases: [
    'SECURITY_TXT_OBSERVATION',
    'security-txt',
    'rfc-9116-observation',
  ],
  name: 'RFC 9116 security.txt Policy Observation Adapter',
  description: 'Observes published vulnerability disclosure contacts and cryptographic policy indicators in /.well-known/security.txt',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-sectxt-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    // 1. Probe /.well-known/security.txt
    const res = await client.request({
      method: 'GET',
      path: '/.well-known/security.txt',
    });

    const isFound = res.statusCode === 200 && typeof res.body === 'string';
    const body = isFound ? res.body : '';

    const hasContact = body.includes('Contact:');
    const hasExpires = body.includes('Expires:');
    const hasEncryption = body.includes('Encryption:');
    const hasPolicy = body.includes('Policy:');
    const hasHiring = body.includes('Hiring:');

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: res.statusCode,
      hasSecurityTxt: isFound,
      fields: {
        hasContact,
        hasExpires,
        hasEncryption,
        hasPolicy,
        hasHiring,
      },
      isRfc9116Compliant: hasContact && hasExpires,
      assessment: isFound && hasContact ? 'SECURITY_TXT_PUBLISHED' : 'SECURITY_TXT_NOT_FOUND',
    };

    const correlationHash = crypto
      .createHash('sha256')
      .update(`${context.capabilityId}:${context.assetId}:${context.executionId}:${res.statusCode}`)
      .digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'SECURITY_TXT_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
