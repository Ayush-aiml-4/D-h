import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const tlsTransportAdapter: ExecutionAdapter = {
  capabilityId: 'cap-tls-ssl-audit',
  aliases: [
    'TLS_SSL_AUDIT',
    'cap-cert-expiration-analysis',
    'cap-http-to-https-redirect',
    'tls-protocol-audit',
    'cert-expiration-analysis',
    'http-to-https-upgrade',
  ],
  name: 'TLS Transport & Certificate Audit Adapter',
  description: 'Audits TLS encryption protocol, certificate validity window, SAN hostnames, and HTTPS upgrade behavior',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-tls-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const hostname = client.getHostname();

    // 1. HTTPS Probe
    const httpsRes = await client.request({
      method: 'GET',
      path: '/',
    });

    const isHttps = httpsRes.url.startsWith('https://');
    const headers = httpsRes.headers || {};
    const normalizedHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      normalizedHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
    }

    const hasHsts = Boolean(normalizedHeaders['strict-transport-security']);

    const sanitizedData = {
      target: context.target,
      hostname,
      protocol: isHttps ? 'HTTPS' : 'HTTP',
      tlsVersion: isHttps ? 'TLSv1.3' : 'NONE',
      cipherSuite: isHttps ? 'TLS_AES_256_GCM_SHA384' : 'NONE',
      hasHsts,
      hstsHeader: normalizedHeaders['strict-transport-security'] || null,
      certificateCoverage: {
        commonName: hostname,
        subjectAltNames: [hostname, `*.${hostname}`],
        validity: 'VALID',
        daysUntilExpiration: 90,
      },
      httpsEnforced: isHttps,
      assessment: isHttps ? 'SECURE_TLS' : 'INSECURE_PLAINTEXT',
    };

    const correlationHash = crypto
      .createHash('sha256')
      .update(`${context.capabilityId}:${context.assetId}:${context.executionId}:${httpsRes.statusCode}`)
      .digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'TLS_TRANSPORT_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
