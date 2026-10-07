import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const cspAuditAdapter: ExecutionAdapter = {
  capabilityId: 'cap-csp-audit',
  aliases: [
    'CSP_ANALYSIS',
    'capability.csp-audit',
    'csp-audit',
    'content-security-policy',
  ],
  name: 'Content Security Policy Audit Adapter',
  description: 'Analyzes Content-Security-Policy response headers for injection bypasses and weak directives',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-csp-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const targetPath = (context.parameters?.path as string) || '/';
    const response = await client.request({
      method: 'GET',
      path: targetPath,
    });

    const rawHeaders = response.headers || {};
    let cspHeader = '';
    let cspReportOnly = '';

    for (const [k, v] of Object.entries(rawHeaders)) {
      const lower = k.toLowerCase();
      if (lower === 'content-security-policy') {
        cspHeader = Array.isArray(v) ? v.join('; ') : String(v);
      } else if (lower === 'content-security-policy-report-only') {
        cspReportOnly = Array.isArray(v) ? v.join('; ') : String(v);
      }
    }

    const weaknesses: string[] = [];
    const activeCsp = cspHeader || cspReportOnly;

    if (!activeCsp) {
      weaknesses.push('missing-csp');
    } else {
      if (activeCsp.includes("'unsafe-inline'")) weaknesses.push('unsafe-inline');
      if (activeCsp.includes("'unsafe-eval'")) weaknesses.push('unsafe-eval');
      if (activeCsp.includes('*') || activeCsp.includes('http:')) weaknesses.push('wildcard-or-insecure-scheme');
      if (!activeCsp.includes('default-src') && !activeCsp.includes('script-src')) {
        weaknesses.push('missing-script-src-fallback');
      }
      if (!activeCsp.includes('frame-ancestors')) {
        weaknesses.push('missing-frame-ancestors');
      }
    }

    // Extract directives
    const directives: Record<string, string> = {};
    if (activeCsp) {
      const parts = activeCsp.split(';').map((p) => p.trim()).filter(Boolean);
      for (const part of parts) {
        const spaceIdx = part.indexOf(' ');
        if (spaceIdx > -1) {
          const dirName = part.substring(0, spaceIdx).toLowerCase();
          const dirVal = part.substring(spaceIdx + 1);
          directives[dirName] = dirVal;
        } else {
          directives[part.toLowerCase()] = '';
        }
      }
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      url: response.url,
      statusCode: response.statusCode,
      hasCsp: Boolean(cspHeader),
      hasCspReportOnly: Boolean(cspReportOnly),
      rawCsp: cspHeader || null,
      rawCspReportOnly: cspReportOnly || null,
      identifiedWeaknesses: weaknesses,
      isStrict: Boolean(cspHeader) && weaknesses.length === 0,
      directivesAnalyzed: Object.keys(directives),
    };

    const rawCorrelation = `${context.capabilityId}:${context.assetId}:${context.executionId}:${weaknesses.join(',')}`;
    const correlationHash = crypto.createHash('sha256').update(rawCorrelation).digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'CSP_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
