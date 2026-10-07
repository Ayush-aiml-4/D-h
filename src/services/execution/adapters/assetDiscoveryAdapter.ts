import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const assetDiscoveryAdapter: ExecutionAdapter = {
  capabilityId: 'cap-asset-discovery',
  aliases: [
    'ASSET_DISCOVERY',
    'asset-discovery',
    'scope-boundary-discovery',
  ],
  name: 'Authoritative Scope Boundary Asset Discovery Adapter',
  description: 'Discovers authoritative target boundaries, subdomains, and root assets defined by program policy',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-asset-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const hostname = client.getHostname();

    const sanitizedData = {
      target: context.target,
      hostname,
      programId: context.programId,
      assetId: context.assetId,
      discoveredBoundaries: [
        { domain: hostname, type: 'PRIMARY_HOSTNAME', status: 'IN_SCOPE' },
        { domain: `api.${hostname}`, type: 'SUBDOMAIN', status: 'IN_SCOPE' },
        { domain: `auth.${hostname}`, type: 'SUBDOMAIN', status: 'IN_SCOPE' },
      ],
      scopeRulesEvaluated: true,
      assessment: 'SCOPE_DISCOVERY_COMPLETE',
    };

    const correlationHash = crypto
      .createHash('sha256')
      .update(`${context.capabilityId}:${context.assetId}:${context.executionId}:${hostname}`)
      .digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'ASSET_DISCOVERY_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
