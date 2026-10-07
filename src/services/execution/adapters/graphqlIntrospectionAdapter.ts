import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const graphqlIntrospectionAdapter: ExecutionAdapter = {
  capabilityId: 'cap-graphql-introspection',
  aliases: [
    'GRAPHQL_INTROSPECTION',
    'graphql-introspection',
    'graphql-schema-audit',
  ],
  name: 'GraphQL Introspection Availability Adapter',
  description: 'Probes GraphQL endpoints with benign introspection queries to verify unauthenticated schema visibility',
  authorizationLevel: 'LOW_RISK',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-gql-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const targetPath = (context.parameters?.path as string) || '/graphql';

    let introspectionEnabled = false;
    let statusCode = 404;
    let schemaTypeCount = 0;

    try {
      const response = await client.request({
        method: 'POST',
        path: targetPath,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query: '{ __schema { types { name kind } } }',
        }),
      });

      statusCode = response.statusCode;
      if (response.statusCode === 200 && response.body) {
        try {
          const parsed = JSON.parse(response.body);
          if (parsed?.data?.__schema?.types) {
            introspectionEnabled = true;
            schemaTypeCount = parsed.data.__schema.types.length;
          }
        } catch {
          // Non-JSON response
        }
      }
    } catch {
      // Governed probe error handled safely
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      path: targetPath,
      statusCode,
      introspectionEnabled,
      schemaTypeCount,
      assessment: introspectionEnabled ? 'INTROSPECTION_ENABLED' : 'INTROSPECTION_DISABLED_OR_NOT_PRESENT',
    };

    const correlationHash = crypto
      .createHash('sha256')
      .update(`${context.capabilityId}:${context.assetId}:${context.executionId}:${statusCode}`)
      .digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'GRAPHQL_INTROSPECTION_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
