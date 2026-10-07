import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const referenceExecutionAdapter: ExecutionAdapter = {
  capabilityId: 'cap-execution-reference',
  aliases: ['capability.execution-reference', 'execution-reference', 'cap-exec-ref-01'],
  name: 'Execution Pipeline Reference Adapter',
  description: 'Proves the complete server-authoritative execution pipeline without attacking targets',
  authorizationLevel: 'LOW_RISK',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    // Target metadata observation (controlled and deterministic)
    const sanitizedData = {
      executionId: context.executionId,
      caseId: context.caseId,
      programId: context.programId,
      programName: context.programName,
      assetId: context.assetId,
      target: context.target,
      hostname: client.getHostname(),
      evaluatedPolicy: context.policyDecision,
      pipelineVerified: true,
      parameters: context.parameters || {},
      status: 'VERIFIED_EXECUTION_FLOW',
    };

    const rawCorrelation = `${context.capabilityId}:${context.assetId}:${context.executionId}`;
    const correlationHash = crypto.createHash('sha256').update(rawCorrelation).digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'EXECUTION_REFERENCE_TRACE',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
