import crypto from 'crypto';
import {
  BrowserExecutionEvidence,
  ClientSideSinkType,
  ClientSideContextType,
} from '../../types/clientSideResearch.ts';

export function createBrowserExecutionEvidence(input: {
  evidenceId?: string;
  fixtureId: string;
  correlationId: string;
  sourceMarker: string;
  sink: ClientSideSinkType;
  executionMarker: string;
  executedContext: ClientSideContextType;
  executionLog?: string[];
}): BrowserExecutionEvidence {
  const evidenceId = input.evidenceId || `ev-xss-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const timestamp = new Date().toISOString();
  const executionLog = input.executionLog || [
    `[FIXTURE_EVIDENCE] Source marker '${input.sourceMarker}' dispatched`,
    `[FIXTURE_EVIDENCE] Reached sink ${input.sink} in context ${input.executedContext}`,
    `[FIXTURE_EVIDENCE] Execution marker '${input.executionMarker}' triggered in local deterministic sandbox`,
  ];

  const payloadToHash = JSON.stringify({
    fixtureId: input.fixtureId,
    correlationId: input.correlationId,
    sourceMarker: input.sourceMarker,
    sink: input.sink,
    executionMarker: input.executionMarker,
    executedContext: input.executedContext,
  });

  const evidenceHash = crypto.createHash('sha256').update(payloadToHash).digest('hex');

  return {
    evidenceId,
    fixtureId: input.fixtureId,
    correlationId: input.correlationId,
    sourceMarker: input.sourceMarker,
    sink: input.sink,
    executionMarker: input.executionMarker,
    executedContext: input.executedContext,
    evidenceHash,
    timestamp,
    isSimulatedExecution: true,
    executionLog,
  };
}
