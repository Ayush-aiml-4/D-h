import {
  ClientSideSourceType,
  SourceDefinition,
  SinkDefinition,
  DataFlowTrace,
  TransformationStep,
  ClientSideContextType,
} from '../../types/clientSideResearch.ts';

/**
 * Creates and registers a controlled source definition.
 */
export function createSourceDefinition(input: {
  sourceId?: string;
  sourceType: ClientSideSourceType;
  name: string;
  value: string;
  isResearcherControlled?: boolean;
  taintMarker?: string;
  actorIdentifier?: string;
}): SourceDefinition {
  return {
    sourceId: input.sourceId || `src-${input.sourceType.toLowerCase()}-${input.name.replace(/[^a-zA-Z0-9]/g, '_')}`,
    sourceType: input.sourceType,
    name: input.name,
    value: input.value,
    isResearcherControlled: input.isResearcherControlled !== false,
    taintMarker: input.taintMarker || `taint-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    actorIdentifier: input.actorIdentifier || 'researcher-001',
  };
}

/**
 * Validates whether a complete Source -> Transformation -> Sink data-flow trace exists.
 */
export function buildDataFlowTrace(
  source: SourceDefinition,
  transformations: TransformationStep[],
  sink: SinkDefinition,
  finalRenderedContext: ClientSideContextType,
  renderedOutput: string
): DataFlowTrace {
  // Check if any transformation step effectively neutralizes the taint path
  const isNeutralized = transformations.some((t) => t.neutralizesContext) || !sink.isDangerous;

  // A taint path is valid if the source value or transformed representation reaches the sink
  const isTaintPathValid = source.isResearcherControlled && (
    renderedOutput.includes(source.value) ||
    transformations.length > 0
  );

  return {
    traceId: `trace-${source.sourceId}-${sink.sinkId}`,
    source,
    transformations,
    sink,
    isTaintPathValid,
    isNeutralized,
    finalRenderedContext,
    renderedOutput,
  };
}
