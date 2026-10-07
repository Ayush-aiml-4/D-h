import {
  ClientSideSinkType,
  ClientSideContextType,
  SinkDefinition,
} from '../../types/clientSideResearch.ts';

const DANGEROUS_SINK_MAP: Record<string, { type: ClientSideSinkType; context: ClientSideContextType }> = {
  innerHTML: { type: 'INNER_HTML', context: 'HTML_TEXT' },
  outerHTML: { type: 'OUTER_HTML', context: 'HTML_TEXT' },
  insertAdjacentHTML: { type: 'INSERT_ADJACENT_HTML', context: 'HTML_TEXT' },
  'document.write': { type: 'DOCUMENT_WRITE', context: 'HTML_TEXT' },
  'document.writeln': { type: 'DOCUMENT_WRITE', context: 'HTML_TEXT' },
  eval: { type: 'EVAL', context: 'JAVASCRIPT_CODE' },
  Function: { type: 'FUNCTION_CONSTRUCTOR', context: 'JAVASCRIPT_CODE' },
  setTimeout: { type: 'SET_TIMEOUT_STRING', context: 'JAVASCRIPT_CODE' },
  setInterval: { type: 'SET_INTERVAL_STRING', context: 'JAVASCRIPT_CODE' },
  'location.href': { type: 'DANGEROUS_URL_ASSIGNMENT', context: 'HTML_ATTRIBUTE_URL' },
  'location.replace': { type: 'DANGEROUS_URL_ASSIGNMENT', context: 'HTML_ATTRIBUTE_URL' },
  'location.assign': { type: 'DANGEROUS_URL_ASSIGNMENT', context: 'HTML_ATTRIBUTE_URL' },
  'window.open': { type: 'DANGEROUS_URL_ASSIGNMENT', context: 'HTML_ATTRIBUTE_URL' },
};

const SAFE_SINK_MAP: Record<string, { type: ClientSideSinkType; context: ClientSideContextType }> = {
  textContent: { type: 'SAFE_TEXT_CONTENT', context: 'HTML_TEXT' },
  innerText: { type: 'SAFE_TEXT_CONTENT', context: 'HTML_TEXT' },
  'document.createTextNode': { type: 'SAFE_TEXT_CONTENT', context: 'HTML_TEXT' },
  setAttribute: { type: 'SAFE_ATTRIBUTE_SETTER', context: 'HTML_ATTRIBUTE' },
  reactBinding: { type: 'SAFE_FRAMEWORK_BINDING', context: 'HTML_TEXT' },
};

/**
 * Registers or resolves a sink definition from its API name or descriptor.
 */
export function resolveSinkDefinition(sinkName: string, customProperty?: string): SinkDefinition {
  const normalized = sinkName.trim();

  if (DANGEROUS_SINK_MAP[normalized]) {
    const info = DANGEROUS_SINK_MAP[normalized];
    return {
      sinkId: `sink-danger-${normalized.replace(/[^a-zA-Z0-9]/g, '_')}`,
      sinkType: info.type,
      apiName: normalized,
      isDangerous: true,
      context: info.context,
      targetProperty: customProperty,
    };
  }

  if (SAFE_SINK_MAP[normalized]) {
    const info = SAFE_SINK_MAP[normalized];
    return {
      sinkId: `sink-safe-${normalized.replace(/[^a-zA-Z0-9]/g, '_')}`,
      sinkType: info.type,
      apiName: normalized,
      isDangerous: false,
      context: info.context,
      targetProperty: customProperty,
    };
  }

  // Fallback heuristic
  const isDangerous = /html|write|eval|function|exec|timeout|interval|href|assign|replace/i.test(normalized);
  return {
    sinkId: `sink-custom-${normalized.replace(/[^a-zA-Z0-9]/g, '_')}`,
    sinkType: isDangerous ? 'POTENTIALLY_DANGEROUS_SINK' : 'SAFE_SINK',
    apiName: normalized,
    isDangerous,
    context: isDangerous ? 'HTML_TEXT' : 'UNKNOWN',
    targetProperty: customProperty,
  };
}

/**
 * Evaluates whether a dangerous sink receives only safe/static constants or verified sanitized data.
 */
export function isSinkReceivingTrustedConstant(sink: SinkDefinition, dataFlowInput: string): boolean {
  if (!sink.isDangerous) return true;
  // If the input is an empty string, a numeric constant, or a non-researcher-controlled static label
  const isStaticConstant = /^[a-zA-Z0-9_.\-\s]+$/.test(dataFlowInput) && !dataFlowInput.includes('<') && !dataFlowInput.includes('javascript:');
  return isStaticConstant;
}
