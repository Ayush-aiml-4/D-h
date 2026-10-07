import {
  ClientSideContextType,
  EncodingClassification,
} from '../../types/clientSideResearch.ts';

export interface XssDifferentialResult {
  isReflected: boolean;
  isExecutableContext: boolean;
  hasBreakout: boolean;
  differentialSummary: string;
}

export function evaluateXssDifferential(
  rawPayload: string,
  renderedSnippet: string,
  context: ClientSideContextType,
  encoding: EncodingClassification
): XssDifferentialResult {
  const isReflected = renderedSnippet.includes(rawPayload) || (
    rawPayload.includes('<') && renderedSnippet.includes('&lt;')
  );

  let hasBreakout = false;
  let isExecutableContext = false;

  if (renderedSnippet.includes(rawPayload)) {
    // Raw payload unencoded
    if (context === 'HTML_TEXT' && /<[a-z][\s\S]*>/i.test(renderedSnippet)) {
      hasBreakout = true;
      isExecutableContext = true;
    } else if (context === 'HTML_ATTRIBUTE' && (rawPayload.includes('"') || rawPayload.includes("'") || /on[a-z]+\s*=/i.test(rawPayload))) {
      hasBreakout = true;
      isExecutableContext = true;
    } else if (context === 'JAVASCRIPT_STRING' && (rawPayload.includes("'") || rawPayload.includes('"') || rawPayload.includes('</script>'))) {
      hasBreakout = true;
      isExecutableContext = true;
    } else if (context === 'JAVASCRIPT_CODE') {
      hasBreakout = true;
      isExecutableContext = true;
    } else if (context === 'HTML_ATTRIBUTE_URL' && rawPayload.toLowerCase().startsWith('javascript:')) {
      hasBreakout = true;
      isExecutableContext = true;
    }
  }

  let differentialSummary = '';
  if (isExecutableContext && hasBreakout) {
    differentialSummary = `Differential analysis confirms unencoded injection broke out of ${context} boundary into executable interpretation.`;
  } else if (isReflected && encoding === 'CORRECT_ENCODING') {
    differentialSummary = `Differential analysis confirms input is reflected but safely encoded in ${context} (benign reflection).`;
  } else if (isReflected) {
    differentialSummary = `Input reflected in non-executable text context without tag or quote breakout.`;
  } else {
    differentialSummary = 'Input is not reflected in rendered output.';
  }

  return {
    isReflected,
    isExecutableContext,
    hasBreakout,
    differentialSummary,
  };
}
