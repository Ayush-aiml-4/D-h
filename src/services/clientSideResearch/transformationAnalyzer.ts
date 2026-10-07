import {
  TransformationType,
  TransformationStep,
  EncodingClassification,
  SanitizerStatus,
  ClientSideContextType,
} from '../../types/clientSideResearch.ts';

/**
 * Checks if input is HTML entity encoded.
 */
export function isHtmlEntityEncoded(text: string): boolean {
  if (!text) return false;
  return /&lt;|&gt;|&quot;|&#39;|&#x27;|&amp;/i.test(text);
}

/**
 * Checks if input is URL encoded.
 */
export function isUrlEncoded(text: string): boolean {
  if (!text) return false;
  return /%[0-9a-fA-F]{2}/.test(text);
}

/**
 * Checks if input is JavaScript escaped (e.g. \x22, \u003c, \').
 */
export function isJavaScriptEscaped(text: string): boolean {
  if (!text) return false;
  return /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\["'\\nrt]/.test(text);
}

/**
 * Evaluates whether a transformation step properly neutralizes executable interpretation in a given context.
 */
export function evaluateTransformationStep(
  stepOrder: number,
  type: TransformationType,
  inputSnippet: string,
  outputSnippet: string,
  targetContext: ClientSideContextType
): TransformationStep {
  let neutralizesContext = false;
  let description = '';

  switch (type) {
    case 'HTML_ENCODING':
      if (targetContext === 'HTML_TEXT' || targetContext === 'HTML_ATTRIBUTE') {
        neutralizesContext = isHtmlEntityEncoded(outputSnippet) || !outputSnippet.includes('<');
        description = neutralizesContext
          ? 'HTML entity encoding successfully neutralizes tag breakout'
          : 'Incomplete HTML entity encoding';
      } else if (targetContext === 'JAVASCRIPT_CODE' || targetContext === 'JAVASCRIPT_STRING') {
        // HTML encoding inside JS context is WRONG_CONTEXT_ENCODING and does NOT reliably prevent breakout
        neutralizesContext = false;
        description = 'HTML entity encoding is ineffective inside JavaScript context';
      }
      break;

    case 'ATTRIBUTE_ENCODING':
      if (targetContext === 'HTML_ATTRIBUTE') {
        neutralizesContext = !outputSnippet.includes('"') && !outputSnippet.includes("'");
        description = 'Attribute escaping neutralizes attribute delimiter breakout';
      }
      break;

    case 'JAVASCRIPT_ESCAPING':
      if (targetContext === 'JAVASCRIPT_STRING') {
        neutralizesContext = isJavaScriptEscaped(outputSnippet) || (!outputSnippet.includes("'") && !outputSnippet.includes('"') && !outputSnippet.includes('`'));
        description = 'JavaScript string escaping neutralizes string delimiter breakout';
      } else if (targetContext === 'HTML_TEXT') {
        neutralizesContext = false;
        description = 'JavaScript escaping alone is insufficient for HTML text context';
      }
      break;

    case 'URL_ENCODING':
      if (targetContext === 'URL' || targetContext === 'HTML_ATTRIBUTE_URL') {
        neutralizesContext = isUrlEncoded(outputSnippet) && !outputSnippet.toLowerCase().startsWith('javascript:');
        description = 'URL encoding neutralizes script scheme and parameter boundaries';
      } else {
        neutralizesContext = false;
        description = 'URL encoding in HTML/JS context can be decoded by parser';
      }
      break;

    case 'SANITIZATION':
      // Sanitizer neutralizes HTML if script/event handlers stripped
      neutralizesContext = !/<script|onerror|onload|onclick|javascript:/i.test(outputSnippet);
      description = neutralizesContext
        ? 'Trusted sanitizer (e.g. DOMPurify) stripped dangerous HTML tags and event attributes'
        : 'Sanitizer bypass or incomplete allowlist observed';
      break;

    case 'DECODING':
      neutralizesContext = false;
      description = 'Decoding step reverses prior protection';
      break;

    case 'NORMALIZATION':
      neutralizesContext = false;
      description = 'String normalization applied';
      break;

    case 'NONE':
    default:
      neutralizesContext = false;
      description = 'No transformation applied (raw passthrough)';
  }

  return {
    stepOrder,
    transformationType: type,
    description,
    inputSnippet,
    outputSnippet,
    neutralizesContext,
  };
}

/**
 * Classifies the overall encoding applied across a data-flow trace.
 */
export function classifyEncoding(
  rawInput: string,
  renderedOutput: string,
  context: ClientSideContextType,
  steps: TransformationStep[]
): {
  classification: EncodingClassification;
  sanitizerStatus: SanitizerStatus;
  isProperlyNeutralized: boolean;
} {
  const hasSanitization = steps.some((s) => s.transformationType === 'SANITIZATION');
  const hasHtmlEncoding = steps.some((s) => s.transformationType === 'HTML_ENCODING') || isHtmlEntityEncoded(renderedOutput);
  const hasUrlEncoding = steps.some((s) => s.transformationType === 'URL_ENCODING') || isUrlEncoded(renderedOutput);
  const hasJsEscaping = steps.some((s) => s.transformationType === 'JAVASCRIPT_ESCAPING') || isJavaScriptEscaped(renderedOutput);
  const hasDecodingAfterEncoding = steps.some((s, idx) => s.transformationType === 'DECODING' && idx > 0);

  let sanitizerStatus: SanitizerStatus = 'NOT_SANITIZED';
  if (hasSanitization) {
    const isClean = !/<script|onerror|onload|onclick|javascript:/i.test(renderedOutput);
    sanitizerStatus = isClean ? 'SANITIZED' : 'BYPASSABLE_FIXTURE';
  }

  // Determine Encoding Classification
  let classification: EncodingClassification = 'NO_ENCODING';

  if (hasDecodingAfterEncoding) {
    classification = 'DECODE_AFTER_ENCODING';
  } else if (context === 'HTML_TEXT' && hasHtmlEncoding) {
    classification = 'CORRECT_ENCODING';
  } else if (context === 'HTML_ATTRIBUTE' && (hasHtmlEncoding || steps.some((s) => s.transformationType === 'ATTRIBUTE_ENCODING'))) {
    classification = 'CORRECT_ENCODING';
  } else if (context === 'JAVASCRIPT_STRING' && hasJsEscaping) {
    classification = 'CORRECT_ENCODING';
  } else if (context === 'JAVASCRIPT_STRING' && hasHtmlEncoding && !hasJsEscaping) {
    classification = 'WRONG_CONTEXT_ENCODING';
  } else if (context === 'HTML_TEXT' && hasUrlEncoding && !hasHtmlEncoding) {
    classification = 'WRONG_CONTEXT_ENCODING';
  } else if (context === 'HTML_ATTRIBUTE_URL' && hasUrlEncoding) {
    classification = 'CORRECT_ENCODING';
  } else if (hasHtmlEncoding && hasUrlEncoding) {
    classification = 'DOUBLE_ENCODING';
  } else if (!hasHtmlEncoding && !hasUrlEncoding && !hasJsEscaping && !hasSanitization) {
    classification = 'NO_ENCODING';
  }

  const isProperlyNeutralized =
    classification === 'CORRECT_ENCODING' ||
    sanitizerStatus === 'SANITIZED' ||
    steps.some((s) => s.neutralizesContext);

  return {
    classification,
    sanitizerStatus,
    isProperlyNeutralized,
  };
}
