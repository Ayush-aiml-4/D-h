import { ClientSideContextType } from '../../types/clientSideResearch.ts';

/**
 * Analyzes HTML/JS snippets to determine the contextual location of researcher-controlled input.
 */
export function determineInputContext(templateSnippet: string, placeholder: string): ClientSideContextType {
  if (!templateSnippet || !placeholder) {
    return 'UNKNOWN';
  }

  const index = templateSnippet.indexOf(placeholder);
  if (index === -1) {
    return 'UNKNOWN';
  }

  const before = templateSnippet.substring(0, index);
  const after = templateSnippet.substring(index + placeholder.length);

  // 1. Check if inside <script> tag
  const lastScriptOpen = before.lastIndexOf('<script');
  const lastScriptClose = before.lastIndexOf('</script>');
  if (lastScriptOpen !== -1 && (lastScriptClose === -1 || lastScriptClose < lastScriptOpen)) {
    // Inside a script block. Check if inside string literal (' or " or `)
    const scriptBodyBefore = before.substring(lastScriptOpen);
    const singleQuotes = (scriptBodyBefore.match(/'/g) || []).length;
    const doubleQuotes = (scriptBodyBefore.match(/"/g) || []).length;
    const backticks = (scriptBodyBefore.match(/`/g) || []).length;

    if (singleQuotes % 2 !== 0 || doubleQuotes % 2 !== 0 || backticks % 2 !== 0) {
      return 'JAVASCRIPT_STRING';
    }
    return 'JAVASCRIPT_CODE';
  }

  // 2. Check if inside <style> tag
  const lastStyleOpen = before.lastIndexOf('<style');
  const lastStyleClose = before.lastIndexOf('</style>');
  if (lastStyleOpen !== -1 && (lastStyleClose === -1 || lastStyleClose < lastStyleOpen)) {
    return 'CSS';
  }

  // 3. Check if inside an HTML tag attribute
  const lastTagOpen = before.lastIndexOf('<');
  const lastTagClose = before.lastIndexOf('>');
  if (lastTagOpen !== -1 && (lastTagClose === -1 || lastTagClose < lastTagOpen)) {
    // Inside an HTML tag attribute
    const tagContentBefore = before.substring(lastTagOpen);
    
    // Check if attribute is a URL attribute (href, src, formaction, action)
    const isUrlAttr = /(href|src|action|formaction|data)\s*=\s*['"]?[^'"]*$/i.test(tagContentBefore);
    if (isUrlAttr) {
      return 'HTML_ATTRIBUTE_URL';
    }

    // Check if event handler attribute (onclick, onerror, onload, onfocus, etc.)
    const isEventHandler = /on[a-z]+\s*=\s*['"]?[^'"]*$/i.test(tagContentBefore);
    if (isEventHandler) {
      return 'JAVASCRIPT_CODE';
    }

    return 'HTML_ATTRIBUTE';
  }

  // 4. Check if inside a plain URL string
  if (/^https?:\/\//i.test(templateSnippet.trim()) || /^\/[a-zA-Z0-9_\-/?&=]+/i.test(templateSnippet.trim())) {
    return 'URL';
  }

  // 5. Default to HTML Text node
  return 'HTML_TEXT';
}

/**
 * Checks if a given context is security-sensitive where unencoded input can trigger execution.
 */
export function isSecuritySensitiveContext(context: ClientSideContextType): boolean {
  switch (context) {
    case 'HTML_TEXT':
    case 'HTML_ATTRIBUTE':
    case 'HTML_ATTRIBUTE_URL':
    case 'JAVASCRIPT_STRING':
    case 'JAVASCRIPT_CODE':
      return true;
    case 'URL':
    case 'CSS':
    case 'UNKNOWN':
    default:
      return false;
  }
}
