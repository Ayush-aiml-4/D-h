import {
  RedirectHop,
  ParsedUrl,
  DestinationPolicyDecision,
} from '../../types/serverInteractionResearch.ts';
import { parseCanonicalUrl } from './urlParserService.ts';
import { dnsResolver } from './dnsResolutionModel.ts';
import { evaluateDestinationPolicy } from './ssrfPolicyEngine.ts';

export interface RedirectEvaluationResult {
  isSafeChain: boolean;
  totalHops: number;
  hops: RedirectHop[];
  terminalDecision: DestinationPolicyDecision;
  hasLoop: boolean;
  blockedAtHop?: number;
}

const MAX_REDIRECT_HOPS = 5;

/**
 * Resolves a redirect location header against a current URL base.
 */
export function resolveRedirectUrl(baseUrl: string, locationHeader: string): string {
  try {
    const base = new URL(baseUrl);
    const resolved = new URL(locationHeader, base);
    return resolved.toString();
  } catch {
    return locationHeader;
  }
}

/**
 * Evaluates a chain of redirect locations against SSRF destination policies.
 */
export function evaluateRedirectChain(
  initialUrl: string,
  redirectLocations: string[],
  dnsStepOffset: number = 0
): RedirectEvaluationResult {
  const hops: RedirectHop[] = [];
  const visitedUrls = new Set<string>();
  visitedUrls.add(initialUrl);

  let currentSource = initialUrl;
  let hasLoop = false;
  let terminalDecision: DestinationPolicyDecision = {
    decision: 'ALLOW',
    reason: 'Initial destination permitted',
    destinationClass: 'PUBLIC_EXTERNAL',
    isRestricted: false,
  };

  for (let i = 0; i < redirectLocations.length; i++) {
    if (i >= MAX_REDIRECT_HOPS) {
      terminalDecision = {
        decision: 'BLOCK',
        reason: `Exceeded maximum redirect hop limit (${MAX_REDIRECT_HOPS})`,
        destinationClass: 'INVALID',
        isRestricted: true,
        violatedRule: 'MAX_REDIRECTS_EXCEEDED',
      };
      return {
        isSafeChain: false,
        totalHops: hops.length,
        hops,
        terminalDecision,
        hasLoop: true,
        blockedAtHop: i,
      };
    }

    const targetUrl = resolveRedirectUrl(currentSource, redirectLocations[i]);

    if (visitedUrls.has(targetUrl)) {
      hasLoop = true;
      terminalDecision = {
        decision: 'BLOCK',
        reason: `Detected circular redirect loop on ${targetUrl}`,
        destinationClass: 'INVALID',
        isRestricted: true,
        violatedRule: 'CIRCULAR_REDIRECT_DETECTED',
      };
      return {
        isSafeChain: false,
        totalHops: hops.length,
        hops,
        terminalDecision,
        hasLoop: true,
        blockedAtHop: i,
      };
    }
    visitedUrls.add(targetUrl);

    const targetParsed: ParsedUrl = parseCanonicalUrl(targetUrl);
    const resolution = dnsResolver.resolve(targetParsed.canonicalHostname, dnsStepOffset + i);
    const policyDecision = evaluateDestinationPolicy(targetParsed, resolution);

    const hop: RedirectHop = {
      hopIndex: i + 1,
      sourceUrl: currentSource,
      targetUrl,
      targetParsedUrl: targetParsed,
      resolution,
      destinationClass: resolution.destinationClass,
      policyDecision: policyDecision.decision === 'BLOCK' ? 'DENY' : (policyDecision.decision as any),
      statusCode: 302,
    };

    hops.push(hop);

    if (policyDecision.decision !== 'ALLOW') {
      terminalDecision = policyDecision;
      return {
        isSafeChain: false,
        totalHops: hops.length,
        hops,
        terminalDecision,
        hasLoop: false,
        blockedAtHop: i + 1,
      };
    }

    currentSource = targetUrl;
    terminalDecision = policyDecision;
  }

  return {
    isSafeChain: true,
    totalHops: hops.length,
    hops,
    terminalDecision,
    hasLoop: false,
  };
}
