import {
  ParsedUrl,
  ResolutionResult,
  RedirectHop,
  DestinationPolicyDecision,
  InteractionObservation,
  ServerSideRequest,
} from '../../types/serverInteractionResearch.ts';
import { parseCanonicalUrl } from './urlParserService.ts';
import { dnsResolver } from './dnsResolutionModel.ts';
import { evaluateDestinationPolicy } from './ssrfPolicyEngine.ts';
import { evaluateRedirectChain } from './redirectAnalysisEngine.ts';
import { interactionRecorder } from './blindInteractionRecorder.ts';

export interface FetchResult {
  success: boolean;
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  destinationClass: string;
  redirectHops: RedirectHop[];
  error?: string;
}

/**
 * Deliberately vulnerable URL fetcher fixture.
 * Simulates a server component that accepts arbitrary URLs, performs no destination validation,
 * resolves DNS blindly, and follows redirects into private networks.
 */
export function executeVulnerableUrlFetch(
  request: ServerSideRequest,
  dnsStep: number = 0
): FetchResult {
  const parsed = parseCanonicalUrl(request.url);
  const resolution = dnsResolver.resolve(parsed.canonicalHostname, dnsStep);

  // Check for simulated redirect endpoints
  if (parsed.canonicalHostname === 'fixture-redirect.test') {
    if (parsed.pathname === '/to-safe') {
      const redirectHopUrl = 'https://safe-external.test/data';
      interactionRecorder.recordInteraction({
        correlationToken: request.correlationToken || '',
        fixtureId: 'safe-external-fixture',
        destinationClass: 'PUBLIC_EXTERNAL',
        requestedUrl: redirectHopUrl,
        method: request.method || 'GET',
        headers: request.headers || {},
        bodySnippet: '{"status":"ok","source":"safe-fixture"}',
      });
      return {
        success: true,
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: '{"status":"ok","source":"safe-fixture"}',
        destinationClass: 'PUBLIC_EXTERNAL',
        redirectHops: [
          {
            hopIndex: 1,
            sourceUrl: request.url,
            targetUrl: redirectHopUrl,
            targetParsedUrl: parseCanonicalUrl(redirectHopUrl),
            resolution: dnsResolver.resolve('safe-external.test'),
            destinationClass: 'PUBLIC_EXTERNAL',
            policyDecision: 'ALLOW',
            statusCode: 302,
          },
        ],
      };
    } else if (parsed.pathname === '/to-private') {
      const redirectHopUrl = 'http://10.0.0.1/internal/admin';
      interactionRecorder.recordInteraction({
        correlationToken: request.correlationToken || '',
        fixtureId: 'private-network-fixture',
        destinationClass: 'PRIVATE_RFC1918',
        requestedUrl: redirectHopUrl,
        method: request.method || 'GET',
        headers: request.headers || {},
        bodySnippet: '{"internal_admin_panel":"active","role":"admin"}',
      });
      return {
        success: true,
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: '{"internal_admin_panel":"active","role":"admin"}',
        destinationClass: 'PRIVATE_RFC1918',
        redirectHops: [
          {
            hopIndex: 1,
            sourceUrl: request.url,
            targetUrl: redirectHopUrl,
            targetParsedUrl: parseCanonicalUrl(redirectHopUrl),
            resolution: dnsResolver.resolve('10.0.0.1'),
            destinationClass: 'PRIVATE_RFC1918',
            policyDecision: 'DENY',
            statusCode: 302,
          },
        ],
      };
    }
  }

  // Record interaction in blind callback recorder
  let responseBody = '{"message":"content fetched successfully"}';
  if (resolution.destinationClass === 'METADATA') {
    responseBody = '{"ami-id":"ami-0123456789","AWS_SECRET_ACCESS_KEY":"MOCK_SECRET_REDACTED"}';
  } else if (resolution.destinationClass === 'LOOPBACK') {
    responseBody = '{"service":"local-redis","status":"connected"}';
  } else if (resolution.destinationClass === 'PRIVATE_RFC1918') {
    responseBody = '{"service":"internal-database","status":"authenticated"}';
  }

  interactionRecorder.recordInteraction({
    correlationToken: request.correlationToken || '',
    fixtureId: `fixture-${resolution.destinationClass.toLowerCase()}`,
    destinationClass: resolution.destinationClass,
    requestedUrl: request.url,
    method: request.method || 'GET',
    headers: request.headers || {},
    bodySnippet: responseBody,
  });

  return {
    success: true,
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    body: responseBody,
    destinationClass: resolution.destinationClass,
    redirectHops: [],
  };
}

/**
 * Secure URL fetcher fixture.
 * Enforces strict canonical parsing, pre-fetch destination policy, post-DNS destination policy,
 * and redirect validation across every single hop.
 */
export function executeSecureUrlFetch(
  request: ServerSideRequest,
  dnsStep: number = 0
): FetchResult {
  // 1. Safe parsing & scheme enforcement
  const parsed = parseCanonicalUrl(request.url);
  if (!parsed.isValid || !parsed.isValidScheme) {
    return {
      success: false,
      statusCode: 400,
      headers: {},
      body: `Blocked: ${parsed.validationError || 'Invalid URL'}`,
      destinationClass: 'INVALID',
      redirectHops: [],
      error: parsed.validationError,
    };
  }

  // 2. DNS resolution and destination policy enforcement
  const resolution = dnsResolver.resolve(parsed.canonicalHostname, dnsStep);
  const initialPolicy = evaluateDestinationPolicy(parsed, resolution);

  if (initialPolicy.decision !== 'ALLOW') {
    return {
      success: false,
      statusCode: 403,
      headers: {},
      body: `Blocked by egress policy: ${initialPolicy.reason}`,
      destinationClass: resolution.destinationClass,
      redirectHops: [],
      error: initialPolicy.reason,
    };
  }

  // 3. Handle redirect destinations securely
  if (parsed.canonicalHostname === 'fixture-redirect.test') {
    const redirectLocations =
      parsed.pathname === '/to-private'
        ? ['http://10.0.0.1/internal/admin']
        : ['https://safe-external.test/data'];

    const redirectEval = evaluateRedirectChain(request.url, redirectLocations, dnsStep);

    if (!redirectEval.isSafeChain) {
      return {
        success: false,
        statusCode: 403,
        headers: {},
        body: `Blocked redirect: ${redirectEval.terminalDecision.reason}`,
        destinationClass: redirectEval.terminalDecision.destinationClass,
        redirectHops: redirectEval.hops,
        error: redirectEval.terminalDecision.reason,
      };
    }
  }

  // Permitted public request
  return {
    success: true,
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    body: '{"status":"ok","content":"public response"}',
    destinationClass: 'PUBLIC_EXTERNAL',
    redirectHops: [],
  };
}
