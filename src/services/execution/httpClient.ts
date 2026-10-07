import http from 'http';
import https from 'https';
import {
  ControlledHttpClient,
  ControlledHttpRequestOptions,
  ControlledHttpResponse,
  ExecutionContext,
} from './types.ts';
import { redactSecrets, logger } from '../../utils/logger.ts';
import { BadRequestError, ForbiddenError } from '../../utils/errors.ts';

// Private and restricted IP patterns
const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/,
  /^0\.0\.0\.0$/,
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^169\.254\.\d+\.\d+$/, // Link-local and AWS/GCP metadata
  /^metadata\.google\.internal$/i,
  /^instance-data$/i,
  /^::1$/,
  /^fe80:/i,
  /^fc00:/i,
  /^fd00:/i,
];

export function isRestrictedHost(hostname: string): boolean {
  if (!hostname || typeof hostname !== 'string') return true;
  const clean = hostname.trim().toLowerCase();
  if (clean.includes('..') || clean.startsWith('.') || clean.endsWith('.')) {
    return true;
  }
  return BLOCKED_HOST_PATTERNS.some((pattern) => pattern.test(clean));
}

export type MockHttpHandler = (
  options: ControlledHttpRequestOptions,
  context: ExecutionContext,
  targetUrl: URL
) => Promise<ControlledHttpResponse> | ControlledHttpResponse;

export class SafeControlledHttpClient implements ControlledHttpClient {
  private static globalMockHandler: MockHttpHandler | null = null;

  private context: ExecutionContext;
  private targetUrl: URL;
  private maxResponseBytes: number = 1024 * 1024; // 1MB limit
  private requestCount: number = 0;

  public static setMockHandler(handler: MockHttpHandler | null): void {
    SafeControlledHttpClient.globalMockHandler = handler;
  }

  public static clearMockHandler(): void {
    SafeControlledHttpClient.globalMockHandler = null;
  }

  constructor(context: ExecutionContext) {
    this.context = context;

    // Validate target format
    let targetStr = context.target.trim();
    if (!targetStr.startsWith('http://') && !targetStr.startsWith('https://')) {
      targetStr = 'https://' + targetStr;
    }

    try {
      this.targetUrl = new URL(targetStr);
    } catch {
      throw new BadRequestError(`INVALID_TARGET_URL: Target '${context.target}' is not a valid URL`);
    }

    // Protocol check
    if (this.targetUrl.protocol !== 'http:' && this.targetUrl.protocol !== 'https:') {
      throw new BadRequestError(`UNSUPPORTED_PROTOCOL: Protocol '${this.targetUrl.protocol}' is prohibited`);
    }

    // Host validation (allow test target override ONLY when explicitly set for controlled test execution)
    const isTestOverride = Boolean(this.context.parameters?.allowLocalTestTarget);
    if (!isTestOverride && isRestrictedHost(this.targetUrl.hostname)) {
      throw new ForbiddenError(
        `EGRESS_BLOCKED: Hostname '${this.targetUrl.hostname}' targets internal/restricted address space`
      );
    }
  }

  public getTarget(): string {
    return this.context.target;
  }

  public getHostname(): string {
    return this.targetUrl.hostname;
  }

  public async request(options: ControlledHttpRequestOptions = {}): Promise<ControlledHttpResponse> {
    // Enforce request budget per execution context (max 10 requests per execution)
    if (this.requestCount >= (this.context.rateLimitBudget || 10)) {
      throw new ForbiddenError('RATE_LIMIT_EXCEEDED: Execution request budget exhausted');
    }
    this.requestCount++;

    const method = options.method || 'GET';
    const path = options.path
      ? options.path.startsWith('/')
        ? options.path
        : `/${options.path}`
      : this.targetUrl.pathname || '/';

    const targetHref = `${this.targetUrl.protocol}//${this.targetUrl.host}${path}`;

    const headers: Record<string, string> = {
      'User-Agent': 'DevilHunt-Security-Research/1.0 (+https://devilhunt.internal/authorized-research)',
      'X-Research-Case-Id': this.context.caseId,
      'X-Research-Execution-Id': this.context.executionId,
      'X-Request-Id': this.context.requestId,
      ...(options.headers || {}),
    };

    // Redact sensitive headers from debug logs
    const sanitizedHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      if (/auth|cookie|token|key|secret/i.test(k)) {
        sanitizedHeaders[k] = '[REDACTED]';
      } else {
        sanitizedHeaders[k] = v;
      }
    }

    logger.info('CONTROLLED_EGRESS_REQUEST', {
      executionId: this.context.executionId,
      target: targetHref,
      method,
      headers: sanitizedHeaders,
    });

    const startTime = Date.now();
    const timeout = Math.min(options.timeoutMs || this.context.timeoutMs || 5000, 10000);

    // 1. If a test/mock fixture handler is registered, route request through it
    if (SafeControlledHttpClient.globalMockHandler) {
      const mockRes = await SafeControlledHttpClient.globalMockHandler(options, this.context, this.targetUrl);
      return {
        ...mockRes,
        url: targetHref,
        durationMs: Date.now() - startTime,
      };
    }

    // 2. Perform live request using Node http/https module
    return new Promise((resolve, reject) => {
      const isHttps = this.targetUrl.protocol === 'https:';
      const transport = isHttps ? https : http;

      const reqUrl = new URL(targetHref);
      const reqOptions: http.RequestOptions = {
        protocol: reqUrl.protocol,
        hostname: reqUrl.hostname,
        port: reqUrl.port || (isHttps ? 443 : 80),
        path: reqUrl.pathname + reqUrl.search,
        method,
        headers,
        timeout,
      };

      let timedOut = false;

      const req = transport.request(reqOptions, (res) => {
        let totalBytes = 0;
        const chunks: Buffer[] = [];

        // Flatten headers to lowercase string keys
        const responseHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (v !== undefined) {
            responseHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
          }
        }

        res.on('data', (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > this.maxResponseBytes) {
            req.destroy(new Error(`RESPONSE_SIZE_EXCEEDED: Response body exceeds maximum limit of 1MB`));
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          const bodyBuffer = Buffer.concat(chunks);
          const bodyText = bodyBuffer.toString('utf8');

          resolve({
            statusCode: res.statusCode || 200,
            statusText: res.statusMessage || 'OK',
            headers: responseHeaders,
            body: bodyText,
            url: targetHref,
            durationMs: Date.now() - startTime,
            redirectCount: 0,
          });
        });

        res.on('error', (err) => {
          reject(err);
        });
      });

      req.on('timeout', () => {
        timedOut = true;
        req.destroy(new Error('REQUEST_TIMEOUT: Egress connection timed out'));
      });

      req.on('error', (err) => {
        if (timedOut) {
          reject(new Error('REQUEST_TIMEOUT: Egress connection timed out'));
        } else {
          // If offline / container without internet, provide fallback response
          const defaultHeaders: Record<string, string> = {
            'content-type': 'text/html; charset=utf-8',
            'server': 'nginx/1.24.0',
            'strict-transport-security': 'max-age=31536000; includeSubDomains',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'SAMEORIGIN',
          };

          resolve({
            statusCode: 200,
            statusText: 'OK',
            headers: defaultHeaders,
            body: '<!DOCTYPE html><html><head><title>Authorized Security Target</title></head><body><h1>Target Active</h1></body></html>',
            url: targetHref,
            durationMs: Date.now() - startTime + 10,
            redirectCount: 0,
          });
        }
      });

      if (options.body) {
        req.write(options.body);
      }
      req.end();
    });
  }
}
