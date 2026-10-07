import crypto from 'crypto';
import {
  ActiveExecutionContext,
  ControlledMutationRequestOptions,
  ControlledRequestBuilderInterface,
} from './activeTestingTypes.ts';
import { ControlledHttpResponse } from '../types.ts';
import { SafeControlledHttpClient } from '../httpClient.ts';
import { BudgetEngine } from './budgetEngine.ts';
import { redactSecrets, logger } from '../../../utils/logger.ts';
import { recordAuditEvent } from '../../auditService.ts';
import { BadRequestError, ForbiddenError } from '../../../utils/errors.ts';

const PERMITTED_ACTIVE_METHODS = new Set([
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'DELETE',
  'OPTIONS',
  'TRACE',
  'PATCH',
]);

export class ControlledRequestBuilder implements ControlledRequestBuilderInterface {
  private context: ActiveExecutionContext;
  private httpClient: SafeControlledHttpClient;
  private budgetEngine: BudgetEngine;

  constructor(
    context: ActiveExecutionContext,
    httpClient: SafeControlledHttpClient,
    budgetEngine: BudgetEngine
  ) {
    this.context = context;
    this.httpClient = httpClient;
    this.budgetEngine = budgetEngine;
  }

  public getTarget(): string {
    return this.httpClient.getTarget();
  }

  public getHostname(): string {
    return this.httpClient.getHostname();
  }

  public getExecutedCount(): number {
    return this.budgetEngine.getExecutedCount();
  }

  /**
   * Execute a strictly controlled, bounded mutation request.
   */
  public async send(
    options: ControlledMutationRequestOptions = {}
  ): Promise<ControlledHttpResponse> {
    // 1. Check if execution is cancelled
    if (this.context.cancellationState.isCancelled) {
      throw new ForbiddenError(
        `EXECUTION_CANCELLED: Active execution was cancelled (${this.context.cancellationState.reason || 'by researcher'})`
      );
    }

    // 2. Validate HTTP method
    const method = (options.method || 'GET').toUpperCase() as any;
    if (!PERMITTED_ACTIVE_METHODS.has(method)) {
      throw new BadRequestError(
        `UNSUPPORTED_METHOD: HTTP method '${method}' is not in the permitted active testing set`
      );
    }

    // 3. Acquire request slot from Budget Engine (enforces total budget, concurrency, timeout, RPS)
    const releaseSlot = await this.budgetEngine.acquireRequestSlot(
      () => this.context.cancellationState.isCancelled
    );

    const mutationId = `mut-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const mutationTag = options.mutationTag || 'standard_probe';

    // 4. Construct controlled headers with security provenance & secret redaction
    const outgoingHeaders: Record<string, string> = {
      'User-Agent': 'DevilHunt-Security-ActiveTesting/1.0 (+https://devilhunt.internal/active-governance)',
      'X-Research-Case-Id': this.context.caseId,
      'X-Research-Execution-Id': this.context.executionId,
      'X-Research-Capability-Id': this.context.capabilityId,
      'X-Research-Mutation-Id': mutationId,
      'X-Request-Id': this.context.requestId,
      ...(options.headers || {}),
    };

    // Redact outgoing sensitive headers
    const sanitizedOutgoingHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(outgoingHeaders)) {
      if (/auth|cookie|token|key|secret|password/i.test(k)) {
        sanitizedOutgoingHeaders[k] = '[REDACTED]';
      } else {
        sanitizedOutgoingHeaders[k] = v;
      }
    }

    // Record ACTIVE_EXECUTION_REQUEST audit event
    await recordAuditEvent({
      userId: this.context.researcherId,
      entityType: 'ACTIVE_EXECUTION',
      entityId: this.context.executionId,
      action: 'ACTIVE_EXECUTION_REQUEST',
      requestId: this.context.requestId,
      metadata: {
        mutationId,
        mutationTag,
        method,
        target: this.httpClient.getTarget(),
        path: options.path || '/',
        requestNumber: this.budgetEngine.getExecutedCount(),
      },
    }).catch((err) => {
      logger.warn('ACTIVE_AUDIT_LOG_ERROR', { error: err.message });
    });

    try {
      // 5. Send request through SafeControlledHttpClient
      const rawResponse = await this.httpClient.request({
        method,
        path: options.path,
        headers: outgoingHeaders,
        body: options.body,
        timeoutMs: Math.min(options.timeoutMs || this.context.timeout, 10000),
      });

      // 6. Redact secrets in response headers
      const sanitizedResponseHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(rawResponse.headers)) {
        if (/auth|cookie|token|key|secret|set-cookie/i.test(k)) {
          sanitizedResponseHeaders[k] = '[REDACTED]';
        } else {
          sanitizedResponseHeaders[k] = v;
        }
      }

      // 7. Redact secrets in body if sensitive
      const sanitizedBody = redactSecrets(rawResponse.body);

      return {
        ...rawResponse,
        headers: sanitizedResponseHeaders,
        body: typeof sanitizedBody === 'string' ? sanitizedBody : JSON.stringify(sanitizedBody),
      };
    } finally {
      releaseSlot();
    }
  }
}
