import { RequestBudget } from './activeTestingTypes.ts';
import { ForbiddenError } from '../../../utils/errors.ts';

export class BudgetEngine {
  private budget: RequestBudget;
  private currentConcurrency: number = 0;
  private requestTimestamps: number[] = [];

  constructor(budget: RequestBudget) {
    this.budget = { ...budget };
  }

  public getBudget(): Readonly<RequestBudget> {
    return { ...this.budget };
  }

  public getExecutedCount(): number {
    return this.budget.totalRequestsExecuted;
  }

  /**
   * Acquire a request slot. Throws ForbiddenError if total budget, duration, or rate limit is violated.
   */
  public async acquireRequestSlot(isCancelled: () => boolean): Promise<() => void> {
    if (isCancelled()) {
      throw new ForbiddenError('EXECUTION_CANCELLED: Active execution has been cancelled');
    }

    const now = Date.now();

    // 1. Duration check
    if (now - this.budget.startedAt > this.budget.maxExecutionDurationMs) {
      throw new ForbiddenError(
        `EXECUTION_TIMEOUT_EXCEEDED: Active execution exceeded maximum duration of ${this.budget.maxExecutionDurationMs}ms`
      );
    }

    // 2. Total request budget check
    if (this.budget.totalRequestsExecuted >= this.budget.maxTotalRequests) {
      throw new ForbiddenError(
        `REQUEST_BUDGET_EXCEEDED: Execution exhausted its total request budget limit (${this.budget.maxTotalRequests} requests)`
      );
    }

    // 3. Concurrency check
    if (this.currentConcurrency >= this.budget.maxConcurrency) {
      // Wait for a slot to free up or timeout
      await this.waitForConcurrencySlot(isCancelled);
    }

    // 4. Rate limiting check (requests per second sliding window)
    this.cleanOldTimestamps(now);
    if (this.requestTimestamps.length >= this.budget.maxRequestsPerSecond) {
      const oldest = this.requestTimestamps[0];
      const waitMs = Math.max(10, 1000 - (now - oldest));
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }

    if (isCancelled()) {
      throw new ForbiddenError('EXECUTION_CANCELLED: Active execution has been cancelled');
    }

    // Mark acquired
    this.currentConcurrency++;
    this.budget.totalRequestsExecuted++;
    this.requestTimestamps.push(Date.now());

    // Return release function
    let released = false;
    return () => {
      if (!released) {
        released = true;
        this.currentConcurrency = Math.max(0, this.currentConcurrency - 1);
      }
    };
  }

  private cleanOldTimestamps(now: number): void {
    const cutoff = now - 1000;
    while (this.requestTimestamps.length > 0 && this.requestTimestamps[0] < cutoff) {
      this.requestTimestamps.shift();
    }
  }

  private async waitForConcurrencySlot(isCancelled: () => boolean): Promise<void> {
    const startTime = Date.now();
    while (this.currentConcurrency >= this.budget.maxConcurrency) {
      if (isCancelled()) {
        throw new ForbiddenError('EXECUTION_CANCELLED: Active execution has been cancelled');
      }
      if (Date.now() - startTime > 5000) {
        throw new ForbiddenError('CONCURRENCY_LIMIT_TIMEOUT: Timeout waiting for concurrency slot');
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }
}
