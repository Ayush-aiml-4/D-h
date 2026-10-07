import { ResourceModel } from '../../types/authorizationResearch.ts';
import { BadRequestError, ForbiddenError } from '../../utils/errors.ts';

export interface MutationVariant {
  parameterName: string;
  originalValue: string;
  mutatedValue: string;
  strategy: 'PEER_RESOURCE_ID' | 'SEQUENTIAL_ADJACENT' | 'NUMERIC_INCREMENT' | 'NUMERIC_DECREMENT' | 'EMPTY_VALUE' | 'TYPE_JUGGLING';
  pathTemplate: string;
  mutatedPath: string;
}

export interface MutationPlan {
  resource: ResourceModel;
  baseEndpoint: string;
  variants: MutationVariant[];
  maxBudget: number;
}

export class ParameterMutationEngine {
  private maxAllowedBudget: number;

  constructor(maxAllowedBudget: number = 10) {
    this.maxAllowedBudget = Math.min(Math.max(1, maxAllowedBudget), 20); // Bound between 1 and 20
  }

  /**
   * Generates a controlled, bounded mutation plan for a resource and comparison identifier.
   */
  public generateMutationPlan(params: {
    resource: ResourceModel;
    comparisonResourceId?: string;
    budget?: number;
  }): MutationPlan {
    const { resource, comparisonResourceId } = params;
    const budget = Math.min(params.budget || 5, this.maxAllowedBudget);
    const variants: MutationVariant[] = [];

    const pathTemplate = resource.endpointPath;
    const originalId = resource.resourceId;

    // 1. Primary peer mutation: mutate target ID to comparison peer ID (e.g. Account A order -> Account B order)
    if (comparisonResourceId && comparisonResourceId !== originalId) {
      const mutatedPath = this.substitutePathId(pathTemplate, originalId, comparisonResourceId);
      variants.push({
        parameterName: 'id',
        originalValue: originalId,
        mutatedValue: comparisonResourceId,
        strategy: 'PEER_RESOURCE_ID',
        pathTemplate,
        mutatedPath,
      });
    }

    // 2. Numeric adjacent mutations if resource ID is or contains digits
    const numericMatch = originalId.match(/\d+/);
    if (numericMatch && variants.length < budget) {
      const numStr = numericMatch[0];
      const num = parseInt(numStr, 10);

      // Increment
      const incVal = originalId.replace(numStr, String(num + 1));
      variants.push({
        parameterName: 'id',
        originalValue: originalId,
        mutatedValue: incVal,
        strategy: 'NUMERIC_INCREMENT',
        pathTemplate,
        mutatedPath: this.substitutePathId(pathTemplate, originalId, incVal),
      });

      // Decrement (if > 1)
      if (num > 1 && variants.length < budget) {
        const decVal = originalId.replace(numStr, String(num - 1));
        variants.push({
          parameterName: 'id',
          originalValue: originalId,
          mutatedValue: decVal,
          strategy: 'NUMERIC_DECREMENT',
          pathTemplate,
          mutatedPath: this.substitutePathId(pathTemplate, originalId, decVal),
        });
      }
    }

    // 3. Fallback sequential adjacent if budget remains
    if (variants.length === 0) {
      const fallbackVal = `${originalId}-alt`;
      variants.push({
        parameterName: 'id',
        originalValue: originalId,
        mutatedValue: fallbackVal,
        strategy: 'SEQUENTIAL_ADJACENT',
        pathTemplate,
        mutatedPath: this.substitutePathId(pathTemplate, originalId, fallbackVal),
      });
    }

    // Enforce strict bounded budget
    const boundedVariants = variants.slice(0, budget);

    return {
      resource,
      baseEndpoint: pathTemplate,
      variants: boundedVariants,
      maxBudget: budget,
    };
  }

  private substitutePathId(template: string, originalId: string, newId: string): string {
    if (template.includes('{id}')) {
      return template.replace('{id}', encodeURIComponent(newId));
    }
    if (template.includes('{orderId}')) {
      return template.replace('{orderId}', encodeURIComponent(newId));
    }
    if (template.includes('{userId}')) {
      return template.replace('{userId}', encodeURIComponent(newId));
    }
    if (template.includes(originalId)) {
      return template.replace(originalId, encodeURIComponent(newId));
    }
    // Append or replace trailing identifier
    return `${template.replace(/\/$/, '')}/${encodeURIComponent(newId)}`;
  }
}

export const parameterMutationEngine = new ParameterMutationEngine();
