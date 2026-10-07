import {
  WorkflowResource,
  WorkflowAction,
} from '../../types/workflowResearch.ts';

export interface BusinessRuleResult {
  valid: boolean;
  ruleName: string;
  expectedValue: any;
  actualValue: any;
  reason?: string;
}

export function validateOrderLineItemsIntegrity(
  resource: WorkflowResource,
  action?: WorkflowAction
): BusinessRuleResult {
  const lineItems = resource.attributes?.lineItems || action?.parameters?.lineItems;
  const totalAmount = resource.attributes?.totalAmount ?? action?.parameters?.totalAmount;

  if (!lineItems || !Array.isArray(lineItems) || totalAmount === undefined) {
    return {
      valid: true,
      ruleName: 'ORDER_TOTAL_INTEGRITY',
      expectedValue: totalAmount,
      actualValue: totalAmount,
    };
  }

  const computedSum = lineItems.reduce((acc: number, item: any) => {
    const price = Number(item.price) || 0;
    const quantity = Number(item.quantity) || 1;
    return acc + price * quantity;
  }, 0);

  const roundedComputed = Math.round(computedSum * 100) / 100;
  const roundedTotal = Math.round(Number(totalAmount) * 100) / 100;

  if (Math.abs(roundedComputed - roundedTotal) > 0.01) {
    return {
      valid: false,
      ruleName: 'ORDER_TOTAL_INTEGRITY',
      expectedValue: roundedComputed,
      actualValue: roundedTotal,
      reason: `Line items sum ($${roundedComputed}) does not equal specified total ($${roundedTotal})`,
    };
  }

  return {
    valid: true,
    ruleName: 'ORDER_TOTAL_INTEGRITY',
    expectedValue: roundedComputed,
    actualValue: roundedTotal,
  };
}

export function validateNumericBoundary(
  field: string,
  value: number,
  min: number,
  max: number,
  allowZero: boolean = true
): BusinessRuleResult {
  if (isNaN(value)) {
    return {
      valid: false,
      ruleName: `NUMERIC_BOUNDARY_${field.toUpperCase()}`,
      expectedValue: `Valid number between ${min} and ${max}`,
      actualValue: value,
      reason: `Field '${field}' is not a valid number`,
    };
  }

  if (value < 0 && !allowZero && min >= 0) {
    return {
      valid: false,
      ruleName: `NUMERIC_BOUNDARY_${field.toUpperCase()}`,
      expectedValue: `>= ${min}`,
      actualValue: value,
      reason: `Field '${field}' cannot be negative (${value})`,
    };
  }

  if (value === 0 && !allowZero) {
    return {
      valid: false,
      ruleName: `NUMERIC_BOUNDARY_${field.toUpperCase()}`,
      expectedValue: `> 0`,
      actualValue: value,
      reason: `Field '${field}' cannot be zero`,
    };
  }

  if (value < min || value > max) {
    return {
      valid: false,
      ruleName: `NUMERIC_BOUNDARY_${field.toUpperCase()}`,
      expectedValue: `${min} <= value <= ${max}`,
      actualValue: value,
      reason: `Value ${value} is outside bounds [${min}, ${max}]`,
    };
  }

  return {
    valid: true,
    ruleName: `NUMERIC_BOUNDARY_${field.toUpperCase()}`,
    expectedValue: `${min} <= value <= ${max}`,
    actualValue: value,
  };
}
