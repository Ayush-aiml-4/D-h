import {
  ControlledParameter,
  InputParameterType,
  SecurityContextType,
  SafePayload,
} from '../../types/authenticationResearch.ts';
import {
  getSafePayloadsForContext,
  validatePayloadSafety,
} from './payloadSafetyEngine.ts';

export interface RegisterParameterParams {
  parameterName: string;
  parameterType: InputParameterType;
  baseValue: any;
  securityContext: SecurityContextType;
  customPayloads?: SafePayload[];
  isSensitive?: boolean;
}

export class InputValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InputValidationError';
  }
}

/**
 * Registers and validates a controlled input parameter with safety-compliant payloads.
 */
export function registerControlledParameter(params: RegisterParameterParams): ControlledParameter {
  if (!params.parameterName || params.parameterName.trim() === '') {
    throw new InputValidationError('Parameter name cannot be empty.');
  }

  // Retrieve default safe payloads for the specified context
  let payloads = params.customPayloads || getSafePayloadsForContext(params.securityContext);

  // Validate every payload
  for (const p of payloads) {
    const safetyCheck = validatePayloadSafety(p.payloadString);
    if (!safetyCheck.isSafe) {
      throw new InputValidationError(`Unsafe payload rejected: ${safetyCheck.reason}`);
    }
  }

  return {
    parameterName: params.parameterName,
    parameterType: params.parameterType,
    baseValue: params.baseValue !== undefined ? params.baseValue : '',
    securityContext: params.securityContext,
    testPayloads: payloads,
    isSensitive: params.isSensitive || false,
  };
}

/**
 * Bounds request budget strictly to platform maximum upper bound.
 */
export function enforceRequestBudget(requestedBudget?: number, maxCeiling: number = 30): number {
  if (!requestedBudget || requestedBudget <= 0) {
    return 10; // Default budget
  }
  return Math.min(requestedBudget, maxCeiling);
}
