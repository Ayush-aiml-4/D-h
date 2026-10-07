import { AuthUser } from '../../middleware/auth.ts';
import { Finding, Asset } from '../../types.ts';

export type ValidationSafetyLevel = 'NON_DESTRUCTIVE' | 'CONTROLLED' | 'PASSIVE';
export type ValidationPolicyRequirement = 'POLICY_CHECK_REQUIRED' | 'ADMIN_APPROVAL_REQUIRED';

export type ValidationResultStatus =
  | 'VALIDATED'
  | 'UNVALIDATED'
  | 'INCONCLUSIVE'
  | 'FAILED'
  | 'BLOCKED'
  | 'REVIEW_REQUIRED';

export interface ValidationEvidence {
  evidenceId: string;
  validationId: string;
  findingId: string;
  assetId: string;
  capabilityId: string;
  observedAt: string;
  result: ValidationResultStatus;
  confidence: number; // 0..100
  sanitizedObservation: Record<string, any>;
  evidenceHash: string;
  requestId: string;
}

export interface ValidationRequest {
  findingId: string;
  validationId?: string;
  observationOverride?: Record<string, any>;
}

export interface ValidationContext {
  finding: Finding;
  asset: Asset;
  programId: string;
  user: AuthUser;
  requestId: string;
  observationData?: Record<string, any>;
}

export interface ValidationResult {
  validationId: string;
  validationType: string;
  findingId: string;
  assetId: string;
  capabilityId: string;
  safetyLevel: ValidationSafetyLevel;
  executed: boolean;
  result: ValidationResultStatus;
  confidence: number;
  policyDecision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
  reason?: string;
  summary: string;
  evidence: ValidationEvidence;
  correlationKey: string;
  validatedAt: string;
  requestId: string;
}

export interface ControlledValidator {
  validationId: string;
  supportedCapability: string;
  aliases: string[];
  validationType: string;
  safetyLevel: ValidationSafetyLevel;
  requiredPolicy: ValidationPolicyRequirement;
  evidenceType: string;
  description: string;
  
  validate(context: ValidationContext): Promise<{
    result: ValidationResultStatus;
    confidence: number;
    summary: string;
    sanitizedObservation: Record<string, any>;
  }>;
}
