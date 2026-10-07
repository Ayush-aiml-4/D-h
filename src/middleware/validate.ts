import { Request, Response, NextFunction } from 'express';
import { z, ZodTypeAny, ZodError } from 'zod';

export const paramIdSchema = z.object({
  id: z
    .string()
    .trim()
    .min(1, 'ID cannot be empty')
    .max(128, 'ID length exceeds maximum limit of 128 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'ID contains invalid characters'),
});

export const createHuntBodySchema = z
  .object({
    programId: z
      .string()
      .trim()
      .min(1, 'programId is required')
      .max(128, 'programId length exceeds maximum limit')
      .regex(/^[a-zA-Z0-9_-]+$/, 'programId contains invalid characters'),
    assetId: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .regex(/^[a-zA-Z0-9_-]+$/, 'assetId contains invalid characters')
      .optional(),
    targetDomain: z
      .string()
      .trim()
      .min(1)
      .max(255)
      .regex(/^[a-zA-Z0-9.-]+$/, 'targetDomain contains invalid characters')
      .optional(),
  })
  .strict();

export const createReportBodySchema = z
  .object({
    title: z
      .string()
      .trim()
      .min(1, 'Title cannot be empty')
      .max(256, 'Title length exceeds maximum limit')
      .optional(),
    summary: z
      .string()
      .trim()
      .min(1, 'Summary cannot be empty')
      .max(2000, 'Summary length exceeds maximum limit')
      .optional(),
  })
  .strict();

export const startDiscoveryBodySchema = z
  .object({
    programId: z
      .string()
      .trim()
      .min(1, 'programId is required')
      .max(128, 'programId length exceeds maximum limit')
      .regex(/^[a-zA-Z0-9_-]+$/, 'programId contains invalid characters'),
    target: z
      .string()
      .trim()
      .min(1, 'target is required')
      .max(255, 'target length exceeds maximum limit'),
    operation: z
      .string()
      .trim()
      .max(128)
      .optional(),
  })
  .strict();

export const assetsQuerySchema = z
  .object({
    programId: z
      .string()
      .trim()
      .max(128)
      .regex(/^[a-zA-Z0-9_-]+$/, 'programId contains invalid characters')
      .optional(),
    discoverySessionId: z
      .string()
      .trim()
      .max(128)
      .regex(/^[a-zA-Z0-9_-]+$/, 'discoverySessionId contains invalid characters')
      .optional(),
    type: z
      .string()
      .trim()
      .max(64)
      .optional(),
    status: z
      .string()
      .trim()
      .max(64)
      .optional(),
    scopeId: z
      .string()
      .trim()
      .max(128)
      .regex(/^[a-zA-Z0-9_-]+$/, 'scopeId contains invalid characters')
      .optional(),
  })
  .strict();

export const attackSurfaceQuerySchema = z
  .object({
    programId: z
      .string()
      .trim()
      .max(128)
      .regex(/^[a-zA-Z0-9_-]+$/, 'programId contains invalid characters')
      .optional(),
  })
  .strict();

export const evaluateCapabilityBodySchema = z
  .object({
    programId: z
      .string()
      .trim()
      .min(1, 'programId is required')
      .max(128, 'programId length exceeds maximum limit')
      .regex(/^[a-zA-Z0-9_-]+$/, 'programId contains invalid characters'),
    target: z
      .string()
      .trim()
      .min(1, 'target is required')
      .max(255, 'target length exceeds maximum limit'),
    capability: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .optional(),
  })
  .strict();

export const capabilitiesQuerySchema = z
  .object({
    category: z.string().trim().max(128).optional(),
    status: z.string().trim().max(64).optional(),
  })
  .strict();

export const evaluateCapabilityFrameworkSchema = z
  .object({
    programId: z
      .string()
      .trim()
      .min(1, 'programId is required')
      .max(128, 'programId length exceeds maximum limit')
      .regex(/^[a-zA-Z0-9_-]+$/, 'programId contains invalid characters'),
    target: z
      .string()
      .trim()
      .min(1, 'target is required')
      .max(255, 'target length exceeds maximum limit'),
    capabilityId: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .optional(),
    capability: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .optional(),
    assetId: z
      .string()
      .trim()
      .max(128)
      .regex(/^[a-zA-Z0-9_-]+$/, 'assetId contains invalid characters')
      .optional(),
  })
  .strict();

export const researchAnalyzeBodySchema = z
  .object({
    programId: z
      .string()
      .trim()
      .min(1, 'programId is required')
      .max(128, 'programId length exceeds maximum limit')
      .regex(/^[a-zA-Z0-9_-]+$/, 'programId contains invalid characters'),
    target: z
      .string()
      .trim()
      .min(1, 'target is required')
      .max(255, 'target length exceeds maximum limit'),
    capabilityId: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .optional(),
    capability: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .optional(),
    assetId: z
      .string()
      .trim()
      .max(128)
      .regex(/^[a-zA-Z0-9_-]+$/, 'assetId contains invalid characters')
      .optional(),
    observationData: z
      .record(z.string(), z.any())
      .optional(),
  })
  .strict();

export const researchValidateBodySchema = z
  .object({
    findingId: z
      .string()
      .trim()
      .min(1, 'findingId is required')
      .max(128, 'findingId length exceeds maximum limit'),
    validationId: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .optional(),
    observationOverride: z
      .record(z.string(), z.any())
      .optional(),
  })
  .strict();

export const transitionFindingBodySchema = z
  .object({
    status: z
      .string()
      .trim()
      .min(1, 'Status is required')
      .max(64, 'Status length exceeds maximum limit'),
  })
  .strict();

export const addEvidenceBodySchema = z
  .object({
    observation: z.union([z.string(), z.record(z.string(), z.any())]),
    observationType: z.string().trim().max(128).optional(),
    source: z.string().trim().max(255).optional(),
    capabilityId: z.string().trim().max(128).optional(),
    assetId: z.string().trim().max(128).optional(),
  })
  .strict();

export const transitionReportBodySchema = z
  .object({
    status: z
      .string()
      .trim()
      .min(1, 'Status is required')
      .max(64, 'Status length exceeds maximum limit'),
  })
  .strict();

export const transitionEvidenceBodySchema = z
  .object({
    status: z
      .string()
      .trim()
      .min(1, 'Status is required')
      .max(64, 'Status length exceeds maximum limit'),
  })
  .strict();

export const createCaseBodySchema = z
  .object({
    programId: z.string().trim().min(1, 'Program ID is required').max(128),
    title: z.string().trim().min(1, 'Title is required').max(255),
    objective: z.string().trim().min(1, 'Objective is required').max(2000),
    scopeSummary: z.string().trim().max(1000).optional(),
  })
  .strict();

export const transitionCaseBodySchema = z
  .object({
    status: z
      .string()
      .trim()
      .min(1, 'Status is required')
      .max(64, 'Status length exceeds maximum limit'),
  })
  .strict();

export const createActivityBodySchema = z
  .object({
    capabilityId: z.string().trim().min(1, 'Capability ID is required').max(128),
    assetId: z.string().trim().min(1, 'Asset ID is required').max(128),
    target: z.string().trim().min(1, 'Target is required').max(255),
    action: z.string().trim().min(1, 'Action is required').max(255),
    policyDecision: z.enum(['ALLOW', 'BLOCK', 'REVIEW_REQUIRED']).optional(),
    status: z.enum(['PLANNED', 'EXECUTING', 'COMPLETED', 'BLOCKED']).optional(),
    metadata: z.record(z.string(), z.any()).optional(),
  })
  .strict();

export const transitionDisclosureBodySchema = z
  .object({
    status: z
      .string()
      .trim()
      .min(1, 'Status is required')
      .max(64, 'Status length exceeds maximum limit'),
  })
  .strict();

export const approveDisclosureBodySchema = z
  .object({
    confirmApproval: z.boolean().optional(),
  })
  .strict();

export const disclosuresQuerySchema = z
  .object({
    findingId: z.string().trim().max(128).optional(),
    caseId: z.string().trim().max(128).optional(),
    programId: z.string().trim().max(128).optional(),
  })
  .strict();

export const exportPackageQuerySchema = z
  .object({
    format: z.enum(['markdown', 'html', 'text', 'json']).optional(),
  })
  .strict();

export const createExecutionBodySchema = z
  .object({
    caseId: z.string().trim().min(1, 'Case ID is required').max(128),
    capabilityId: z.string().trim().min(1, 'Capability ID is required').max(128),
    assetId: z.string().trim().min(1, 'Asset ID is required').max(128),
    target: z.string().trim().max(255).optional(),
    parameters: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
    confirmApproval: z.boolean().optional(),
  })
  .strict();

export const executionsQuerySchema = z
  .object({
    caseId: z.string().trim().max(128).optional(),
    programId: z.string().trim().max(128).optional(),
    status: z.enum(['REQUESTED', 'AUTHORIZED', 'APPROVED', 'RUNNING', 'COMPLETED', 'CANCELLED', 'FAILED', 'BLOCKED']).optional(),
  })
  .strict();

export const cancelExecutionBodySchema = z
  .object({
    reason: z.string().trim().max(255).optional(),
  })
  .strict();

export const createActiveExecutionBodySchema = z
  .object({
    caseId: z.string().trim().min(1, 'Case ID is required').max(128),
    capabilityId: z.string().trim().min(1, 'Capability ID is required').max(128),
    assetId: z.string().trim().min(1, 'Asset ID is required').max(128),
    target: z.string().trim().max(255).optional(),
    approvalId: z.string().trim().max(128).optional(),
    confirmApproval: z.boolean().optional(),
    parameters: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
  })
  .strict();

export const requestApprovalBodySchema = z
  .object({
    programId: z.string().trim().min(1, 'Program ID is required').max(128),
    assetId: z.string().trim().min(1, 'Asset ID is required').max(128),
    capabilityId: z.string().trim().min(1, 'Capability ID is required').max(128),
    target: z.string().trim().max(255).optional(),
  })
  .strict();

export const confirmApprovalBodySchema = z
  .object({
    approvalId: z.string().trim().min(1, 'Approval ID is required').max(128),
  })
  .strict();

export const activeExecutionsQuerySchema = z
  .object({
    caseId: z.string().trim().max(128).optional(),
    programId: z.string().trim().max(128).optional(),
    status: z
      .enum(['QUEUED', 'AUTHORIZED', 'APPROVED', 'RUNNING', 'COMPLETED', 'CANCELLED', 'BLOCKED', 'FAILED'])
      .optional(),
  })
  .strict();

export const cancelActiveExecutionBodySchema = z
  .object({
    reason: z.string().trim().max(255).optional(),
  })
  .strict();


interface SchemaGroup {
  params?: ZodTypeAny;
  query?: ZodTypeAny;
  body?: ZodTypeAny;
}

export const validateRequest = (schemas: SchemaGroup) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (schemas.params) {
        req.params = (await schemas.params.parseAsync(req.params)) as any;
      }
      if (schemas.query) {
        req.query = (await schemas.query.parseAsync(req.query)) as any;
      }
      if (schemas.body) {
        req.body = await schemas.body.parseAsync(req.body);
      }
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        const firstIssue = err.issues[0];
        let issueMsg = firstIssue
          ? `${firstIssue.path.join('.') || 'payload'}: ${firstIssue.message}`
          : 'Validation failed';

        if (firstIssue && firstIssue.code === 'unrecognized_keys') {
          issueMsg = `Mass assignment blocked: Unrecognized field(s) provided (${firstIssue.keys.join(', ')})`;
        }

        return res.status(400).json({
          error: {
            code: 'BAD_REQUEST',
            message: `Invalid input: ${issueMsg}`,
          },
        });
      }

      return res.status(400).json({
        error: {
          code: 'BAD_REQUEST',
          message: 'Invalid request parameters or malformed body format',
        },
      });
    }
  };
};
