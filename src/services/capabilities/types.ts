import { AuthUser } from '../../middleware/auth.ts';
import { Asset, CapabilityDefinition } from '../../types.ts';

export interface CookieObservation {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  expires?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None' | string;
}

export interface TlsObservation {
  version?: string;
  cipher?: string;
  validTo?: string;
  validFrom?: string;
  issuer?: string;
  subject?: string;
  authorized?: boolean;
  error?: string;
}

export interface ObservationData {
  url?: string;
  target?: string;
  path?: string;
  status?: number;
  statusCode?: number;
  headers?: Record<string, string | string[]>;
  body?: string;
  cookies?: CookieObservation[];
  tls?: TlsObservation;
  metadata?: Record<string, any>;
}

export interface SanitizedEvidence {
  evidenceId: string;
  capabilityId: string;
  assetId: string;
  observedAt: string;
  evidenceType: string;
  sanitizedObservation: Record<string, any>;
  confidence: number;
  hash: string;
  redactedSecrets: boolean;
}

export interface FindingCandidate {
  correlationKey: string;
  title: string;
  category: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  confidence: number; // 0 to 100
  status: 'Potential';
  whatWeFound: string;
  whyItMatters: string;
  affectedTarget: string;
  recommendedFix: string;
  evidence: SanitizedEvidence;
}

export interface PassiveAnalysisResult {
  capabilityId: string;
  capabilityName: string;
  assetId: string;
  observedAt: string;
  observations: Record<string, any>[];
  findingCandidates: FindingCandidate[];
  evidence: SanitizedEvidence[];
  executed: boolean;
  policyDecision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
  reason?: string;
}

export interface CapabilityAnalyzerInput {
  asset: Asset;
  capability: CapabilityDefinition;
  observationData: ObservationData;
  programId: string;
  user: AuthUser;
  requestId?: string;
}

export interface CapabilityAnalyzer {
  capabilityId: string;
  aliases: string[];
  name: string;
  description: string;
  analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult>;
}
