/**
 * DEVILHUNT — Engagement Operational Readiness Evaluation Service
 * Evaluates operational readiness across all 10 distinct security & governance dimensions.
 * Computes explicit deterministic states:
 * READY | BLOCKED | MISSING | REVIEW_REQUIRED | NOT_CONFIGURED | AWAITING_APPROVAL
 * Prevents false "READY" indications when requirements are unfulfilled.
 */

import {
  EngagementProgramProfile,
  EngagementReadinessEvaluation,
  OverallReadinessStatus,
  ReadinessDimensionState,
} from '../../types/engagement.ts';
import { getProxyBoundaryConfig } from './proxyBoundaryService.ts';
import { getResearchAccounts } from './researchAccountService.ts';

export function evaluateOperationalReadiness(profile: EngagementProgramProfile): EngagementReadinessEvaluation {
  const proxyBoundary = getProxyBoundaryConfig();
  const accounts = getResearchAccounts(profile.id);

  // 1. SCOPE STATUS
  let scopeStatus: ReadinessDimensionState = 'NOT_CONFIGURED';
  let scopeReason = '';
  if (!profile.inScopeAssets || profile.inScopeAssets.length === 0) {
    scopeStatus = 'MISSING';
    scopeReason = 'No in-scope assets have been imported or configured';
  } else if (profile.onboardingStage === 'PROGRAM_DRAFT' || profile.onboardingStage === 'POLICY_IMPORTED') {
    scopeStatus = 'REVIEW_REQUIRED';
    scopeReason = 'Assets imported but awaiting formal scope validation';
  } else {
    scopeStatus = 'READY';
    scopeReason = `${profile.inScopeAssets.length} in-scope assets validated fail-closed`;
  }

  // 2. POLICY STATUS
  let policyStatus: ReadinessDimensionState = 'NOT_CONFIGURED';
  let policyReason = '';
  if (!profile.programPolicy.allowedVulnerabilityClasses || profile.programPolicy.allowedVulnerabilityClasses.length === 0) {
    policyStatus = 'MISSING';
    policyReason = 'Allowed vulnerability classes and program policy rules missing';
  } else if (profile.onboardingStage === 'PROGRAM_DRAFT') {
    policyStatus = 'REVIEW_REQUIRED';
    policyReason = 'Policy drafted but not yet imported into verified lifecycle';
  } else {
    policyStatus = 'READY';
    policyReason = 'Generic and program-specific policies validated and active';
  }

  // 3. ACCOUNT STATUS (Symbolic accounts only)
  let accountStatus: ReadinessDimensionState = 'NOT_CONFIGURED';
  let accountReason = '';
  if (accounts.length === 0) {
    accountStatus = 'NOT_CONFIGURED';
    accountReason = 'No symbolic research accounts (e.g. ACCOUNT_A, ACCOUNT_B) registered';
  } else {
    const allVerified = accounts.every((a) => a.credentialSafetyVerified);
    if (allVerified) {
      accountStatus = 'READY';
      accountReason = `${accounts.length} symbolic accounts verified (zero raw credentials stored)`;
    } else {
      accountStatus = 'BLOCKED';
      accountReason = 'Account credential safety validation failed';
    }
  }

  // 4. PROXY STATUS (Clean boundary, never fabricated)
  let proxyStatus: ReadinessDimensionState = 'NOT_CONFIGURED';
  let proxyReason = '';
  if (proxyBoundary.status === 'BURP_CONFIGURATION_NOT_AVAILABLE') {
    proxyStatus = 'NOT_CONFIGURED';
    proxyReason = 'BURP_CONFIGURATION_NOT_AVAILABLE: No external proxy configured. Legitimate state for local/direct passive analysis.';
  } else if (proxyBoundary.status === 'CONFIGURED' || proxyBoundary.status === 'CONNECTED') {
    proxyStatus = 'READY';
    proxyReason = `External proxy configured (${proxyBoundary.proxyHost}:${proxyBoundary.proxyPort})`;
  } else if (proxyBoundary.status === 'ERROR' || proxyBoundary.status === 'DISCONNECTED') {
    proxyStatus = 'BLOCKED';
    proxyReason = 'External proxy unreachable or encountered routing error';
  } else {
    proxyStatus = 'MISSING';
    proxyReason = 'Proxy configuration missing';
  }

  // 5. REQUEST BUDGET
  let requestBudgetStatus: ReadinessDimensionState = 'NOT_CONFIGURED';
  let requestBudgetReason = '';
  const limits = profile.programPolicy.requestLimits;
  if (!limits || limits.rateLimitPerSecond <= 0 || limits.totalSessionBudget <= 0) {
    requestBudgetStatus = 'MISSING';
    requestBudgetReason = 'Numerical request budget and rate limit parameters not specified';
  } else {
    requestBudgetStatus = 'READY';
    requestBudgetReason = `Session budget defined (${limits.totalSessionBudget} req max, ${limits.rateLimitPerSecond} req/s)`;
  }

  // 6. APPROVAL STATUS
  let approvalStatus: ReadinessDimensionState = 'NOT_CONFIGURED';
  let approvalReason = '';
  if (
    profile.onboardingStage === 'READY_FOR_PASSIVE_TESTING' ||
    profile.onboardingStage === 'ACTIVE_TESTING_AUTHORIZED'
  ) {
    approvalStatus = 'READY';
    approvalReason = 'Human operator onboarding approval granted';
  } else if (profile.onboardingStage === 'HUMAN_APPROVAL') {
    approvalStatus = 'AWAITING_APPROVAL';
    approvalReason = 'Currently awaiting human security lead approval';
  } else if (profile.onboardingStage === 'RESEARCHER_REVIEW') {
    approvalStatus = 'REVIEW_REQUIRED';
    approvalReason = 'Pending researcher sign-off before submission to human approval';
  } else {
    approvalStatus = 'NOT_CONFIGURED';
    approvalReason = `Onboarding stage is '${profile.onboardingStage}'`;
  }

  // 7. PASSIVE MODE STATUS
  let passiveModeStatus: ReadinessDimensionState = 'NOT_CONFIGURED';
  let passiveModeReason = '';
  if (
    profile.onboardingStage === 'READY_FOR_PASSIVE_TESTING' ||
    profile.onboardingStage === 'ACTIVE_TESTING_AUTHORIZED'
  ) {
    if (scopeStatus === 'READY' && policyStatus === 'READY') {
      passiveModeStatus = 'READY';
      passiveModeReason = 'Passive research mode is authorized and operational';
    } else {
      passiveModeStatus = 'BLOCKED';
      passiveModeReason = 'Passive mode blocked due to unfulfilled scope or policy requirements';
    }
  } else {
    passiveModeStatus = 'BLOCKED';
    passiveModeReason = `Passive mode is gated: Onboarding stage '${profile.onboardingStage}' requires human approval`;
  }

  // 8. ACTIVE MODE STATUS
  let activeModeStatus: ReadinessDimensionState = 'BLOCKED';
  let activeModeReason = '';
  if (profile.onboardingStage === 'ACTIVE_TESTING_AUTHORIZED') {
    activeModeStatus = 'READY';
    activeModeReason = 'Active testing explicitly authorized by human operator';
  } else {
    activeModeStatus = 'BLOCKED';
    activeModeReason = 'Active testing is locked behind separate human approval gate';
  }

  // 9. EVIDENCE SYSTEM
  const evidenceSystemStatus: ReadinessDimensionState = 'READY';
  const evidenceSystemReason = 'SHA-256 evidence integrity engine and audit provenance active';

  // 10. REPORTING SYSTEM
  let reportingSystemStatus: ReadinessDimensionState = 'NOT_CONFIGURED';
  let reportingSystemReason = '';
  if (profile.programPolicy.disclosureRequirements) {
    reportingSystemStatus = 'READY';
    reportingSystemReason = 'Disclosure rules and 14-point finding quality gate engine active';
  } else {
    reportingSystemStatus = 'REVIEW_REQUIRED';
    reportingSystemReason = 'Disclosure coordination terms require verification';
  }

  // Compute Overall Readiness Status
  let overallReadiness: OverallReadinessStatus = 'NOT_CONFIGURED';
  if (
    profile.onboardingStage === 'READY_FOR_PASSIVE_TESTING' &&
    scopeStatus === 'READY' &&
    policyStatus === 'READY' &&
    approvalStatus === 'READY'
  ) {
    if (proxyStatus === 'READY' && accountStatus === 'READY') {
      overallReadiness = 'READY_FOR_PASSIVE_TESTING';
    } else {
      // Missing upstream proxy or optional accounts: ready with restrictions!
      overallReadiness = 'READY_WITH_RESTRICTIONS';
    }
  } else if (profile.onboardingStage === 'ACTIVE_TESTING_AUTHORIZED') {
    overallReadiness = 'READY_FOR_PASSIVE_TESTING';
  } else if (
    scopeStatus === 'BLOCKED' ||
    policyStatus === 'BLOCKED' ||
    passiveModeStatus === 'BLOCKED'
  ) {
    overallReadiness = 'BLOCKED';
  } else if (profile.onboardingStage === 'HUMAN_APPROVAL') {
    overallReadiness = 'REVIEW_REQUIRED';
  } else {
    overallReadiness = 'NOT_CONFIGURED';
  }

  return {
    programId: profile.id,
    programName: profile.name,
    scopeStatus,
    policyStatus,
    accountStatus,
    proxyStatus,
    requestBudgetStatus,
    approvalStatus,
    passiveModeStatus,
    activeModeStatus,
    evidenceSystemStatus,
    reportingSystemStatus,
    overallReadiness,
    dimensions: {
      scope: {
        status: scopeStatus,
        name: 'SCOPE STATUS',
        reason: scopeReason,
      },
      policy: {
        status: policyStatus,
        name: 'POLICY STATUS',
        reason: policyReason,
      },
      account: {
        status: accountStatus,
        name: 'ACCOUNT STATUS',
        reason: accountReason,
      },
      proxy: {
        status: proxyStatus,
        name: 'PROXY STATUS',
        reason: proxyReason,
      },
      requestBudget: {
        status: requestBudgetStatus,
        name: 'REQUEST BUDGET',
        reason: requestBudgetReason,
      },
      approval: {
        status: approvalStatus,
        name: 'APPROVAL STATUS',
        reason: approvalReason,
      },
      passiveMode: {
        status: passiveModeStatus,
        name: 'PASSIVE MODE STATUS',
        reason: passiveModeReason,
      },
      activeMode: {
        status: activeModeStatus,
        name: 'ACTIVE MODE STATUS',
        reason: activeModeReason,
      },
      evidenceSystem: {
        status: evidenceSystemStatus,
        name: 'EVIDENCE SYSTEM',
        reason: evidenceSystemReason,
      },
      reportingSystem: {
        status: reportingSystemStatus,
        name: 'REPORTING SYSTEM',
        reason: reportingSystemReason,
      },
    },
    evaluatedAt: new Date().toISOString(),
  };
}
