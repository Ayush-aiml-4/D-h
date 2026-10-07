import { Program, Hunt, Finding, Report, HistorySession, HuntStatus, FindingStatus, ReportStatus } from '../types';

// Centralized status categories and definitions
export const ACTIVE_HUNT_STATUSES: HuntStatus[] = ['Starting', 'Running', 'Hunting', 'Analyzing'];
export const INACTIVE_HUNT_STATUSES: HuntStatus[] = ['Ready', 'Completed', 'Stopped', 'Blocked', 'Paused', 'Complete'];

export const ACTIONABLE_FINDING_STATUSES: FindingStatus[] = ['Potential', 'Needs review', 'Under review'];
export const VERIFIED_FINDING_STATUSES: FindingStatus[] = ['Verified', 'Submitted', 'Accepted', 'Resolved'];

// Requirement 1: OPEN REPORTS = READY + SUBMITTED (Excludes: RESOLVED, REJECTED, DUPLICATE)
export const OPEN_REPORT_STATUSES: ReportStatus[] = ['Ready', 'Submitted'];
export const SUBMITTED_REPORT_STATUSES: ReportStatus[] = ['Submitted', 'Accepted', 'Resolved'];
export const PAID_REPORT_STATUSES: ReportStatus[] = ['Accepted', 'Resolved'];

// Requirement 2: Hunt Lifecycle Transitions State Machine
export const HUNT_TRANSITIONS: Record<string, HuntStatus[]> = {
  Ready: ['Starting', 'Hunting', 'Blocked'],
  Starting: ['Hunting', 'Blocked'],
  Hunting: ['Analyzing', 'Paused', 'Stopped', 'Completed', 'Blocked'],
  Running: ['Hunting', 'Analyzing', 'Paused', 'Stopped', 'Completed', 'Blocked'],
  Analyzing: ['Hunting', 'Paused', 'Stopped', 'Completed', 'Blocked'],
  Paused: ['Hunting', 'Running', 'Stopped', 'Completed'],
  Completed: [],
  Complete: [],
  Stopped: [],
  Blocked: [],
};

export const canTransitionHunt = (from: HuntStatus, to: HuntStatus): boolean => {
  return (HUNT_TRANSITIONS[from] || []).includes(to);
};

// Requirement 5: Hunt Progress Rules
export const getHuntProgressForStatus = (status: HuntStatus, currentProgress = 0): number => {
  switch (status) {
    case 'Ready':
      return 0;
    case 'Starting':
      return Math.max(currentProgress, 5);
    case 'Hunting':
    case 'Running':
      return Math.max(1, Math.min(95, currentProgress || 25));
    case 'Analyzing':
      return Math.max(50, Math.min(99, currentProgress || 80));
    case 'Completed':
    case 'Complete':
      return 100;
    case 'Stopped':
    case 'Blocked':
    case 'Paused':
      return currentProgress;
    default:
      return currentProgress;
  }
};

// Requirement 8: Finding Lifecycle Transitions State Machine
export const FINDING_TRANSITIONS: Record<string, FindingStatus[]> = {
  Potential: ['Under review', 'Needs review', 'Validated', 'Dismissed'],
  'Needs review': ['Under review', 'Validated', 'Dismissed'],
  'Under review': ['Validated', 'Dismissed'],
  Validated: ['Verified', 'Dismissed'],
  Verified: ['Submitted', 'Dismissed'],
  Submitted: ['Accepted', 'Rejected', 'Duplicate'],
  Accepted: ['Resolved'],
  Rejected: [],
  Duplicate: [],
  Resolved: [],
  Dismissed: [],
};

export const canTransitionFinding = (from: FindingStatus, to: FindingStatus): boolean => {
  return (FINDING_TRANSITIONS[from] || []).includes(to);
};

// Requirement 9: Finding Action Button CTA map
export const getFindingActionLabel = (status: FindingStatus): string => {
  switch (status) {
    case 'Potential':
      return 'REVIEW FINDING';
    case 'Needs review':
    case 'Under review':
      return 'VALIDATE FINDING';
    case 'Validated':
      return 'VERIFY FINDING';
    case 'Verified':
      return 'PREPARE REPORT';
    case 'Submitted':
    case 'Accepted':
    case 'Resolved':
      return 'VIEW REPORT';
    case 'Rejected':
    case 'Duplicate':
    case 'Dismissed':
    default:
      return 'VIEW FINDING';
  }
};

// Requirement 14: Report Lifecycle Transitions State Machine
export const REPORT_TRANSITIONS: Record<string, ReportStatus[]> = {
  Draft: ['Ready'],
  Ready: ['Submitted'],
  Submitted: ['Accepted', 'Rejected', 'Duplicate'],
  Accepted: ['Resolved'],
  Rejected: [],
  Duplicate: [],
  Resolved: [],
};

export const canTransitionReport = (from: ReportStatus, to: ReportStatus): boolean => {
  return (REPORT_TRANSITIONS[from] || []).includes(to);
};

// Status Boolean Checkers
export const isActiveHuntStatus = (status: HuntStatus): boolean => {
  return ACTIVE_HUNT_STATUSES.includes(status);
};

export const isActionableFindingStatus = (status: FindingStatus): boolean => {
  return ACTIONABLE_FINDING_STATUSES.includes(status);
};

export const isVerifiedFindingStatus = (status: FindingStatus): boolean => {
  return VERIFIED_FINDING_STATUSES.includes(status);
};

export const isOpenReportStatus = (status: ReportStatus): boolean => {
  return OPEN_REPORT_STATUSES.includes(status);
};

export const isSubmittedReportStatus = (status: ReportStatus): boolean => {
  return SUBMITTED_REPORT_STATUSES.includes(status);
};

// Application-wide Derived Counts
export const getActiveHuntsCount = (hunts: Hunt[]): number => {
  return hunts.filter((h) => isActiveHuntStatus(h.status)).length;
};

export const getActionableFindingsCount = (findings: Finding[]): number => {
  return findings.filter((f) => isActionableFindingStatus(f.status)).length;
};

export const getVerifiedBugsCount = (findings: Finding[]): number => {
  return findings.filter((f) => isVerifiedFindingStatus(f.status)).length;
};

// OPEN REPORTS = READY + SUBMITTED
export const getOpenReportsCount = (reports: Report[]): number => {
  return reports.filter((r) => isOpenReportStatus(r.status)).length;
};

export const getSubmittedReportsCount = (reports: Report[]): number => {
  return reports.filter((r) => isSubmittedReportStatus(r.status)).length;
};

// Hunt-specific Derived Finding Metrics
export const getHuntFindings = (findings: Finding[], huntId: string): Finding[] => {
  return findings.filter((f) => f.huntId === huntId);
};

export const getHuntPotentialCount = (findings: Finding[], huntId: string): number => {
  return findings.filter((f) => f.huntId === huntId && isActionableFindingStatus(f.status)).length;
};

export const getHuntVerifiedCount = (findings: Finding[], huntId: string): number => {
  return findings.filter((f) => f.huntId === huntId && isVerifiedFindingStatus(f.status)).length;
};

export const getHuntPolicyViolationsCount = (findings: Finding[], huntId: string): number => {
  return findings.filter((f) => f.huntId === huntId && f.policyCheck && !f.policyCheck.noRestrictedAction).length;
};

// Program-specific Derived Metrics
export const getProgramHunts = (hunts: Hunt[], programId: string): Hunt[] => {
  return hunts.filter((h) => h.programId === programId);
};

export const getProgramActiveHuntsCount = (hunts: Hunt[], programId: string): number => {
  return hunts.filter((h) => h.programId === programId && isActiveHuntStatus(h.status)).length;
};

export const getProgramVerifiedCount = (findings: Finding[], programName: string): number => {
  return findings.filter((f) => f.programName === programName && isVerifiedFindingStatus(f.status)).length;
};

// Bounty Accounting Calculations
export interface CalculatedBounty {
  paidAmount: number;
  pendingAmount: number;
  potentialAmount: number;
  paidFormatted: string;
  pendingFormatted: string;
  potentialFormatted: string;
}

export const getCalculatedBounty = (history: HistorySession[], reports: Report[]): CalculatedBounty => {
  let paidAmount = 0;
  let pendingAmount = 0;

  history.forEach((sess) => {
    const rawVal = parseInt(sess.bountyEarned.replace(/[^0-9]/g, ''), 10) || 0;
    if (sess.reportStatus === 'Resolved' || sess.reportStatus === 'Accepted') {
      paidAmount += rawVal;
    } else if (sess.reportStatus === 'Submitted') {
      pendingAmount += rawVal;
    }
  });

  const potentialAmount = paidAmount + pendingAmount;

  const formatRupee = (num: number) => `₹${num.toLocaleString('en-IN')}`;

  return {
    paidAmount,
    pendingAmount,
    potentialAmount,
    paidFormatted: formatRupee(paidAmount),
    pendingFormatted: formatRupee(pendingAmount),
    potentialFormatted: formatRupee(potentialAmount),
  };
};

// "What's Worth Checking" - Priority review sorting for researcher attention
export const getWorthCheckingFindings = (findings: Finding[]): Finding[] => {
  return [...findings]
    .filter((f) => isActionableFindingStatus(f.status) || f.confidence >= 90)
    .sort((a, b) => {
      const aActionable = isActionableFindingStatus(a.status) ? 1 : 0;
      const bActionable = isActionableFindingStatus(b.status) ? 1 : 0;
      if (aActionable !== bActionable) return bActionable - aActionable;

      const severityScore = { Critical: 4, High: 3, Medium: 2, Low: 1 };
      const sevDiff = (severityScore[b.severity] || 0) - (severityScore[a.severity] || 0);
      if (sevDiff !== 0) return sevDiff;

      return b.confidence - a.confidence;
    });
};
