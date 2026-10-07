/**
 * Deterministic known-issue filter for Meesho policy.
 * Matching titles → KNOWN_DUPLICATE (never a new discovery).
 */

import { MEESHO_KNOWN_DUPLICATES } from './meeshoPolicyValidator.ts';

export type FixtureFindingClass = 'KNOWN_DUPLICATE' | 'UNKNOWN_UNVERIFIED' | 'NOT_A_DISCOVERY';

export interface FixtureFindingClassification {
  classification: FixtureFindingClass;
  matchedIssueId: string | null;
  matchedTitle: string | null;
  claimAsVulnerability: false;
}

function normalize(s: string): string {
  return s.toLowerCase().replace(/\s+/g, ' ').trim();
}

export function classifyFixtureFinding(title: string): FixtureFindingClassification {
  const n = normalize(title);
  for (const issue of MEESHO_KNOWN_DUPLICATES) {
    const it = normalize(issue.title);
    // Deterministic partial match on distinctive phrases
    const phrases = [
      it,
      it.slice(0, Math.min(40, it.length)),
      issue.id.replace(/dup-/g, '').replace(/-/g, ' '),
    ];
    if (phrases.some((p) => p.length > 8 && n.includes(p.slice(0, 28)))) {
      return {
        classification: 'KNOWN_DUPLICATE',
        matchedIssueId: issue.id,
        matchedTitle: issue.title,
        claimAsVulnerability: false,
      };
    }
  }
  return {
    classification: 'UNKNOWN_UNVERIFIED',
    matchedIssueId: null,
    matchedTitle: null,
    claimAsVulnerability: false,
  };
}

export function isKnownDuplicateFinding(title: string): boolean {
  return classifyFixtureFinding(title).classification === 'KNOWN_DUPLICATE';
}
