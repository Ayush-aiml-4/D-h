import { SynthesizedFindingCandidate } from '../../types/researchSynthesis.ts';

export interface DuplicateComparisonResult {
  isDuplicate: boolean;
  sharedFactors: string[];
  confidence: number;
}

export function compareFindingsForDuplicate(
  candidateA: SynthesizedFindingCandidate,
  candidateB: SynthesizedFindingCandidate
): DuplicateComparisonResult {
  const sharedFactors: string[] = [];
  let score = 0;

  // 1. Same Target and Affected Asset
  if (
    candidateA.target === candidateB.target &&
    candidateA.affectedAsset === candidateB.affectedAsset
  ) {
    sharedFactors.push('SAME_TARGET_AND_ASSET');
    score += 2;
  }

  // 2. Same Root Cause description / classification
  if (
    candidateA.rootCause.toLowerCase().trim() === candidateB.rootCause.toLowerCase().trim() ||
    candidateA.vulnerabilityClass === candidateB.vulnerabilityClass
  ) {
    sharedFactors.push('SAME_ROOT_CAUSE');
    score += 3;
  }

  // 3. Same Affected Resource
  const resA = candidateA.reproductionSteps.join(' ');
  const resB = candidateB.reproductionSteps.join(' ');
  if (candidateA.cweId === candidateB.cweId && candidateA.target === candidateB.target) {
    sharedFactors.push('SAME_CWE_AND_TARGET');
    score += 1;
  }

  // 4. Materially Same Exploitation Path
  const chainA = candidateA.attackChain.steps.map((s) => s.action).join('->');
  const chainB = candidateB.attackChain.steps.map((s) => s.action).join('->');
  if (chainA === chainB && chainA.length > 0) {
    sharedFactors.push('SAME_EXPLOITATION_PATH');
    score += 3;
  }

  // Deduplication requires both shared root cause, same target/asset, and same exploitation path or high composite score
  const isDuplicate = score >= 7 || (sharedFactors.includes('SAME_TARGET_AND_ASSET') && sharedFactors.includes('SAME_ROOT_CAUSE') && sharedFactors.includes('SAME_EXPLOITATION_PATH'));

  return {
    isDuplicate,
    sharedFactors,
    confidence: Math.min(1.0, score / 9),
  };
}

export function deduplicateCandidates(
  candidates: SynthesizedFindingCandidate[]
): {
  uniqueCandidates: SynthesizedFindingCandidate[];
  duplicateGroups: Map<string, SynthesizedFindingCandidate[]>;
} {
  const duplicateGroups = new Map<string, SynthesizedFindingCandidate[]>();
  const processed = new Set<string>();
  const uniqueCandidates: SynthesizedFindingCandidate[] = [];

  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i];
    if (processed.has(candidate.findingId)) continue;

    processed.add(candidate.findingId);
    const duplicates: SynthesizedFindingCandidate[] = [candidate];

    for (let j = i + 1; j < candidates.length; j++) {
      const other = candidates[j];
      if (processed.has(other.findingId)) continue;

      const { isDuplicate } = compareFindingsForDuplicate(candidate, other);
      if (isDuplicate) {
        processed.add(other.findingId);
        duplicates.push(other);
      }
    }

    if (duplicates.length > 1) {
      const groupId = `dup-group-${Date.now()}-${uniqueCandidates.length + 1}`;
      duplicates.forEach((d) => {
        d.duplicateGroupId = groupId;
      });
      duplicateGroups.set(groupId, duplicates);
    }

    // Always preserve the primary candidate
    uniqueCandidates.push(candidate);
  }

  return {
    uniqueCandidates,
    duplicateGroups,
  };
}
