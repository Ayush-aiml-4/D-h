import crypto from 'crypto';
import { EvidenceArtifact, NormalizedPassiveResponse } from './types.ts';
import { redactHeaders, redactSecretsFromText } from './secretRedaction.ts';

const store = new Map<string, EvidenceArtifact>();

export function clearEvidenceStore(): void {
  store.clear();
}

export function computeEvidenceHash(input: {
  url: string;
  method: string;
  status: number;
  headers: Record<string, string>;
  bodySnippet: string;
}): string {
  const normalized = JSON.stringify({
    url: input.url.toLowerCase(),
    method: input.method.toUpperCase(),
    status: input.status,
    headers: Object.keys(input.headers)
      .sort()
      .reduce((acc, k) => ({ ...acc, [k.toLowerCase()]: input.headers[k] }), {} as Record<string, string>),
    bodySnippet: input.bodySnippet.trim(),
  });
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

export function createEvidenceFromResponse(
  response: NormalizedPassiveResponse,
  observationId?: string
): EvidenceArtifact {
  const hdr = redactHeaders(response.headers);
  const body = redactSecretsFromText(response.body.slice(0, 2000));
  const sha256 = computeEvidenceHash({
    url: response.url,
    method: response.method,
    status: response.status,
    headers: hdr.headers,
    bodySnippet: body.text,
  });

  const artifact: EvidenceArtifact = {
    id: `evd-${crypto.randomBytes(5).toString('hex')}`,
    researchCaseId: response.researchCaseId,
    executionId: response.executionId,
    requestId: response.requestId,
    target: response.target,
    observationId,
    timestamp: response.timestamp,
    sha256,
    method: response.method,
    url: response.url,
    status: response.status,
    headersRedacted: hdr.headers,
    bodySnippetRedacted: body.text,
    integrityValid: true,
  };
  store.set(artifact.id, artifact);
  return artifact;
}

export function getEvidence(id: string): EvidenceArtifact | undefined {
  return store.get(id);
}

export function listEvidence(researchCaseId?: string): EvidenceArtifact[] {
  const all = [...store.values()];
  if (!researchCaseId) return all;
  return all.filter((e) => e.researchCaseId === researchCaseId);
}

/** Tamper detection: recompute hash and compare */
export function verifyEvidenceIntegrity(id: string): boolean {
  const e = store.get(id);
  if (!e) return false;
  const recomputed = computeEvidenceHash({
    url: e.url,
    method: e.method,
    status: e.status,
    headers: e.headersRedacted,
    bodySnippet: e.bodySnippetRedacted,
  });
  const valid = recomputed === e.sha256;
  e.integrityValid = valid;
  return valid;
}

/** Simulate tampering for tests */
export function tamperEvidenceBody(id: string, newBody: string): void {
  const e = store.get(id);
  if (!e) return;
  e.bodySnippetRedacted = newBody;
  // hash intentionally NOT updated — integrity should fail
}
