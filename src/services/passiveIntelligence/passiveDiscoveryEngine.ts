/**
 * PassiveDiscoveryEngine — analyzes authorized passive responses only.
 * Does NOT automatically request every discovered endpoint.
 */

import crypto from 'crypto';
import {
  NormalizedPassiveResponse,
  DiscoveryRecord,
  SecurityObservation,
  TechnologyFingerprint,
  EndpointInventoryEntry,
} from './types.ts';
import { analyzeJavaScriptContent } from './jsAnalyzer.ts';
import { analyzeSecurityHeaders } from './securityHeaderAnalyzer.ts';
import { analyzeCorsPassive } from './corsAnalyzer.ts';
import { analyzeInformationDisclosure } from './informationDisclosureAnalyzer.ts';
import { fingerprintTechnology } from './technologyFingerprinter.ts';
import { upsertFromDiscovery, listInventory } from './endpointInventory.ts';
import { evaluateScope } from './scopeGuard.ts';
import { createEvidenceFromResponse } from './evidenceStore.ts';
import { appendTimelineEvent } from './researchTimeline.ts';

export interface DiscoveryEngineResult {
  evidenceId: string;
  discoveries: DiscoveryRecord[];
  observations: SecurityObservation[];
  fingerprints: TechnologyFingerprint[];
  inventory: EndpointInventoryEntry[];
}

export function analyzePassiveResponse(response: NormalizedPassiveResponse): DiscoveryEngineResult {
  // Scope gate on the response URL itself
  const scope = evaluateScope(response.programId, response.url);
  if (!scope.allowed) {
    appendTimelineEvent({
      type: 'SCOPE_BLOCKED',
      programId: response.programId,
      researchCaseId: response.researchCaseId,
      requestId: response.requestId,
      target: response.url,
      details: { reason: scope.reason },
    });
    return {
      evidenceId: '',
      discoveries: [],
      observations: [],
      fingerprints: [],
      inventory: listInventory(response.programId),
    };
  }

  appendTimelineEvent({
    type: 'RESPONSE_CAPTURED',
    programId: response.programId,
    researchCaseId: response.researchCaseId,
    executionId: response.executionId,
    requestId: response.requestId,
    target: response.url,
    details: { status: response.status, method: response.method },
  });

  const evidence = createEvidenceFromResponse(response);
  appendTimelineEvent({
    type: 'EVIDENCE_CREATED',
    programId: response.programId,
    researchCaseId: response.researchCaseId,
    executionId: response.executionId,
    requestId: response.requestId,
    target: response.url,
    details: { evidenceId: evidence.id, sha256: evidence.sha256 },
  });

  const discoveries: DiscoveryRecord[] = [];
  const observations: SecurityObservation[] = [];

  // URL path discovery
  try {
    const u = new URL(response.url);
    if (u.pathname && u.pathname !== '/') {
      const disc: DiscoveryRecord = {
        id: `disc-${crypto.randomBytes(4).toString('hex')}`,
        discoveryType: 'DISCOVERED_ENDPOINT',
        sourceUrl: response.url,
        extractedValue: u.pathname,
        methodHint: response.method,
        confidence: 'HIGH',
        evidenceRef: evidence.id,
        scopeAllowed: true,
        scopeReason: scope.reason,
        programId: response.programId,
        researchCaseId: response.researchCaseId,
        timestamp: response.timestamp,
      };
      discoveries.push(disc);
      upsertFromDiscovery(disc);
      appendTimelineEvent({
        type: 'ENDPOINT_DISCOVERED',
        programId: response.programId,
        researchCaseId: response.researchCaseId,
        target: response.url,
        details: { path: u.pathname },
      });
    }
  } catch {
    /* ignore */
  }

  // JS analysis when content-type suggests JS/HTML
  const ct = (response.contentType || response.headers['content-type'] || '').toLowerCase();
  if (ct.includes('javascript') || ct.includes('html') || /\.js(\?|$)/i.test(response.url)) {
    const jsDisc = analyzeJavaScriptContent({
      sourceUrl: response.url,
      body: response.body,
      programId: response.programId,
      researchCaseId: response.researchCaseId,
      evidenceRef: evidence.id,
    });
    for (const d of jsDisc) {
      discoveries.push(d);
      upsertFromDiscovery(d);
      if (d.discoveryType === 'DISCOVERED_ENDPOINT') {
        appendTimelineEvent({
          type: 'ENDPOINT_DISCOVERED',
          programId: response.programId,
          researchCaseId: response.researchCaseId,
          target: response.url,
          details: { extracted: d.extractedValue },
        });
      }
    }
  }

  // Header / CORS / disclosure
  const headerObs = analyzeSecurityHeaders({
    url: response.url,
    headers: response.headers,
    programId: response.programId,
    researchCaseId: response.researchCaseId,
    requestId: response.requestId,
    evidenceRef: evidence.id,
  });
  const corsObs = analyzeCorsPassive({
    url: response.url,
    headers: response.headers,
    programId: response.programId,
    researchCaseId: response.researchCaseId,
    requestId: response.requestId,
    evidenceRef: evidence.id,
  });
  const disclosureObs = analyzeInformationDisclosure({
    url: response.url,
    headers: response.headers,
    body: response.body,
    programId: response.programId,
    researchCaseId: response.researchCaseId,
    requestId: response.requestId,
    evidenceRef: evidence.id,
  });

  for (const o of [...headerObs, ...corsObs, ...disclosureObs]) {
    observations.push(o);
    appendTimelineEvent({
      type: 'OBSERVATION_CREATED',
      programId: response.programId,
      researchCaseId: response.researchCaseId,
      requestId: response.requestId,
      target: response.url,
      details: { observationId: o.id, kind: o.kind, signal: o.signal },
    });
  }

  const fingerprints = fingerprintTechnology({
    url: response.url,
    headers: response.headers,
    body: response.body,
    evidenceRef: evidence.id,
  });

  return {
    evidenceId: evidence.id,
    discoveries,
    observations,
    fingerprints,
    inventory: listInventory(response.programId),
  };
}
