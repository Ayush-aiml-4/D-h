/**
 * Endpoint inventory — discovered endpoints remain DISCOVERED_ONLY.
 * POST/PUT/PATCH/DELETE are never made executable by discovery alone.
 */

import crypto from 'crypto';
import { DiscoveryRecord, EndpointInventoryEntry, EndpointInventoryStatus } from './types.ts';
import { evaluateScope, isSafePassiveMethod } from './scopeGuard.ts';

const inventory = new Map<string, EndpointInventoryEntry>();

function inventoryKey(programId: string, method: string, endpoint: string): string {
  return `${programId}::${method.toUpperCase()}::${endpoint}`;
}

export function clearEndpointInventory(): void {
  inventory.clear();
}

export function upsertFromDiscovery(disc: DiscoveryRecord): EndpointInventoryEntry | null {
  if (disc.discoveryType !== 'DISCOVERED_ENDPOINT' && disc.discoveryType !== 'DISCOVERED_REFERENCE') {
    return null;
  }

  let method = (disc.methodHint || 'GET').toUpperCase();
  if (method === 'UNKNOWN') method = 'GET';

  // Non-safe methods stay DISCOVERED_ONLY forever — never passive-executable
  const safe = isSafePassiveMethod(method);
  const scope = evaluateScope(disc.programId, disc.extractedValue.startsWith('http') ? disc.extractedValue : disc.sourceUrl);

  let status: EndpointInventoryStatus = 'DISCOVERED_ONLY';
  if (!scope.allowed && disc.extractedValue.startsWith('http')) status = 'OUT_OF_SCOPE';
  if (!disc.scopeAllowed && disc.extractedValue.startsWith('http')) status = 'OUT_OF_SCOPE';

  const endpoint = disc.extractedValue;
  const key = inventoryKey(disc.programId, method, endpoint);
  const existing = inventory.get(key);
  const now = new Date().toISOString();

  if (existing) {
    existing.lastObserved = now;
    existing.evidenceCount += 1;
    inventory.set(key, existing);
    return existing;
  }

  const entry: EndpointInventoryEntry = {
    id: `ep-${crypto.randomBytes(5).toString('hex')}`,
    endpoint,
    method,
    source: disc.sourceUrl,
    scopeDecision: scope.decision === 'IN_SCOPE' ? 'IN_SCOPE' : scope.decision === 'OUT_OF_SCOPE' ? 'OUT_OF_SCOPE' : 'UNKNOWN',
    authenticationIndicator: /auth|login|oauth|token|session/i.test(endpoint),
    firstDiscovered: now,
    lastObserved: now,
    evidenceCount: 1,
    status: safe ? status : 'DISCOVERED_ONLY',
    programId: disc.programId,
  };

  inventory.set(key, entry);
  return entry;
}

export function listInventory(programId?: string): EndpointInventoryEntry[] {
  const all = [...inventory.values()];
  if (!programId) return all;
  return all.filter((e) => e.programId === programId);
}

export function isPassivelyExecutable(entry: EndpointInventoryEntry): boolean {
  return (
    entry.status !== 'OUT_OF_SCOPE' &&
    entry.status !== 'BLOCKED' &&
    isSafePassiveMethod(entry.method) &&
    entry.scopeDecision === 'IN_SCOPE'
  );
}
