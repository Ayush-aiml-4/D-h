import { ExecutionAdapter } from './types.ts';
import { NotFoundError, ConflictError } from '../../utils/errors.ts';

class AdapterRegistry {
  private adapters: Map<string, ExecutionAdapter> = new Map();

  public registerAdapter(adapter: ExecutionAdapter): void {
    const primaryId = adapter.capabilityId.trim().toLowerCase();
    this.adapters.set(primaryId, adapter);

    if (adapter.aliases) {
      for (const alias of adapter.aliases) {
        this.adapters.set(alias.trim().toLowerCase(), adapter);
      }
    }
  }

  public getAdapter(capabilityId: string): ExecutionAdapter | undefined {
    if (!capabilityId) return undefined;
    return this.adapters.get(capabilityId.trim().toLowerCase());
  }

  public listAdapters(): ExecutionAdapter[] {
    // Return unique adapters
    const seen = new Set<string>();
    const list: ExecutionAdapter[] = [];
    for (const adapter of this.adapters.values()) {
      if (!seen.has(adapter.capabilityId)) {
        seen.add(adapter.capabilityId);
        list.push(adapter);
      }
    }
    return list;
  }

  public isAdapterRegistered(capabilityId: string): boolean {
    if (!capabilityId) return false;
    return this.adapters.has(capabilityId.trim().toLowerCase());
  }

  public clearAdaptersForTesting(): void {
    this.adapters.clear();
  }
}

export const adapterRegistry = new AdapterRegistry();

export function resolveExecutionAdapter(capabilityId: string): ExecutionAdapter {
  if (!capabilityId) {
    throw new NotFoundError('CAPABILITY_ID_REQUIRED: Capability ID must be provided');
  }

  const adapter = adapterRegistry.getAdapter(capabilityId);
  if (!adapter) {
    throw new NotFoundError(
      `UNREGISTERED_ADAPTER: No execution adapter is registered for capability '${capabilityId}'`
    );
  }

  if (!adapter.enabled) {
    throw new ConflictError(
      `ADAPTER_DISABLED: Execution adapter for capability '${capabilityId}' is currently disabled`
    );
  }

  return adapter;
}
