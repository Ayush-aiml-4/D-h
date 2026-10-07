import { activeAdapterRegistry } from '../activeCapabilityRegistry.ts';
import { httpMethodBehaviorAdapter } from './httpMethodBehaviorAdapter.ts';
import { securityHeaderMutationAdapter } from './securityHeaderMutationAdapter.ts';
import { authBoundaryObservationAdapter } from './authBoundaryObservationAdapter.ts';
import { parameterHandlingAdapter } from './parameterHandlingAdapter.ts';
import { redirectPolicyValidationAdapter } from './redirectPolicyValidationAdapter.ts';

export function initializeActiveAdapters(): void {
  activeAdapterRegistry.registerAdapter(httpMethodBehaviorAdapter);
  activeAdapterRegistry.registerAdapter(securityHeaderMutationAdapter);
  activeAdapterRegistry.registerAdapter(authBoundaryObservationAdapter);
  activeAdapterRegistry.registerAdapter(parameterHandlingAdapter);
  activeAdapterRegistry.registerAdapter(redirectPolicyValidationAdapter);
}

// Auto-initialize
initializeActiveAdapters();
