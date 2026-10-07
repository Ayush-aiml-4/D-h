import { adapterRegistry } from '../adapterRegistry.ts';
import { referenceExecutionAdapter } from './referenceAdapter.ts';
import { webSecurityHeadersAdapter } from './webSecurityHeadersAdapter.ts';
import { cspAuditAdapter } from './cspAuditAdapter.ts';
import { hstsAuditAdapter } from './hstsAuditAdapter.ts';
import { cookieSecurityAdapter } from './cookieSecurityAdapter.ts';
import { corsAnalysisAdapter } from './corsAnalysisAdapter.ts';
import { debugDisclosureAdapter } from './debugDisclosureAdapter.ts';
import { directoryListingAdapter } from './directoryListingAdapter.ts';
import { sourceMapExposureAdapter } from './sourceMapExposureAdapter.ts';
import { httpMethodsAdapter } from './httpMethodsAdapter.ts';
import { redirectChainAdapter } from './redirectChainAdapter.ts';
import { cacheControlAdapter } from './cacheControlAdapter.ts';
import { mimeSniffingAdapter } from './mimeSniffingAdapter.ts';
import { crossOriginPoliciesAdapter } from './crossOriginPoliciesAdapter.ts';
import { tlsTransportAdapter } from './tlsTransportAdapter.ts';
import { dnsIntelligenceAdapter } from './dnsIntelligenceAdapter.ts';
import { apiSecurityAdapter } from './apiSecurityAdapter.ts';
import { graphqlIntrospectionAdapter } from './graphqlIntrospectionAdapter.ts';
import { authSessionAdapter } from './authSessionAdapter.ts';
import { techFingerprintAdapter } from './techFingerprintAdapter.ts';
import { exposureMetadataAdapter } from './exposureMetadataAdapter.ts';
import { clientSecurityAdapter } from './clientSecurityAdapter.ts';
import { cloudInfrastructureAdapter } from './cloudInfrastructureAdapter.ts';
import { securityTxtAdapter } from './securityTxtAdapter.ts';
import { rateLimitAdapter } from './rateLimitAdapter.ts';
import { assetDiscoveryAdapter } from './assetDiscoveryAdapter.ts';

export function initializeAdapters(): void {
  adapterRegistry.registerAdapter(referenceExecutionAdapter);
  adapterRegistry.registerAdapter(webSecurityHeadersAdapter);
  adapterRegistry.registerAdapter(cspAuditAdapter);
  adapterRegistry.registerAdapter(hstsAuditAdapter);
  adapterRegistry.registerAdapter(cookieSecurityAdapter);
  adapterRegistry.registerAdapter(corsAnalysisAdapter);
  adapterRegistry.registerAdapter(debugDisclosureAdapter);
  adapterRegistry.registerAdapter(directoryListingAdapter);
  adapterRegistry.registerAdapter(sourceMapExposureAdapter);
  adapterRegistry.registerAdapter(httpMethodsAdapter);
  adapterRegistry.registerAdapter(redirectChainAdapter);
  adapterRegistry.registerAdapter(cacheControlAdapter);
  adapterRegistry.registerAdapter(mimeSniffingAdapter);
  adapterRegistry.registerAdapter(crossOriginPoliciesAdapter);
  adapterRegistry.registerAdapter(tlsTransportAdapter);
  adapterRegistry.registerAdapter(dnsIntelligenceAdapter);
  adapterRegistry.registerAdapter(apiSecurityAdapter);
  adapterRegistry.registerAdapter(graphqlIntrospectionAdapter);
  adapterRegistry.registerAdapter(authSessionAdapter);
  adapterRegistry.registerAdapter(techFingerprintAdapter);
  adapterRegistry.registerAdapter(exposureMetadataAdapter);
  adapterRegistry.registerAdapter(clientSecurityAdapter);
  adapterRegistry.registerAdapter(cloudInfrastructureAdapter);
  adapterRegistry.registerAdapter(securityTxtAdapter);
  adapterRegistry.registerAdapter(rateLimitAdapter);
  adapterRegistry.registerAdapter(assetDiscoveryAdapter);
}

// Auto-initialize standard adapters on load
initializeAdapters();


