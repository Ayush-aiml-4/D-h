export interface DiscoveryCandidate {
  rawTarget: string;
  domain?: string;
  hostname?: string;
  url?: string;
  path?: string;
  type?: string;
  httpMethod?: string;
}

export interface DiscoveryAdapter {
  discoverCandidates(target: string): Promise<DiscoveryCandidate[]>;
}

export class FixtureDiscoveryAdapter implements DiscoveryAdapter {
  async discoverCandidates(target: string): Promise<DiscoveryCandidate[]> {
    // Return deterministic fictional candidates only.
    // Do NOT fetch these domains over the network.
    return [
      {
        rawTarget: 'acme-security.test',
        domain: 'acme-security.test',
        hostname: 'acme-security.test',
        url: 'https://acme-security.test',
        path: '/',
        type: 'DOMAIN',
        httpMethod: 'GET',
      },
      {
        rawTarget: 'api.acme-security.test',
        domain: 'api.acme-security.test',
        hostname: 'api.acme-security.test',
        url: 'https://api.acme-security.test',
        path: '/',
        type: 'SUBDOMAIN',
        httpMethod: 'GET',
      },
      {
        rawTarget: 'auth.acme-security.test',
        domain: 'auth.acme-security.test',
        hostname: 'auth.acme-security.test',
        url: 'https://auth.acme-security.test',
        path: '/',
        type: 'SUBDOMAIN',
        httpMethod: 'GET',
      },
      {
        rawTarget: 'api.acme-security.test/v1/auth/token',
        domain: 'api.acme-security.test',
        hostname: 'api.acme-security.test',
        url: 'https://api.acme-security.test/v1/auth/token',
        path: '/v1/auth/token',
        type: 'API_ENDPOINT',
        httpMethod: 'POST',
      },
      {
        rawTarget: 'evil-nexus-pay.dev',
        domain: 'evil-nexus-pay.dev',
        hostname: 'evil-nexus-pay.dev',
        url: 'https://evil-nexus-pay.dev',
        path: '/',
        type: 'SUBDOMAIN',
        httpMethod: 'GET',
      },
      {
        rawTarget: 'evil-acme-security.test.attacker.com',
        domain: 'evil-acme-security.test.attacker.com',
        hostname: 'evil-acme-security.test.attacker.com',
        url: 'https://evil-acme-security.test.attacker.com',
        path: '/',
        type: 'SUBDOMAIN',
        httpMethod: 'GET',
      },
    ];
  }
}
