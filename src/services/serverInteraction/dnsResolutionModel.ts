import { ResolutionResult, DestinationClass } from '../../types/serverInteractionResearch.ts';
import { classifyDestination } from './destinationClassificationService.ts';

export interface MockDnsRecord {
  hostname: string;
  resolutions: string[]; // sequence of IPs for rebinding simulation
  currentIndex: number;
}

class DnsResolutionModel {
  private customMappings: Map<string, MockDnsRecord> = new Map();

  constructor() {
    this.initDefaultFixtures();
  }

  private initDefaultFixtures() {
    // Standard public mapping
    this.registerMapping('safe-external.test', ['93.184.216.34']);
    this.registerMapping('api.public-service.test', ['104.244.42.1']);
    this.registerMapping('www.valmo.in', ['13.235.12.100']);
    this.registerMapping('meesho.com', ['13.235.12.101']);

    // Public names resolving directly to internal IPs (DNS Misconfiguration / Intranet DNS)
    this.registerMapping('public-to-private.test', ['10.0.4.15']);
    this.registerMapping('public-to-loopback.test', ['127.0.0.1']);
    this.registerMapping('public-to-linklocal.test', ['169.254.10.20']);
    this.registerMapping('public-to-metadata.test', ['169.254.169.254']);

    // DNS Rebinding simulation: Step 1 -> Public IP, Step 2 -> Loopback/Private IP
    this.registerMapping('rebinding.test', ['93.184.216.34', '127.0.0.1']);
    this.registerMapping('rebinding-rfc1918.test', ['198.51.100.1', '10.0.0.1']);
  }

  public registerMapping(hostname: string, ips: string | string[]): void {
    const hostKey = hostname.toLowerCase().trim();
    const resolutionList = Array.isArray(ips) ? ips : [ips];
    this.customMappings.set(hostKey, {
      hostname: hostKey,
      resolutions: resolutionList,
      currentIndex: 0,
    });
  }

  public reset(): void {
    this.customMappings.clear();
    this.initDefaultFixtures();
  }

  /**
   * Deterministically resolves a hostname to an IP address without executing real network DNS calls.
   * If step is explicitly provided, uses that index; otherwise increments step for rebinding.
   */
  public resolve(hostname: string, step?: number): ResolutionResult {
    let cleanHost = hostname.toLowerCase().trim();
    while (cleanHost.endsWith('.')) {
      cleanHost = cleanHost.slice(0, -1);
    }

    // Direct IP given as hostname
    const directClass = classifyDestination(cleanHost);
    if (directClass !== 'INVALID' && directClass !== 'PUBLIC_EXTERNAL' && directClass !== 'CONTROLLED_FIXTURE') {
      const isV6 = cleanHost.includes(':');
      return {
        hostname: cleanHost,
        ipAddress: cleanHost,
        ipVersion: isV6 ? 'IPv6' : 'IPv4',
        destinationClass: directClass,
        status: 'RESOLVED',
        dnsRebindingStep: 0,
        resolvedAt: new Date().toISOString(),
      };
    }

    // Look up mock record
    const record = this.customMappings.get(cleanHost);
    let resolvedIp = '93.184.216.34'; // default mock public IP
    let resolutionStep = 0;

    if (record) {
      if (typeof step === 'number') {
        resolutionStep = step;
        const targetIndex = step % record.resolutions.length;
        resolvedIp = record.resolutions[targetIndex];
      } else {
        resolutionStep = record.currentIndex;
        resolvedIp = record.resolutions[record.currentIndex % record.resolutions.length];
        record.currentIndex++;
      }
    } else {
      // Inferred resolution based on destination classification
      if (cleanHost.includes('loopback') || cleanHost === 'localhost') {
        resolvedIp = '127.0.0.1';
      } else if (cleanHost.includes('private')) {
        resolvedIp = '10.0.0.1';
      } else if (cleanHost.includes('metadata')) {
        resolvedIp = '169.254.169.254';
      } else if (cleanHost.includes('linklocal')) {
        resolvedIp = '169.254.1.1';
      } else if (directClass === 'PUBLIC_EXTERNAL') {
        resolvedIp = '93.184.216.34';
      } else {
        return {
          hostname: cleanHost,
          ipAddress: '',
          ipVersion: 'IPv4',
          destinationClass: 'INVALID',
          status: 'FAILED',
          resolvedAt: new Date().toISOString(),
        };
      }
    }

    const destClass = classifyDestination(resolvedIp);
    const ipVersion = resolvedIp.includes(':') ? 'IPv6' : 'IPv4';

    return {
      hostname: cleanHost,
      ipAddress: resolvedIp,
      ipVersion,
      destinationClass: destClass,
      status: 'RESOLVED',
      dnsRebindingStep: resolutionStep,
      resolvedAt: new Date().toISOString(),
    };
  }
}

export const dnsResolver = new DnsResolutionModel();
