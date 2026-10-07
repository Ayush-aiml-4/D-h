import { DestinationClass } from '../../types/serverInteractionResearch.ts';

const METADATA_HOSTNAMES = new Set([
  'metadata.google.internal',
  'metadata',
  'instance-data',
  '169.254.169.254',
  '169.254.169.253',
  '169.254.170.2',
  '100.100.100.200',
  'fixture-metadata.test',
  'metadata.fixture.local',
]);

const FIXTURE_HOSTNAMES = new Set([
  'fixture-safe.test',
  'fixture-private.test',
  'fixture-metadata.test',
  'fixture-loopback.test',
  'fixture-linklocal.test',
  'fixture-redirect.test',
  'fixture-rebinding.test',
  'safe.fixture.local',
  'private.fixture.local',
  'loopback.fixture.local',
]);

/**
 * Normalizes decimal, octal, hex, or dotted-decimal string into standard 4-part decimal IPv4.
 * Returns null if string is not a valid IPv4 representation.
 */
export function normalizeIpv4(ipStr: string): string | null {
  const trimmed = ipStr.trim().replace(/^\[|\]$/g, '');

  // Check for standard dotted-quad
  const parts = trimmed.split('.');
  if (parts.length === 4) {
    const octets: number[] = [];
    for (const part of parts) {
      let val: number;
      if (part.startsWith('0x') || part.startsWith('0X')) {
        val = parseInt(part, 16);
      } else if (part.startsWith('0') && part.length > 1 && /^[0-7]+$/.test(part)) {
        val = parseInt(part, 8);
      } else if (/^\d+$/.test(part)) {
        val = parseInt(part, 10);
      } else {
        return null;
      }
      if (isNaN(val) || val < 0 || val > 255) {
        return null;
      }
      octets.push(val);
    }
    return octets.join('.');
  }

  // Check for single 32-bit integer (e.g. 2130706433 or 0x7f000001)
  if (/^\d+$/.test(trimmed) || /^0x[0-9a-fA-F]+$/.test(trimmed)) {
    const num = trimmed.startsWith('0x') ? parseInt(trimmed, 16) : parseInt(trimmed, 10);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      const o1 = (num >>> 24) & 255;
      const o2 = (num >>> 16) & 255;
      const o3 = (num >>> 8) & 255;
      const o4 = num & 255;
      return `${o1}.${o2}.${o3}.${o4}`;
    }
  }

  return null;
}

/**
 * Checks if an IPv6 string is valid and canonicalizes basic forms.
 */
export function isIpv6(ipStr: string): boolean {
  const trimmed = ipStr.trim().replace(/^\[|\]$/g, '');
  if (!trimmed.includes(':')) return false;

  // Basic validation of IPv6 structure
  const parts = trimmed.split('::');
  if (parts.length > 2) return false;

  const validHexSegment = /^[0-9a-fA-F]{1,4}$/;
  const allSegments = trimmed.split(':').filter(s => s.length > 0);

  for (const seg of allSegments) {
    if (seg.includes('.')) {
      // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
      const mappedIpv4 = normalizeIpv4(seg);
      if (!mappedIpv4) return false;
    } else if (!validHexSegment.test(seg)) {
      return false;
    }
  }

  return true;
}

/**
 * Classifies an IP address or hostname into a deterministic DestinationClass.
 */
export function classifyDestination(hostnameOrIp: string): DestinationClass {
  if (!hostnameOrIp || typeof hostnameOrIp !== 'string') {
    return 'INVALID';
  }

  let host = hostnameOrIp.trim().toLowerCase();
  while (host.endsWith('.')) {
    host = host.slice(0, -1);
  }

  // Check explicit metadata hostnames
  if (METADATA_HOSTNAMES.has(host)) {
    return 'METADATA';
  }

  // Check known controlled fixture hostnames
  if (FIXTURE_HOSTNAMES.has(host) || host.endsWith('.fixture.local') || host.endsWith('.fixture.test')) {
    if (host.includes('metadata')) return 'METADATA';
    if (host.includes('loopback')) return 'LOOPBACK';
    if (host.includes('private')) return 'PRIVATE_RFC1918';
    if (host.includes('linklocal')) return 'LINK_LOCAL';
    return 'CONTROLLED_FIXTURE';
  }

  // Check localhost string
  if (host === 'localhost' || host.endsWith('.localhost')) {
    return 'LOOPBACK';
  }

  // Check IPv4 forms
  const normalizedV4 = normalizeIpv4(host);
  if (normalizedV4) {
    const [o1, o2, o3, o4] = normalizedV4.split('.').map(n => parseInt(n, 10));

    // Metadata IP: 169.254.169.254 or 169.254.169.253 or 169.254.170.2 or 100.100.100.200
    if (
      (o1 === 169 && o2 === 254 && o3 === 169 && (o4 === 254 || o4 === 253)) ||
      (o1 === 169 && o2 === 254 && o3 === 170 && o4 === 2) ||
      (o1 === 100 && o2 === 100 && o3 === 100 && o4 === 200)
    ) {
      return 'METADATA';
    }

    // Loopback: 127.0.0.0/8
    if (o1 === 127) {
      return 'LOOPBACK';
    }

    // Unspecified: 0.0.0.0/8
    if (o1 === 0) {
      return 'UNSPECIFIED';
    }

    // Private RFC1918:
    // 10.0.0.0/8
    if (o1 === 10) {
      return 'PRIVATE_RFC1918';
    }
    // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
    if (o1 === 172 && o2 >= 16 && o2 <= 31) {
      return 'PRIVATE_RFC1918';
    }
    // 192.168.0.0/16
    if (o1 === 192 && o2 === 168) {
      return 'PRIVATE_RFC1918';
    }

    // Link-Local: 169.254.0.0/16
    if (o1 === 169 && o2 === 254) {
      return 'LINK_LOCAL';
    }

    // Broadcast: 255.255.255.255
    if (o1 === 255 && o2 === 255 && o3 === 255 && o4 === 255) {
      return 'INVALID';
    }

    return 'PUBLIC_EXTERNAL';
  }

  // Check IPv6 forms
  if (isIpv6(host)) {
    const cleanV6 = host.replace(/^\[|\]$/g, '').toLowerCase();

    // Loopback ::1
    if (cleanV6 === '::1' || cleanV6 === '0:0:0:0:0:0:0:1') {
      return 'LOOPBACK';
    }

    // Unspecified ::
    if (cleanV6 === '::' || cleanV6 === '0:0:0:0:0:0:0:0') {
      return 'UNSPECIFIED';
    }

    // IPv4-mapped IPv6: ::ffff:127.0.0.1 or ::ffff:7f00:1
    if (cleanV6.startsWith('::ffff:')) {
      const v4Part = cleanV6.slice(7);
      const normalizedMapped = normalizeIpv4(v4Part);
      if (normalizedMapped) {
        return classifyDestination(normalizedMapped);
      }
    }

    // Link-Local: fe80::/10
    if (cleanV6.startsWith('fe80:') || cleanV6.startsWith('fe8') || cleanV6.startsWith('fe9') || cleanV6.startsWith('fea') || cleanV6.startsWith('feb')) {
      return 'LINK_LOCAL';
    }

    // Unique Local: fc00::/7 (fc00:: to fdff::)
    if (cleanV6.startsWith('fc') || cleanV6.startsWith('fd')) {
      return 'PRIVATE_RFC1918';
    }

    return 'PUBLIC_EXTERNAL';
  }

  // Hostname string without IP formatting
  if (!host.includes('.') && host !== 'localhost') {
    // Single-label non-FQDN host (e.g. "internal-server", "intranet", "corp")
    return 'PRIVATE_RFC1918';
  }

  // Valid public domain
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host)) {
    return 'PUBLIC_EXTERNAL';
  }

  return 'INVALID';
}
