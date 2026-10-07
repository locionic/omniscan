import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

export interface SsrfValidationResult {
  valid: boolean;
  url?: URL;
  resolvedIp?: string;
  error?: string;
}

// Subnet matcher for IPv4
function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return true; // Malformed = reject
  }

  const [a, b] = parts;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 10.0.0.0/8 (Private)
  if (a === 10) return true;
  // 172.16.0.0/12 (Private)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 (Private)
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 (Link-Local / AWS Metadata)
  if (a === 169 && b === 254) return true;
  // 100.64.0.0/10 (Carrier-Grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;
  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (a >= 224) return true;

  return false;
}

/**
 * Expand the tail of an IPv4-mapped IPv6 address into dotted-decimal so it can be handed
 * to the IPv4 matcher. WHATWG serialises `::ffff:127.0.0.1` as the hex form `::ffff:7f00:1`,
 * while `dns.lookup` hands back the dotted form, so both spellings are accepted.
 * Returns null when the tail is neither shape.
 */
function expandIpv4MappedTail(tail: string): string | null {
  if (tail.includes(".")) return tail;

  const groups = tail.split(":");
  if (groups.length !== 2 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    return null;
  }

  const value = parseInt(groups[0], 16) * 0x10000 + parseInt(groups[1], 16);
  return `${value >>> 24}.${(value >>> 16) & 0xff}.${(value >>> 8) & 0xff}.${value & 0xff}`;
}

function isPrivateIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  // Loopback
  if (normalized === "::1" || normalized === "0:0:0:0:0:0:0:1") return true;
  // Unspecified
  if (normalized === "::" || normalized === "0:0:0:0:0:0:0:0") return true;
  // Link-local fe80::/10
  if (normalized.startsWith("fe80:") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) return true;
  // Unique local fc00::/7 (fd00::)
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  // IPv4-mapped IPv6 ::ffff:127.0.0.1, in either its dotted or its hex serialisation
  if (normalized.startsWith("::ffff:")) {
    const v4 = expandIpv4MappedTail(normalized.slice("::ffff:".length));
    if (v4 !== null && isIP(v4) === 4) return isPrivateIpv4(v4);
  }
  return false;
}

export async function validateAndPinUrl(rawUrl: string): Promise<SsrfValidationResult> {
  if (!rawUrl || typeof rawUrl !== "string") {
    return { valid: false, error: "URL is required" };
  }

  // Ensure protocol scheme
  let parsedUrl: URL;
  try {
    const withScheme = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
    parsedUrl = new URL(withScheme);
  } catch {
    return { valid: false, error: "Invalid URL format" };
  }

  // Only allow HTTP/HTTPS
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    return { valid: false, error: `Protocol '${parsedUrl.protocol}' is forbidden; only http/https allowed` };
  }

  const hostname = parsedUrl.hostname;
  if (!hostname || hostname === "localhost") {
    return { valid: false, error: "Localhost addresses are strictly forbidden" };
  }

  // Check if direct IP provided. WHATWG always serialises an IPv6 host with its brackets
  // ("[::1]"), and isIP() only understands the bare address, so strip them first —
  // otherwise every IPv6 literal reads as a hostname and falls through to DNS.
  const bareHostname = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  const directIpVersion = isIP(bareHostname);
  if (directIpVersion === 4) {
    if (isPrivateIpv4(bareHostname)) {
      return { valid: false, error: `Private/internal IPv4 address '${hostname}' is forbidden` };
    }
    return { valid: true, url: parsedUrl, resolvedIp: hostname };
  } else if (directIpVersion === 6) {
    if (isPrivateIpv6(bareHostname)) {
      return { valid: false, error: `Private/internal IPv6 address '${hostname}' is forbidden` };
    }
    return { valid: true, url: parsedUrl, resolvedIp: hostname };
  }

  // Resolve hostname via DNS
  try {
    const lookupRes = await lookup(hostname);
    const resolvedIp = lookupRes.address;

    if (lookupRes.family === 4) {
      if (isPrivateIpv4(resolvedIp)) {
        return { valid: false, error: `Host '${hostname}' resolved to forbidden private IP '${resolvedIp}'` };
      }
    } else if (lookupRes.family === 6) {
      if (isPrivateIpv6(resolvedIp)) {
        return { valid: false, error: `Host '${hostname}' resolved to forbidden private IP '${resolvedIp}'` };
      }
    }

    return { valid: true, url: parsedUrl, resolvedIp };
  } catch (err: any) {
    return { valid: false, error: `DNS resolution failed for host '${hostname}': ${err.message}` };
  }
}
