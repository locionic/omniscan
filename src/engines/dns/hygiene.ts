import { resolveTxt, resolveMx, resolveCaa } from "node:dns/promises";
import type { DnsResult } from "../../types/index.js";

export function countSpfLookups(spfRecord: string): number {
  const tokens = spfRecord.split(/\s+/);
  let count = 0;
  for (const token of tokens) {
    const lower = token.toLowerCase();
    if (
      lower.startsWith("include:") ||
      lower.startsWith("a:") ||
      lower === "a" ||
      lower.startsWith("mx:") ||
      lower === "mx" ||
      lower.startsWith("ptr:") ||
      lower === "ptr" ||
      lower.startsWith("exists:") ||
      lower.startsWith("redirect=")
    ) {
      count++;
    }
  }
  return count;
}

export async function auditDns(domain: string): Promise<DnsResult> {
  let score = 100;
  const recommendations: string[] = [];

  let hasSpf = false;
  let spfRecord: string | undefined;
  let spfLookupCount = 0;
  let spfValid = false;

  let hasDmarc = false;
  let dmarcRecord: string | undefined;
  let dmarcPolicy: "reject" | "quarantine" | "none" | "invalid" | undefined;

  let hasMx = false;
  const mxRecords: string[] = [];
  let hasCaa = false;
  const hasDnssec = false; // Passive resolver check

  // 1. Audit SPF via TXT
  try {
    const txtRecords = await resolveTxt(domain);
    for (const group of txtRecords) {
      const fullTxt = group.join("");
      if (fullTxt.toLowerCase().startsWith("v=spf1")) {
        hasSpf = true;
        spfRecord = fullTxt;
        spfLookupCount = countSpfLookups(fullTxt);
        break;
      }
    }
  } catch {
    // No TXT records or resolution error
  }

  if (!hasSpf) {
    score -= 30;
    recommendations.push("Add an SPF record (v=spf1) to protect your domain from sender email spoofing.");
  } else {
    if (spfLookupCount > 10) {
      score -= 20;
      spfValid = false;
      recommendations.push(`SPF record has ${spfLookupCount} DNS lookups, exceeding the RFC 7208 limit of 10. Flatten your SPF record.`);
    } else {
      spfValid = true;
    }
  }

  // 2. Audit DMARC
  try {
    const dmarcTxt = await resolveTxt(`_dmarc.${domain}`);
    for (const group of dmarcTxt) {
      const full = group.join("");
      if (full.toLowerCase().startsWith("v=dmarc1")) {
        hasDmarc = true;
        dmarcRecord = full;

        const policyMatch = full.match(/p=([a-zA-Z]+)/i);
        if (policyMatch) {
          const pol = policyMatch[1].toLowerCase();
          if (pol === "reject" || pol === "quarantine" || pol === "none") {
            dmarcPolicy = pol;
          } else {
            dmarcPolicy = "invalid";
          }
        }
        break;
      }
    }
  } catch {
    // No DMARC record
  }

  if (!hasDmarc) {
    score -= 35;
    recommendations.push("Publish a DMARC policy (_dmarc record) with p=quarantine or p=reject to enforce email protection.");
  } else {
    if (dmarcPolicy === "none") {
      score -= 15;
      recommendations.push("DMARC policy is currently set to 'p=none' (monitoring only). Upgrade to 'p=quarantine' or 'p=reject' for active protection.");
    } else if (dmarcPolicy === "reject" || dmarcPolicy === "quarantine") {
      // Strong enforcement!
    } else {
      score -= 25;
      recommendations.push("DMARC record syntax is invalid or missing 'p=' tag.");
    }
  }

  // 3. Audit MX Records
  try {
    const mxList = await resolveMx(domain);
    if (mxList && mxList.length > 0) {
      hasMx = true;
      for (const mx of mxList) {
        mxRecords.push(`${mx.exchange} (priority ${mx.priority})`);
      }
    }
  } catch {
    // No MX
  }

  // 4. Audit CAA Records
  try {
    const caaList = await resolveCaa(domain);
    if (caaList && caaList.length > 0) {
      hasCaa = true;
    }
  } catch {
    // No CAA
  }

  if (!hasCaa) {
    score -= 10;
    recommendations.push("Add CAA (Certificate Authority Authorization) records to specify which CAs are permitted to issue certificates for your domain.");
  }

  const finalScore = Math.max(0, Math.min(100, score));

  return {
    score: finalScore,
    hasSpf,
    spfRecord,
    spfLookupCount,
    spfValid,
    hasDmarc,
    dmarcRecord,
    dmarcPolicy,
    hasMx,
    mxRecords,
    hasCaa,
    hasDnssec,
    recommendations,
  };
}
