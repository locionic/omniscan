import type {
  CompositeScore,
  DnsResult,
  PriorityFix,
  SecurityHeadersResult,
  TlsResult,
} from "../types/index.js";

/** Relative weight of each engine in the OmniScore. Must sum to 1. */
export const COMPOSITE_WEIGHTS = { headers: 0.4, tls: 0.3, dns: 0.3 } as const;

/** Component scores are clamped to this range before weighting. */
const SCORE_MIN = 0;
const SCORE_MAX = 100;

const SEVERITY_RANK: Record<PriorityFix["severity"], number> = {
  critical: 0,
  warning: 1,
  info: 2,
};

export type Grade = CompositeScore["grade"];

export function gradeFromScore(score: number): Grade {
  if (score >= 95) return "A+";
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

export interface CompositeInputs {
  headers: SecurityHeadersResult;
  tls: TlsResult;
  dns: DnsResult;
}

function clamp(value: number): number {
  if (Number.isNaN(value)) return SCORE_MIN;
  return Math.max(SCORE_MIN, Math.min(SCORE_MAX, value));
}

/** Cookie issues expose sessions outright; framework banners only leak trivia. */
function headerFixSeverity(header: string): PriorityFix["severity"] {
  if (header === "Set-Cookie Flags") return "critical";
  if (header === "X-Powered-By") return "info";
  return "warning";
}

/** Protocol versions that are actually deprecated — TLS 1.2/1.3 are fine. */
function isDeprecatedProtocol(protocol: string): boolean {
  return /^SSL/.test(protocol) || protocol === "TLSv1" || protocol === "TLSv1.1";
}

function collectFixes(inputs: CompositeInputs): PriorityFix[] {
  const { headers, tls, dns } = inputs;
  const fixes: PriorityFix[] = [];

  // --- Security headers -------------------------------------------------
  for (const check of headers.checks) {
    if (check.pass !== false) continue;
    fixes.push({
      title: `Missing or weak ${check.header}`,
      category: "Security",
      severity: headerFixSeverity(check.header),
      detail: check.recommendation,
      impact: "Closes a gap attackers can use against this site.",
    });
  }

  // --- TLS --------------------------------------------------------------
  const daysRemaining = tls.cert?.daysRemaining;
  if (daysRemaining !== undefined && daysRemaining <= 0) {
    fixes.push({
      title: "TLS certificate has expired",
      category: "Security",
      severity: "critical",
      detail: "Renew the certificate immediately; browsers show security warnings to every visitor.",
      impact: "Visitors see full-page browser security warnings.",
    });
  } else if (daysRemaining !== undefined && daysRemaining < 14) {
    fixes.push({
      title: `TLS certificate expires in ${daysRemaining} days`,
      category: "Security",
      severity: "warning",
      detail: "Renew the certificate before it expires to avoid visitor-facing downtime.",
      impact: "Prevents an outage once the certificate lapses.",
    });
  }

  if (!tls.authorized) {
    fixes.push({
      title: "Untrusted TLS certificate",
      category: "Security",
      severity: "critical",
      detail: "The certificate chain did not validate. Replace a self-signed or otherwise untrusted certificate with one from a recognized CA.",
      impact: "Visitors see browser security warnings and cannot safely authenticate.",
    });
  }

  if (isDeprecatedProtocol(tls.protocol)) {
    fixes.push({
      title: `Deprecated TLS protocol: ${tls.protocol}`,
      category: "Security",
      severity: "critical",
      detail: `Disable ${tls.protocol} and restrict the server to TLS 1.2 and TLS 1.3.`,
      impact: "Legacy protocols are exposed to downgrade and padding-oracle attacks.",
    });
  }

  // --- DNS --------------------------------------------------------------
  if (!dns.hasSpf) {
    fixes.push({
      title: "Missing SPF record",
      category: "DNS",
      severity: "critical",
      detail: "Publish an SPF record (v=spf1 ...) listing the servers allowed to send mail for this domain.",
      impact: "Anyone can spoof your domain as an email sender.",
    });
  } else if (!dns.spfValid) {
    fixes.push({
      title: "Invalid SPF record",
      category: "DNS",
      severity: "warning",
      detail: "The SPF record exceeds the RFC 7208 limit of 10 DNS lookups. Flatten the record or remove unused mechanisms.",
      impact: "Receivers may discard the SPF result and fall back to weaker checks.",
    });
  }

  if (!dns.hasDmarc) {
    fixes.push({
      title: "Missing DMARC record",
      category: "DNS",
      severity: "critical",
      detail: "Publish a _dmarc TXT record with p=quarantine or p=reject to enforce email protection.",
      impact: "Nothing instructs receivers to quarantine or reject spoofed mail.",
    });
  } else if (dns.dmarcPolicy === "none") {
    fixes.push({
      title: "DMARC policy is monitoring-only (p=none)",
      category: "DNS",
      severity: "warning",
      detail: "Upgrade the policy to p=quarantine or p=reject once the reports are clean.",
      impact: "Spoofed mail is reported but never blocked or quarantined.",
    });
  } else if (dns.dmarcPolicy === "invalid" || dns.dmarcPolicy === undefined) {
    fixes.push({
      title: "Invalid or missing DMARC policy",
      category: "DNS",
      severity: "critical",
      detail: "The DMARC record is malformed or has no usable p= tag. Fix the record syntax.",
      impact: "Receivers ignore malformed DMARC records entirely.",
    });
  }

  if (!dns.hasCaa) {
    fixes.push({
      title: "Missing CAA record",
      category: "DNS",
      severity: "warning",
      detail: "Add CAA records naming the certificate authorities permitted to issue certificates for this domain.",
      impact: "Any public CA may issue certificates for your domain.",
    });
  }

  // Stable sort: severity order only, so insertion order breaks ties.
  return fixes.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

function countSeverity(fixes: PriorityFix[], severity: PriorityFix["severity"]): number {
  return fixes.filter((fix) => fix.severity === severity).length;
}

export function computeCompositeScore(inputs: CompositeInputs): CompositeScore {
  const headersScore = clamp(inputs.headers.score);
  const tlsScore = clamp(inputs.tls.score);
  const dnsScore = clamp(inputs.dns.score);

  const omniScore = Math.round(
    headersScore * COMPOSITE_WEIGHTS.headers + tlsScore * COMPOSITE_WEIGHTS.tls + dnsScore * COMPOSITE_WEIGHTS.dns,
  );
  const grade = gradeFromScore(omniScore);

  // TODO: performance engine does not exist yet — wire Lighthouse/Core Web Vitals
  // in once it lands, and keep it out of omniScore until its weight is decided.
  const performanceScore = 0;
  // TODO: best-practices signal has no engine yet either.
  const bestPracticesScore = 0;

  const priorityFixes = collectFixes(inputs);

  const summary =
    priorityFixes.length === 0
      ? `OmniScore ${omniScore}/100 (${grade}) — no issues found.`
      : `OmniScore ${omniScore}/100 (${grade}) — ${countSeverity(priorityFixes, "critical")} critical, ` +
        `${countSeverity(priorityFixes, "warning")} warnings, ${countSeverity(priorityFixes, "info")} info.`;

  return {
    omniScore,
    grade,
    // TODO: placeholder until the performance engine ships.
    performanceScore,
    securityScore: Math.round((headersScore + tlsScore) / 2),
    dnsScore,
    // TODO: placeholder until the best-practices signal ships.
    bestPracticesScore,
    summary,
    priorityFixes,
  };
}
