export interface ScanRequest {
  url: string;
  email: string;
  scanId?: string;
}

export interface HeaderCheck {
  header: string;
  present: boolean;
  value?: string;
  pass: boolean;
  score: number;
  recommendation: string;
}

export interface SecurityHeadersResult {
  score: number; // 0-100
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  checks: HeaderCheck[];
}

export interface TlsCertInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  sans: string[];
}

export interface TlsResult {
  score: number; // 0-100
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  protocol: string; // e.g. "TLSv1.3"
  cipher: string;
  authorized: boolean;
  cert?: TlsCertInfo;
  vulnerabilities: string[];
  recommendations: string[];
}

export interface DnsResult {
  score: number; // 0-100
  hasSpf: boolean;
  spfRecord?: string;
  spfLookupCount: number;
  spfValid: boolean;
  hasDmarc: boolean;
  dmarcRecord?: string;
  dmarcPolicy?: "reject" | "quarantine" | "none" | "invalid";
  hasMx: boolean;
  mxRecords: string[];
  hasCaa: boolean;
  hasDnssec: boolean;
  recommendations: string[];
}

export interface CoreWebVitals {
  lcp: number; // ms
  inp: number; // ms (or tbt proxy)
  cls: number; // unitless
  fcp: number; // ms
  ttfb: number; // ms
  speedIndex: number; // ms
}

export interface PerformanceResult {
  score: number; // 0-100
  accessibilityScore: number; // 0-100
  seoScore: number; // 0-100
  bestPracticesScore: number; // 0-100
  webVitals: CoreWebVitals;
  recommendations: string[];
}

export interface PriorityFix {
  title: string;
  category: "Performance" | "Security" | "DNS" | "SEO";
  severity: "critical" | "warning" | "info";
  detail: string;
  impact: string;
}

export interface CompositeScore {
  omniScore: number; // 0-100
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  performanceScore: number;
  securityScore: number;
  dnsScore: number;
  bestPracticesScore: number;
  summary: string;
  priorityFixes: PriorityFix[];
}

export interface FullAuditReport {
  scanId: string;
  targetUrl: string;
  targetDomain: string;
  recipientEmail: string;
  scannedAt: string;
  composite: CompositeScore;
  performance: PerformanceResult;
  security: {
    headers: SecurityHeadersResult;
    tls: TlsResult;
  };
  dns: DnsResult;
}
