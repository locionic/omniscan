import { test } from "node:test";
import assert from "node:assert/strict";
import type { CompositeScore, DnsResult, PriorityFix, SecurityHeadersResult, TlsCertInfo, TlsResult } from "../../src/types/index.ts";
import {
  COMPOSITE_WEIGHTS,
  computeCompositeScore,
  gradeFromScore,
} from "../../src/scoring/composite.ts";

/** Retrieve a single priority fix whose title contains `needle`, failing loudly when absent. */
function fixFor(composite: CompositeScore, needle: string): PriorityFix {
  const found = composite.priorityFixes.find((f) => f.title.includes(needle));
  assert.ok(found, `expected a fix matching "${needle}", got: ${composite.priorityFixes.map((f) => f.title).join(", ") || "(none)"}`);
  return found;
}

function makeHeaders(overrides: Partial<SecurityHeadersResult> = {}): SecurityHeadersResult {
  return { score: 100, grade: "A+", checks: [], ...overrides };
}

function makeCert(overrides: Partial<TlsCertInfo> = {}): TlsCertInfo {
  return {
    subject: "CN=example.com",
    issuer: "CN=R11",
    validFrom: "2026-01-01T00:00:00.000Z",
    validTo: "2027-01-01T00:00:00.000Z",
    daysRemaining: 90,
    sans: ["example.com"],
    ...overrides,
  };
}

function makeTls(overrides: Partial<TlsResult> = {}): TlsResult {
  return {
    score: 100,
    grade: "A+",
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    authorized: true,
    cert: makeCert(),
    vulnerabilities: [],
    recommendations: [],
    ...overrides,
  };
}

function makeDns(overrides: Partial<DnsResult> = {}): DnsResult {
  return {
    score: 100,
    hasSpf: true,
    spfRecord: "v=spf1 include:_spf.example.com ~all",
    spfLookupCount: 1,
    spfValid: true,
    hasDmarc: true,
    dmarcRecord: "v=DMARC1; p=reject",
    dmarcPolicy: "reject",
    hasMx: true,
    mxRecords: ["mx.example.com (priority 10)"],
    hasCaa: true,
    hasDnssec: false,
    recommendations: [],
    ...overrides,
  };
}

/** A failing header check, defaulting the fields a factory caller does not care about. */
function failingCheck(header: string, recommendation = `Fix ${header}.`) {
  return { header, present: false, pass: false, score: 0, recommendation };
}

test("perfect inputs score 100 / A+ with no priority fixes", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls(),
    dns: makeDns(),
  });

  assert.equal(composite.omniScore, 100);
  assert.equal(composite.grade, "A+");
  assert.deepEqual(composite.priorityFixes, []);
  assert.equal(composite.summary, "OmniScore 100/100 (A+) — no issues found.");
});

test("all-zero inputs score 0 / F", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders({ score: 0 }),
    tls: makeTls({ score: 0, authorized: false, protocol: "SSLv3", cert: makeCert({ daysRemaining: -1 }) }),
    dns: makeDns({ score: 0, hasSpf: false, hasDmarc: false, hasCaa: false }),
  });

  assert.equal(composite.omniScore, 0);
  assert.equal(composite.grade, "F");
  assert.equal(composite.securityScore, 0);
  assert.equal(composite.dnsScore, 0);
  assert.equal(composite.summary, "OmniScore 0/100 (F) — 5 critical, 1 warnings, 0 info.");
});

test("omniScore weights headers 0.4, tls 0.3 and dns 0.3", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders({ score: 100 }),
    tls: makeTls({ score: 50 }),
    dns: makeDns({ score: 0 }),
  });

  assert.deepEqual(COMPOSITE_WEIGHTS, { headers: 0.4, tls: 0.3, dns: 0.3 });
  assert.equal(composite.omniScore, 55); // 100*0.4 + 50*0.3 + 0*0.3
  assert.equal(composite.grade, "C");
});

test("securityScore averages headers and TLS while dnsScore passes through", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders({ score: 100 }),
    tls: makeTls({ score: 50 }),
    dns: makeDns({ score: 20 }),
  });

  assert.equal(composite.securityScore, 75); // (100 + 50) / 2
  assert.equal(composite.dnsScore, 20);
});

test("performanceScore and bestPracticesScore are 0 until their engines exist", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders({ score: 100 }),
    tls: makeTls({ score: 100 }),
    dns: makeDns({ score: 100 }),
  });

  assert.equal(composite.performanceScore, 0);
  assert.equal(composite.bestPracticesScore, 0);
});

test("gradeFromScore honours every grade boundary", () => {
  const table: Array<[number, string]> = [
    [95, "A+"],
    [94, "A"],
    [85, "A"],
    [84, "B"],
    [70, "B"],
    [69, "C"],
    [55, "C"],
    [54, "D"],
    [40, "D"],
    [39, "F"],
  ];

  for (const [score, expected] of table) {
    assert.equal(gradeFromScore(score), expected, `score ${score} should grade ${expected}`);
  }
});

test("a failing header check becomes a warning naming the header", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders({
      score: 75,
      checks: [failingCheck("Content-Security-Policy", "Implement CSP to block XSS.")],
    }),
    tls: makeTls(),
    dns: makeDns(),
  });

  assert.equal(composite.priorityFixes.length, 1);
  const fix = fixFor(composite, "Content-Security-Policy");
  assert.equal(fix.title, "Missing or weak Content-Security-Policy");
  assert.equal(fix.severity, "warning");
  assert.equal(fix.category, "Security");
  assert.equal(fix.detail, "Implement CSP to block XSS.");
  assert.ok(fix.impact.length > 0);
});

test("Set-Cookie failures are critical and X-Powered-By is only informational", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders({
      score: 70,
      checks: [failingCheck("X-Powered-By"), failingCheck("Set-Cookie Flags")],
    }),
    tls: makeTls(),
    dns: makeDns(),
  });

  assert.equal(fixFor(composite, "Set-Cookie Flags").severity, "critical");
  assert.equal(fixFor(composite, "X-Powered-By").severity, "info");
  // Sorted: critical ahead of info.
  assert.deepEqual(
    composite.priorityFixes.map((f) => f.severity),
    ["critical", "info"],
  );
});

test("an expired certificate is critical and one under 14 days is a warning", () => {
  const expired = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls({ cert: makeCert({ daysRemaining: 0 }) }),
    dns: makeDns(),
  });

  assert.equal(fixFor(expired, "certificate").severity, "critical");
  assert.equal(fixFor(expired, "certificate").title, "TLS certificate has expired");
  // Expiry subsumes the <14 day warning — it must not be reported twice.
  assert.equal(expired.priorityFixes.length, 1);

  const expiringSoon = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls({ cert: makeCert({ daysRemaining: 5 }) }),
    dns: makeDns(),
  });

  assert.equal(expiringSoon.priorityFixes.length, 1);
  assert.equal(fixFor(expiringSoon, "certificate").severity, "warning");
  assert.equal(fixFor(expiringSoon, "certificate").title, "TLS certificate expires in 5 days");
});

test("untrusted certificates and legacy protocols are critical", () => {
  const untrusted = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls({ authorized: false }),
    dns: makeDns(),
  });
  assert.equal(fixFor(untrusted, "Untrusted TLS certificate").severity, "critical");

  for (const protocol of ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]) {
    const legacy = computeCompositeScore({
      headers: makeHeaders(),
      tls: makeTls({ protocol }),
      dns: makeDns(),
    });
    const fix = fixFor(legacy, "Deprecated TLS protocol");
    assert.equal(fix.severity, "critical", `${protocol} should be critical`);
    assert.equal(fix.category, "Security");
    assert.ok(fix.title.includes(protocol));
  }

  // Modern protocols are not flagged.
  for (const protocol of ["TLSv1.2", "TLSv1.3"]) {
    const modern = computeCompositeScore({
      headers: makeHeaders(),
      tls: makeTls({ protocol }),
      dns: makeDns(),
    });
    assert.deepEqual(modern.priorityFixes, [], `${protocol} should not raise a fix`);
  }
});

test("missing SPF and DMARC records are critical", () => {
  const noSpf = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls(),
    dns: makeDns({ hasSpf: false, spfRecord: undefined }),
  });
  assert.equal(fixFor(noSpf, "Missing SPF record").severity, "critical");
  assert.equal(fixFor(noSpf, "Missing SPF record").category, "DNS");

  const noDmarc = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls(),
    dns: makeDns({ hasDmarc: false, dmarcRecord: undefined, dmarcPolicy: undefined }),
  });
  assert.equal(fixFor(noDmarc, "Missing DMARC record").severity, "critical");
});

test("an SPF record that fails validation is a warning", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls(),
    dns: makeDns({ spfValid: false, spfLookupCount: 12 }),
  });

  assert.equal(fixFor(composite, "Invalid SPF record").severity, "warning");
});

test("DMARC p=none is a warning while an invalid policy is critical", () => {
  const monitoring = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls(),
    dns: makeDns({ dmarcPolicy: "none" }),
  });
  assert.equal(fixFor(monitoring, "p=none").severity, "warning");

  const invalid = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls(),
    dns: makeDns({ dmarcPolicy: "invalid" }),
  });
  assert.equal(fixFor(invalid, "Invalid or missing DMARC policy").severity, "critical");

  // hasDmarc with no parsed policy is the same failure.
  const noPolicy = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls(),
    dns: makeDns({ dmarcPolicy: undefined }),
  });
  assert.equal(fixFor(noPolicy, "Invalid or missing DMARC policy").severity, "critical");
});

test("a missing CAA record is a warning", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders(),
    tls: makeTls(),
    dns: makeDns({ hasCaa: false }),
  });

  assert.equal(composite.priorityFixes.length, 1);
  assert.equal(fixFor(composite, "Missing CAA record").severity, "warning");
  assert.equal(fixFor(composite, "Missing CAA record").category, "DNS");
});

test("critical fixes sort ahead of warnings, which sort ahead of info", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders({
      score: 40,
      checks: [failingCheck("X-Powered-By"), failingCheck("Content-Security-Policy"), failingCheck("Set-Cookie Flags")],
    }),
    tls: makeTls({ authorized: false }),
    dns: makeDns({ hasSpf: false, hasCaa: false }),
  });

  assert.deepEqual(
    composite.priorityFixes.map((f) => [f.severity, f.title]),
    [
      ["critical", "Missing or weak Set-Cookie Flags"],
      ["critical", "Untrusted TLS certificate"],
      ["critical", "Missing SPF record"],
      ["warning", "Missing or weak Content-Security-Policy"],
      ["warning", "Missing CAA record"],
      ["info", "Missing or weak X-Powered-By"],
    ],
  );
  assert.equal(composite.summary, `OmniScore ${composite.omniScore}/100 (${composite.grade}) — 3 critical, 2 warnings, 1 info.`);
});

test("out-of-range component scores clamp into 0-100", () => {
  const composite = computeCompositeScore({
    headers: makeHeaders({ score: 150 }),
    tls: makeTls({ score: -20 }),
    dns: makeDns({ score: 150 }),
  });

  assert.equal(composite.securityScore, 50); // (100 + 0) / 2
  assert.equal(composite.dnsScore, 100);
  assert.equal(composite.omniScore, 70); // 100*0.4 + 0*0.3 + 100*0.3
  assert.equal(composite.grade, "B");

  // A lone 150 weights to 100, not 150 — an unclamped run would land on 60 / C.
  const loneSpike = computeCompositeScore({
    headers: makeHeaders({ score: 150 }),
    tls: makeTls({ score: 0 }),
    dns: makeDns({ score: 0 }),
  });
  assert.equal(loneSpike.omniScore, 40);
  assert.equal(loneSpike.grade, "D");

  for (const value of [composite.omniScore, composite.securityScore, composite.dnsScore]) {
    assert.ok(value >= 0 && value <= 100, `score ${value} should sit within 0-100`);
  }
});
