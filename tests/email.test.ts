import { test, describe } from "node:test";
import assert from "node:assert/strict";
import type { FullAuditReport } from "../src/types/index.ts";
import {
  AuditReportEmail,
  buildPdfUrl,
  buildReportUrl,
  buildSubject,
  CategoryCards,
  categoryMetrics,
  clampScore,
  DownloadButtons,
  EmailTemplate,
  escapeHtml,
  formatScannedAt,
  GradeBanner,
  gradeColor,
  PriorityFixes,
  renderCategoryCards,
  renderDownloadButtons,
  renderEmailHtml,
  renderEmailText,
  renderGradeBanner,
  renderMeter,
  renderPriorityFixes,
  ReportEmail,
  safeUrl,
  scoreColor,
} from "../src/reports/email-template.ts";
import {
  buildMessage,
  createMemoryTransport,
  createResendTransport,
  dispatchEmail,
  dispatchResendEmail,
  EmailValidationError,
  encodeRfc2047,
  formatAddress,
  generateMessageId,
  isValidEmail,
  normalizeRecipient,
  sanitizeHeaderValue,
  serializeMessage,
  type EmailMessage,
} from "../src/email/dispatcher.ts";

function makeReport(overrides: Partial<FullAuditReport> = {}): FullAuditReport {
  const report: FullAuditReport = {
    scanId: "scan-001",
    targetUrl: "https://example.com",
    targetDomain: "example.com",
    recipientEmail: "ops@example.com",
    scannedAt: "2026-10-10T12:00:00.000Z",
    composite: {
      omniScore: 88,
      grade: "B",
      performanceScore: 90,
      securityScore: 85,
      dnsScore: 80,
      bestPracticesScore: 95,
      summary: "Solid foundation with a few gaps.",
      priorityFixes: [
        {
          title: "Add a Content-Security-Policy",
          category: "Security",
          severity: "critical",
          detail: "No CSP header is returned.",
          impact: "Blocks XSS and code injection.",
        },
        {
          title: "Publish a DMARC record",
          category: "DNS",
          severity: "warning",
          detail: "No _dmarc TXT record found.",
          impact: "Stops domain spoofing.",
        },
        {
          title: "Enable Brotli compression",
          category: "Performance",
          severity: "info",
          detail: "Text assets are served uncompressed.",
          impact: "Faster first paint.",
        },
        {
          title: "Trim unused CSS",
          category: "Performance",
          severity: "info",
          detail: "Stylesheet is larger than needed.",
          impact: "Lower render cost.",
        },
      ],
    },
    performance: {
      score: 90,
      accessibilityScore: 88,
      seoScore: 92,
      bestPracticesScore: 95,
      webVitals: { lcp: 1200, inp: 80, cls: 0.05, fcp: 700, ttfb: 220, speedIndex: 1400 },
      recommendations: ["Enable Brotli compression."],
    },
    security: {
      headers: {
        score: 85,
        grade: "B",
        checks: [
          {
            header: "Content-Security-Policy",
            present: false,
            pass: false,
            score: 0,
            recommendation: "Implement CSP.",
          },
        ],
      },
      tls: {
        score: 90,
        grade: "A",
        protocol: "TLSv1.3",
        cipher: "TLS_AES_256_GCM_SHA384",
        authorized: true,
        vulnerabilities: [],
        recommendations: [],
      },
    },
    dns: {
      score: 80,
      hasSpf: true,
      spfRecord: "v=spf1 -all",
      spfLookupCount: 0,
      spfValid: true,
      hasDmarc: false,
      hasMx: true,
      mxRecords: ["mail.example.com (priority 10)"],
      hasCaa: true,
      hasDnssec: false,
      recommendations: [],
    },
    ...overrides,
  };
  return report;
}

describe("escapeHtml", () => {
  test("escapes every character that could break out of markup", () => {
    assert.equal(escapeHtml(`<script>"x" & 'y'</script>`), "&lt;script&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/script&gt;");
  });

  test("ampersand is escaped first so entities are not double-broken", () => {
    assert.equal(escapeHtml("&lt;"), "&amp;lt;");
  });

  test("tolerates null and undefined", () => {
    assert.equal(escapeHtml(null), "");
    assert.equal(escapeHtml(undefined), "");
  });
});

describe("safeUrl", () => {
  test("allows http and https", () => {
    assert.equal(safeUrl("https://app.omniscan.io/x"), "https://app.omniscan.io/x");
    assert.equal(safeUrl("  http://example.com  "), "http://example.com");
  });

  test("rejects script and data URLs", () => {
    assert.equal(safeUrl("javascript:alert(1)"), undefined);
    assert.equal(safeUrl("data:text/html,<script>alert(1)</script>"), undefined);
    assert.equal(safeUrl("vbscript:msgbox(1)"), undefined);
    assert.equal(safeUrl(""), undefined);
    assert.equal(safeUrl(undefined), undefined);
  });
});

describe("score helpers", () => {
  test("clamps scores into 0-100", () => {
    assert.equal(clampScore(150), 100);
    assert.equal(clampScore(-20), 0);
    assert.equal(clampScore(72.6), 73);
    assert.equal(clampScore(Number.NaN), 0);
  });

  test("maps scores to severity colors", () => {
    assert.equal(scoreColor(95), "#16a34a");
    assert.equal(scoreColor(75), "#0284c7");
    assert.equal(scoreColor(55), "#d97706");
    assert.equal(scoreColor(10), "#dc2626");
  });

  test("maps every letter grade to a color", () => {
    for (const grade of ["A+", "A", "B", "C", "D", "F"] as const) {
      assert.match(gradeColor(grade), /^#[0-9a-f]{6}$/);
    }
  });

  test("formats scan date, blanking unparseable input", () => {
    assert.equal(formatScannedAt("2026-10-10T12:00:00.000Z"), "Oct 10, 2026");
    assert.equal(formatScannedAt("not-a-date"), "");
  });
});

describe("categoryMetrics", () => {
  test("exposes exactly the four category cards in order", () => {
    const metrics = categoryMetrics(makeReport());
    assert.deepEqual(
      metrics.map((m) => m.key),
      ["performance", "security", "dns", "bestPractices"]
    );
    assert.deepEqual(
      metrics.map((m) => m.score),
      [90, 85, 80, 95]
    );
  });

  test("survives missing engine output", () => {
    const metrics = categoryMetrics({ composite: makeReport().composite } as FullAuditReport);
    assert.deepEqual(
      metrics.map((m) => m.score),
      [0, 0, 0, 0]
    );
  });
});

describe("grade banner", () => {
  test("renders the letter grade, score, summary and domain", () => {
    const banner = renderGradeBanner(makeReport());
    assert.match(banner, /aria-label="Overall grade B, 88 out of 100"/);
    assert.match(banner, />B</);
    assert.match(banner, /88 out of 100/);
    assert.match(banner, /Solid foundation with a few gaps\./);
    assert.match(banner, /example\.com/);
  });

  test("escapes a hostile summary and domain", () => {
    const report = makeReport({
      targetDomain: "evil<svg/onload=alert(1)>",
      composite: { ...makeReport().composite, summary: "<img src=x onerror=alert(1)>" },
    });
    const banner = renderGradeBanner(report);
    assert.ok(!banner.includes("<svg"));
    assert.ok(!banner.includes("<img src=x"));
    assert.match(banner, /&lt;svg\/onload=alert\(1\)&gt;/);
  });
});

describe("radial progress meters", () => {
  test("renders a conic gradient plus a table-safe fallback bar", () => {
    const meter = renderMeter(75, "#0284c7", "Performance");
    assert.match(meter, /conic-gradient\(#0284c7 0deg 270deg, #e2e8f0 270deg 360deg\)/);
    assert.equal((meter.match(/height:6px/g) ?? []).length, 10);
    assert.equal((meter.match(/bgcolor="#0284c7"/g) ?? []).length, 8);
    assert.match(meter, /aria-label="Performance: 75 out of 100"/);
  });

  test("scales arc and filled segments with the score", () => {
    assert.match(renderMeter(0, "#dc2626", "DNS"), /0deg 0deg, #e2e8f0 0deg 360deg/);
    assert.equal((renderMeter(0, "#dc2626", "DNS").match(/bgcolor="#dc2626"/g) ?? []).length, 0);
    assert.match(renderMeter(100, "#16a34a", "Security"), /#16a34a 0deg 360deg/);
    assert.equal((renderMeter(100, "#16a34a", "Security").match(/bgcolor="#16a34a"/g) ?? []).length, 10);
  });

  test("clamps out-of-range scores so the arc stays renderable", () => {
    assert.match(renderMeter(140, "#16a34a", "Security"), /0deg 360deg/);
    assert.match(renderMeter(-30, "#dc2626", "Security"), /0deg 0deg/);
  });
});

describe("category cards", () => {
  test("renders all four categories with their meters", () => {
    const cards = renderCategoryCards(makeReport());
    for (const label of ["Performance", "Security", "DNS", "Best Practices"]) {
      assert.ok(cards.includes(label), `missing card: ${label}`);
    }
    assert.match(cards, /aria-label="Performance: 90 out of 100"/);
    assert.match(cards, /aria-label="DNS: 80 out of 100"/);
    assert.match(cards, /LCP 1200ms/);
    assert.match(cards, /TLSv1\.3/);
  });

  test("falls back to a no-DMARC blurb when the record is absent", () => {
    assert.match(renderCategoryCards(makeReport()), /No DMARC/);
  });

  test("pairs MSO conditionals with a two-column row for Outlook", () => {
    const cards = renderCategoryCards(makeReport());
    assert.match(cards, /<!--\[if mso\]><table role="presentation" width="100%"/);
    assert.match(cards, /<!--\[if mso\]><\/td><td width="264" valign="top"><!\[endif\]-->/);
    assert.match(cards, /<!--\[if mso\]><\/td><\/tr><\/table><!\[endif\]-->/);
  });
});

describe("priority fixes", () => {
  test("shows at most the top three fixes", () => {
    const fixes = renderPriorityFixes(makeReport());
    assert.ok(fixes.includes("Add a Content-Security-Policy"));
    assert.ok(fixes.includes("Publish a DMARC record"));
    assert.ok(fixes.includes("Enable Brotli compression"));
    assert.ok(!fixes.includes("Trim unused CSS"));
  });

  test("numbers the rows and tags severity and category", () => {
    const fixes = renderPriorityFixes(makeReport());
    assert.match(fixes, /font-size:18px;font-weight:700;color:#cbd5e1;line-height:24px;">1</);
    assert.match(fixes, /Critical/);
    assert.match(fixes, /Warning/);
    assert.match(fixes, />Performance</);
  });

  test("omits the divider on the final row", () => {
    const single = { ...makeReport(), composite: { ...makeReport().composite, priorityFixes: [] } };
    assert.match(renderPriorityFixes(single), /No critical issues found/);
    assert.equal((renderPriorityFixes(makeReport()).match(/border-bottom/g) ?? []).length, 2);
  });

  test("escapes fix text", () => {
    const report = makeReport();
    report.composite.priorityFixes = [
      { title: "<b>x</b>", category: "Security", severity: "critical", detail: "a & b", impact: "<i>y</i>" },
    ];
    const fixes = renderPriorityFixes(report);
    assert.ok(!fixes.includes("<b>x</b>"));
    assert.match(fixes, /&lt;b&gt;x&lt;\/b&gt;/);
  });
});

describe("report links and download buttons", () => {
  test("derives PDF and report URLs from the base URL", () => {
    const report = makeReport();
    assert.equal(buildPdfUrl(report, { baseUrl: "https://app.omniscan.io" }), "https://app.omniscan.io/reports/scan-001/download.pdf");
    assert.equal(buildReportUrl(report, { baseUrl: "https://app.omniscan.io" }), "https://app.omniscan.io/reports/scan-001");
  });

  test("normalizes a trailing slash on the base URL", () => {
    assert.equal(buildPdfUrl(makeReport(), { baseUrl: "https://app.omniscan.io///" }), "https://app.omniscan.io/reports/scan-001/download.pdf");
  });

  test("percent-encodes an unsafe scan id", () => {
    assert.match(buildPdfUrl(makeReport({ scanId: "a/../b c" }), { baseUrl: "https://x.io" }), /reports\/a%2F..%2Fb%20c\/download\.pdf$/);
  });

  test("honours explicit overrides", () => {
    const report = makeReport();
    assert.equal(buildPdfUrl(report, { pdfUrl: "https://cdn.omniscan.io/r.pdf" }), "https://cdn.omniscan.io/r.pdf");
    assert.equal(buildReportUrl(report, { reportUrl: "https://omniscan.io/r/9" }), "https://omniscan.io/r/9");
  });

  test("ignores a javascript: override", () => {
    assert.equal(buildPdfUrl(makeReport(), { pdfUrl: "javascript:alert(1)" }), "https://app.omniscan.io/reports/scan-001/download.pdf");
  });

  test("renders both buttons with the PDF one primary", () => {
    const buttons = renderDownloadButtons(makeReport(), { baseUrl: "https://app.omniscan.io" });
    assert.match(buttons, /Download PDF Report/);
    assert.match(buttons, /View Full Report Online/);
    assert.match(buttons, /href="https:\/\/app\.omniscan\.io\/reports\/scan-001\/download\.pdf"/);
    assert.match(buttons, /background:#0f172a;border:2px solid #0f172a/);
  });

  test("gives Outlook a VML roundrect fallback", () => {
    const buttons = renderDownloadButtons(makeReport());
    assert.match(buttons, /<v:roundrect xmlns:v="urn:schemas-microsoft-com:vml"/);
    assert.match(buttons, /mso-hide:all/);
  });
});

describe("subject line", () => {
  test("includes the domain, score and grade", () => {
    assert.equal(buildSubject(makeReport()), "example.com scored 88/100 (B) — OmniScan audit");
  });

  test("falls back when the domain is missing", () => {
    assert.match(buildSubject(makeReport({ targetDomain: "" })), /^your site scored/);
  });
});

describe("renderEmailHtml", () => {
  const html = renderEmailHtml(makeReport());

  test("emits a complete responsive email document", () => {
    assert.match(html, /^<!DOCTYPE html PUBLIC/);
    assert.match(html, /<meta name="viewport" content="width=device-width,initial-scale=1"/);
    assert.match(html, /@media only screen and \(max-width:600px\)/);
    assert.match(html, /<\/html>\s*$/);
  });

  test("stacks category cards and pads sections on small screens", () => {
    assert.match(html, /\.stack-column \{ display:block !important; width:100% !important;/);
    assert.match(html, /\.stack-pad \{ padding-left:20px !important; padding-right:20px !important; \}/);
    assert.match(html, /class="stack-column"/);
  });

  test("hides the preheader from the visible body", () => {
    assert.match(html, /<div class="preheader" style="display:none;max-height:0;max-width:0;overflow:hidden;">/);
  });

  test("contains every required section", () => {
    assert.match(html, /Overall grade B, 88 out of 100/);
    assert.ok(html.includes("Performance") && html.includes("Security") && html.includes("DNS") && html.includes("Best Practices"));
    assert.match(html, /Top priority fixes/);
    assert.match(html, /Download PDF Report/);
  });

  test("uses table-based markup with presentational roles", () => {
    assert.match(html, /<table role="presentation"/);
    assert.match(html, /cellpadding="0" cellspacing="0" border="0"/);
  });

  test("keeps user-controlled content out of the href attributes", () => {
    const report = makeReport({ targetUrl: 'javascript:alert("xss")' });
    const rendered = renderEmailHtml(report);
    assert.ok(!/href="javascript:/i.test(rendered));
  });

  test("applies a custom app name", () => {
    assert.match(renderEmailHtml(makeReport(), { appName: "Acme Audit" }), /Acme Audit/);
  });
});

describe("renderEmailText", () => {
  const text = renderEmailText(makeReport());

  test("includes the grade and every category score", () => {
    assert.match(text, /OVERALL GRADE: B \(88\/100\)/);
    for (const label of ["Performance", "Security", "DNS", "Best Practices"]) {
      assert.match(text, new RegExp(`${label}\\s+\\d+/100`));
    }
  });

  test("lists only the top three fixes with severity", () => {
    assert.match(text, /\[CRITICAL\] Add a Content-Security-Policy/);
    assert.ok(!text.includes("Trim unused CSS"));
  });

  test("appends both download links", () => {
    assert.match(text, /Download the PDF report: https:\/\/app\.omniscan\.io\/reports\/scan-001\/download\.pdf/);
    assert.match(text, /View the full report online: https:\/\/app\.omniscan\.io\/reports\/scan-001/);
  });

  test("stays readable with no fixes", () => {
    const report = makeReport();
    report.composite.priorityFixes = [];
    assert.match(renderEmailText(report), /No critical issues found\./);
  });
});

describe("email validation", () => {
  test("accepts ordinary addresses", () => {
    for (const email of ["ops@example.com", "a.b+tag@sub.example.co.uk"]) {
      assert.equal(isValidEmail(email), true, email);
    }
  });

  test("rejects malformed addresses and header injection", () => {
    for (const email of ["", "  ", "no-at-sign", "@example.com", "a@b", "a b@example.com", "a@example.com\r\nBcc: x@y.com"]) {
      assert.equal(isValidEmail(email), false, JSON.stringify(email));
    }
  });

  test("normalizes a recipient and keeps the display name", () => {
    assert.deepEqual(normalizeRecipient({ email: "  ops@example.com ", name: "Ops" }), { email: "ops@example.com", name: "Ops" });
    assert.deepEqual(normalizeRecipient("ops@example.com"), { email: "ops@example.com", name: undefined });
  });

  test("throws on a missing or invalid recipient", () => {
    assert.throws(() => normalizeRecipient(undefined), EmailValidationError);
    assert.throws(() => normalizeRecipient({ email: "nope" }), EmailValidationError);
  });

  test("rejects a CRLF-bearing display name", () => {
    assert.throws(() => normalizeRecipient({ email: "ops@example.com", name: "Ops\r\nBcc: x@y.com" }), EmailValidationError);
  });
});

describe("address formatting", () => {
  test("quotes an ASCII display name", () => {
    assert.equal(formatAddress({ email: "ops@example.com", name: 'Ops "The Fixer"' }), '"Ops \\"The Fixer\\"" <ops@example.com>');
  });

  test("omits the brackets when there is no name", () => {
    assert.equal(formatAddress({ email: "ops@example.com" }), "ops@example.com");
  });

  test("RFC 2047 encodes a non-ASCII display name", () => {
    const formatted = formatAddress({ email: "ops@example.com", name: "Équipe" });
    assert.match(formatted, /^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?= <ops@example\.com>$/);
    assert.equal(Buffer.from(encodeRfc2047("Équipe").slice("=?UTF-8?B?".length, -2), "base64").toString("utf8"), "Équipe");
  });

  test("sanitizes header values by folding CR/LF into spaces", () => {
    assert.equal(sanitizeHeaderValue("a\r\nBcc: x@y.com"), "a Bcc: x@y.com");
  });

  test("generates unique message ids", () => {
    assert.match(generateMessageId(), /^<[a-z0-9]+\.[0-9a-f]{24}@omniscan\.io>$/);
    assert.notEqual(generateMessageId(), generateMessageId());
  });
});

describe("message building", () => {
  const report = makeReport();

  /** Pulls one MIME part's body out of the serialized payload and decodes it. */
  function decodePart(raw: string, type: "text/plain" | "text/html"): string {
    const header = new RegExp(`Content-Type: ${type}; charset="UTF-8"\\r\\nContent-Transfer-Encoding: base64\\r\\n\\r\\n([\\s\\S]*?)\\r\\n--`);
    const match = raw.match(header);
    assert.ok(match, `missing ${type} part`);
    return Buffer.from(match[1].replace(/\r\n/g, ""), "base64").toString("utf8");
  }

  test("builds an RFC 5322 payload with alternative parts", () => {
    const message = buildMessage({ report }, { email: "ops@example.com" }, "reports@omniscan.io");
    const raw = serializeMessage(message).toString("utf8");

    assert.match(raw, /^Message-ID: <[^>]+>\r\n/);
    assert.match(raw, /\r\nFrom: reports@omniscan\.io\r\n/);
    assert.match(raw, /\r\nTo: ops@example\.com\r\n/);
    assert.match(raw, /MIME-Version: 1\.0/);
    assert.match(raw, /Content-Type: multipart\/alternative/);
    assert.match(raw, /Content-Type: text\/plain; charset="UTF-8"/);
    assert.match(raw, /Content-Type: text\/html; charset="UTF-8"/);
    assert.match(raw, /X-Omniscan-Scan-Id: scan-001/);
    assert.match(raw, /List-Unsubscribe: <mailto:unsubscribe@omniscan\.io>/);
    assert.match(decodePart(raw, "text/plain"), /OVERALL GRADE: B \(88\/100\)/);
    assert.match(decodePart(raw, "text/html"), /<!DOCTYPE html PUBLIC/);
  });

  test("keeps the wire payload free of raw non-ASCII bytes", () => {
    const unicode = makeReport({ targetDomain: "café.example" });
    const raw = serializeMessage(buildMessage({ report: unicode }, { email: "ops@example.com" }, "reports@omniscan.io")).toString(
      "latin1"
    );
    // eslint-disable-next-line no-control-regex
    assert.match(raw, /^[\x00-\x7f]*$/, "payload contains non-ASCII bytes outside encoded-words/base64");
  });

  test("CRLF-delimits every header line", () => {
    const raw = serializeMessage(buildMessage({ report }, { email: "ops@example.com" }, "reports@omniscan.io")).toString("utf8");
    assert.ok(!/[^\r]\n/.test(raw), "found a bare LF in the payload");
  });

  test("encodes a non-ASCII subject", () => {
    const unicode = makeReport({ targetDomain: "café.example" });
    const message = buildMessage({ report: unicode }, { email: "ops@example.com" }, "reports@omniscan.io");
    assert.match(message.headers["Subject"], /=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=/);
  });

  test("strips CR/LF from the subject so it cannot inject headers", () => {
    const evil = makeReport({ targetDomain: "example.com\r\nBcc: attacker@evil.com" });
    const message = buildMessage({ report: evil }, { email: "ops@example.com" }, "reports@omniscan.io");
    assert.ok(!message.headers["Subject"].includes("\r"));
    assert.ok(!message.headers["Subject"].includes("\n"));
  });

  test("adds a base64 PDF attachment when supplied", () => {
    const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]);
    const message = buildMessage({ report, pdf }, { email: "ops@example.com" }, "reports@omniscan.io");
    assert.equal(message.attachments.length, 1);
    assert.equal(message.attachments[0].filename, "omniscan-scan-001.pdf");
    assert.equal(message.attachments[0].contentType, "application/pdf");

    const raw = serializeMessage(message).toString("utf8");
    assert.match(raw, /Content-Type: multipart\/mixed/);
    assert.match(raw, /Content-Disposition: attachment; filename="omniscan-scan-001\.pdf"/);
    assert.ok(raw.includes(Buffer.from(pdf).toString("base64")));
  });

  test("honours an explicit attachment filename", () => {
    const message = buildMessage(
      { report, pdf: new Uint8Array([1]), attachmentFilename: "report.pdf" },
      { email: "ops@example.com" },
      "reports@omniscan.io"
    );
    assert.equal(message.attachments[0].filename, "report.pdf");
  });

  test("omits the mixed part when no PDF is supplied", () => {
    const message = buildMessage({ report }, { email: "ops@example.com" }, "reports@omniscan.io");
    assert.equal(message.attachments.length, 0);
    assert.ok(!serializeMessage(message).toString("utf8").includes("multipart/mixed"));
  });
});

describe("dispatchEmail", () => {
  test("sends through the supplied transport", async () => {
    const sent: EmailMessage[] = [];
    const result = await dispatchEmail({ report: makeReport(), transport: createMemoryTransport(sent) });

    assert.equal(result.sent, true);
    assert.equal(result.to, "ops@example.com");
    assert.equal(result.subject, "example.com scored 88/100 (B) — OmniScan audit");
    assert.match(result.messageId, /^<[^>]+@omniscan\.io>$/);
    assert.ok(result.bytes > 0);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].to.email, "ops@example.com");
  });

  test("prefers an explicit recipient over the report's recipient", async () => {
    const sent: EmailMessage[] = [];
    const result = await dispatchEmail({
      report: makeReport(),
      recipient: { email: "dev@example.com", name: "Dev" },
      transport: createMemoryTransport(sent),
    });
    assert.equal(result.to, "dev@example.com");
    assert.equal(sent[0].headers["To"], '"Dev" <dev@example.com>');
  });

  test("renders without sending when no transport is configured", async () => {
    const result = await dispatchEmail({ report: makeReport() });
    assert.equal(result.sent, false);
    assert.match(result.error ?? "", /not sent/);
    assert.ok(result.bytes > 0);
  });

  test("reports transport failures instead of throwing", async () => {
    const result = await dispatchEmail({
      report: makeReport(),
      transport: async () => {
        throw new Error("SMTP connection refused");
      },
    });
    assert.equal(result.sent, false);
    assert.equal(result.error, "SMTP connection refused");
  });

  test("rejects an invalid recipient before any transport runs", async () => {
    let called = false;
    await assert.rejects(
      dispatchEmail({
        report: makeReport(),
        recipient: "not-an-email",
        transport: async () => {
          called = true;
        },
      }),
      EmailValidationError
    );
    assert.equal(called, false);
  });

  test("uses a custom From address and the email's download links", async () => {
    const sent: EmailMessage[] = [];
    await dispatchEmail({
      report: makeReport(),
      from: "Custom Sender <sender@acme.com>",
      template: { baseUrl: "https://acme.com" },
      transport: createMemoryTransport(sent),
    });
    assert.equal(sent[0].headers["From"], "Custom Sender <sender@acme.com>");
    assert.match(sent[0].html, /https:\/\/acme\.com\/reports\/scan-001\/download\.pdf/);
  });

  test("attaches the generated PDF to the dispatched message", async () => {
    const sent: EmailMessage[] = [];
    await dispatchEmail({
      report: makeReport(),
      pdf: new Uint8Array([0x25, 0x50, 0x44, 0x46]),
      transport: createMemoryTransport(sent),
    });
    assert.equal(sent[0].attachments.length, 1);
    assert.equal(sent[0].attachments[0].contentType, "application/pdf");
  });
});
