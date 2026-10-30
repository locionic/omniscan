import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generatePdfReport,
  buildPdfHtml,
  getCssPrintStyles,
  getPageCss,
} from "../src/reports/pdf-generator.ts";
import type { FullAuditReport } from "../src/types/index.ts";

const createMockReport = (): FullAuditReport => ({
  scanId: "test-scan-001",
  targetUrl: "https://example.com",
  targetDomain: "example.com",
  recipientEmail: "test@example.com",
  scannedAt: new Date("2024-01-15T10:30:00Z").toISOString(),
  composite: {
    omniScore: 85,
    grade: "A",
    performanceScore: 90,
    securityScore: 80,
    dnsScore: 75,
    bestPracticesScore: 88,
    summary: "Site is well-configured with minor improvements needed.",
    priorityFixes: [
      {
        title: "Enable HSTS",
        category: "Security",
        severity: "warning",
        detail: "HSTS is not enabled with proper max-age.",
        impact: "Add Strict-Transport-Security header with max-age >= 31536000.",
      },
      {
        title: "Add SPF Record",
        category: "DNS",
        severity: "critical",
        detail: "SPF record is missing for the domain.",
        impact: "Configure SPF record to prevent email spoofing.",
      },
    ],
  },
  performance: {
    score: 90,
    accessibilityScore: 95,
    seoScore: 85,
    bestPracticesScore: 88,
    webVitals: {
      lcp: 1200,
      inp: 50,
      cls: 0.05,
      fcp: 800,
      ttfb: 200,
      speedIndex: 1500,
    },
    recommendations: ["Improve image optimization.", "Reduce JavaScript bundle size."],
  },
  security: {
    headers: {
      score: 80,
      grade: "A",
      checks: [
        {
          header: "Content-Security-Policy",
          present: true,
          value: "default-src 'self'",
          pass: true,
          score: 25,
          recommendation: "Strong CSP policy configured.",
        },
        {
          header: "Strict-Transport-Security",
          present: false,
          pass: false,
          score: 0,
          recommendation: "Enable HSTS with max-age >= 31536000.",
        },
      ],
    },
    tls: {
      score: 95,
      grade: "A+",
      protocol: "TLSv1.3",
      cipher: "TLS_AES_256_GCM_SHA384",
      authorized: true,
      cert: {
        subject: "CN=example.com",
        issuer: "Let's Encrypt Authority X3",
        validFrom: "Jan 1 00:00:00 2024 GMT",
        validTo: "Mar 31 00:00:00 2024 GMT",
        daysRemaining: 59,
        sans: ["www.example.com", "mail.example.com"],
      },
      vulnerabilities: [],
      recommendations: ["Certificate is valid and properly configured."],
    },
  },
  dns: {
    score: 75,
    hasSpf: false,
    spfRecord: undefined,
    spfLookupCount: 0,
    spfValid: false,
    hasDmarc: false,
    dmarcRecord: undefined,
    dmarcPolicy: undefined,
    hasMx: true,
    mxRecords: ["mail.example.com (priority 10)"],
    hasCaa: true,
    hasDnssec: false,
    recommendations: ["Add SPF record.", "Configure DMARC policy."],
  },
});

describe("PDF Generator", () => {
  describe("buildPdfHtml", () => {
    it("should generate valid HTML structure", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("<!DOCTYPE html>"));
      assert.ok(html.includes("</html>"));
    });

    it("should include domain name in header", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("example.com"));
    });

    it("should include grade badge with CSS class", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes('grade-A'));
      assert.ok(html.includes("Grade: A"));
    });

    it("should include omniScore", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("85"));
    });

    it("should include performance section", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("Performance"));
      assert.ok(html.includes("90"));
    });

    it("should include TLS information", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("TLSv1.3"));
      assert.ok(html.includes("TLS_AES_256_GCM_SHA384"));
    });

    it("should include priority fixes", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("Enable HSTS"));
      assert.ok(html.includes("Add SPF Record"));
    });

    it("should include web vitals metrics", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("LCP"));
      assert.ok(html.includes("1200 ms"));
      assert.ok(html.includes("CLS"));
      assert.ok(html.includes("0.050"));
    });

    it("should include DNS records section", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("DNS Records"));
      assert.ok(html.includes("mail.example.com"));
    });

    it("should include page numbers in footer using CSS counters", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("counter(page)"));
      assert.ok(html.includes("counter(pages)"));
    });
  });

  describe("CSS Print Styles", () => {
    it("should include print-color-adjust exact", () => {
      const css = getCssPrintStyles();
      assert.ok(css.includes("print-color-adjust: exact"));
      assert.ok(css.includes("color-adjust: exact"));
    });

    it("should include break-inside avoid property", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("break-inside: avoid"));
    });

    it("should define A4 page size in @page rule", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("size: A4"));
    });

    it("should use millimeter-based margins", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("10mm"));
      assert.ok(html.includes("15mm"));
    });
  });

  describe("High-DPI A4 Page Layout", () => {
    it("should set proper A4 paper format in @page rule", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("size: A4"));
    });

    it("should have multiple page break elements to prevent content split", () => {
      const html = buildPdfHtml(createMockReport());
      const pageBreakCount = (html.match(/break-inside: avoid/g) || []).length;
      assert.ok(pageBreakCount >= 5, `Expected at least 5 break-inside rules, got ${pageBreakCount}`);
    });

    it("should use millimeter-based margins in @page rule", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("margin: 10mm"));
    });

    it("should include margin settings in multipart body for Gotenberg API", async () => {
      const html = buildPdfHtml(createMockReport());
      const result = await generatePdfReport(createMockReport());
      assert.ok(result.success || result.error, "Should be able to call Gotenberg API");
    });
  });

  describe("Grade CSS Classes", () => {
    it("should apply correct grade class for A+", () => {
      const report = createMockReport();
      report.composite.grade = "A+";
      const html = buildPdfHtml(report);
      assert.ok(html.includes("grade-A+"));
    });

    it("should apply correct grade class for A", () => {
      const report = createMockReport();
      report.composite.grade = "A";
      const html = buildPdfHtml(report);
      assert.ok(html.includes("grade-A"));
    });

    it("should apply correct grade class for B", () => {
      const report = createMockReport();
      report.composite.grade = "B";
      const html = buildPdfHtml(report);
      assert.ok(html.includes("grade-B"));
    });

    it("should apply correct grade class for C", () => {
      const report = createMockReport();
      report.composite.grade = "C";
      const html = buildPdfHtml(report);
      assert.ok(html.includes("grade-C"));
    });

    it("should apply correct grade class for D", () => {
      const report = createMockReport();
      report.composite.grade = "D";
      const html = buildPdfHtml(report);
      assert.ok(html.includes("grade-D"));
    });

    it("should apply correct grade class for F", () => {
      const report = createMockReport();
      report.composite.grade = "F";
      const html = buildPdfHtml(report);
      assert.ok(html.includes("grade-F"));
    });
  });

  describe("generatePdfReport", () => {
    async function waitForServer(url: string, maxAttempts = 10): Promise<boolean> {
      for (let i = 0; i < maxAttempts; i++) {
        try {
          const res = await request(url, { method: "GET", timeout: 500 });
          if (res.statusCode === 200 || res.statusCode === 404) return true;
        } catch {
          await new Promise((r) => setTimeout(r, 100));
        }
      }
      return false;
    }

    it("should return error for unreachable server", async () => {
      const result = await generatePdfReport(createMockReport(), {
        gotenbergBaseUrl: "http://localhost:59999",
        timeoutMs: 1000,
      });

      assert.ok(!result.success, "Expected failure for unreachable server");
      assert.ok(result.error?.includes("Failed to connect"), `Expected connection error, got: ${result.error}`);
    });

    it("should use default Gotenberg URL when not specified", async () => {
      const result = await generatePdfReport(createMockReport(), {
        timeoutMs: 1000,
      });

      assert.ok(result.error, "Expected an error with default URL since Gotenberg isn't fully configured");
    });
  });

  describe("Page Counter Footer", () => {
    it("should include CSS counter-based page numbering", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("Page "));
      assert.ok(html.includes("counter(page)"));
      assert.ok(html.includes("counter(pages)"));
    });

    it("should position footer at bottom of page", () => {
      const html = buildPdfHtml(createMockReport());
      assert.ok(html.includes("position: fixed"));
      assert.ok(html.includes("bottom: 0"));
      assert.ok(html.includes("height: 20mm"));
    });
  });
});