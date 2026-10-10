import { test, describe } from "node:test";
import assert from "node:assert/strict";
import type { FullAuditReport } from "../src/types/index.js";
import { buildPdfRequest, generatePdf } from "../src/reports/pdf-generator.ts";

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
        title: "Add CSP",
        category: "Security",
        severity: "critical",
        detail: "No Content-Security-Policy header.",
        impact: "Reduced XSS exposure.",
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
      score: 95,
      grade: "A",
      protocol: "TLSv1.3",
      cipher: "TLS_AES_256_GCM_SHA384",
      authorized: true,
      cert: {
        subject: "CN=example.com",
        issuer: "CN=Example CA",
        validFrom: "2026-01-01T00:00:00.000Z",
        validTo: "2027-01-01T00:00:00.000Z",
        daysRemaining: 448,
        sans: ["example.com"],
      },
      vulnerabilities: [],
      recommendations: [],
    },
  },
  dns: {
    score: 80,
    hasSpf: true,
    spfRecord: "v=spf1 include:_spf.example.com ~all",
    spfLookupCount: 1,
    spfValid: true,
    hasDmarc: true,
    dmarcRecord: "v=DMARC1; p=quarantine",
    dmarcPolicy: "quarantine",
    hasMx: true,
    mxRecords: ["mx.example.com (priority 10)"],
    hasCaa: false,
    hasDnssec: false,
    recommendations: ["Add a CAA record."],
  },
};

async function readFiles(formData: FormData): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (const [key, value] of formData.entries()) {
    if (key === "files" && value instanceof File) {
      out.set(value.name, await value.text());
    }
  }
  return out;
}

function field(formData: FormData, name: string): string {
  const value = formData.get(name);
  assert.equal(typeof value, "string", `expected string field '${name}'`);
  return value as string;
}

describe("buildPdfRequest", () => {
  test("targets Gotenberg's Chromium HTML endpoint", () => {
    const { endpoint } = buildPdfRequest(report, { gotenbergUrl: "https://gotenberg.internal:3000" });
    assert.equal(endpoint, "https://gotenberg.internal:3000/forms/chromium/convert/html");
  });

  test("tolerates a trailing slash on the base URL", () => {
    const { endpoint } = buildPdfRequest(report, { gotenbergUrl: "https://gotenberg.internal:3000///" });
    assert.equal(endpoint, "https://gotenberg.internal:3000/forms/chromium/convert/html");
  });

  test("uploads index.html, header.html and footer.html under the 'files' field", async () => {
    const { formData } = buildPdfRequest(report);
    const files = [...formData.getAll("files")];
    assert.equal(files.length, 3);
    assert.deepEqual(files.map((f) => (f as File).name), ["index.html", "header.html", "footer.html"]);

    const contents = await readFiles(formData);
    assert.equal(contents.size, 3);
    for (const html of contents.values()) {
      assert.match(html, /^<!DOCTYPE html>|^<html>/);
    }
  });

  test("requests A4 portrait page dimensions", () => {
    const { formData } = buildPdfRequest(report);
    assert.equal(field(formData, "paperWidth"), "8.27");
    assert.equal(field(formData, "paperHeight"), "11.7");
    assert.equal(field(formData, "landscape"), "false");
    assert.equal(field(formData, "singlePage"), "false");
  });

  test("derives a high-DPI scale factor from the target resolution", () => {
    // Chromium's print baseline is 72dpi, so 300dpi is a ~4.167x zoom.
    const { formData } = buildPdfRequest(report, { dpi: 300 });
    assert.equal(Number(field(formData, "scale")), 4.167);

    const preview = buildPdfRequest(report, { dpi: 144 });
    assert.equal(Number(field(preview.formData, "scale")), 2);
  });

  test("enables background printing so print-color-adjust takes effect", () => {
    const { formData } = buildPdfRequest(report);
    assert.equal(field(formData, "printBackground"), "true");
    assert.equal(field(formData, "omitBackground"), "false");
  });

  test("names the output file after the scan", () => {
    assert.equal(buildPdfRequest(report).filename, "omniscan-scan-001.pdf");
  });
});

describe("print CSS", () => {
  test("main document declares print-color-adjust: exact", async () => {
    const { formData } = buildPdfRequest(report);
    const files = await readFiles(formData);
    const html = files.get("index.html")!;
    assert.match(html, /-webkit-print-color-adjust:\s*exact/);
    assert.match(html, /print-color-adjust:\s*exact/);
  });

  test("main document declares break-inside: avoid with the legacy page-break alias", async () => {
    const { formData } = buildPdfRequest(report);
    const html = (await readFiles(formData)).get("index.html")!;
    assert.match(html, /break-inside:\s*avoid/);
    assert.match(html, /page-break-inside:\s*avoid/);
  });

  test("keeps score cards and table rows from splitting across pages", async () => {
    const { formData } = buildPdfRequest(report);
    const html = (await readFiles(formData)).get("index.html")!;
    const scoreCard = html.slice(html.indexOf(".score-card {"), html.indexOf(".score-card .label"));
    assert.match(scoreCard, /break-inside:\s*avoid/);
    const rowRule = html.slice(html.indexOf("tr {"), html.indexOf(".avoid-break"));
    assert.match(rowRule, /break-inside:\s*avoid/);
  });

  test("sets an A4 @page rule", async () => {
    const { formData } = buildPdfRequest(report);
    const html = (await readFiles(formData)).get("index.html")!;
    assert.match(html, /@page\s*\{\s*size:\s*A4/);
  });

  test("repeats table headers across page breaks", async () => {
    const { formData } = buildPdfRequest(report);
    const html = (await readFiles(formData)).get("index.html")!;
    assert.match(html, /thead\s*\{\s*display:\s*table-header-group/);
  });
});

describe("header and footer", () => {
  test("footer uses Gotenberg's pageNumber and totalPages classes", async () => {
    const { formData } = buildPdfRequest(report);
    const footer = (await readFiles(formData)).get("footer.html")!;
    assert.match(footer, /class="pageNumber"/);
    assert.match(footer, /class="totalPages"/);
    assert.match(footer, /Page\s*<span class="pageNumber"><\/span>\s*of\s*<span class="totalPages"><\/span>/);
  });

  test("footer carries its own copy of the print rules", async () => {
    // Header/footer render in a separate Chromium context, so they cannot
    // inherit the main document's stylesheet.
    const { formData } = buildPdfRequest(report);
    const footer = (await readFiles(formData)).get("footer.html")!;
    assert.match(footer, /-webkit-print-color-adjust:\s*exact/);
    assert.match(footer, /print-color-adjust:\s*exact/);
  });

  test("header shows the audited domain", async () => {
    const { formData } = buildPdfRequest(report);
    const header = (await readFiles(formData)).get("header.html")!;
    assert.match(header, /example\.com/);
  });
});

describe("content rendering", () => {
  test("includes the composite scores and vitals", async () => {
    const { formData } = buildPdfRequest(report);
    const html = (await readFiles(formData)).get("index.html")!;
    assert.match(html, />88</, "omniScore");
    assert.match(html, />B</, "grade");
    assert.match(html, /LCP/);
    assert.match(html, /TLS_AES_256_GCM_SHA384/);
    assert.match(html, /Add a CAA record\./);
  });

  test("escapes user-controlled strings", async () => {
    const hostile: FullAuditReport = {
      ...report,
      targetUrl: 'https://x.test/"><script>alert(1)</script>',
      composite: { ...report.composite, summary: "<img src=x onerror=alert(1)>" },
    };
    const { formData } = buildPdfRequest(hostile);
    const html = (await readFiles(formData)).get("index.html")!;
    // The payloads survive only as inert text; no live tags are introduced.
    assert.ok(!html.includes("<script"), "live script tag leaked into output");
    assert.ok(!html.includes("<img"), "live img tag leaked into output");
    assert.match(html, /&lt;script&gt;/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  });

  test("handles empty collections without producing broken markup", async () => {
    const empty: FullAuditReport = {
      ...report,
      composite: { ...report.composite, priorityFixes: [] },
      performance: { ...report.performance, recommendations: [] },
      security: { ...report.security, headers: { score: 0, grade: "F", checks: [] } },
      dns: { ...report.dns, recommendations: [] },
    };
    const { formData } = buildPdfRequest(empty);
    const html = (await readFiles(formData)).get("index.html")!;
    assert.ok(!html.includes("undefined"));
    assert.match(html, /No outstanding issues\./);
    assert.match(html, /No recommendations\./);
  });
});

describe("generatePdf", () => {
  const realFetch = globalThis.fetch;

  function stubFetch(response: Response) {
    const calls: { url: string; init: RequestInit }[] = [];
    globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
      calls.push({ url: String(input), init });
      return response;
    }) as typeof fetch;
    return calls;
  }

  test("posts the form to Gotenberg and returns the PDF bytes", async () => {
    const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]);
    const calls = stubFetch(new Response(pdfBytes, { status: 200 }));
    try {
      const result = await generatePdf(report, { gotenbergUrl: "http://127.0.0.1:3000" });
      assert.deepEqual([...result], [...pdfBytes]);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].url, "http://127.0.0.1:3000/forms/chromium/convert/html");
      assert.equal(calls[0].init.method, "POST");
      assert.ok(calls[0].init.body instanceof FormData);
      const headers = calls[0].init.headers as Record<string, string>;
      assert.equal(headers["Gotenberg-Output-Filename"], "omniscan-scan-001.pdf");
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  test("surfaces Gotenberg error responses with status and body", async () => {
    stubFetch(new Response("invalid form data", { status: 400 }));
    try {
      await assert.rejects(
        () => generatePdf(report, { gotenbergUrl: "http://127.0.0.1:3000" }),
        /Gotenberg returned 400: invalid form data/
      );
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  test("wraps transport failures", async () => {
    globalThis.fetch = (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch;
    try {
      await assert.rejects(
        () => generatePdf(report, { gotenbergUrl: "http://127.0.0.1:3000" }),
        /Gotenberg conversion failed: ECONNREFUSED/
      );
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
