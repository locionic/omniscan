import type { FullAuditReport } from "../types/index.js";

const DEFAULT_GOTENBERG_URL = "http://localhost:3000";
const CONVERT_ENDPOINT = "/forms/chromium/convert/html";

// A4 in inches. Chromium's CSS pixel page box is 96px/inch, so these are the
// dimensions Gotenberg expects to reproduce true A4 output.
const A4_WIDTH_IN = 8.27;
const A4_HEIGHT_IN = 11.7;

// Chromium's print default is 72dpi. `scale` is the zoom factor applied to the
// rendered page, so 300/72 is the factor that yields 300dpi vector output.
const CHROMIUM_BASE_DPI = 72;
const DEFAULT_TARGET_DPI = 300;

const PRINT_MARGIN_IN = 0.4;

export interface PdfGeneratorOptions {
  /** Base URL of the Gotenberg instance. */
  gotenbergUrl?: string;
  /** Vector rendering density. 300 is print-grade; 150 is a lighter preview. */
  dpi?: number;
  /** Abort the conversion after this long. Gotenberg's own limit applies too. */
  timeoutMs?: number;
}

export interface PdfRequest {
  endpoint: string;
  formData: FormData;
  filename: string;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function cssForDpi(dpi: number): string {
  const px = (inches: number) => `${round(inches * dpi)}px`;
  return `
    * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    html { font-size: ${px(0.0125)}px; margin: 0; }
    body { margin: 0; padding: 0; }
    .page-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: ${px(0.08)}px;
    }
    .page-footer {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-top: 1px solid #e2e8f0;
      padding-top: ${px(0.08)}px;
    }
    .hf-text { font-size: ${px(0.09)}px; color: #64748b; }
    .hf-muted { font-size: ${px(0.08)}px; color: #94a3b8; }
    .page-number { font-weight: 600; color: #334155; }`;
}

// Header and footer render in their own Chromium context, so the main page's CSS
// does not apply here. Each template carries its own copy of the print rules.
function headerHtml(targetDomain: string, dpi: number): string {
  const label = targetDomain || "OmniScan Audit Report";
  return `<html>
<head><meta charset="utf-8" /><style>${cssForDpi(dpi)}</style></head>
<body>
  <div class="page-header">
    <span class="hf-text">${escapeHtml(label)}</span>
    <span class="hf-muted">OmniScan Audit Report</span>
  </div>
</body>
</html>`;
}

function footerHtml(scanId: string, dpi: number): string {
  return `<html>
<head><meta charset="utf-8" /><style>${cssForDpi(dpi)}</style></head>
<body>
  <div class="page-footer">
    <span class="hf-muted">Scan ${escapeHtml(scanId)}</span>
    <span class="hf-text">Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
  </div>
</body>
</html>`;
}

function mainHtml(report: FullAuditReport, dpi: number): string {
  const { composite, performance, security, dns } = report;
  const vitals = performance.webVitals;
  const fixList = composite.priorityFixes
    .map(
      (fix) => `
        <tr>
          <td><strong>${escapeHtml(fix.title)}</strong><br /><span class="muted">${escapeHtml(fix.detail)}</span></td>
          <td>${escapeHtml(fix.category)}</td>
          <td>${escapeHtml(fix.severity)}</td>
        </tr>`
    )
    .join("");

  const checks = security.headers.checks
    .map(
      (check) => `
        <tr>
          <td>${escapeHtml(check.header)}</td>
          <td>${check.pass ? "Pass" : "Fail"}</td>
          <td class="muted">${escapeHtml(check.recommendation)}</td>
        </tr>`
    )
    .join("");

  const recommendations = performance.recommendations
    .map((rec) => `<li>${escapeHtml(rec)}</li>`)
    .join("");

  const dnsRecs = dns.recommendations.map((rec) => `<li>${escapeHtml(rec)}</li>`).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>OmniScan Audit Report — ${escapeHtml(report.targetDomain)}</title>
  <style>
    ${cssForDpi(dpi)}
    body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; font-size: ${round(0.14 * dpi)}px; }
    h1 { font-size: ${round(0.32 * dpi)}px; margin: 0 0 ${round(0.06 * dpi)}px; }
    h2 { font-size: ${round(0.2 * dpi)}px; margin: 0 0 ${round(0.12 * dpi)}px; padding-bottom: ${round(0.06 * dpi)}px; border-bottom: 1px solid #e2e8f0; break-after: avoid; page-break-after: avoid; }
    h3 { font-size: ${round(0.16 * dpi)}px; margin: 0 0 ${round(0.08 * dpi)}px; }
    p, li { line-height: 1.5; }
    .muted { color: #64748b; }
    .score-grid { display: flex; flex-wrap: wrap; gap: ${round(0.12 * dpi)}px; }
    .score-card {
      border: 1px solid #e2e8f0;
      border-radius: ${round(0.06 * dpi)}px;
      padding: ${round(0.12 * dpi)}px;
      min-width: ${round(1.4 * dpi)}px;
      background-color: #f8fafc;
      break-inside: avoid;
      page-break-inside: avoid;
    }
    .score-card .label { display: block; font-size: ${round(0.12 * dpi)}px; color: #64748b; }
    .score-card .value { display: block; font-size: ${round(0.28 * dpi)}px; font-weight: 700; }
    section { margin-top: ${round(0.24 * dpi)}px; }
    table { width: 100%; border-collapse: collapse; font-size: ${round(0.12 * dpi)}px; }
    th, td { text-align: left; padding: ${round(0.06 * dpi)}px ${round(0.08 * dpi)}px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    th { background-color: #f1f5f9; }
    tr { break-inside: avoid; page-break-inside: avoid; }
    .avoid-break { break-inside: avoid; page-break-inside: avoid; }
    thead { display: table-header-group; }
    @page { size: A4; margin: ${PRINT_MARGIN_IN}in; }
  </style>
</head>
<body>
  <h1>${escapeHtml(report.targetUrl)}</h1>
  <p class="muted">Scanned ${escapeHtml(report.scannedAt)} for ${escapeHtml(report.recipientEmail)}</p>

  <section>
    <h2>Overview</h2>
    <div class="score-grid">
      <div class="score-card"><span class="label">OmniScore</span><span class="value">${composite.omniScore}</span></div>
      <div class="score-card"><span class="label">Grade</span><span class="value">${escapeHtml(composite.grade)}</span></div>
      <div class="score-card"><span class="label">Performance</span><span class="value">${performance.score}</span></div>
      <div class="score-card"><span class="label">Security</span><span class="value">${security.headers.score}</span></div>
      <div class="score-card"><span class="label">DNS</span><span class="value">${dns.score}</span></div>
    </div>
    <p style="margin-top:${round(0.12 * dpi)}px">${escapeHtml(composite.summary)}</p>
  </section>

  <section>
    <h2>Core Web Vitals</h2>
    <table>
      <thead><tr><th>Metric</th><th>Value</th></tr></thead>
      <tbody>
        <tr><td>LCP</td><td>${vitals.lcp} ms</td></tr>
        <tr><td>INP</td><td>${vitals.inp} ms</td></tr>
        <tr><td>CLS</td><td>${vitals.cls}</td></tr>
        <tr><td>FCP</td><td>${vitals.fcp} ms</td></tr>
        <tr><td>TTFB</td><td>${vitals.ttfb} ms</td></tr>
        <tr><td>Speed Index</td><td>${vitals.speedIndex} ms</td></tr>
      </tbody>
    </table>
  </section>

  <section>
    <h2>Priority Fixes</h2>
    <table>
      <thead><tr><th>Fix</th><th>Category</th><th>Severity</th></tr></thead>
      <tbody>${fixList || '<tr><td colspan="3" class="muted">No outstanding issues.</td></tr>'}</tbody>
    </table>
  </section>

  <section>
    <h2>Security Headers</h2>
    <table>
      <thead><tr><th>Header</th><th>Result</th><th>Recommendation</th></tr></thead>
      <tbody>${checks || '<tr><td colspan="3" class="muted">No checks recorded.</td></tr>'}</tbody>
    </table>
  </section>

  <section>
    <h2>TLS</h2>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>
        <tr><td>Protocol</td><td>${escapeHtml(security.tls.protocol)}</td></tr>
        <tr><td>Cipher</td><td>${escapeHtml(security.tls.cipher)}</td></tr>
        <tr><td>Score</td><td>${security.tls.score} (${escapeHtml(security.tls.grade)})</td></tr>
        <tr><td>Expires</td><td>${escapeHtml(security.tls.cert?.validTo ?? "unknown")}</td></tr>
      </tbody>
    </table>
  </section>

  <section>
    <h2>DNS</h2>
    <table>
      <thead><tr><th>Record</th><th>Present</th></tr></thead>
      <tbody>
        <tr><td>SPF</td><td>${dns.hasSpf ? "Yes" : "No"}</td></tr>
        <tr><td>DMARC</td><td>${dns.hasDmarc ? "Yes" : "No"}</td></tr>
        <tr><td>MX</td><td>${dns.hasMx ? "Yes" : "No"}</td></tr>
        <tr><td>CAA</td><td>${dns.hasCaa ? "Yes" : "No"}</td></tr>
      </tbody>
    </table>
    ${dnsRecs ? `<ul>${dnsRecs}</ul>` : ""}
  </section>

  <section>
    <h2>Performance Recommendations</h2>
    ${recommendations ? `<ul>${recommendations}</ul>` : '<p class="muted">No recommendations.</p>'}
  </section>
</body>
</html>`;
}

function htmlFile(content: string): File {
  return new File([content], "index.html", { type: "text/html" });
}

function headerFile(content: string): File {
  return new File([content], "header.html", { type: "text/html" });
}

function footerFile(content: string): File {
  return new File([content], "footer.html", { type: "text/html" });
}

/**
 * Builds the multipart request Gotenberg needs. Exposed separately so callers
 * (and tests) can inspect the form without performing a network round-trip.
 */
export function buildPdfRequest(
  report: FullAuditReport,
  options: PdfGeneratorOptions = {}
): PdfRequest {
  const gotenbergUrl = (options.gotenbergUrl ?? process.env.GOTENBERG_URL ?? DEFAULT_GOTENBERG_URL).replace(/\/+$/, "");
  const dpi = options.dpi ?? DEFAULT_TARGET_DPI;

  const formData = new FormData();
  formData.append("files", htmlFile(mainHtml(report, dpi)));
  formData.append("files", headerFile(headerHtml(report.targetDomain, dpi)));
  formData.append("files", footerFile(footerHtml(report.scanId, dpi)));

  formData.append("paperWidth", String(A4_WIDTH_IN));
  formData.append("paperHeight", String(A4_HEIGHT_IN));
  formData.append("marginTop", String(PRINT_MARGIN_IN));
  formData.append("marginBottom", String(PRINT_MARGIN_IN));
  formData.append("marginLeft", String(PRINT_MARGIN_IN));
  formData.append("marginRight", String(PRINT_MARGIN_IN));
  // Zoom factor that lifts Chromium's 72dpi print baseline to the target DPI.
  formData.append("scale", String(round(dpi / CHROMIUM_BASE_DPI)));
  formData.append("printBackground", "true");
  formData.append("omitBackground", "false");
  formData.append("preferCssPageSize", "false");
  formData.append("landscape", "false");
  formData.append("singlePage", "false");

  const endpoint = `${gotenbergUrl}${CONVERT_ENDPOINT}`;

  return {
    endpoint,
    formData,
    filename: `omniscan-${report.scanId}.pdf`,
  };
}

export async function generatePdf(
  report: FullAuditReport,
  options: PdfGeneratorOptions = {}
): Promise<Uint8Array> {
  const { endpoint, formData, filename } = buildPdfRequest(report, options);
  const timeoutMs = options.timeoutMs ?? 30_000;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      body: formData,
      signal: controller.signal,
      headers: { "Gotenberg-Output-Filename": filename },
    });
  } catch (err) {
    const reason = controller.signal.aborted
      ? `timed out after ${timeoutMs}ms`
      : (err as Error).message;
    throw new Error(`Gotenberg conversion failed: ${reason}`);
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(`Gotenberg returned ${response.status}: ${detail.slice(0, 500)}`);
  }

  const buffer = await response.arrayBuffer();
  return new Uint8Array(buffer);
}