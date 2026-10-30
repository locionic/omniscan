import { request } from "undici";
import type { FullAuditReport } from "../types/index.js";

export interface PdfGenerationOptions {
  gotenbergBaseUrl?: string;
  timeoutMs?: number;
}

export interface PdfGenerationResult {
  success: boolean;
  pdfBuffer?: Buffer;
  error?: string;
}

const DEFAULT_GOTENBERG_URL = "http://localhost:3000";

export function generatePdfReport(
  report: FullAuditReport,
  options: PdfGenerationOptions = {}
): Promise<PdfGenerationResult> {
  const baseUrl = options.gotenbergBaseUrl ?? DEFAULT_GOTENBERG_URL;
  const timeoutMs = options.timeoutMs ?? 30000;

  const html = buildPdfHtml(report);
  const boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";

  const body = `<--*-- boundary="${boundary}" Content-Disposition: form-data; name="files[0]" Content-Type: text/html; charset=utf-8

${html}
--*-- Content-Disposition: form-data; name="landscape" Content-Type: text/plain

false
--*-- Content-Disposition: form-data; name="paperFormat" Content-Type: text/plain

A4
--*-- Content-Disposition: form-data; name="marginTop" Content-Type: text/plain

10mm
--*-- Content-Disposition: form-data; name="marginBottom" Content-Type: text/plain

10mm
--*-- Content-Disposition: form-data; name="marginLeft" Content-Type: text/plain

15mm
--*-- Content-Disposition: form-data; name="marginRight" Content-Type: text/plain

15mm
----*-->`;

  return new Promise((resolve) => {
    request(
      `${baseUrl}/forms/v1/pdf`,
      {
        method: "POST",
        headers: {
          "Content-Type": `multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW`,
        },
        body: body,
        bodyTimeout: timeoutMs,
      }
    )
      .then(async (response) => {
        if (response.statusCode >= 200 && response.statusCode < 300) {
          const chunks: Buffer[] = [];
          for await (const chunk of response.body) {
            chunks.push(Buffer.from(chunk));
          }
          resolve({
            success: true,
            pdfBuffer: Buffer.concat(chunks),
          });
        } else {
          const errorText = await response.body.text().catch(() => "Unknown error");
          resolve({
            success: false,
            error: `Gotenberg API error: ${response.statusCode} - ${errorText}`,
          });
        }
      })
      .catch((err: any) => {
        resolve({
          success: false,
          error: `Failed to connect to Gotenberg API: ${err.message}`,
        });
      });
  });
}

export function buildPdfHtml(report: FullAuditReport): string {
  const { composite, performance, security, dns } = report;
  const domain = report.targetDomain;
  const formattedDate = new Date(report.scannedAt).toLocaleString("en-US", {
    timeZone: "UTC",
    dateStyle: "full",
    timeStyle: "long",
  });

  const gradeClass = `grade-${composite.grade.toLowerCase()}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OmniScan Audit Report - ${domain}</title>
  <style>
    @page {
      size: A4;
      margin: 10mm 15mm;
    }

    @media print {
      -webkit-print-color-adjust: exact;
      color-adjust: exact;
      print-color-adjust: exact;
    }

    .page-break {
      break-inside: avoid;
      page-break-inside: avoid;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.6;
      color: #1a1a1a;
      background: #ffffff;
    }

    .header {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: #ffffff;
      padding: 24px;
    }

    .header h1 {
      margin: 0 0 8px 0;
      font-size: 28px;
      font-weight: 600;
    }

    .header .domain {
      font-size: 18px;
      opacity: 0.9;
      margin: 0;
    }

    .header .meta {
      font-size: 12px;
      opacity: 0.8;
      margin-top: 12px;
    }

    .grade-badge {
      display: inline-block;
      padding: 8px 16px;
      border-radius: 24px;
      font-weight: 700;
      font-size: 16px;
      margin-left: 12px;
      background: rgba(255, 255, 255, 0.15);
    }

    .grade-A+ { background: linear-gradient(135deg, #059669, #047857); }
    .grade-A { background: linear-gradient(135deg, #16a34a, #15803d); }
    .grade-B { background: linear-gradient(135deg, #d97706, #b45309); }
    .grade-C { background: linear-gradient(135deg, #dc2626, #b91c1c); }
    .grade-D { background: linear-gradient(135deg, #7c3aed, #6d28a9); }
    .grade-F { background: linear-gradient(135deg, #6b7280, #4b5563); }

    .score-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      padding: 24px;
    }

    .score-card {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 20px;
    }

    .score-card h3 {
      margin: 0 0 8px 0;
      font-size: 14px;
      color: #64748b;
      font-weight: 500;
    }

    .score-value {
      font-size: 32px;
      font-weight: 700;
      margin: 0;
    }

    .score-grade {
      font-size: 14px;
      color: #64748b;
      margin: 4px 0 0 0;
    }

    .section {
      padding: 0 24px 24px;
    }

    .section h2 {
      font-size: 20px;
      font-weight: 600;
      margin: 0 0 16px 0;
      color: #1a1a1a;
      border-bottom: 2px solid #e2e8f0;
      padding-bottom: 8px;
    }

    .check-item {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 12px 0;
      border-bottom: 1px solid #f1f5f9;
      break-inside: avoid;
    }

    .check-item:last-child {
      border-bottom: none;
    }

    .check-status {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      font-weight: bold;
      font-size: 14px;
    }

    .check-status.pass {
      background: #dcfce7;
      color: #166534;
    }

    .check-status.fail {
      background: #fee2e2;
      color: #991b1b;
    }

    .check-status.warning {
      background: #fff7ed;
      color: #ea580c;
    }

    .check-details {
      flex: 1;
      min-width: 0;
    }

    .check-title {
      font-size: 14px;
      font-weight: 500;
      margin: 0;
    }

    .check-score {
      font-size: 12px;
      color: #64748b;
    }

    .check-value {
      font-size: 12px;
      color: #64748b;
      margin: 4px 0 0 0;
      word-break: break-all;
    }

    .check-recommendation {
      font-size: 12px;
      color: #475569;
      margin: 4px 0 0 0;
      padding-left: 4px;
      border-left: 3px solid #cbd5e1;
    }

    .priority-item {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 16px;
      margin-bottom: 12px;
      border-radius: 8px;
      border-left: 4px solid;
      break-inside: avoid;
    }

    .priority-critical {
      background: #fef2f2;
      border-color: #dc2626;
    }

    .priority-warning {
      background: #fff7ed;
      border-color: #ea580c;
    }

    .priority-info {
      background: #eff6ff;
      border-color: #0284c7;
    }

    .priority-title {
      font-size: 14px;
      font-weight: 600;
      margin: 0 0 4px 0;
    }

    .priority-category {
      font-size: 11px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .priority-detail {
      font-size: 12px;
      color: #475569;
      margin: 4px 0 0 0;
    }

    .footer {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      height: 20mm;
      background: #f1f5f9;
      border-top: 1px solid #cbd5e1;
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0 15mm 5mm;
      font-size: 10px;
      color: #64748b;
    }

    .footer .page-number::before {
      content: "Page " counter(page) " of " counter(pages);
    }

    .footer .generated {
      opacity: 0.8;
    }

    .metric-card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 16px;
      break-inside: avoid;
    }

    .metric-label {
      font-size: 12px;
      color: #64748b;
      margin: 0 0 4px 0;
    }

    .metric-value {
      font-size: 18px;
      font-weight: 600;
      margin: 0;
    }

    .metric-detail {
      font-size: 11px;
      color: #94a3b8;
      margin-top: 4px;
    }

    .dns-section {
      display: grid;
      gap: 12px;
    }

    .dns-item {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
    }

    .dns-item span {
      color: #64748b;
    }

    .score-bar {
      height: 8px;
      background: #e2e8f0;
      border-radius: 4px;
      overflow: hidden;
      margin-top: 8px;
    }

    .score-fill {
      height: 100%;
      border-radius: 4px;
    }

    .progress-good { background: linear-gradient(90deg, #16a34a, #22c55e); }
    .progress-ok { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
    .progress-bad { background: linear-gradient(90deg, #ef4444, #f87171); }

    ul {
      margin: 8px 0 0 0;
      padding-left: 20px;
    }

    li {
      margin: 4px 0;
    }
  </style>
</head>
<body>
  <div class="page-break">
    <div class="header">
      <h1>OmniScan Security Audit</h1>
      <p class="domain">${domain}</p>
      <p class="meta">Report generated: ${formattedDate}</p>
      <span class="grade-badge ${gradeClass}">Grade: ${composite.grade}</span>
    </div>

    <div class="score-grid">
      <div class="score-card">
        <h3>OmniScore</h3>
        <p class="score-value">${composite.omniScore}</p>
        <p class="score-grade">Overall Grade: ${composite.grade}</p>
      </div>
      <div class="score-card">
        <h3>Performance</h3>
        <p class="score-value">${performance.score}</p>
        <p class="score-grade">Grade: ${gradeForScore(performance.score)}</p>
      </div>
      <div class="score-card">
        <h3>Security</h3>
        <p class="score-value">${security.headers.score}</p>
        <p class="score-grade">Headers Grade: ${security.headers.grade} | TLS Grade: ${security.tls.grade}</p>
        <div class="score-bar">
          <div class="score-fill ${scoreClass(performance.score)}" style="width: ${performance.score}%"></div>
        </div>
      </div>
      <div class="score-card">
        <h3>DNS Security</h3>
        <p class="score-value">${dns.score}</p>
        <p class="score-grade">Grade: ${gradeForScore(dns.score)}</p>
      </div>
      <div class="score-card">
        <h3>Best Practices</h3>
        <p class="score-value">${composite.bestPracticesScore}</p>
        <p class="score-grade">Grade: ${gradeForScore(composite.bestPracticesScore)}</p>
      </div>
    </div>
  </div>

  <div class="page-break">
    <h2>Priority Fixes</h2>
    ${renderPriorityFixes(composite.priorityFixes)}
  </div>

  <div class="page-break">
    <h2>Performance Report</h2>
    <div class="score-grid">
      <div class="metric-card">
        <p class="metric-label">LCP (Largest Contentful Paint)</p>
        <p class="metric-value">${performance.webVitals.lcp.toFixed(0)} ms</p>
      </div>
      <div class="metric-card">
        <p class="metric-label">CLS (Cumulative Layout Shift)</p>
        <p class="metric-value">${performance.webVitals.cls.toFixed(3)}</p>
      </div>
      <div class="metric-card">
        <p class="metric-label">FID / INP</p>
        <p class="metric-value">${performance.webVitals.inp.toFixed(0)} ms</p>
      </div>
      <div class="metric-card">
        <p class="metric-label">FCP (First Contentful Paint)</p>
        <p class="metric-value">${performance.webVitals.fcp.toFixed(0)} ms</p>
      </div>
      <div class="metric-card">
        <p class="metric-label">TTFB</p>
        <p class="metric-value">${performance.webVitals.ttfb.toFixed(0)} ms</p>
      </div>
      <div class="metric-card">
        <p class="metric-label">Speed Index</p>
        <p class="metric-value">${performance.webVitals.speedIndex.toFixed(0)} ms</p>
      </div>
    </div>
  </div>

  <div class="page-break">
    <h2>Security Headers</h2>
    ${renderSecurityChecks(security.headers.checks)}
  </div>

  <div class="page-break">
    <h2>TLS Configuration</h2>
    ${renderTlsReport(security.tls)}
  </div>

  <div class="page-break">
    <h2>DNS Records</h2>
    ${renderDnsReport(dns)}
  </div>
</body>
</html>`;
}

function renderPriorityFixes(fixes: FullAuditReport["composite"]["priorityFixes"]): string {
  if (fixes.length === 0) {
    return "<p style='color: #64748b; font-style: italic;'>No critical issues found.</p>";
  }

  return fixes
    .map((fix) => {
      const icon = fix.severity === "critical" ? "!" : fix.severity === "warning" ? "!" : "i";
      const statusClass = fix.severity;
      return `
    <div class="priority-item priority-${fix.severity}">
      <div class="check-status ${statusClass}">${icon}</div>
      <div class="check-details">
        <p class="priority-title">${fix.title}</p>
        <p class="priority-category">${fix.category}</p>
        <p class="priority-detail">${fix.detail}</p>
        <p class="check-recommendation">${fix.impact}</p>
      </div>
    </div>`;
    })
    .join("");
}

function renderSecurityChecks(checks: FullAuditReport["security"]["headers"]["checks"]): string {
  return checks
    .map((check) => {
      const statusClass = check.pass ? "pass" : "fail";
      const icon = check.pass ? "✓" : "✗";
      return `
    <div class="check-item">
      <div class="check-status ${statusClass}">${icon}</div>
      <div class="check-details">
        <div class="check-header">
          <h3 class="check-title">${check.header}</h3>
          <span class="check-score">${check.score} pts</span>
        </div>
        ${check.value ? `<p class="check-value">${check.value}</p>` : ""}
        <p class="check-recommendation">${check.recommendation}</p>
      </div>
    </div>`;
    })
    .join("");
}

function renderTlsReport(tls: FullAuditReport["security"]["tls"]): string {
  const authorizedClass = tls.authorized ? "pass" : "fail";
  const authorizedIcon = tls.authorized ? "✓" : "✗";

  let html = `
    <div class="check-item">
      <div class="check-status ${authorizedClass}">${authorizedIcon}</div>
      <div class="check-details">
        <h3 class="check-title">TLS Configuration</h3>
        <p class="check-value">Protocol: ${tls.protocol} | Cipher: ${tls.cipher}</p>
        <p class="check-recommendation">Authorized: ${tls.authorized ? "Yes" : "No"}</p>
      </div>
    </div>`;

  if (tls.vulnerabilities && tls.vulnerabilities.length > 0) {
    html += `
    <div class="check-item">
      <div class="check-status fail">✗</div>
      <div class="check-details">
        <h3 class="check-title">Vulnerabilities</h3>
        <ul>
          ${tls.vulnerabilities.map((v) => `<li>${v}</li>`).join("")}
        </ul>
      </div>
    </div>`;
  }

  if (tls.cert) {
    html += `
    <div class="check-item">
      <div class="check-status info">i</div>
      <div class="check-details">
        <h3 class="check-title">Certificate Details</h3>
        <p class="check-value">Subject: ${tls.cert.subject}</p>
        <p class="check-value">Issuer: ${tls.cert.issuer}</p>
        <p class="check-value">Valid Until: ${tls.cert.validTo} (${tls.cert.daysRemaining} days remaining)</p>
        <p class="check-recommendation">SANs: ${tls.cert.sans.join(", ") || "None"}</p>
      </div>
    </div>`;
  }

  html += `
    <div class="check-item">
      <div class="check-status pass">✓</div>
      <div class="check-details">
        <h3 class="check-title">Recommendations</h3>
        <ul>
          ${tls.recommendations.map((r) => `<li>${r}</li>`).join("")}
        </ul>
      </div>
    </div>`;

  return html;
}

function renderDnsReport(dns: FullAuditReport["dns"]): string {
  return `
    <div class="dns-section">
      <div class="dns-item">
        <strong>SPF:</strong> ${dns.hasSpf ? "✓ " + (dns.spfRecord || "") : "✗ Not configured"}
        ${dns.spfRecord ? `<br><small style="color: #64748b;">SPF Lookups: ${dns.spfLookupCount}${dns.spfValid ? " (valid)" : " (exceeds 10 limit)"}</small>` : ""}
      </div>
      <div class="dns-item">
        <strong>DMARC:</strong> ${dns.hasDmarc ? "✓ Policy: " + (dns.dmarcPolicy || "") : "✗ Not configured"}
      </div>
      <div class="dns-item">
        <strong>MX Records:</strong> ${dns.hasMx ? "✓ " + dns.mxRecords.join(", ") : "✗ Not configured"}
      </div>
      <div class="dns-item">
        <strong>CAA:</strong> ${dns.hasCaa ? "✓ Configured" : "✗ Not configured"}
      </div>
      <div class="dns-item">
        <strong>DNSSEC:</strong> ${dns.hasDnssec ? "✓ Enabled" : "✗ Not enabled"}
      </div>
    </div>
    <h3 style="margin-top: 16px;">Recommendations</h3>
    <ul>
      ${dns.recommendations.map((r) => `<li>${r}</li>`).join("")}
    </ul>`;
}

function gradeForScore(score: number): string {
  if (score >= 95) return "A+";
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

function scoreClass(score: number): string {
  if (score >= 80) return "progress-good";
  if (score >= 50) return "progress-ok";
  return "progress-bad";
}

export function getCssPrintStyles(): string {
  return `
    @media print {
      -webkit-print-color-adjust: exact;
      color-adjust: exact;
      print-color-adjust: exact;
    }
  `;
}

export function getPageCss(): string {
  return `
    @page {
      size: A4;
      margin: 10mm;
    }
  `;
}