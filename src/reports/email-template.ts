import type { CompositeScore, FullAuditReport, PriorityFix } from "../types/index.js";

export interface EmailTemplateOptions {
  /** Base URL of the dashboard; PDF and report links are built from it. */
  baseUrl?: string;
  /** Overrides the generated PDF download URL entirely. */
  pdfUrl?: string;
  /** Overrides the "view full report" URL entirely. */
  reportUrl?: string;
  /** Brand name shown in the header and footer. */
  appName?: string;
  /** One-line preview text shown in the inbox next to the subject. */
  preheader?: string;
}

export interface ReportLinkOptions {
  baseUrl?: string;
  pdfUrl?: string;
  reportUrl?: string;
}

const DEFAULT_APP_NAME = "OmniScan";
const DEFAULT_BASE_URL = "https://app.omniscan.io";
const CONTENT_WIDTH = 600;

export interface CategoryMetric {
  key: "performance" | "security" | "dns" | "bestPractices";
  label: string;
  score: number;
  blurb: string;
}

const GRADE_COLORS: Record<CompositeScore["grade"], string> = {
  "A+": "#059669",
  A: "#16a34a",
  B: "#0284c7",
  C: "#d97706",
  D: "#ea580c",
  F: "#dc2626",
};

const SEVERITY_COLORS: Record<PriorityFix["severity"], { bg: string; fg: string; label: string }> = {
  critical: { bg: "#fee2e2", fg: "#991b1b", label: "Critical" },
  warning: { bg: "#fef3c7", fg: "#92400e", label: "Warning" },
  info: { bg: "#dbeafe", fg: "#1e40af", label: "Info" },
};

export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Report values originate from user-supplied URLs and remote server responses, so
 * they reach `href` attributes untrusted. Anything that is not http(s) is dropped.
 */
export function safeUrl(value: string | undefined | null): string | undefined {
  if (!value) return undefined;
  const trimmed = String(value).trim();
  if (!/^https?:\/\//i.test(trimmed)) return undefined;
  return trimmed;
}

export function gradeColor(grade: CompositeScore["grade"]): string {
  return GRADE_COLORS[grade] ?? GRADE_COLORS.F;
}

export function scoreColor(score: number): string {
  const clamped = Math.max(0, Math.min(100, Number.isFinite(score) ? score : 0));
  if (clamped >= 85) return "#16a34a";
  if (clamped >= 70) return "#0284c7";
  if (clamped >= 50) return "#d97706";
  return "#dc2626";
}

export function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(Number.isFinite(score) ? score : 0)));
}

export function formatScannedAt(iso: string): string {
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return "";
  return parsed.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}

export function categoryMetrics(report: FullAuditReport): CategoryMetric[] {
  return [
    {
      key: "performance",
      label: "Performance",
      score: report.performance?.score ?? 0,
      blurb: `LCP ${report.performance?.webVitals?.lcp ?? 0}ms`,
    },
    {
      key: "security",
      label: "Security",
      score: report.security?.headers?.score ?? 0,
      blurb: `${report.security?.tls?.protocol ?? "No TLS"}`,
    },
    {
      key: "dns",
      label: "DNS",
      score: report.dns?.score ?? 0,
      blurb: report.dns?.hasDmarc ? "DMARC present" : "No DMARC",
    },
    {
      key: "bestPractices",
      label: "Best Practices",
      score: report.performance?.bestPracticesScore ?? 0,
      blurb: `A11y ${report.performance?.accessibilityScore ?? 0}`,
    },
  ];
}

export function buildPdfUrl(report: FullAuditReport, options: ReportLinkOptions = {}): string | undefined {
  const override = safeUrl(options.pdfUrl);
  if (override) return override;

  const base = (safeUrl(options.baseUrl ?? DEFAULT_BASE_URL) ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  return `${base}/reports/${encodeURIComponent(report.scanId)}/download.pdf`;
}

export function buildReportUrl(report: FullAuditReport, options: ReportLinkOptions = {}): string | undefined {
  const override = safeUrl(options.reportUrl);
  if (override) return override;

  const base = (safeUrl(options.baseUrl ?? DEFAULT_BASE_URL) ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  return `${base}/reports/${encodeURIComponent(report.scanId)}`;
}

export function buildSubject(report: FullAuditReport): string {
  const domain = report.targetDomain || "your site";
  const grade = report.composite.grade;
  return `${domain} scored ${clampScore(report.composite.omniScore)}/100 (${grade}) — OmniScan audit`;
}

/**
 * conic-gradient is unsupported in the Word rendering engine (Outlook desktop).
 * The segmented bar underneath carries the same value using table-safe markup,
 * so clients without gradient support degrade to a readable meter instead of a
 * blank square.
 */
export function renderMeter(score: number, accent: string, label: string): string {
  const value = clampScore(score);
  const degrees = (value / 100) * 360;
  const gradient = `conic-gradient(${accent} 0deg ${degrees}deg, #e2e8f0 ${degrees}deg 360deg)`;
  const segments = 10;
  const filled = Math.round((value / 100) * segments);

  let bars = "";
  for (let i = 0; i < segments; i++) {
    const color = i < filled ? accent : "#e2e8f0";
    bars +=
      `<td width="10%" height="6" bgcolor="${color}" style="width:10%;height:6px;font-size:0;line-height:0;">&nbsp;</td>`;
  }

  return `<table role="presentation" width="104" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;border-collapse:separate;">
  <tr>
    <td align="center" valign="top">
      <div role="img" aria-label="${escapeHtml(label)}: ${value} out of 100" style="width:104px;height:104px;border-radius:52px;background:${gradient};background-image:${gradient};">
        <div style="width:78px;height:78px;border-radius:39px;background:#ffffff;margin:13px 0 0 13px;line-height:78px;text-align:center;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:26px;font-weight:700;color:${accent};">${value}</div>
      </div>
      <table role="presentation" width="104" cellpadding="0" cellspacing="0" border="0" style="margin:10px auto 0 auto;border-collapse:separate;">
        <tr>${bars}</tr>
      </table>
    </td>
  </tr>
</table>`;
}

export function renderGradeBanner(report: FullAuditReport): string {
  const composite = report.composite;
  const accent = gradeColor(composite.grade);
  const score = clampScore(composite.omniScore);
  const scanned = formatScannedAt(report.scannedAt);
  const domain = escapeHtml(report.targetDomain || report.targetUrl || "Your website");

  const meta = [domain, scanned ? `Scanned ${escapeHtml(scanned)}` : ""].filter(Boolean).join(" &middot; ");

  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate;background:#f8fafc;border-radius:12px;">
  <tr>
    <td align="center" style="padding:28px 24px 24px 24px;">
      <div role="img" aria-label="Overall grade ${escapeHtml(composite.grade)}, ${score} out of 100" style="width:112px;height:112px;border-radius:56px;background:${accent};margin:0 auto;line-height:112px;text-align:center;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:52px;font-weight:700;color:#ffffff;">${escapeHtml(composite.grade)}</div>
      <div style="margin-top:12px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:26px;font-weight:700;color:#0f172a;line-height:32px;">${score} out of 100</div>
      <div style="margin-top:8px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;line-height:22px;color:#475569;">${escapeHtml(composite.summary ?? "")}</div>
      <div style="margin-top:10px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:13px;line-height:18px;color:#94a3b8;">${meta}</div>
    </td>
  </tr>
</table>`;
}

function renderCategoryCard(metric: CategoryMetric): string {
  const accent = scoreColor(metric.score);

  return `<td class="stack-column" valign="top" width="264" style="width:264px;padding:0 8px 16px 8px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;">
    <tr>
      <td align="center" style="padding:24px 16px 20px 16px;">
        ${renderMeter(metric.score, accent, metric.label)}
        <div style="margin-top:14px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:17px;font-weight:700;color:#0f172a;line-height:22px;">${escapeHtml(metric.label)}</div>
        <div style="margin-top:4px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:13px;line-height:18px;color:#64748b;">${escapeHtml(metric.blurb)}</div>
      </td>
    </tr>
  </table>
</td>`;
}

export function renderCategoryCards(report: FullAuditReport): string {
  const cards = categoryMetrics(report)
    .map(renderCategoryCard)
    .join(`<!--[if mso]></td><td width="264" valign="top"><![endif]-->\n      `);

  return `<!--[if mso]><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td width="264" valign="top"><![endif]-->
      ${cards}
      <!--[if mso]></td></tr></table><![endif]-->`;
}

function renderFixRow(fix: PriorityFix, index: number, isLast: boolean): string {
  const severity = SEVERITY_COLORS[fix.severity] ?? SEVERITY_COLORS.info;
  const divider = isLast ? "" : "border-bottom:1px solid #e2e8f0;";

  return `<tr>
    <td valign="top" style="padding:16px 0;${divider}">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate;">
        <tr>
          <td valign="top" width="34" style="width:34px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:18px;font-weight:700;color:#cbd5e1;line-height:24px;">${index}</td>
          <td valign="top" style="font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
            <div style="font-size:16px;font-weight:700;color:#0f172a;line-height:22px;">${escapeHtml(fix.title)}</div>
            <div style="margin-top:6px;font-size:14px;line-height:21px;color:#475569;">${escapeHtml(fix.detail)}</div>
            <div style="margin-top:8px;font-size:13px;line-height:19px;color:#64748b;"><strong>Impact:</strong> ${escapeHtml(fix.impact)}</div>
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-top:8px;border-collapse:separate;">
              <tr>
                <td bgcolor="${severity.bg}" style="background:${severity.bg};border-radius:4px;padding:3px 8px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:11px;font-weight:700;letter-spacing:0.4px;color:${severity.fg};text-transform:uppercase;">${escapeHtml(severity.label)}</td>
                <td style="padding-left:8px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:11px;font-weight:700;letter-spacing:0.4px;color:#94a3b8;text-transform:uppercase;">${escapeHtml(fix.category)}</td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </td>
  </tr>`;
}

export function renderPriorityFixes(report: FullAuditReport): string {
  const fixes = (report.composite?.priorityFixes ?? []).slice(0, 3);

  if (fixes.length === 0) {
    return `<p style="margin:0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;line-height:22px;color:#475569;">No critical issues found. Your site is in good shape.</p>`;
  }

  const rows = fixes.map((fix, i) => renderFixRow(fix, i + 1, i === fixes.length - 1)).join("\n      ");

  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate;">
      ${rows}
    </table>`;
}

function renderButton(href: string, label: string, options: { primary?: boolean } = {}): string {
  const primary = options.primary ?? false;
  const bg = primary ? "#0f172a" : "#ffffff";
  const fg = primary ? "#ffffff" : "#0f172a";
  const border = primary ? `#0f172a` : "#cbd5e1";

  // Outlook ignores border-radius on anchors, so a VML roundrect keeps the pill shape.
  return `<!--[if mso]>
      <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="${escapeHtml(href)}" style="height:48px;v-text-anchor:middle;width:300px;" arcsize="50%" stroke="f" fillcolor="${bg}">
        <w:anchorlock/>
        <center style="color:${fg};font-family:Helvetica,Arial,sans-serif;font-size:15px;font-weight:bold;">${escapeHtml(label)}</center>
      </v:roundrect>
    <![endif]-->
    <!--[if !mso]><!-- -->
    <a href="${escapeHtml(href)}" style="display:inline-block;background:${bg};border:2px solid ${border};border-radius:8px;padding:14px 32px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;font-weight:700;color:${fg};text-decoration:none;mso-hide:all;">${escapeHtml(label)}</a>
    <!--<![endif]-->`;
}

export function renderDownloadButtons(report: FullAuditReport, options: EmailTemplateOptions = {}): string {
  const pdfUrl = buildPdfUrl(report, options);
  const reportUrl = buildReportUrl(report, options);
  const buttons: string[] = [];

  if (pdfUrl) buttons.push(renderButton(pdfUrl, "Download PDF Report", { primary: true }));
  if (reportUrl) buttons.push(renderButton(reportUrl, "View Full Report Online"));

  if (buttons.length === 0) return "";

  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate;">
      <tr>
        <td align="center" style="padding:8px 0;">
          ${buttons.join(`\n          <div style="height:12px;line-height:12px;font-size:12px;">&nbsp;</div>\n          `)}
        </td>
      </tr>
    </table>`;
}

function sectionHeading(title: string): string {
  return `<h2 style="margin:0 0 4px 0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:18px;font-weight:700;color:#0f172a;line-height:24px;">${escapeHtml(title)}</h2>`;
}

function sectionSubheading(title: string, sub: string): string {
  return `${sectionHeading(title)}<p style="margin:0 0 16px 0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:14px;line-height:20px;color:#64748b;">${escapeHtml(sub)}</p>`;
}

export function renderEmailHtml(report: FullAuditReport, options: EmailTemplateOptions = {}): string {
  const appName = escapeHtml(options.appName ?? DEFAULT_APP_NAME);
  const target = escapeHtml(report.targetUrl || report.targetDomain || "");
  const reportUrl = buildReportUrl(report, options);
  const scanned = formatScannedAt(report.scannedAt);
  const preheader = escapeHtml(
    options.preheader ?? `Grade ${report.composite.grade} — ${clampScore(report.composite.omniScore)}/100 across performance, security, DNS and best practices.`
  );

  const footerLink = reportUrl
    ? `<a href="${escapeHtml(reportUrl)}" style="color:#0284c7;text-decoration:underline;">View this report online</a>`
    : "";

  return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta name="x-apple-disable-message-reformatting" />
<title>${escapeHtml(buildSubject(report))}</title>
<style type="text/css">
  body { margin:0 !important; padding:0 !important; width:100% !important; -webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; }
  table { border-collapse:collapse !important; }
  img { border:0; line-height:100%; outline:none; text-decoration:none; -ms-interpolation-mode:bicubic; }
  a { color:#0284c7; }
  .preheader { display:none !important; max-height:0 !important; max-width:0 !important; overflow:hidden !important; mso-hide:all !important; }
  @media only screen and (max-width:600px) {
    .container { width:100% !important; }
    .stack-column { display:block !important; width:100% !important; max-width:100% !important; }
    .stack-pad { padding-left:20px !important; padding-right:20px !important; }
    .grade-circle { width:88px !important; height:88px !important; line-height:88px !important; font-size:40px !important; border-radius:44px !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;">
  <div class="preheader" style="display:none;max-height:0;max-width:0;overflow:hidden;">${preheader}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f1f5f9;">
    <tr>
      <td align="center" style="padding:24px 12px;">
        <!--[if mso]><table role="presentation" width="${CONTENT_WIDTH}" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->
        <table role="presentation" class="container" width="${CONTENT_WIDTH}" cellpadding="0" cellspacing="0" border="0" style="width:${CONTENT_WIDTH}px;max-width:${CONTENT_WIDTH}px;background:#ffffff;border-radius:16px;">
          <tr>
            <td align="left" style="padding:28px 28px 8px 28px;">
              <div style="font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:20px;font-weight:700;color:#0f172a;line-height:26px;">${appName}</div>
              <div style="margin-top:4px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:14px;line-height:20px;color:#64748b;">Website health report${scanned ? ` for ${escapeHtml(scanned)}` : ""}</div>
            </td>
          </tr>
          <tr>
            <td class="stack-pad" style="padding:20px 28px 0 28px;">
              ${renderGradeBanner(report)}
            </td>
          </tr>
          <tr>
            <td class="stack-pad" style="padding:28px 28px 0 28px;">
              ${sectionSubheading("Category breakdown", "How your site scores across the four OmniScan engines.")}
              ${renderCategoryCards(report)}
            </td>
          </tr>
          <tr>
            <td class="stack-pad" style="padding:20px 28px 0 28px;">
              ${sectionSubheading("Top priority fixes", "The three changes with the biggest impact on your score.")}
              ${renderPriorityFixes(report)}
            </td>
          </tr>
          <tr>
            <td class="stack-pad" style="padding:28px 28px 32px 28px;">
              ${sectionHeading("Get the full report")}
              ${renderDownloadButtons(report, options)}
            </td>
          </tr>
          <tr>
            <td class="stack-pad" style="padding:20px 28px 24px 28px;border-top:1px solid #e2e8f0;">
              <p style="margin:0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:12px;line-height:18px;color:#94a3b8;">
                ${appName} audit of <a href="${escapeHtml(safeUrl(target) ?? "#")}" style="color:#64748b;text-decoration:underline;">${escapeHtml(report.targetUrl || report.targetDomain || "your site")}</a>${report.scanId ? ` &middot; Scan ${escapeHtml(report.scanId)}` : ""}.
                ${footerLink}
              </p>
            </td>
          </tr>
        </table>
        <!--[if mso]></td></tr></table><![endif]-->
      </td>
    </tr>
  </table>
</body>
</html>`;
}

export function renderEmailText(report: FullAuditReport, options: EmailTemplateOptions = {}): string {
  const lines: string[] = [];
  const appName = options.appName ?? DEFAULT_APP_NAME;
  const scanned = formatScannedAt(report.scannedAt);

  lines.push(`${appName} website health report`);
  lines.push(report.targetDomain || report.targetUrl || "");
  if (scanned) lines.push(`Scanned ${scanned}`);
  lines.push("");
  lines.push(`OVERALL GRADE: ${report.composite.grade} (${clampScore(report.composite.omniScore)}/100)`);
  if (report.composite.summary) lines.push(report.composite.summary);
  lines.push("");

  lines.push("CATEGORY BREAKDOWN");
  for (const metric of categoryMetrics(report)) {
    lines.push(`  ${metric.label.padEnd(16)} ${String(clampScore(metric.score)).padStart(3)}/100  -  ${metric.blurb}`);
  }
  lines.push("");

  lines.push("TOP PRIORITY FIXES");
  const fixes = (report.composite?.priorityFixes ?? []).slice(0, 3);
  if (fixes.length === 0) {
    lines.push("  No critical issues found.");
  } else {
    fixes.forEach((fix, i) => {
      lines.push(`  ${i + 1}. [${fix.severity.toUpperCase()}] ${fix.title}`);
      lines.push(`     ${fix.detail}`);
      lines.push(`     Impact: ${fix.impact}`);
    });
  }
  lines.push("");

  const pdfUrl = buildPdfUrl(report, options);
  const reportUrl = buildReportUrl(report, options);
  if (pdfUrl) lines.push(`Download the PDF report: ${pdfUrl}`);
  if (reportUrl) lines.push(`View the full report online: ${reportUrl}`);

  return lines.join("\n");
}

export interface ReportEmailProps {
  report: FullAuditReport;
  options?: EmailTemplateOptions;
}

/**
 * Responsive report email template component for React Email composition.
 * Returns the fully rendered responsive HTML document.
 */
export function ReportEmail(props: ReportEmailProps): string {
  return renderEmailHtml(props.report, props.options);
}

export const AuditReportEmail = ReportEmail;
export const EmailTemplate = ReportEmail;

export function GradeBanner(props: { report: FullAuditReport }): string {
  return renderGradeBanner(props.report);
}

export function CategoryCards(props: { report: FullAuditReport }): string {
  return renderCategoryCards(props.report);
}

export function PriorityFixes(props: { report: FullAuditReport }): string {
  return renderPriorityFixes(props.report);
}

export function DownloadButtons(props: { report: FullAuditReport; options?: EmailTemplateOptions }): string {
  return renderDownloadButtons(props.report, props.options);
}

