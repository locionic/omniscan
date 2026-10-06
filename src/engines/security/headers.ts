import type { HeaderCheck, SecurityHeadersResult } from "../../types/index.js";

export function evaluateHeaders(headers: Record<string, string | string[] | undefined>, cookies?: string[]): SecurityHeadersResult {
  const normHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v !== undefined) {
      normHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
    }
  }

  const checks: HeaderCheck[] = [];
  let score = 100;

  // 1. Content-Security-Policy (CSP)
  const csp = normHeaders["content-security-policy"];
  if (!csp) {
    score -= 25;
    checks.push({
      header: "Content-Security-Policy",
      present: false,
      pass: false,
      score: 0,
      recommendation: "Implement CSP to protect against Cross-Site Scripting (XSS) and code injection attacks.",
    });
  } else {
    const hasUnsafe = csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'");
    if (hasUnsafe) {
      score -= 10;
      checks.push({
        header: "Content-Security-Policy",
        present: true,
        value: csp,
        pass: true,
        score: 15,
        recommendation: "CSP is present but contains 'unsafe-inline' or 'unsafe-eval'. Use nonces or hashes instead.",
      });
    } else {
      checks.push({
        header: "Content-Security-Policy",
        present: true,
        value: csp,
        pass: true,
        score: 25,
        recommendation: "Strong CSP policy configured.",
      });
    }
  }

  // 2. Strict-Transport-Security (HSTS)
  const hsts = normHeaders["strict-transport-security"];
  if (!hsts) {
    score -= 20;
    checks.push({
      header: "Strict-Transport-Security",
      present: false,
      pass: false,
      score: 0,
      recommendation: "Enable HSTS (Strict-Transport-Security) with max-age >= 31536000 and includeSubDomains to prevent SSL stripping.",
    });
  } else {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    const hasSubdomains = hsts.toLowerCase().includes("includesubdomains");
    const hasPreload = hsts.toLowerCase().includes("preload");

    if (maxAge < 10886400) {
      score -= 10;
      checks.push({
        header: "Strict-Transport-Security",
        present: true,
        value: hsts,
        pass: false,
        score: 10,
        recommendation: "HSTS max-age is too short. Recommended value is at least 31536000 (1 year).",
      });
    } else {
      checks.push({
        header: "Strict-Transport-Security",
        present: true,
        value: hsts,
        pass: true,
        score: 20 + (hasPreload && hasSubdomains ? 5 : 0),
        recommendation: "HSTS policy configured with sufficient duration.",
      });
    }
  }

  // 3. X-Frame-Options (Clickjacking)
  const xfo = normHeaders["x-frame-options"];
  if (!xfo && (!csp || !csp.includes("frame-ancestors"))) {
    score -= 15;
    checks.push({
      header: "X-Frame-Options",
      present: false,
      pass: false,
      score: 0,
      recommendation: "Set X-Frame-Options to DENY or SAMEORIGIN (or CSP frame-ancestors) to prevent clickjacking.",
    });
  } else {
    checks.push({
      header: "X-Frame-Options",
      present: !!xfo,
      value: xfo || "Covered via CSP frame-ancestors",
      pass: true,
      score: 15,
      recommendation: "Clickjacking protection is active.",
    });
  }

  // 4. X-Content-Type-Options (MIME Sniffing)
  const xcto = normHeaders["x-content-type-options"];
  if (!xcto || xcto.toLowerCase() !== "nosniff") {
    score -= 10;
    checks.push({
      header: "X-Content-Type-Options",
      present: !!xcto,
      value: xcto,
      pass: false,
      score: 0,
      recommendation: "Set X-Content-Type-Options to 'nosniff' to prevent MIME-type confusion attacks.",
    });
  } else {
    checks.push({
      header: "X-Content-Type-Options",
      present: true,
      value: xcto,
      pass: true,
      score: 10,
      recommendation: "MIME-sniffing protection enabled.",
    });
  }

  // 5. Referrer-Policy
  const rp = normHeaders["referrer-policy"];
  if (!rp) {
    score -= 10;
    checks.push({
      header: "Referrer-Policy",
      present: false,
      pass: false,
      score: 0,
      recommendation: "Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer' to protect sensitive URLs.",
    });
  } else {
    checks.push({
      header: "Referrer-Policy",
      present: true,
      value: rp,
      pass: true,
      score: 10,
      recommendation: "Referrer-Policy configured.",
    });
  }

  // 6. Permissions-Policy
  const pp = normHeaders["permissions-policy"];
  if (!pp) {
    score -= 5;
    checks.push({
      header: "Permissions-Policy",
      present: false,
      pass: false,
      score: 0,
      recommendation: "Define Permissions-Policy to restrict camera, microphone, geolocation, and payment APIs.",
    });
  } else {
    checks.push({
      header: "Permissions-Policy",
      present: true,
      value: pp,
      pass: true,
      score: 5,
      recommendation: "Browser hardware permissions policy configured.",
    });
  }

  // 7. Information Leakage (Server / X-Powered-By)
  const server = normHeaders["server"];
  const xpb = normHeaders["x-powered-by"];
  if (xpb) {
    score -= 5;
    checks.push({
      header: "X-Powered-By",
      present: true,
      value: xpb,
      pass: false,
      score: 0,
      recommendation: "Remove X-Powered-By header to avoid leaking backend framework details to attackers.",
    });
  }

  // 8. Cookie Security Flags
  if (cookies && cookies.length > 0) {
    let insecureCookies = 0;
    for (const cookie of cookies) {
      const lower = cookie.toLowerCase();
      if (!lower.includes("secure") || !lower.includes("httponly")) {
        insecureCookies++;
      }
    }
    if (insecureCookies > 0) {
      score -= 10;
      checks.push({
        header: "Set-Cookie Flags",
        present: true,
        pass: false,
        score: 0,
        recommendation: `${insecureCookies} cookies are missing 'Secure' or 'HttpOnly' flags. Always protect session cookies.`,
      });
    } else {
      checks.push({
        header: "Set-Cookie Flags",
        present: true,
        pass: true,
        score: 10,
        recommendation: "All session cookies enforce Secure and HttpOnly flags.",
      });
    }
  }

  // Clamp score
  const finalScore = Math.max(0, Math.min(100, score));

  // Determine Grade
  let grade: "A+" | "A" | "B" | "C" | "D" | "F" = "F";
  if (finalScore >= 95) grade = "A+";
  else if (finalScore >= 85) grade = "A";
  else if (finalScore >= 70) grade = "B";
  else if (finalScore >= 55) grade = "C";
  else if (finalScore >= 40) grade = "D";
  else grade = "F";

  return {
    score: finalScore,
    grade,
    checks,
  };
}
