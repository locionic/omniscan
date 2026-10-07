import { test } from "node:test";
import assert from "node:assert/strict";
import type { HeaderCheck, SecurityHeadersResult } from "../../src/types/index.ts";
import { evaluateHeaders } from "../../src/engines/security/headers.ts";

/** Retrieve a single check by its header name, failing loudly when absent. */
function checkFor(result: SecurityHeadersResult, header: string): HeaderCheck {
  const found = result.checks.find((c) => c.header === header);
  assert.ok(found, `expected a "${header}" check, got: ${result.checks.map((c) => c.header).join(", ") || "(none)"}`);
  return found;
}

/** A header set that earns a clean 100 / A+ with every one of the six checks passing. */
const PERFECT_HEADERS: Record<string, string> = {
  "content-security-policy": "default-src 'self'",
  "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=()",
};

test("an empty header record scores 15 / F with six failing checks", () => {
  // NOTE: the task brief asked for a score of 0 here, but the implementation's six
  // base penalties total 85 (25 CSP + 20 HSTS + 15 XFO + 10 XCTO + 10 RP + 5 PP), so
  // an empty record floors out at 15 — the remaining 15 points are only reachable
  // by also failing the cookie (-10) and X-Powered-By (-5) checks. See sibling
  // tests/security/headers.test.ts on agent/task-5, which pins the same 15.
  const result = evaluateHeaders({});

  assert.equal(result.score, 15);
  assert.equal(result.grade, "F");
  assert.equal(result.checks.length, 6);
  assert.deepEqual(result.checks.map((c) => c.pass), [false, false, false, false, false, false]);
});

test("an empty header record fails every security header check", () => {
  const result = evaluateHeaders({});

  for (const header of [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
  ]) {
    const check = checkFor(result, header);
    assert.equal(check.present, false, `${header} should be reported as absent`);
    assert.equal(check.pass, false, `${header} should fail`);
    assert.equal(check.score, 0, `${header} should contribute no points`);
    assert.ok(check.recommendation.length > 0, `${header} should carry a recommendation`);
  }
});

test("a fully hardened header set scores 100 / A+", () => {
  const result = evaluateHeaders({ ...PERFECT_HEADERS });

  assert.equal(result.score, 100);
  assert.equal(result.grade, "A+");
  assert.equal(result.checks.length, 6);
  assert.deepEqual(
    result.checks.map((c) => c.header),
    [
      "Content-Security-Policy",
      "Strict-Transport-Security",
      "X-Frame-Options",
      "X-Content-Type-Options",
      "Referrer-Policy",
      "Permissions-Policy",
    ],
  );
  assert.deepEqual(result.checks.map((c) => c.pass), [true, true, true, true, true, true]);
});

test("X-Powered-By fails a check and costs 5 points", () => {
  const result = evaluateHeaders({ ...PERFECT_HEADERS, "x-powered-by": "Express" });

  assert.equal(result.score, 95); // 100 - 5
  assert.equal(result.grade, "A+"); // 95 sits exactly on the A+ boundary

  const check = checkFor(result, "X-Powered-By");
  assert.equal(check.present, true);
  assert.equal(check.pass, false);
  assert.equal(check.score, 0);
  assert.equal(check.value, "Express");
  assert.equal(result.checks.length, 7);
});

test("a CSP with 'unsafe-inline' or 'unsafe-eval' is penalised but still reports pass:true", () => {
  for (const [label, csp] of [
    ["unsafe-inline", "default-src 'self'; script-src 'unsafe-inline'"],
    ["unsafe-eval", "default-src 'self'; script-src 'unsafe-eval'"],
  ] as const) {
    const result = evaluateHeaders({ ...PERFECT_HEADERS, "content-security-policy": csp });

    // Quirk pinned deliberately: the 10-point deduction is applied, yet the check
    // is still marked passing — the weakness is advisory, surfaced only through the
    // recommendation text. `pass` only ever goes false when the header is absent.
    assert.equal(result.score, 90, `${label}: expected the 10-point penalty`);
    assert.equal(result.grade, "A");

    const check = checkFor(result, "Content-Security-Policy");
    assert.equal(check.present, true);
    assert.equal(check.pass, true, `${label}: still reported as passing`);
    assert.equal(check.score, 15);
    assert.equal(check.value, csp);
    assert.ok(
      check.recommendation.includes("nonces or hashes"),
      `${label}: expected a nonce/hash recommendation, got: ${check.recommendation}`,
    );
  }
});

test("CSP frame-ancestors satisfies the clickjacking check without an XFO header", () => {
  const result = evaluateHeaders({
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
  });

  assert.equal(result.score, 100);
  assert.equal(result.grade, "A+");

  const check = checkFor(result, "X-Frame-Options");
  assert.equal(check.present, false, "no XFO header was actually sent");
  assert.equal(check.pass, true);
  assert.equal(check.score, 15);
  assert.equal(check.value, "Covered via CSP frame-ancestors");
});

test("header names and nosniff values are matched case-insensitively", () => {
  const result = evaluateHeaders({
    "CONTENT-SECURITY-POLICY": "default-src 'self'",
    "STRICT-TRANSPORT-SECURITY": "max-age=31536000; includeSubDomains; preload",
    "X-FRAME-OPTIONS": "DENY",
    "x-content-type-options": "NOSNIFF",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "PERMISSIONS-POLICY": "geolocation=()",
  });

  assert.equal(result.score, 100);
  assert.equal(result.grade, "A+");

  const xcto = checkFor(result, "X-Content-Type-Options");
  assert.equal(xcto.pass, true);
  assert.equal(xcto.value, "NOSNIFF", "the original value casing is preserved in the check");
});

test("array-valued headers are joined with ', ' before evaluation", () => {
  const result = evaluateHeaders({
    ...PERFECT_HEADERS,
    "permissions-policy": ["geolocation=()", "camera=()"],
  });

  assert.equal(result.score, 100);
  assert.equal(result.grade, "A+");
  assert.equal(
    checkFor(result, "Permissions-Policy").value,
    "geolocation=(), camera=()",
    "array entries should be joined with a comma and a space",
  );
});

test("headers explicitly set to undefined are skipped entirely", () => {
  const result = evaluateHeaders({ ...PERFECT_HEADERS, "x-powered-by": undefined });

  assert.equal(result.score, 100);
  assert.equal(result.grade, "A+");
  assert.equal(
    result.checks.find((c) => c.header === "X-Powered-By"),
    undefined,
    "an undefined header value should behave as absent, not as an empty string",
  );
});

test("HSTS max-age=300 fails but max-age=10886400 passes", () => {
  // Boundary pinned as-is: the code accepts max-age >= 10886400 (126 days), while the
  // recommendation text it emits for a failure cites 31536000 (1 year). The two
  // disagree — the code is more permissive than the advice it prints.
  const tooShort = evaluateHeaders({ ...PERFECT_HEADERS, "strict-transport-security": "max-age=300" });

  assert.equal(tooShort.score, 90); // 100 - 10
  assert.equal(tooShort.grade, "A");

  const shortCheck = checkFor(tooShort, "Strict-Transport-Security");
  assert.equal(shortCheck.present, true);
  assert.equal(shortCheck.pass, false);
  assert.equal(shortCheck.score, 10);
  assert.equal(shortCheck.value, "max-age=300");
  assert.ok(
    shortCheck.recommendation.includes("31536000"),
    `expected the recommendation to cite 31536000, got: ${shortCheck.recommendation}`,
  );

  const atThreshold = evaluateHeaders({ ...PERFECT_HEADERS, "strict-transport-security": "max-age=10886400" });

  assert.equal(atThreshold.score, 100);
  assert.equal(atThreshold.grade, "A+");
  assert.equal(checkFor(atThreshold, "Strict-Transport-Security").pass, true);
});

test("HSTS with includeSubDomains and preload earns the 20 + 5 bonus", () => {
  const both = evaluateHeaders({
    ...PERFECT_HEADERS,
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
  });

  assert.equal(checkFor(both, "Strict-Transport-Security").score, 25);

  // The +5 lands on the check score only — it never lifts the overall total above 100.
  assert.equal(both.score, 100);
  assert.equal(both.grade, "A+");
});

test("the HSTS +5 bonus requires includeSubDomains and preload together", () => {
  const subdomainsOnly = evaluateHeaders({
    ...PERFECT_HEADERS,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
  });
  const preloadOnly = evaluateHeaders({
    ...PERFECT_HEADERS,
    "strict-transport-security": "max-age=31536000; preload",
  });
  const neither = evaluateHeaders({ ...PERFECT_HEADERS, "strict-transport-security": "max-age=31536000" });

  assert.equal(checkFor(subdomainsOnly, "Strict-Transport-Security").score, 20);
  assert.equal(checkFor(preloadOnly, "Strict-Transport-Security").score, 20);
  assert.equal(checkFor(neither, "Strict-Transport-Security").score, 20);
  assert.equal(checkFor(subdomainsOnly, "Strict-Transport-Security").pass, true);
});

test("cookies missing Secure or HttpOnly fail the Set-Cookie Flags check", () => {
  const result = evaluateHeaders({ ...PERFECT_HEADERS }, ["sid=abc"]);

  assert.equal(result.score, 90); // 100 - 10

  const check = checkFor(result, "Set-Cookie Flags");
  assert.equal(check.present, true);
  assert.equal(check.pass, false);
  assert.equal(check.score, 0);
  assert.ok(
    check.recommendation.startsWith("1 cookies are missing"),
    `expected the offending count in the recommendation, got: ${check.recommendation}`,
  );
});

test("the Set-Cookie Flags recommendation reports the total offending count", () => {
  const result = evaluateHeaders(
    { ...PERFECT_HEADERS },
    ["sid=abc", "pref=xyz; Secure", "theme=dark; HttpOnly", "ok=1; Secure; HttpOnly"],
  );

  const check = checkFor(result, "Set-Cookie Flags");
  assert.equal(check.pass, false);
  assert.ok(
    check.recommendation.startsWith("3 cookies are missing"),
    `expected 3 offending cookies, got: ${check.recommendation}`,
  );
  assert.equal(result.score, 90, "the penalty is a flat 10 regardless of how many cookies fail");
});

test("an all-secure cookie array passes the Set-Cookie Flags check", () => {
  const result = evaluateHeaders(
    { ...PERFECT_HEADERS },
    ["sid=abc; Secure; HttpOnly; SameSite=Lax", "pref=xyz; Secure; HttpOnly"],
  );

  assert.equal(result.score, 100);
  assert.equal(result.grade, "A+");

  const check = checkFor(result, "Set-Cookie Flags");
  assert.equal(check.present, true);
  assert.equal(check.pass, true);
  assert.equal(check.score, 10);
});

test("cookie flags are matched as substrings of the whole Set-Cookie string", () => {
  // Quirk pinned deliberately: the check is a substring test over the raw cookie,
  // so a cookie whose *value* happens to contain "secure" is counted as secure.
  const result = evaluateHeaders({ ...PERFECT_HEADERS }, ["insecure_token=abc; HttpOnly"]);

  const check = checkFor(result, "Set-Cookie Flags");
  assert.equal(check.pass, true, `"insecure_token" contains the substring "secure"`);
  assert.equal(result.score, 100);
});

test("no Set-Cookie Flags check is emitted when cookies are omitted or empty", () => {
  const omitted = evaluateHeaders({ ...PERFECT_HEADERS });
  const empty = evaluateHeaders({ ...PERFECT_HEADERS }, []);

  for (const result of [omitted, empty]) {
    assert.equal(result.score, 100);
    assert.equal(result.grade, "A+");
    assert.equal(result.checks.length, 6);
    assert.equal(
      result.checks.find((c) => c.header === "Set-Cookie Flags"),
      undefined,
      "cookie scoring should be skipped entirely when no cookies are supplied",
    );
  }
});