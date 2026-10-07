import { test } from "node:test";
import assert from "node:assert/strict";
import type { HeaderCheck, SecurityHeadersResult } from "../../src/types/index.ts";
import { evaluateHeaders } from "../../src/engines/security/headers.ts";

/** Retrieve a single check by its header name, failing loudly when absent. */
function checkFor(result: SecurityHeadersResult, header: string): HeaderCheck {
  const found = result.checks.find((c) => c.header === header);
  assert.ok(found, `expected a "${header}" check, got: ${result.checks.map((c) => c.header).join(", ")}`);
  return found;
}

const PERFECT_HEADERS: Record<string, string> = {
  "content-security-policy": "default-src 'self'",
  "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=()",
};

test("no headers at all scores 15 / F with 6 failed checks", () => {
  const result = evaluateHeaders({});

  assert.equal(result.score, 15);
  assert.equal(result.grade, "F");
  assert.equal(result.checks.length, 6);
});

test("perfect headers score 100 / A+ with 6 passing checks", () => {
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
});

test("header names are matched case-insensitively", () => {
  const result = evaluateHeaders({
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
  });

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
});

test("HSTS max-age below the threshold fails the check", () => {
  const result = evaluateHeaders({ "strict-transport-security": "max-age=100" });

  const hsts = checkFor(result, "Strict-Transport-Security");
  assert.equal(hsts.present, true);
  assert.equal(hsts.value, "max-age=100");
  assert.equal(hsts.pass, false);
  assert.equal(hsts.score, 10);
});

test("CSP with 'unsafe-inline' passes but is penalised", () => {
  const result = evaluateHeaders({
    "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
  });

  const csp = checkFor(result, "Content-Security-Policy");
  assert.equal(csp.present, true);
  assert.equal(csp.pass, true);
  assert.equal(csp.score, 15);
});

test("CSP frame-ancestors covers a missing X-Frame-Options", () => {
  const result = evaluateHeaders({
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  });

  const xfo = checkFor(result, "X-Frame-Options");
  assert.equal(xfo.present, false);
  assert.equal(xfo.pass, true);
  assert.equal(xfo.value, "Covered via CSP frame-ancestors");
});

test("array header values are joined before evaluation", () => {
  const result = evaluateHeaders({ "X-Powered-By": ["Express", "5"] });

  const xpb = checkFor(result, "X-Powered-By");
  assert.equal(xpb.present, true);
  assert.equal(xpb.value, "Express, 5");
  assert.equal(xpb.pass, false);
  assert.equal(xpb.score, 0);
});

test("cookie flags are reported per set-cookie array", () => {
  const insecure = evaluateHeaders({}, ["sid=abc"]);
  const insecureCheck = checkFor(insecure, "Set-Cookie Flags");
  assert.equal(insecureCheck.present, true);
  assert.equal(insecureCheck.pass, false);
  assert.equal(insecureCheck.score, 0);

  const secure = evaluateHeaders({}, ["sid=abc; Secure; HttpOnly"]);
  const secureCheck = checkFor(secure, "Set-Cookie Flags");
  assert.equal(secureCheck.present, true);
  assert.equal(secureCheck.pass, true);
  assert.equal(secureCheck.score, 10);
});

test("weak CSP, short HSTS, X-Powered-By and insecure cookies stack to 25 / F", () => {
  const result = evaluateHeaders(
    {
      "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
      "strict-transport-security": "max-age=100",
      "X-Powered-By": ["Express", "5"],
    },
    ["sid=abc"],
  );

  assert.equal(result.score, 25);
  assert.equal(result.grade, "F");
  assert.equal(result.checks.length, 8);
});