import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  runPerformanceAudit,
  simulatePerformance,
  simulateWebVitals,
  extractWebVitals,
  scoreFromWebVitals,
  buildPerformanceResult,
  buildRecommendations,
  tbtToInpProxy,
  isCiEnvironment,
} from "../src/engines/performance/lighthouse.ts";
import type { CoreWebVitals } from "../src/types/index.ts";

describe("extractWebVitals", () => {
  test("extracts all five Core Web Vitals from a Lighthouse LHR audit map", () => {
    const vitals = extractWebVitals({
      "largest-contentful-paint": { numericValue: 2340.7 },
      "first-contentful-paint": { numericValue: 1610.2 },
      "total-blocking-time": { numericValue: 180 },
      "cumulative-layout-shift": { numericValue: 0.0432 },
      "server-response-time": { numericValue: 640.5 },
      "speed-index": { numericValue: 2050 },
    });

    assert.equal(vitals.lcp, 2341);
    assert.equal(vitals.fcp, 1610);
    assert.equal(vitals.cls, 0.043);
    assert.equal(vitals.ttfb, 641);
    assert.equal(vitals.speedIndex, 2050);
  });

  test("uses a real INP value when Lighthouse observed an interaction", () => {
    const vitals = extractWebVitals({
      "interaction-to-next-paint": { numericValue: 120 },
      "total-blocking-time": { numericValue: 300 },
    });

    assert.equal(vitals.inp, 120);
  });

  test("falls back to a TBT proxy for INP when no interaction was recorded", () => {
    const vitals = extractWebVitals({ "total-blocking-time": { numericValue: 200 } });

    assert.equal(vitals.inp, tbtToInpProxy(200));
    assert.equal(vitals.inp, 500);
  });

  test("defaults Speed Index to FCP when the audit is absent", () => {
    const vitals = extractWebVitals({ "first-contentful-paint": { numericValue: 900 } });

    assert.equal(vitals.speedIndex, 900);
  });

  test("yields zeroed vitals rather than NaN for a malformed audit map", () => {
    const vitals = extractWebVitals({ "largest-contentful-paint": { numericValue: "not-a-number" } });

    for (const value of Object.values(vitals)) {
      assert.ok(Number.isFinite(value), `expected finite value, got ${value}`);
    }
  });
});

describe("scoreFromWebVitals", () => {
  test("scores metrics sitting at half the threshold well, and saturated metrics at zero", () => {
    // Every ratio is 0.5 of its 'good' threshold, which the curve maps to 75.
    const healthy = scoreFromWebVitals({ lcp: 1250, inp: 100, cls: 0.05, fcp: 900, ttfb: 400, speedIndex: 1400 });
    const terrible = scoreFromWebVitals({ lcp: 9000, inp: 900, cls: 0.6, fcp: 8000, ttfb: 4000, speedIndex: 9000 });

    assert.equal(healthy, 75);
    assert.equal(terrible, 0);
  });

  test("scores metrics at the 'good' threshold at the midpoint", () => {
    const atThreshold = scoreFromWebVitals({ lcp: 2500, inp: 200, cls: 0.1, fcp: 1800, ttfb: 800, speedIndex: 2500 });

    assert.equal(atThreshold, 50);
  });

  test("stays within the 0-100 range for extreme inputs", () => {
    const low = scoreFromWebVitals({ lcp: 1, inp: 1, cls: 0, fcp: 1, ttfb: 1, speedIndex: 1 });
    const high = scoreFromWebVitals({ lcp: 999999, inp: 999999, cls: 999, fcp: 999999, ttfb: 999999, speedIndex: 999999 });

    assert.ok(low >= 0 && low <= 100);
    assert.ok(high >= 0 && high <= 100);
  });
});

describe("buildRecommendations", () => {
  test("flags each Core Web Vital that misses its 'good' threshold", () => {
    const recs = buildRecommendations({ lcp: 4000, inp: 500, cls: 0.3, fcp: 3000, ttfb: 1500, speedIndex: 3000 });
    const joined = recs.join(" ");

    assert.ok(joined.includes("TTFB"));
    assert.ok(joined.includes("FCP"));
    assert.ok(joined.includes("LCP"));
    assert.ok(joined.includes("INP"));
    assert.ok(joined.includes("CLS"));
  });

  test("returns a single positive note when all vitals pass", () => {
    const recs = buildRecommendations({ lcp: 1500, inp: 100, cls: 0.05, fcp: 1000, ttfb: 300, speedIndex: 1400 });

    assert.equal(recs.length, 1);
    assert.ok(recs[0].includes("within"));
  });
});

describe("simulateWebVitals", () => {
  test("is deterministic for the same URL", () => {
    assert.deepEqual(simulateWebVitals("https://example.com"), simulateWebVitals("https://example.com"));
  });

  test("differs between different URLs", () => {
    assert.notDeepEqual(simulateWebVitals("https://example.com"), simulateWebVitals("https://other.com"));
  });

  test("produces plausible, ordered metrics within realistic bounds", () => {
    for (const url of ["https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://e.com"]) {
      const v = simulateWebVitals(url);

      assert.ok(v.ttfb > 0 && v.ttfb < 1000, `ttfb out of range: ${v.ttfb}`);
      assert.ok(v.fcp > v.ttfb, "FCP must be slower than TTFB");
      assert.ok(v.lcp > v.fcp, "LCP must be slower than FCP");
      assert.ok(v.inp > 0, "INP must be positive");
      assert.ok(v.cls >= 0 && v.cls < 1, `cls out of range: ${v.cls}`);
    }
  });
});

describe("isCiEnvironment", () => {
  test("detects CI and GitHub Actions markers", () => {
    assert.equal(isCiEnvironment({ CI: "true" }), true);
    assert.equal(isCiEnvironment({ CI: "1" }), true);
    assert.equal(isCiEnvironment({ GITHUB_ACTIONS: "true" }), true);
  });

  test("treats an absent or non-CI marker as not CI", () => {
    assert.equal(isCiEnvironment({}), false);
    assert.equal(isCiEnvironment({ CI: "false" }), false);
  });
});

describe("runPerformanceAudit", () => {
  test("returns the simulation fallback when explicitly requested", async () => {
    const result = await runPerformanceAudit("https://example.com", { simulate: true });

    assert.equal(result.source, "simulated");
    assert.ok(result.fallbackReason);
    assert.equal(result.performance.score, scoreFromWebVitals(result.performance.webVitals));
    assert.ok(result.performance.recommendations.length > 0);
  });

  test("returns a complete PerformanceResult shape under simulation", async () => {
    const { performance } = await runPerformanceAudit("https://example.com", { simulate: true });

    assert.ok(performance.score >= 0 && performance.score <= 100);
    assert.ok(performance.accessibilityScore >= 0 && performance.accessibilityScore <= 100);
    assert.ok(performance.seoScore >= 0 && performance.seoScore <= 100);
    assert.ok(performance.bestPracticesScore >= 0 && performance.bestPracticesScore <= 100);
    assert.ok(Array.isArray(performance.recommendations));

    const v = performance.webVitals;
    assert.ok(Number.isFinite(v.lcp) && v.lcp >= 0);
    assert.ok(Number.isFinite(v.inp) && v.inp >= 0);
    assert.ok(Number.isFinite(v.cls) && v.cls >= 0);
    assert.ok(Number.isFinite(v.fcp) && v.fcp >= 0);
    assert.ok(Number.isFinite(v.ttfb) && v.ttfb >= 0);
    assert.ok(Number.isFinite(v.speedIndex) && v.speedIndex >= 0);
  });

  test("falls back to simulation rather than throwing when Chrome cannot run", async () => {
    // 1ms budget forces the timeout path without depending on host Chrome availability.
    const result = await runPerformanceAudit("http://127.0.0.1:1/definitely-not-listening", { timeoutMs: 1 });

    assert.equal(result.source, "simulated");
    assert.ok(result.fallbackReason, "expected a fallback reason to be recorded");
    assert.ok(result.performance.webVitals.lcp > 0);
  });

  test("simulation is stable across repeated audits of the same target", async () => {
    const a = await runPerformanceAudit("https://stable.example.com", { simulate: true });
    const b = await runPerformanceAudit("https://stable.example.com", { simulate: true });

    assert.deepEqual(a.performance.webVitals, b.performance.webVitals);
  });
});

describe("simulatePerformance", () => {
  test("mirrors the composite score into the sub-scores", () => {
    const performance = simulatePerformance("https://example.com");

    assert.equal(performance.accessibilityScore, performance.score);
    assert.equal(performance.seoScore, performance.score);
    assert.equal(performance.bestPracticesScore, performance.score);
  });
});

describe("buildPerformanceResult", () => {
  const vitals: CoreWebVitals = { lcp: 2000, inp: 150, cls: 0.08, fcp: 1500, ttfb: 600, speedIndex: 2200 };

  test("uses the supplied Lighthouse category scores instead of the composite", () => {
    const performance = buildPerformanceResult(vitals, {
      accessibilityScore: 84,
      seoScore: 82,
      bestPracticesScore: 100,
    });

    assert.equal(performance.accessibilityScore, 84);
    assert.equal(performance.seoScore, 82);
    assert.equal(performance.bestPracticesScore, 100);
    assert.notEqual(performance.accessibilityScore, performance.score);
  });

  test("falls back to the composite score per-field when a category score is missing", () => {
    const performance = buildPerformanceResult(vitals, { seoScore: 82 });

    assert.equal(performance.seoScore, 82);
    assert.equal(performance.accessibilityScore, performance.score);
    assert.equal(performance.bestPracticesScore, performance.score);
  });
});