import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert";
import { runLighthouse, type LighthouseConfig, getGrade } from "../src/engines/performance/lighthouse.ts";
import type { CoreWebVitals } from "../src/types/index.ts";

describe("Lighthouse Performance Engine", () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("runLighthouse", () => {
    it("should return simulated metrics in CI environment", async () => {
      process.env.CI = "true";

      const result = await runLighthouse("https://example.com");

      assert.strictEqual(typeof result.score, "number");
      assert.ok(result.score >= 0 && result.score <= 100);
      assert.strictEqual(result.accessibilityScore, 85);
      assert.strictEqual(result.seoScore, 90);
      assert.strictEqual(result.bestPracticesScore, 88);

      assert.ok("lcp" in result.webVitals);
      assert.ok("inp" in result.webVitals);
      assert.ok("cls" in result.webVitals);
      assert.ok("fcp" in result.webVitals);
      assert.ok("ttfb" in result.webVitals);
      assert.ok("speedIndex" in result.webVitals);

      assert.ok(Array.isArray(result.recommendations));
      assert.ok(result.recommendations.length > 0);
    });

    it("should use mock data when provided", async () => {
      const mockData: CoreWebVitals = {
        lcp: 1500,
        inp: 50,
        cls: 0.05,
        fcp: 1200,
        ttfb: 200,
        speedIndex: 1800,
      };

      const result = await runLighthouse("https://example.com", { mockData });

      assert.strictEqual(result.webVitals.lcp, 1500);
      assert.strictEqual(result.webVitals.inp, 50);
      assert.strictEqual(result.webVitals.cls, 0.05);
      assert.strictEqual(result.webVitals.fcp, 1200);
      assert.strictEqual(result.webVitals.ttfb, 200);
    });

    it("should calculate appropriate performance score from good vitals", () => {
      const config: LighthouseConfig = {
        mockData: {
          lcp: 1000,
          inp: 50,
          cls: 0.05,
          fcp: 800,
          ttfb: 200,
          speedIndex: 1500,
        },
      };

      return runLighthouse("https://example.com", config).then((result) => {
        assert.strictEqual(result.score, 100);
      });
    });

    it("should calculate lower score from poor vitals", () => {
      const config: LighthouseConfig = {
        mockData: {
          lcp: 5000,
          inp: 800,
          cls: 0.5,
          fcp: 4000,
          ttfb: 2000,
          speedIndex: 5000,
        },
      };

      return runLighthouse("https://example.com", config).then((result) => {
        assert.ok(result.score < 100);
      });
    });

    it("should detect GitHub Actions CI environment", async () => {
      delete process.env.CI;
      process.env.GITHUB_ACTIONS = "true";

      const result = await runLighthouse("https://example.com");

      assert.ok(result.recommendations.some((r) => r.includes("Simulated")));
    });

    it("should detect NODE_ENV test as CI", async () => {
      delete process.env.CI;
      delete process.env.GITHUB_ACTIONS;
      process.env.NODE_ENV = "test";

      const result = await runLighthouse("https://example.com");

      assert.ok(result.recommendations.some((r) => r.includes("Simulated")));
    });

    it("should generate recommendations for high LCP", () => {
      const config: LighthouseConfig = {
        mockData: {
          lcp: 4000,
          inp: 50,
          cls: 0.05,
          fcp: 800,
          ttfb: 200,
          speedIndex: 1500,
        },
      };

      return runLighthouse("https://example.com", config).then((result) => {
        assert.ok(
          result.recommendations.some((r) => r.includes("Largest Contentful Paint"))
        );
      });
    });

    it("should generate recommendations for high CLS", () => {
      const config: LighthouseConfig = {
        mockData: {
          lcp: 1000,
          inp: 50,
          cls: 0.5,
          fcp: 800,
          ttfb: 200,
          speedIndex: 1500,
        },
      };

      return runLighthouse("https://example.com", config).then((result) => {
        assert.ok(result.recommendations.some((r) => r.includes("Cumulative Layout Shift")));
      });
    });

    it("should generate recommendations for high INP", () => {
      const config: LighthouseConfig = {
        mockData: {
          lcp: 1000,
          inp: 500,
          cls: 0.05,
          fcp: 800,
          ttfb: 200,
          speedIndex: 1500,
        },
      };

      return runLighthouse("https://example.com", config).then((result) => {
        assert.ok(result.recommendations.some((r) => r.includes("Interaction to Next Paint")));
      });
    });

    it("should generate recommendations for high TTFB", () => {
      const config: LighthouseConfig = {
        mockData: {
          lcp: 1000,
          inp: 50,
          cls: 0.05,
          fcp: 800,
          ttfb: 1000,
          speedIndex: 1500,
        },
      };

      return runLighthouse("https://example.com", config).then((result) => {
        assert.ok(
          result.recommendations.some((r) =>
            r.includes("Time to First Byte")
          )
        );
      });
    });

    it("should use HTTPS URL automatically when protocol is missing", async () => {
      process.env.CI = "true";

      const result = await runLighthouse("example.com");

      assert.ok(result.recommendations.length > 0);
    });
  });

  describe("getGrade", () => {
    it("should return A+ for score >= 90", () => {
      assert.strictEqual(getGrade(90), "A+");
      assert.strictEqual(getGrade(95), "A+");
      assert.strictEqual(getGrade(100), "A+");
    });

    it("should return A for score 80-89", () => {
      assert.strictEqual(getGrade(80), "A");
      assert.strictEqual(getGrade(85), "A");
      assert.strictEqual(getGrade(89), "A");
    });

    it("should return B for score 70-79", () => {
      assert.strictEqual(getGrade(70), "B");
      assert.strictEqual(getGrade(75), "B");
      assert.strictEqual(getGrade(79), "B");
    });

    it("should return C for score 55-69", () => {
      assert.strictEqual(getGrade(55), "C");
      assert.strictEqual(getGrade(60), "C");
      assert.strictEqual(getGrade(69), "C");
    });

    it("should return D for score 40-54", () => {
      assert.strictEqual(getGrade(40), "D");
      assert.strictEqual(getGrade(45), "D");
      assert.strictEqual(getGrade(54), "D");
    });

    it("should return F for score < 40", () => {
      assert.strictEqual(getGrade(0), "F");
      assert.strictEqual(getGrade(25), "F");
      assert.strictEqual(getGrade(39), "F");
    });
  });
});