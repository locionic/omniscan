import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AGGREGATE_QUEUE,
  CHILD_QUEUE,
  CHILD_SCAN_KINDS,
  JOB_AGGREGATE,
  JOB_CHILD,
  JOB_PARENT,
  SCAN_QUEUE,
  aggregateScan,
  aggregatorJobId,
  buildChildJobs,
  buildPriorityFixes,
  childJobId,
  clampScore,
  computeComposite,
  computeSecurityScore,
  createAggregatorProcessor,
  createChildProcessor,
  createParentProcessor,
  domainOf,
  fallbackDns,
  fallbackPerformance,
  fallbackSecurity,
  isScanComplete,
  parentJobId,
  rankFixes,
  scoreToGrade,
  withTimeout,
  type AggregateScanJob,
  type ChildOutcome,
  type ChildScanJob,
  type DnsResult,
  type EnqueueOptions,
  type FlowDeps,
  type FullAuditReport,
  type JobLike,
  type PerformanceResult,
  type PriorityFix,
  type QueuePort,
  type ScanEngines,
  type ScanKind,
  type ScanStore,
  type SecurityScanResult,
  type TlsResult,
  type UrlValidation,
} from "../src/queue/flow.ts";

// ---------------------------------------------------------------------------
// Test doubles
//
// No Redis in this environment, and none is needed: the flow's logic sits
// behind a `QueuePort` and a `ScanStore`, so these in-memory stand-ins drive
// the real processors through the same code paths the BullMQ workers use.
// ---------------------------------------------------------------------------

interface QueuedJob {
  name: string;
  data: unknown;
  opts?: EnqueueOptions;
  attemptsMade: number;
}

/** FIFO queue that reproduces BullMQ's two behaviours the flow relies on. */
class InMemoryQueue implements QueuePort {
  readonly added: { name: string; data: unknown; opts?: EnqueueOptions }[] = [];
  private pending: QueuedJob[] = [];
  private pendingIds = new Set<string>();

  async add(name: string, data: unknown, opts?: EnqueueOptions): Promise<unknown> {
    this.added.push({ name, data, opts });
    if (opts?.jobId) {
      // BullMQ drops a job whose id is already queued.
      if (this.pendingIds.has(opts.jobId)) return null;
      this.pendingIds.add(opts.jobId);
    }
    this.pending.push({ name, data, opts, attemptsMade: 0 });
    return { id: opts?.jobId };
  }

  /** Re-queue a failed job for another attempt, preserving its attempt count. */
  reenqueue(job: QueuedJob): void {
    this.pending.push(job);
    if (job.opts?.jobId) this.pendingIds.add(job.opts.jobId);
  }

  get size(): number {
    return this.pending.length;
  }

  take(): QueuedJob | undefined {
    const job = this.pending.shift();
    if (!job) return undefined;
    if (job.opts?.jobId) this.pendingIds.delete(job.opts.jobId);
    return job;
  }

  byId(jobId: string): QueuedJob | undefined {
    return this.pending.find((job) => job.opts?.jobId === jobId);
  }
}

class InMemoryScanStore implements ScanStore {
  private readonly outcomes = new Map<string, ChildOutcome[]>();
  private readonly claimed = new Set<string>();

  async recordOutcome(scanId: string, outcome: ChildOutcome): Promise<void> {
    const existing = this.outcomes.get(scanId) ?? [];
    // Upsert: a redelivered job must not duplicate its leg.
    this.outcomes.set(
      scanId,
      [...existing.filter((entry) => entry.kind !== outcome.kind), outcome]
    );
  }

  async getOutcomes(scanId: string): Promise<ChildOutcome[]> {
    return [...(this.outcomes.get(scanId) ?? [])];
  }

  async claimAggregation(scanId: string): Promise<boolean> {
    if (this.claimed.has(scanId)) return false;
    this.claimed.add(scanId);
    return true;
  }
}

const FIXED_NOW = new Date("2026-10-07T12:00:00.000Z");

// --- result builders -------------------------------------------------------

function perfResult(score: number): PerformanceResult {
  return {
    score,
    accessibilityScore: score,
    seoScore: score,
    bestPracticesScore: score,
    webVitals: { lcp: 1000, inp: 50, cls: 0.05, fcp: 800, ttfb: 200, speedIndex: 1200 },
    recommendations: [],
  };
}

function headersResult(score: number): SecurityScanResult["headers"] {
  return { score, grade: scoreToGrade(score), checks: [] };
}

function tlsResult(score: number, overrides: Partial<TlsResult> = {}): TlsResult {
  return {
    score,
    grade: scoreToGrade(score),
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    authorized: true,
    vulnerabilities: [],
    recommendations: [],
    ...overrides,
  };
}

function securityResult(headersScore: number, tlsScore: number, tlsOverrides: Partial<TlsResult> = {}): SecurityScanResult {
  return { headers: headersResult(headersScore), tls: tlsResult(tlsScore, tlsOverrides) };
}

function dnsResult(score: number, overrides: Partial<DnsResult> = {}): DnsResult {
  return {
    score,
    hasSpf: true,
    spfRecord: "v=spf1 include:_spf.example.com ~all",
    spfLookupCount: 1,
    spfValid: true,
    hasDmarc: true,
    dmarcRecord: "v=DMARC1; p=reject",
    dmarcPolicy: "reject",
    hasMx: true,
    mxRecords: ["mx.example.com"],
    hasCaa: true,
    hasDnssec: false,
    recommendations: [],
    ...overrides,
  };
}

function securityOutcome(result: SecurityScanResult, attempts = 1): ChildOutcome {
  return { kind: "security", ok: true, result, attempts, completedAt: FIXED_NOW.toISOString() };
}

function perfOutcome(score: number, attempts = 1): ChildOutcome {
  return { kind: "lighthouse", ok: true, result: perfResult(score), attempts, completedAt: FIXED_NOW.toISOString() };
}

function dnsOutcome(score: number, overrides: Partial<DnsResult> = {}, attempts = 1): ChildOutcome {
  return { kind: "dns", ok: true, result: dnsResult(score, overrides), attempts, completedAt: FIXED_NOW.toISOString() };
}

// --- harness ---------------------------------------------------------------

interface Harness {
  deps: FlowDeps;
  queues: { parent: InMemoryQueue; child: InMemoryQueue; aggregate: InMemoryQueue };
  store: InMemoryScanStore;
  engines: { calls: string[]; performance: (url: string) => Promise<PerformanceResult>; security: (url: string) => Promise<SecurityScanResult>; dns: (domain: string) => Promise<DnsResult> };
  delivered: FullAuditReport[];
  validateUrl: (url: string) => Promise<UrlValidation>;
}

interface HarnessOverrides {
  validation?: UrlValidation;
  engines?: Partial<ScanEngines>;
  childAttempts?: number;
  childTimeoutMs?: number;
}

function makeHarness(overrides: HarnessOverrides = {}): Harness {
  const queues = {
    parent: new InMemoryQueue(),
    child: new InMemoryQueue(),
    aggregate: new InMemoryQueue(),
  };
  const store = new InMemoryScanStore();
  const calls: string[] = [];
  const delivered: FullAuditReport[] = [];

  const engines = {
    performance: async (url: string) => {
      calls.push(`performance:${url}`);
      return overrides.engines?.performance ? overrides.engines.performance(url) : perfResult(90);
    },
    security: async (url: string) => {
      calls.push(`security:${url}`);
      return overrides.engines?.security ? overrides.engines.security(url) : securityResult(90, 90);
    },
    dns: async (domain: string) => {
      calls.push(`dns:${domain}`);
      return overrides.engines?.dns ? overrides.engines.dns(domain) : dnsResult(90);
    },
  };

  const validateUrl = async (url: string): Promise<UrlValidation> =>
    overrides.validation ?? { valid: true, url: new URL(url), resolvedIp: "93.184.216.34" };

  const deps: FlowDeps = {
    engines,
    store,
    queues,
    validateUrl,
    deliverReport: async (report) => {
      delivered.push(report);
    },
    childAttempts: overrides.childAttempts ?? 3,
    childTimeoutMs: overrides.childTimeoutMs ?? 5_000,
    now: () => FIXED_NOW,
  };

  return { deps, queues, store, engines: { calls, ...engines }, delivered, validateUrl };
}

/**
 * Drains a queue the way BullMQ does: on rejection, `attemptsMade` increments
 * and the job is retried while attempts remain.
 */
async function drain<T>(
  queue: InMemoryQueue,
  processor: (job: JobLike<T>) => Promise<unknown>
): Promise<{ ok: boolean; value?: unknown; error?: unknown }[]> {
  const results: { ok: boolean; value?: unknown; error?: unknown }[] = [];
  while (queue.size > 0) {
    const job = queue.take() as QueuedJob & { data: T };
    try {
      results.push({ ok: true, value: await processor(job) });
    } catch (error) {
      results.push({ ok: false, error });
      const maxAttempts = job.opts?.attempts ?? 1;
      const attemptsMade = (job.attemptsMade ?? 0) + 1;
      if (attemptsMade < maxAttempts) {
        queue.reenqueue({ ...job, attemptsMade });
      }
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe("score helpers", () => {
  it("clamps scores into 0-100 and rejects non-numeric input", () => {
    assert.equal(clampScore(42), 42);
    assert.equal(clampScore(-10), 0);
    assert.equal(clampScore(180), 100);
    assert.equal(clampScore(72.6), 73);
    assert.equal(clampScore(Number.NaN), 0);
    assert.equal(clampScore(undefined), 0);
  });

  it("maps scores to grades at the documented thresholds", () => {
    assert.equal(scoreToGrade(100), "A+");
    assert.equal(scoreToGrade(95), "A+");
    assert.equal(scoreToGrade(94), "A");
    assert.equal(scoreToGrade(85), "A");
    assert.equal(scoreToGrade(84), "B");
    assert.equal(scoreToGrade(70), "B");
    assert.equal(scoreToGrade(69), "C");
    assert.equal(scoreToGrade(55), "C");
    assert.equal(scoreToGrade(54), "D");
    assert.equal(scoreToGrade(40), "D");
    assert.equal(scoreToGrade(39), "F");
    assert.equal(scoreToGrade(0), "F");
  });

  it("averages the header and TLS halves into one security score", () => {
    assert.equal(computeSecurityScore(securityResult(100, 40)), 70);
    assert.equal(computeSecurityScore(securityResult(90, 90)), 90);
  });

  it("weights the composite 40/35/25 across performance, security, and DNS", () => {
    assert.equal(computeComposite({ performanceScore: 100, securityScore: 100, dnsScore: 100 }), 100);
    assert.equal(computeComposite({ performanceScore: 0, securityScore: 0, dnsScore: 0 }), 0);
    // 100*0.40 + 100*0.35 + 0*0.25 = 75
    assert.equal(computeComposite({ performanceScore: 100, securityScore: 100, dnsScore: 0 }), 75);
    // 100*0.40 + 0*0.35 + 0*0.25 = 40
    assert.equal(computeComposite({ performanceScore: 100, securityScore: 0, dnsScore: 0 }), 40);
  });

  it("extracts a hostname from full and scheme-less URLs", () => {
    assert.equal(domainOf("https://www.example.com/path?q=1"), "www.example.com");
    assert.equal(domainOf("example.com"), "example.com");
    assert.equal(domainOf(""), "");
  });
});

describe("scan completion", () => {
  it("requires all three legs before a scan counts as complete", () => {
    assert.equal(isScanComplete([]), false);
    assert.equal(isScanComplete([perfOutcome(90)]), false);
    assert.equal(isScanComplete([perfOutcome(90), dnsOutcome(90)]), false);
    assert.equal(isScanComplete([perfOutcome(90), dnsOutcome(90), securityOutcome(securityResult(90, 90))]), true);
  });

  it("treats a failed leg as settled", () => {
    const outcomes: ChildOutcome[] = [
      perfOutcome(90),
      { kind: "dns", ok: false, error: "NXDOMAIN", attempts: 3, completedAt: FIXED_NOW.toISOString() },
      securityOutcome(securityResult(90, 90)),
    ];
    assert.equal(isScanComplete(outcomes), true);
  });

  it("ignores duplicate legs and does not double-count them", () => {
    const outcomes: ChildOutcome[] = [
      perfOutcome(10),
      perfOutcome(90),
      dnsOutcome(90),
      securityOutcome(securityResult(90, 90)),
    ];
    assert.equal(isScanComplete(outcomes), true);
  });
});

describe("job ids", () => {
  it("derives stable ids per scan and per leg", () => {
    assert.equal(parentJobId("s1"), "parent:s1");
    assert.equal(childJobId("s1", "dns"), "child:s1:dns");
    assert.equal(aggregatorJobId("s1"), "aggregate:s1");
    // Deterministic: the same input always yields the same id, which is what
    // makes enqueue idempotent.
    assert.equal(childJobId("s1", "dns"), childJobId("s1", "dns"));
  });

  it("gives each of the three legs a distinct child id", () => {
    const ids = CHILD_SCAN_KINDS.map((kind) => childJobId("s1", kind));
    assert.equal(new Set(ids).size, 3);
  });
});

// ---------------------------------------------------------------------------
// Parent processor
// ---------------------------------------------------------------------------

describe("parent processor", () => {
  it("fans out exactly one child job per scan kind", async () => {
    const h = makeHarness();
    const parent = createParentProcessor(h.deps);

    const result = await parent({
      data: { scanId: "s1", url: "https://example.com", email: "ops@example.com" },
    });

    assert.equal(h.queues.child.size, 3);
    assert.deepEqual(result, {
      scanId: "s1",
      childJobIds: ["child:s1:lighthouse", "child:s1:security", "child:s1:dns"],
    });
    assert.deepEqual(
      h.queues.child.added.map((entry) => entry.name),
      [JOB_CHILD, JOB_CHILD, JOB_CHILD]
    );
    assert.deepEqual(
      (h.queues.child.added.map((entry) => entry.data as ChildScanJob).map((job) => job.kind).sort()),
      [...CHILD_SCAN_KINDS].sort()
    );
  });

  it("gives each child a deterministic job id, retry budget, and backoff", async () => {
    const h = makeHarness({ childAttempts: 5 });
    const parent = createParentProcessor(h.deps);
    await parent({ data: { scanId: "s1", url: "https://example.com", email: "a@b.co" } });

    for (const entry of h.queues.child.added) {
      assert.equal(entry.opts?.jobId, childJobId("s1", (entry.data as ChildScanJob).kind));
      assert.equal(entry.opts?.attempts, 5);
      assert.deepEqual(entry.opts?.backoff, { type: "exponential", delay: 1_000 });
    }
  });

  it("hands each child the target domain the DNS leg needs", async () => {
    const h = makeHarness();
    const parent = createParentProcessor(h.deps);
    await parent({ data: { scanId: "s1", url: "https://shop.example.com/pricing", email: "a@b.co" } });

    for (const entry of h.queues.child.added) {
      const job = entry.data as ChildScanJob;
      assert.equal(job.url, "https://shop.example.com/pricing");
      assert.equal(job.domain, "shop.example.com");
      assert.equal(job.email, "a@b.co");
    }
  });

  it("dedupes a re-enqueued scan instead of fanning out twice", async () => {
    const h = makeHarness();
    const parent = createParentProcessor(h.deps);
    const data = { scanId: "s1", url: "https://example.com", email: "a@b.co" };

    await parent({ data });
    await parent({ data });

    assert.equal(h.queues.child.size, 3, "second fan-out must not add duplicate child jobs");
    assert.equal(h.queues.child.added.length, 6, "add was called twice");
  });

  it("refuses an SSRF-rejected target and never fans out", async () => {
    const h = makeHarness({ validation: { valid: false, error: "resolves to a private address" } });
    const parent = createParentProcessor(h.deps);

    await assert.rejects(
      () => parent({ data: { scanId: "s1", url: "http://169.254.169.254/", email: "a@b.co" } }),
      (error: Error & { permanent?: boolean; code?: string }) => {
        assert.match(error.message, /169\.254\.169\.254/);
        assert.match(error.message, /private address/);
        assert.equal(error.permanent, true, "SSRF rejection must not be retried");
        assert.equal(error.code, "SSRF_REJECTED");
        return true;
      }
    );

    assert.equal(h.queues.child.size, 0);
  });

  it("rejects a payload with no scanId permanently", async () => {
    const h = makeHarness();
    const parent = createParentProcessor(h.deps);
    await assert.rejects(
      () => parent({ data: { url: "https://example.com", email: "a@b.co" } as never }),
      /missing scanId/
    );
    assert.equal(h.queues.child.size, 0);
  });

  it("rejects a payload with no url permanently", async () => {
    const h = makeHarness();
    const parent = createParentProcessor(h.deps);
    await assert.rejects(
      () => parent({ data: { scanId: "s1", email: "a@b.co" } as never }),
      /missing url/
    );
  });
});

// ---------------------------------------------------------------------------
// Child processors
// ---------------------------------------------------------------------------

describe("child processor", () => {
  const baseJob = (kind: ScanKind): ChildScanJob => ({
    scanId: "s1",
    kind,
    url: "https://example.com/page",
    domain: "example.com",
    email: "a@b.co",
  });

  it("routes each kind to its own engine with the right argument", async () => {
    const h = makeHarness();
    const child = createChildProcessor(h.deps);

    await child({ data: baseJob("lighthouse"), opts: { attempts: 3 } });
    await child({ data: baseJob("security"), opts: { attempts: 3 } });
    await child({ data: baseJob("dns"), opts: { attempts: 3 } });

    assert.deepEqual(h.engines.calls, [
      "performance:https://example.com/page",
      "security:https://example.com/page",
      // DNS works on the hostname, not the URL.
      "dns:example.com",
    ]);
  });

  it("records a successful outcome and returns it", async () => {
    const h = makeHarness({ engines: { performance: async () => perfResult(88) } });
    const child = createChildProcessor(h.deps);

    const outcome = await child({ data: baseJob("lighthouse"), attemptsMade: 0, opts: { attempts: 3 } });

    assert.equal(outcome?.ok, true);
    assert.deepEqual(await h.store.getOutcomes("s1"), [outcome]);
  });

  it("counts the current run as attempt one on a fresh job", async () => {
    const h = makeHarness();
    const child = createChildProcessor(h.deps);

    const outcome = (await child({ data: baseJob("dns"), attemptsMade: 0, opts: { attempts: 3 } })) as ChildOutcome;
    assert.equal(outcome.attempts, 1);
  });

  it("rethrows a transient failure and records nothing while attempts remain", async () => {
    const h = makeHarness({
      engines: {
        performance: async () => {
          throw new Error("lighthouse: connection reset");
        },
      },
    });
    const child = createChildProcessor(h.deps);

    await assert.rejects(
      () => child({ data: baseJob("lighthouse"), attemptsMade: 0, opts: { attempts: 3 } }),
      /connection reset/
    );

    assert.deepEqual(await h.store.getOutcomes("s1"), [], "a retryable failure must not be recorded");
    assert.equal(h.queues.aggregate.size, 0);
  });

  it("retries through the queue and only records the failure on the final attempt", async () => {
    const h = makeHarness({
      childAttempts: 3,
      engines: {
        performance: async () => {
          throw new Error("lighthouse: timeout");
        },
      },
    });
    const parent = createParentProcessor(h.deps);
    const child = createChildProcessor(h.deps);

    await parent({ data: { scanId: "s1", url: "https://example.com", email: "a@b.co" } });

    // Isolate the lighthouse leg (added first) so its retries drain against a
    // queue that holds nothing else, the way BullMQ would drive it.
    const leg = new InMemoryQueue();
    leg.reenqueue(h.queues.child.take()!);

    const results = await drain<ChildScanJob>(leg, child);

    assert.equal(results.length, 3, "one result per attempt");
    assert.equal(results[0].ok, false, "attempt 1 throws so the queue can retry");
    assert.equal(results[1].ok, false, "attempt 2 throws as well");
    assert.equal(results[2].ok, true, "the final attempt records instead of throwing");
    assert.match(String((results[0].error as Error).message), /timeout/);

    const outcomes = await h.store.getOutcomes("s1");
    assert.equal(outcomes.length, 1, "exactly one failure recorded, after the last retry");
    assert.equal(outcomes[0].ok, false);
    assert.equal(outcomes[0].attempts, 3);
  });

  it("records a permanent failure on the final attempt instead of throwing", async () => {
    const h = makeHarness({
      childAttempts: 2,
      engines: {
        dns: async () => {
          throw new Error("resolver refused");
        },
      },
    });
    const child = createChildProcessor(h.deps);

    // Final attempt: attemptsMade 1 of attempts 2.
    const outcome = (await child({ data: baseJob("dns"), attemptsMade: 1, opts: { attempts: 2 } })) as ChildOutcome;

    assert.equal(outcome.ok, false);
    assert.equal(outcome.kind, "dns");
    assert.match(outcome.error as string, /resolver refused/);
    assert.deepEqual(await h.store.getOutcomes("s1"), [outcome]);
  });

  it("treats an engine that exceeds the timeout as a failure", async () => {
    const h = makeHarness({
      childAttempts: 1,
      childTimeoutMs: 20,
      engines: {
        security: () => new Promise<SecurityScanResult>(() => { /* never settles */ }),
      },
    });
    const child = createChildProcessor(h.deps);

    const outcome = (await child({ data: baseJob("security"), attemptsMade: 0, opts: { attempts: 1 } })) as ChildOutcome;

    assert.equal(outcome.ok, false);
    assert.match(outcome.error as string, /timed out after 20ms/);
  });

  it("rejects an unknown kind permanently", async () => {
    const h = makeHarness();
    const child = createChildProcessor(h.deps);
    await assert.rejects(
      () => child({ data: { ...baseJob("dns"), kind: "wat" as ScanKind }, opts: { attempts: 3 } }),
      (error: Error & { permanent?: boolean }) => {
        assert.equal(error.permanent, true);
        return true;
      }
    );
  });

  it("rejects a child payload with no scanId", async () => {
    const h = makeHarness();
    const child = createChildProcessor(h.deps);
    await assert.rejects(() => child({ data: { kind: "dns" } as never, opts: { attempts: 3 } }), /scanId or kind/);
  });

  it("does not enqueue the aggregator until the last leg settles", async () => {
    const h = makeHarness();
    const child = createChildProcessor(h.deps);

    await child({ data: baseJob("lighthouse"), opts: { attempts: 3 } });
    assert.equal(h.queues.aggregate.size, 0, "two legs outstanding");

    await child({ data: baseJob("security"), opts: { attempts: 3 } });
    assert.equal(h.queues.aggregate.size, 0, "one leg outstanding");

    await child({ data: baseJob("dns"), opts: { attempts: 3 } });
    assert.equal(h.queues.aggregate.size, 1, "last leg settled");
  });

  it("enqueues the aggregator with the aggregate job name and a deterministic id", async () => {
    const h = makeHarness();
    const child = createChildProcessor(h.deps);

    for (const kind of CHILD_SCAN_KINDS) await child({ data: baseJob(kind), opts: { attempts: 3 } });

    const entry = h.queues.aggregate.added[0];
    assert.equal(entry.name, JOB_AGGREGATE);
    assert.equal(entry.opts?.jobId, "aggregate:s1");
    assert.deepEqual(entry.data, { scanId: "s1", url: "https://example.com/page", email: "a@b.co" });
  });

  it("enqueues the aggregator only once even when legs complete out of order and re-trigger", async () => {
    const h = makeHarness();
    const child = createChildProcessor(h.deps);

    // Deliberately non-sequential completion, then replay two settled legs as
    // if the jobs had been redelivered.
    await child({ data: baseJob("dns"), opts: { attempts: 3 } });
    await child({ data: baseJob("lighthouse"), opts: { attempts: 3 } });
    await child({ data: baseJob("security"), opts: { attempts: 3 } });
    await child({ data: baseJob("dns"), opts: { attempts: 3 } });
    await child({ data: baseJob("lighthouse"), opts: { attempts: 3 } });

    assert.equal(h.queues.aggregate.size, 1, "redelivered legs must not spawn a second aggregator");
    assert.equal(h.queues.aggregate.added.length, 3, "each settled leg re-checks completeness");
  });

  it("triggers the aggregator even when the last leg to settle is the one that failed", async () => {
    const h = makeHarness({
      childAttempts: 1,
      engines: {
        dns: async () => {
          throw new Error("dns: SERVFAIL");
        },
      },
    });
    const child = createChildProcessor(h.deps);

    await child({ data: baseJob("lighthouse"), opts: { attempts: 1 } });
    await child({ data: baseJob("security"), opts: { attempts: 1 } });
    assert.equal(h.queues.aggregate.size, 0);

    await child({ data: baseJob("dns"), attemptsMade: 0, opts: { attempts: 1 } });
    assert.equal(h.queues.aggregate.size, 1, "a degraded scan must still aggregate");
  });

  it("keeps concurrent legs from double-enqueueing the aggregator", async () => {
    const h = makeHarness();
    const child = createChildProcessor(h.deps);

    // All three legs finish at once and each observes a complete store.
    await Promise.all(CHILD_SCAN_KINDS.map((kind) => child({ data: baseJob(kind), opts: { attempts: 3 } })));

    assert.equal(h.queues.aggregate.size, 1);
  });

  it("upserts rather than duplicates when a leg is redelivered", async () => {
    const h = makeHarness({ engines: { dns: async () => dnsResult(70) } });
    const child = createChildProcessor(h.deps);

    await child({ data: baseJob("dns"), attemptsMade: 0, opts: { attempts: 3 } });
    await child({ data: baseJob("dns"), attemptsMade: 0, opts: { attempts: 3 } });
    await child({ data: baseJob("dns"), attemptsMade: 0, opts: { attempts: 3 } });

    const outcomes = await h.store.getOutcomes("s1");
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0].kind, "dns");
  });
});

// ---------------------------------------------------------------------------
// withTimeout
// ---------------------------------------------------------------------------

describe("withTimeout", () => {
  it("resolves fast work untouched", async () => {
    assert.equal(await withTimeout(Promise.resolve("ok"), 1_000, "test"), "ok");
  });

  it("passes through when the timeout is disabled", async () => {
    assert.equal(await withTimeout(Promise.resolve("ok"), 0, "test"), "ok");
  });

  it("rejects with a retryable ScanFlowError once the deadline passes", async () => {
    const stalled = new Promise<string>(() => {});
    await assert.rejects(
      () => withTimeout(stalled, 10, "dns"),
      (error: Error & { permanent?: boolean; code?: string }) => {
        assert.match(error.message, /dns scan timed out after 10ms/);
        assert.equal(error.code, "CHILD_TIMEOUT");
        assert.equal(error.permanent, false, "a timeout may succeed on retry");
        return true;
      }
    );
  });
});

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

describe("aggregateScan", () => {
  it("builds a full report from three successful outcomes", () => {
    const report = aggregateScan({
      scanId: "s1",
      url: "https://shop.example.com/pricing",
      email: "ops@example.com",
      now: FIXED_NOW,
      outcomes: [
        perfOutcome(90),
        securityOutcome(securityResult(80, 100)),
        dnsOutcome(85),
      ],
    });

    assert.equal(report.scanId, "s1");
    assert.equal(report.targetUrl, "https://shop.example.com/pricing");
    assert.equal(report.targetDomain, "shop.example.com");
    assert.equal(report.recipientEmail, "ops@example.com");
    assert.equal(report.scannedAt, FIXED_NOW.toISOString());

    // security = mean(80, 100) = 90; composite = 90*.4 + 90*.35 + 85*.25 = 88.75 -> 89
    assert.equal(report.composite.performanceScore, 90);
    assert.equal(report.composite.securityScore, 90);
    assert.equal(report.composite.dnsScore, 85);
    assert.equal(report.composite.omniScore, 89);
    assert.equal(report.composite.grade, "A");
    // Carried straight through from the Lighthouse leg's own sub-score.
    assert.equal(report.composite.bestPracticesScore, report.performance.bestPracticesScore);
    assert.match(report.composite.summary, /All three scans completed/);
    assert.equal(report.composite.summary.includes("Provisional"), false);
  });

  it("produces a well-formed report when a leg failed", () => {
    const report = aggregateScan({
      scanId: "s2",
      url: "https://example.com",
      email: "a@b.co",
      now: FIXED_NOW,
      outcomes: [
        perfOutcome(90),
        { kind: "dns", ok: false, error: "SERVFAIL", attempts: 3, completedAt: FIXED_NOW.toISOString() },
        securityOutcome(securityResult(90, 90)),
      ],
    });

    assert.equal(report.dns.score, 0, "failed leg scores zero");
    assert.match(report.dns.recommendations.join(" "), /SERVFAIL/);
    assert.match(report.composite.summary, /Provisional/);
    assert.match(report.composite.summary, /dns scan did not complete/);
    // 90*.4 + 90*.35 + 0*.25 = 67.5 -> 68
    assert.equal(report.composite.omniScore, 68);

    const failure = report.composite.priorityFixes.find((fix) => fix.title === "DNS scan failed");
    assert.ok(failure, "a failed leg must surface as a fix");
    assert.equal(failure.severity, "critical");
    assert.equal(failure.category, "DNS");
  });

  it("still returns a report when every leg failed", () => {
    const failed = (kind: ScanKind): ChildOutcome => ({
      kind,
      ok: false,
      error: `boom ${kind}`,
      attempts: 3,
      completedAt: FIXED_NOW.toISOString(),
    });
    const report = aggregateScan({
      scanId: "s3",
      url: "https://example.com",
      email: "a@b.co",
      now: FIXED_NOW,
      outcomes: CHILD_SCAN_KINDS.map(failed),
    });

    assert.equal(report.composite.omniScore, 0);
    assert.equal(report.composite.grade, "F");
    assert.equal(report.performance.score, 0);
    assert.equal(report.composite.bestPracticesScore, 0);
    assert.equal(report.security.headers.score, 0);
    assert.equal(report.security.tls.score, 0);
    assert.equal(report.dns.score, 0);
    // Not provisional: nothing succeeded.
    assert.equal(report.composite.summary.includes("Provisional"), false);
    assert.equal(report.composite.priorityFixes.filter((fix) => fix.severity === "critical").length >= 3, true);
  });

  it("tolerates a missing outcome entirely", () => {
    const report = aggregateScan({
      scanId: "s4",
      url: "https://example.com",
      email: "a@b.co",
      now: FIXED_NOW,
      outcomes: [perfOutcome(90)],
    });

    assert.match(report.security.tls.vulnerabilities.join(" "), /no result was recorded/);
    assert.match(report.dns.recommendations.join(" "), /no result was recorded/);
  });

  it("keeps every result section populated so the report template never reads undefined", () => {
    const report = aggregateScan({
      scanId: "s5",
      url: "https://example.com",
      email: "a@b.co",
      now: FIXED_NOW,
      outcomes: [],
    });

    assert.deepEqual(Object.keys(report.performance).sort(), [
      "accessibilityScore",
      "bestPracticesScore",
      "recommendations",
      "score",
      "seoScore",
      "webVitals",
    ]);
    assert.equal(typeof report.security.tls.protocol, "string");
    assert.equal(report.security.tls.authorized, false);
    assert.deepEqual(report.dns.mxRecords, []);
    assert.equal(Array.isArray(report.composite.priorityFixes), true);
  });
});

describe("fallback builders", () => {
  it("zeroes performance and names the failure", () => {
    const result = fallbackPerformance("ECONNRESET");
    assert.equal(result.score, 0);
    assert.equal(result.webVitals.lcp, 0);
    assert.match(result.recommendations[0], /ECONNRESET/);
  });

  it("zeroes both security halves and names the failure", () => {
    const result = fallbackSecurity("handshake failed");
    assert.equal(result.headers.score, 0);
    assert.equal(result.headers.grade, "F");
    assert.equal(result.tls.score, 0);
    assert.equal(result.tls.grade, "F");
    assert.match(result.tls.vulnerabilities[0], /handshake failed/);
  });

  it("zeroes DNS flags and names the failure", () => {
    const result = fallbackDns("timeout");
    assert.equal(result.score, 0);
    assert.equal(result.hasSpf, false);
    assert.equal(result.hasDmarc, false);
    assert.equal(result.hasMx, false);
    assert.equal(result.hasCaa, false);
    assert.match(result.recommendations[0], /timeout/);
  });
});

describe("priority fixes", () => {
  it("sorts by severity, keeping insertion order within a severity", () => {
    const fix = (title: string, severity: PriorityFix["severity"]): PriorityFix => ({
      title,
      category: "Security",
      severity,
      detail: "",
      impact: "",
    });
    const ranked = rankFixes([
      fix("info-a", "info"),
      fix("critical-a", "critical"),
      fix("warning-a", "warning"),
      fix("critical-b", "critical"),
      fix("info-b", "info"),
    ]);
    assert.deepEqual(
      ranked.map((entry) => entry.title),
      ["critical-a", "critical-b", "warning-a", "info-a", "info-b"]
    );
  });

  it("flags an untrusted certificate as critical", () => {
    const fixes = buildPriorityFixes({
      performance: perfResult(95),
      security: securityResult(95, 10, { authorized: false, vulnerabilities: ["self-signed"] }),
      dns: dnsResult(95, { hasCaa: true }),
      failures: [],
    });
    const untrusted = fixes.find((entry) => entry.title === "TLS certificate is not trusted");
    assert.ok(untrusted);
    assert.equal(untrusted.severity, "critical");
    assert.match(untrusted.detail, /self-signed/);
  });

  it("escalates an expired certificate and warns on a soon-to-expire one", () => {
    const cert = (daysRemaining: number) => ({
      subject: "CN=example.com",
      issuer: "CN=Example CA",
      validFrom: "2026-01-01T00:00:00.000Z",
      validTo: "2026-12-01T00:00:00.000Z",
      daysRemaining,
      sans: ["example.com"],
    });

    const expired = buildPriorityFixes({
      performance: perfResult(95),
      security: securityResult(95, 95, { cert: cert(-3) }),
      dns: dnsResult(95, { hasCaa: true }),
      failures: [],
    });
    assert.ok(expired.some((entry) => entry.title === "TLS certificate has expired"));

    const soon = buildPriorityFixes({
      performance: perfResult(95),
      security: securityResult(95, 95, { cert: cert(7) }),
      dns: dnsResult(95, { hasCaa: true }),
      failures: [],
    });
    assert.ok(soon.some((entry) => entry.title === "TLS certificate expires soon"));
  });

  it("treats missing DMARC as critical and monitor-only as a warning", () => {
    const missing = buildPriorityFixes({
      performance: perfResult(95),
      security: securityResult(95, 95),
      dns: dnsResult(50, { hasDmarc: false }),
      failures: [],
    });
    assert.equal(missing.find((entry) => entry.title === "No DMARC policy published")?.severity, "critical");

    const monitorOnly = buildPriorityFixes({
      performance: perfResult(95),
      security: securityResult(95, 95),
      dns: dnsResult(50, { hasDmarc: true, dmarcPolicy: "none" }),
      failures: [],
    });
    assert.equal(monitorOnly.find((entry) => entry.title === "DMARC policy is monitor-only")?.severity, "warning");
  });

  it("reports missing CAA as informational, not urgent", () => {
    const fixes = buildPriorityFixes({
      performance: perfResult(95),
      security: securityResult(95, 95),
      dns: dnsResult(95, { hasCaa: false }),
      failures: [],
    });
    assert.equal(fixes.find((entry) => entry.title === "No CAA records")?.severity, "info");
  });

  it("flags poor Core Web Vitals", () => {
    const slow = perfResult(40);
    slow.webVitals = { lcp: 4200, inp: 300, cls: 0.4, fcp: 900, ttfb: 300, speedIndex: 4000 };
    const fixes = buildPriorityFixes({
      performance: slow,
      security: securityResult(95, 95),
      dns: dnsResult(95, { hasCaa: true }),
      failures: [],
    });

    const titles = fixes.map((entry) => entry.title);
    assert.ok(titles.includes("Core Web Vitals are failing"));
    assert.ok(titles.includes("LCP is poor"));
    assert.ok(titles.includes("INP is poor"));
    assert.ok(titles.includes("CLS is poor"));
  });

  it("emits a critical fix for every failed leg, ahead of everything else", () => {
    const fixes = buildPriorityFixes({
      performance: perfResult(95),
      security: securityResult(95, 95),
      dns: dnsResult(95, { hasCaa: true }),
      failures: [
        { kind: "lighthouse", error: "lighthouse exploded" },
        { kind: "security", error: "security exploded" },
        { kind: "dns", error: "dns exploded" },
      ],
    });

    assert.equal(fixes.length, 3);
    assert.deepEqual(
      fixes.map((entry) => entry.title),
      ["Performance scan failed", "Security scan failed", "DNS scan failed"]
    );
    assert.ok(fixes.every((entry) => entry.severity === "critical"));
  });
});

describe("buildChildJobs", () => {
  it("derives one job per kind from the parent payload", () => {
    const children = buildChildJobs({ scanId: "s1", url: "https://example.com", email: "a@b.co" });
    assert.deepEqual(
      children.map((job) => job.kind),
      [...CHILD_SCAN_KINDS]
    );
    assert.ok(children.every((job) => job.scanId === "s1" && job.email === "a@b.co"));
  });
});

// ---------------------------------------------------------------------------
// Aggregator processor
// ---------------------------------------------------------------------------

describe("aggregator processor", () => {
  async function settleAll(h: Harness): Promise<void> {
    const parent = createParentProcessor(h.deps);
    const child = createChildProcessor(h.deps);
    await parent({ data: { scanId: "s1", url: "https://example.com", email: "a@b.co" } });
    await drain<ChildScanJob>(h.queues.child, child);
  }

  it("delivers a report built from the settled outcomes", async () => {
    const h = makeHarness({
      engines: {
        performance: async () => perfResult(100),
        security: async () => securityResult(100, 100),
        dns: async () => dnsResult(100),
      },
    });
    await settleAll(h);

    const aggregator = createAggregatorProcessor(h.deps);
    const report = (await aggregator({
      data: { scanId: "s1", url: "https://example.com", email: "a@b.co" },
    })) as FullAuditReport;

    assert.equal(h.delivered.length, 1);
    assert.equal(report.composite.omniScore, 100);
    assert.equal(report.composite.grade, "A+");
    assert.equal(h.delivered[0], report);
  });

  it("delivers exactly once even if the aggregator is retried", async () => {
    const h = makeHarness();
    await settleAll(h);

    const aggregator = createAggregatorProcessor(h.deps);
    const data: AggregateScanJob = { scanId: "s1", url: "https://example.com", email: "a@b.co" };

    const first = await aggregator({ data });
    const second = await aggregator({ data });
    const third = await aggregator({ data, attemptsMade: 1, opts: { attempts: 5 } });

    assert.equal(h.delivered.length, 1, "a redelivered aggregator must not re-send the report");
    assert.ok(first);
    assert.equal(second, null);
    assert.equal(third, null);
  });

  it("delivers a degraded report when a leg failed", async () => {
    const h = makeHarness({
      childAttempts: 1,
      engines: {
        performance: async () => perfResult(95),
        security: async () => securityResult(95, 95),
        dns: async () => {
          throw new Error("dns: timeout");
        },
      },
    });
    await settleAll(h);

    const aggregator = createAggregatorProcessor(h.deps);
    await aggregator({ data: { scanId: "s1", url: "https://example.com", email: "a@b.co" } });

    assert.equal(h.delivered.length, 1);
    const report = h.delivered[0];
    assert.equal(report.dns.score, 0);
    assert.match(report.composite.summary, /Provisional/);
    assert.ok(report.composite.priorityFixes.some((fix) => fix.title === "DNS scan failed"));
  });

  it("rejects an aggregator payload with no scanId", async () => {
    const h = makeHarness();
    const aggregator = createAggregatorProcessor(h.deps);
    await assert.rejects(() => aggregator({ data: { url: "https://example.com" } as never }), /missing scanId/);
  });

  it("still produces a usable report if the aggregator fires before every leg settles", async () => {
    const h = makeHarness();
    await h.store.recordOutcome("s1", perfOutcome(90));

    const aggregator = createAggregatorProcessor(h.deps);
    await aggregator({ data: { scanId: "s1", url: "https://example.com", email: "a@b.co" } });

    assert.equal(h.delivered.length, 1);
    assert.equal(h.delivered[0].performance.score, 90);
    assert.match(h.delivered[0].composite.summary, /Provisional/);
    assert.match(h.delivered[0].security.tls.vulnerabilities.join(" "), /no result was recorded/);
    assert.match(h.delivered[0].dns.recommendations.join(" "), /no result was recorded/);
  });
});

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

describe("end to end", () => {
  it("fans out, runs all three legs, aggregates once, and delivers one report", async () => {
    const h = makeHarness({
      engines: {
        // The slow leg finishes first to prove completion order does not matter.
        performance: async () => perfResult(92),
        security: async () => securityResult(70, 90, { cert: undefined }),
        dns: async () => dnsResult(88),
      },
    });

    const parent = createParentProcessor(h.deps);
    const child = createChildProcessor(h.deps);
    const aggregator = createAggregatorProcessor(h.deps);

    // 1. Enqueue the parent scan.
    await h.queues.parent.add(
      JOB_PARENT,
      { scanId: "e2e", url: "https://acme.test/landing", email: "cto@acme.test" },
      { jobId: parentJobId("e2e") }
    );

    // 2. Parent fans out.
    const parentJob = h.queues.parent.take()!;
    await parent({ ...parentJob, data: parentJob.data as never });
    assert.equal(h.queues.child.size, 3);

    // 3. All three legs run to completion, one of them failing on its last try.
    const childResults = await drain<ChildScanJob>(h.queues.child, child);
    assert.equal(childResults.every((entry) => entry.ok), true);
    assert.equal(h.queues.aggregate.size, 1);

    // 4. The aggregator runs.
    const aggregateJob = h.queues.aggregate.take()!;
    await aggregator({ ...aggregateJob, data: aggregateJob.data as AggregateScanJob });

    // 5. Exactly one report, correctly assembled.
    assert.equal(h.delivered.length, 1);
    const report = h.delivered[0];
    assert.equal(report.scanId, "e2e");
    assert.equal(report.targetUrl, "https://acme.test/landing");
    assert.equal(report.targetDomain, "acme.test");
    assert.equal(report.recipientEmail, "cto@acme.test");
    assert.equal(report.performance.score, 92);
    assert.equal(report.security.headers.score, 70);
    assert.equal(report.security.tls.score, 90);
    assert.equal(report.dns.score, 88);
    // security = mean(70, 90) = 80; composite = 92*.4 + 80*.35 + 88*.25 = 86.8 -> 87
    assert.equal(report.composite.securityScore, 80);
    assert.equal(report.composite.omniScore, 87);
    assert.equal(report.composite.grade, "A");
    assert.match(report.composite.summary, /All three scans completed/);
    assert.deepEqual(h.engines.calls.toSorted(), [
      "dns:acme.test",
      "performance:https://acme.test/landing",
      "security:https://acme.test/landing",
    ]);
  });

  it("still delivers a report when a leg exhausts every retry", async () => {
    const h = makeHarness({
      childAttempts: 2,
      engines: {
        performance: async () => perfResult(90),
        security: async () => securityResult(90, 90),
        dns: async () => {
          throw new Error("dns: SERVFAIL");
        },
      },
    });

    const parent = createParentProcessor(h.deps);
    const child = createChildProcessor(h.deps);
    const aggregator = createAggregatorProcessor(h.deps);

    await parent({ data: { scanId: "s1", url: "https://example.com", email: "a@b.co" } });
    const results = await drain<ChildScanJob>(h.queues.child, child);

    // The failing leg throws once (the transient retry) and records on its last
    // try; the healthy legs never throw at all.
    assert.equal(results.filter((entry) => !entry.ok).length, 1, "only the transient retry throws");
    assert.equal((await h.store.getOutcomes("s1")).filter((entry) => !entry.ok).length, 1);

    const aggregateJob = h.queues.aggregate.take()!;
    await aggregator({ ...aggregateJob, data: aggregateJob.data as AggregateScanJob });

    assert.equal(h.delivered.length, 1);
    assert.match(h.delivered[0].composite.summary, /dns scan did not complete/);
    assert.match(h.delivered[0].dns.recommendations[0], /SERVFAIL/);
  });

  it("keeps concurrent scans isolated from each other", async () => {
    const h = makeHarness();
    const parent = createParentProcessor(h.deps);
    const child = createChildProcessor(h.deps);

    await parent({ data: { scanId: "a", url: "https://a.test", email: "a@a.test" } });
    await parent({ data: { scanId: "b", url: "https://b.test", email: "b@b.test" } });
    assert.equal(h.queues.child.size, 6);

    await drain<ChildScanJob>(h.queues.child, child);
    assert.equal(h.queues.aggregate.size, 2, "one aggregator per scan, not per leg");

    const aggregator = createAggregatorProcessor(h.deps);
    await drain<AggregateScanJob>(h.queues.aggregate, aggregator);

    assert.equal(h.delivered.length, 2);
    assert.deepEqual(h.delivered.map((report) => report.scanId).sort(), ["a", "b"]);
    assert.deepEqual(h.delivered.map((report) => report.targetDomain).sort(), ["a.test", "b.test"]);
  });
});

// ---------------------------------------------------------------------------
// Queue/worker names
// ---------------------------------------------------------------------------

describe("queue wiring", () => {
  it("namespaces the three queues and their job names", () => {
    assert.equal(SCAN_QUEUE, "omniscan:scans");
    assert.equal(CHILD_QUEUE, "omniscan:children");
    assert.equal(AGGREGATE_QUEUE, "omniscan:aggregates");
    assert.equal(new Set([SCAN_QUEUE, CHILD_QUEUE, AGGREGATE_QUEUE]).size, 3);
    assert.equal(JOB_PARENT, "scan:parent");
    assert.equal(JOB_CHILD, "scan:child");
    assert.equal(JOB_AGGREGATE, "scan:aggregate");
  });
});