import { Queue, UnrecoverableError, Worker, type ConnectionOptions } from "bullmq";
import { randomUUID } from "node:crypto";
import type {
  CompositeScore,
  DnsResult,
  FullAuditReport,
  PerformanceResult,
  PriorityFix,
  ScanRequest,
  SecurityHeadersResult,
  TlsResult,
} from "../types/index.js";

/**
 * Asynchronous scan flow: parent fan-out -> child scans -> parent aggregator.
 *
 * A scan is three independent measurements of one origin (performance,
 * security, DNS). They share no data, take wildly different amounts of time —
 * a Lighthouse run is minutes, DNS is milliseconds — and any one of them can
 * fail without invalidating the other two. So the flow is modelled as one
 * parent job that fans out to three child jobs, each writing its own outcome
 * into a `ScanStore`, and an aggregator that fires once the last child
 * reports. That gives three properties that matter more than elegance here:
 *
 *  1. **Parallelism.** The three scans run concurrently instead of serially.
 *  2. **Isolation.** One child throwing cannot take down its siblings or the
 *     scan as a whole — a failed child is recorded, not propagated.
 *  3. **Degradation.** A scan that loses one leg still produces a full report
 *     with that section zeroed and the gap called out, rather than no report
 *     at all. A user who asked for an audit gets one.
 *
 * Two design rules keep this testable without a Redis server, which the test
 * suite deliberately does not have:
 *
 *  - Every collaborator (engines, store, queues, url validator, report sink) is
 *    injected. Nothing here reaches for the network, DNS, or `validateAndPinUrl`
 *    on its own.
 *  - Processors take a structural `JobLike`, not BullMQ's `Job`. BullMQ's job
 *    object satisfies `JobLike`, so the real workers pass it straight through,
 *    while tests pass plain literals.
 *
 * The only BullMQ import at runtime is the thin adapter at the bottom of this
 * file. Everything above it is plain async functions.
 */

// ---------------------------------------------------------------------------
// Names and tuning constants
// ---------------------------------------------------------------------------

export const SCAN_QUEUE = "omniscan:scans";
export const CHILD_QUEUE = "omniscan:children";
export const AGGREGATE_QUEUE = "omniscan:aggregates";

export const JOB_PARENT = "scan:parent";
export const JOB_CHILD = "scan:child";
export const JOB_AGGREGATE = "scan:aggregate";

/**
 * The fan-out legs. Order is the order children are enqueued in and is not
 * meaningful beyond that — completion order is whatever the workers do.
 */
export const CHILD_SCAN_KINDS = ["lighthouse", "security", "dns"] as const;
export type ScanKind = (typeof CHILD_SCAN_KINDS)[number];

export const DEFAULT_CHILD_ATTEMPTS = 3;
export const DEFAULT_CHILD_BACKOFF_MS = 1_000;
/** Generous: a cold Lighthouse run on a slow origin is legitimately minutes. */
export const DEFAULT_CHILD_TIMEOUT_MS = 120_000;

/**
 * Composite weights. Security and DNS are weighted above raw performance
 * because the platform's pitch is that a fast site which leaks mail or serves
 * a self-signed cert is not actually healthy. The three weights sum to 1.
 */
export const COMPOSITE_WEIGHTS = {
  performance: 0.4,
  security: 0.35,
  dns: 0.25,
} as const;

const KIND_CATEGORY: Record<ScanKind, PriorityFix["category"]> = {
  lighthouse: "Performance",
  security: "Security",
  dns: "DNS",
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * `permanent` marks a failure that retrying cannot fix — a private-IP URL, a
 * bad payload. The BullMQ adapter turns those into `UnrecoverableError` so the
 * queue does not burn retries re-running a guaranteed failure.
 */
export class ScanFlowError extends Error {
  readonly code: string;
  readonly permanent: boolean;

  constructor(message: string, code = "SCAN_FLOW_ERROR", permanent = false) {
    super(message);
    this.name = "ScanFlowError";
    this.code = code;
    this.permanent = permanent;
  }
}

// ---------------------------------------------------------------------------
// Job payloads
// ---------------------------------------------------------------------------

export interface ParentScanJob extends ScanRequest {
  scanId: string;
}

export interface ChildScanJob {
  scanId: string;
  kind: ScanKind;
  url: string;
  domain: string;
  email: string;
}

export interface AggregateScanJob {
  scanId: string;
  url: string;
  email: string;
}

export interface SecurityScanResult {
  headers: SecurityHeadersResult;
  tls: TlsResult;
}

/**
 * Terminal record for one leg of a scan. Success carries the engine result;
 * failure carries the reason. Written only once a leg is settled — a leg that
 * will be retried writes nothing, so the store never sees a half-finished run.
 */
export type ChildOutcome =
  | { kind: "lighthouse"; ok: true; result: PerformanceResult; attempts: number; completedAt: string }
  | { kind: "security"; ok: true; result: SecurityScanResult; attempts: number; completedAt: string }
  | { kind: "dns"; ok: true; result: DnsResult; attempts: number; completedAt: string }
  | { kind: ScanKind; ok: false; error: string; attempts: number; completedAt: string };

// ---------------------------------------------------------------------------
// Collaborator ports
// ---------------------------------------------------------------------------

/** Matches the shape returned by `validateAndPinUrl`. */
export interface UrlValidation {
  valid: boolean;
  url?: URL;
  resolvedIp?: string;
  error?: string;
}
export type UrlValidator = (url: string) => Promise<UrlValidation>;

/** The three measurement engines, injected. */
export interface ScanEngines {
  performance(url: string): Promise<PerformanceResult>;
  security(url: string): Promise<SecurityScanResult>;
  dns(domain: string): Promise<DnsResult>;
}

/**
 * Durable per-scan state. In production this is Redis; in tests, a Map. Kept
 * behind an interface because it is the only piece of the flow that must
 * survive a worker restart.
 */
export interface ScanStore {
  /** Upserts the outcome for `outcome.kind`, so a redelivered job is idempotent. */
  recordOutcome(scanId: string, outcome: ChildOutcome): Promise<void>;
  getOutcomes(scanId: string): Promise<ChildOutcome[]>;
  /**
   * Atomically claims the right to aggregate `scanId`. Returns false if another
   * attempt already claimed it — the guard that stops a retried aggregator from
   * emailing the same report twice.
   */
  claimAggregation(scanId: string): Promise<boolean>;
}

export interface EnqueueOptions {
  jobId: string;
  attempts?: number;
  backoff?: { type: "exponential" | "fixed"; delay: number };
  removeOnComplete?: boolean | number;
  removeOnFail?: boolean | number;
}

/** The slice of BullMQ's `Queue` the flow actually uses. */
export interface QueuePort {
  add(name: string, data: unknown, opts?: EnqueueOptions): Promise<unknown>;
}

export interface QueueBag {
  parent: QueuePort;
  child: QueuePort;
  aggregate: QueuePort;
}

/** Where a finished report goes — in the app, the email dispatcher. */
export type ReportSink = (report: FullAuditReport) => Promise<void>;

/**
 * Structural subset of BullMQ's `Job` that the processors actually read. The
 * real job object satisfies this; tests pass object literals.
 */
export interface JobLike<T> {
  id?: string;
  name?: string;
  data: T;
  attemptsMade?: number;
  opts?: { attempts?: number };
}

export type Processor<T> = (job: JobLike<T>) => Promise<unknown>;

export interface FlowDeps {
  engines: ScanEngines;
  store: ScanStore;
  queues: QueueBag;
  validateUrl: UrlValidator;
  deliverReport: ReportSink;
  childAttempts: number;
  childTimeoutMs: number;
  now: () => Date;
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/** Coerces arbitrary input to an integer in [0, 100]; non-numeric becomes 0. */
export function clampScore(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

/** Grade thresholds shared with the report templates. */
export function scoreToGrade(score: unknown): CompositeScore["grade"] {
  const s = clampScore(score);
  if (s >= 95) return "A+";
  if (s >= 85) return "A";
  if (s >= 70) return "B";
  if (s >= 55) return "C";
  if (s >= 40) return "D";
  return "F";
}

/** Hostname for a target, tolerating a scheme-less input. Empty if unparseable. */
export function domainOf(url: string): string {
  try {
    return new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`).hostname;
  } catch {
    return "";
  }
}

/*
 * Job ids are deterministic functions of the scan id. That single choice buys
 * idempotency everywhere: re-enqueueing a parent, a child, or the aggregator
 * collides on the same id and BullMQ drops the duplicate rather than running
 * the work twice.
 */
export function parentJobId(scanId: string): string {
  return `parent:${scanId}`;
}

export function childJobId(scanId: string, kind: ScanKind): string {
  return `child:${scanId}:${kind}`;
}

export function aggregatorJobId(scanId: string): string {
  return `aggregate:${scanId}`;
}

/** The three child jobs a parent scan fans out into. */
export function buildChildJobs(parent: ParentScanJob): ChildScanJob[] {
  const domain = domainOf(parent.url);
  return CHILD_SCAN_KINDS.map((kind) => ({
    scanId: parent.scanId,
    kind,
    url: parent.url,
    domain,
    email: parent.email,
  }));
}

/** True once every leg has settled — successfully or not. */
export function isScanComplete(outcomes: readonly ChildOutcome[]): boolean {
  const settled = new Set(outcomes.map((outcome) => outcome.kind));
  return CHILD_SCAN_KINDS.every((kind) => settled.has(kind));
}

/** The `ChildOutcome` member(s) carrying a given kind, narrowed to its `ok` discriminant. */
export type OutcomeOf<K extends ScanKind> = Extract<ChildOutcome, { kind: K }>;

/**
 * Looks up one leg. Narrowing by kind here is what lets callers reach
 * `outcome.result` without re-asserting the union member by hand.
 */
export function findOutcome<K extends ScanKind>(
  outcomes: readonly ChildOutcome[],
  kind: K
): OutcomeOf<K> | undefined {
  return outcomes.find((outcome) => outcome.kind === kind) as OutcomeOf<K> | undefined;
}

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

/**
 * Bounds one engine call. The underlying promise is not cancellable, so this
 * rejects the race and lets the engine finish in the background — which is why
 * the caller's real work must be independently idempotent (it is: outcomes are
 * upserted by kind).
 *
 * The timer is deliberately *not* unref'd. It is the only thing that settles
 * this race when the engine stalls, so an unref'd handle would let the loop go
 * idle first and turn "times out after Nms" into "hangs forever". It is cleared
 * in the `finally`, so the ordinary path costs nothing.
 */
export async function withTimeout<T>(work: Promise<T>, ms: number, label: string): Promise<T> {
  if (!Number.isFinite(ms) || ms <= 0) return work;

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new ScanFlowError(`${label} scan timed out after ${ms}ms`, "CHILD_TIMEOUT")),
          ms
        );
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Degraded-result fallbacks
// ---------------------------------------------------------------------------

/**
 * A scan that could not run still has to produce a well-formed section, because
 * the report template reads every field unconditionally. These builders return
 * a zeroed section that names the failure, so the gap is visible in the report
 * instead of silently reading as "the site scored 0 on everything".
 */
export function fallbackPerformance(error: string): PerformanceResult {
  return {
    score: 0,
    accessibilityScore: 0,
    seoScore: 0,
    bestPracticesScore: 0,
    webVitals: { lcp: 0, inp: 0, cls: 0, fcp: 0, ttfb: 0, speedIndex: 0 },
    recommendations: [`Performance scan did not complete: ${error}`],
  };
}

export function fallbackSecurity(error: string): SecurityScanResult {
  return {
    headers: {
      score: 0,
      grade: "F",
      checks: [],
    },
    tls: {
      score: 0,
      grade: "F",
      protocol: "Unknown",
      cipher: "None",
      authorized: false,
      vulnerabilities: [`Security scan did not complete: ${error}`],
      recommendations: ["Re-run the security scan to verify this section."],
    },
  };
}

export function fallbackDns(error: string): DnsResult {
  return {
    score: 0,
    hasSpf: false,
    spfLookupCount: 0,
    spfValid: false,
    hasDmarc: false,
    hasMx: false,
    mxRecords: [],
    hasCaa: false,
    hasDnssec: false,
    recommendations: [`DNS scan did not complete: ${error}`],
  };
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/**
 * Security is the mean of the header and TLS scores. Both are already 0-100
 * and independently meaningful, so a mean is the honest combination — and it
 * lets one strong half offset one weak half, which is what a reader expects
 * from a single "Security" number.
 */
export function computeSecurityScore(security: SecurityScanResult): number {
  return clampScore((security.headers.score + security.tls.score) / 2);
}

export function computeComposite(input: {
  performanceScore: number;
  securityScore: number;
  dnsScore: number;
}): number {
  const w = COMPOSITE_WEIGHTS;
  return clampScore(
    input.performanceScore * w.performance + input.securityScore * w.security + input.dnsScore * w.dns
  );
}

/**
 * One-line verdict. Names the degraded legs explicitly — a provisional score
 * that does not say it is provisional is worse than no score.
 */
export function buildSummary(input: {
  omniScore: number;
  grade: CompositeScore["grade"];
  performanceScore: number;
  securityScore: number;
  dnsScore: number;
  failedKinds: readonly ScanKind[];
}): string {
  const base =
    `OmniScore ${input.omniScore} (${input.grade}). ` +
    `Performance ${input.performanceScore} · Security ${input.securityScore} · DNS ${input.dnsScore}.`;

  if (input.failedKinds.length === 0) return `${base} All three scans completed.`;

  const named = input.failedKinds.join(", ");
  const provisional = input.failedKinds.length < CHILD_SCAN_KINDS.length;
  return (
    `${base} ${provisional ? "Provisional: " : ""}the ${named} scan${input.failedKinds.length === 1 ? "" : "s"} ` +
    `did not complete and ${input.failedKinds.length === 1 ? "is" : "are"} scored as 0.`
  );
}

// ---------------------------------------------------------------------------
// Priority fixes
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<PriorityFix["severity"], number> = {
  critical: 0,
  warning: 1,
  info: 2,
};

/** Stable sort: critical, then warning, then info; ties keep insertion order. */
export function rankFixes(fixes: PriorityFix[]): PriorityFix[] {
  return fixes
    .map((fix, index) => ({ fix, index }))
    .sort((a, b) => {
      const rank = SEVERITY_RANK[a.fix.severity] - SEVERITY_RANK[b.fix.severity];
      return rank !== 0 ? rank : a.index - b.index;
    })
    .map((entry) => entry.fix);
}

/**
 * Turns scan results into the ranked action list the report leads with.
 *
 * Failed legs are emitted first and always critical: a missing measurement is
 * a bigger problem for the reader than a low score, because it is the one
 * finding that cannot be acted on.
 */
export function buildPriorityFixes(input: {
  performance: PerformanceResult;
  security: SecurityScanResult;
  dns: DnsResult;
  failures: readonly { kind: ScanKind; error: string }[];
}): PriorityFix[] {
  const fixes: PriorityFix[] = [];

  for (const failure of input.failures) {
    fixes.push({
      title: `${KIND_CATEGORY[failure.kind]} scan failed`,
      category: KIND_CATEGORY[failure.kind],
      severity: "critical",
      detail: failure.error,
      impact: "This section is unmeasured. Re-run the scan before acting on the rest of this report.",
    });
  }

  const { headers, tls } = input.security;

  if (!tls.authorized) {
    fixes.push({
      title: "TLS certificate is not trusted",
      category: "Security",
      severity: "critical",
      detail: tls.vulnerabilities[0] ?? "Certificate chain validation failed.",
      impact: "Browsers show a full-page interstitial that blocks most visitors.",
    });
  }

  const daysRemaining = tls.cert?.daysRemaining;
  if (daysRemaining !== undefined) {
    if (daysRemaining <= 0) {
      fixes.push({
        title: "TLS certificate has expired",
        category: "Security",
        severity: "critical",
        detail: `Certificate expired ${Math.abs(daysRemaining)} day(s) ago.`,
        impact: "Every HTTPS visitor sees a security warning; most leave.",
      });
    } else if (daysRemaining < 14) {
      fixes.push({
        title: "TLS certificate expires soon",
        category: "Security",
        severity: "warning",
        detail: `Certificate expires in ${daysRemaining} day(s).`,
        impact: "Renew before it lapses to avoid a hard outage rather than a scheduled one.",
      });
    }
  }

  if (headers.score < 50) {
    fixes.push({
      title: "Missing core security headers",
      category: "Security",
      severity: "critical",
      detail: `Security header score is ${headers.score}/100.`,
      impact: "Leaves the site exposed to XSS, clickjacking, and MIME-confusion attacks.",
    });
  } else if (headers.score < 80) {
    fixes.push({
      title: "Harden security headers",
      category: "Security",
      severity: "warning",
      detail: `Security header score is ${headers.score}/100.`,
      impact: "Closing the remaining header gaps removes common injection and sniffing vectors.",
    });
  }

  if (!input.dns.hasDmarc) {
    fixes.push({
      title: "No DMARC policy published",
      category: "DNS",
      severity: "critical",
      detail: "No v=DMARC1 record found at _dmarc.",
      impact: "Anyone can spoof mail from this domain; deliverability and brand trust both suffer.",
    });
  } else if (input.dns.dmarcPolicy === "none") {
    fixes.push({
      title: "DMARC policy is monitor-only",
      category: "DNS",
      severity: "warning",
      detail: "DMARC is published with p=none.",
      impact: "Spoofed mail is reported but never blocked. Move to p=quarantine, then p=reject.",
    });
  }

  if (!input.dns.hasSpf) {
    fixes.push({
      title: "No SPF record",
      category: "DNS",
      severity: "warning",
      detail: "No v=spf1 TXT record found.",
      impact: "Outbound mail is trivially spoofable and is often filtered by receivers.",
    });
  }

  if (!input.dns.hasCaa) {
    fixes.push({
      title: "No CAA records",
      category: "DNS",
      severity: "info",
      detail: "No CAA record restricts which CAs may issue for this domain.",
      impact: "Any CA can issue a certificate for the domain if it passes validation.",
    });
  }

  const perf = clampScore(input.performance.score);
  if (perf < 50) {
    fixes.push({
      title: "Core Web Vitals are failing",
      category: "Performance",
      severity: "critical",
      detail: `Performance score is ${perf}/100.`,
      impact: "Slow first paint and poor responsiveness cost both rankings and conversions.",
    });
  } else if (perf < 75) {
    fixes.push({
      title: "Performance needs work",
      category: "Performance",
      severity: "warning",
      detail: `Performance score is ${perf}/100.`,
      impact: "Closing the remaining vitals gaps improves rankings and lowers bounce.",
    });
  }

  for (const metric of ["lcp", "inp", "cls"] as const) {
    const value = input.performance.webVitals?.[metric];
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) continue;
    const poor = metric === "cls" ? value > 0.25 : value > (metric === "lcp" ? 2500 : 200);
    if (poor) {
      fixes.push({
        title: `${metric.toUpperCase()} is poor`,
        category: "Performance",
        severity: "warning",
        detail: `${metric.toUpperCase()} measured ${value}${metric === "cls" ? "" : "ms"} against a poor threshold.`,
        impact: "Poor vitals are a confirmed ranking factor and a measurable conversion drag.",
      });
    }
  }

  return rankFixes(fixes);
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

export interface AggregateInput {
  scanId: string;
  url: string;
  email: string;
  outcomes: readonly ChildOutcome[];
  now: Date;
}

/**
 * Folds the settled outcomes into one report. Pure and total: every leg is
 * resolved to a real result section, whether it succeeded or failed, so the
 * caller always gets a complete `FullAuditReport` back.
 */
export function aggregateScan(input: AggregateInput): FullAuditReport {
  const outcomes = input.outcomes;
  const failedKinds: ScanKind[] = [];

  const perfOutcome = findOutcome(outcomes, "lighthouse");
  const performance =
    perfOutcome && perfOutcome.ok ? perfOutcome.result : fallbackPerformance(describeFailure(perfOutcome));
  if (!perfOutcome || !perfOutcome.ok) failedKinds.push("lighthouse");

  const secOutcome = findOutcome(outcomes, "security");
  const security = secOutcome && secOutcome.ok ? secOutcome.result : fallbackSecurity(describeFailure(secOutcome));
  if (!secOutcome || !secOutcome.ok) failedKinds.push("security");

  const dnsOutcome = findOutcome(outcomes, "dns");
  const dns = dnsOutcome && dnsOutcome.ok ? dnsOutcome.result : fallbackDns(describeFailure(dnsOutcome));
  if (!dnsOutcome || !dnsOutcome.ok) failedKinds.push("dns");

  const performanceScore = clampScore(performance.score);
  const securityScore = computeSecurityScore(security);
  const dnsScore = clampScore(dns.score);
  const omniScore = computeComposite({ performanceScore, securityScore, dnsScore });
  const grade = scoreToGrade(omniScore);

  const composite: CompositeScore = {
    omniScore,
    grade,
    performanceScore,
    securityScore,
    dnsScore,
    bestPracticesScore: clampScore(performance.bestPracticesScore),
    summary: buildSummary({
      omniScore,
      grade,
      performanceScore,
      securityScore,
      dnsScore,
      failedKinds,
    }),
    priorityFixes: buildPriorityFixes({
      performance,
      security,
      dns,
      failures: failedKinds.map((kind) => ({
        kind,
        error: describeFailure(findOutcome(outcomes, kind)),
      })),
    }),
  };

  return {
    scanId: input.scanId,
    targetUrl: input.url,
    targetDomain: domainOf(input.url),
    recipientEmail: input.email,
    scannedAt: input.now.toISOString(),
    composite,
    performance,
    security,
    dns,
  };
}

function describeFailure(outcome: ChildOutcome | undefined): string {
  if (!outcome) return "no result was recorded";
  if (outcome.ok) return "unexpected failure";
  return outcome.error;
}

// ---------------------------------------------------------------------------
// Processors
// ---------------------------------------------------------------------------

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

async function runChildEngine(
  engines: ScanEngines,
  job: ChildScanJob
): Promise<PerformanceResult | SecurityScanResult | DnsResult> {
  switch (job.kind) {
    case "lighthouse":
      return engines.performance(job.url);
    case "security":
      return engines.security(job.url);
    case "dns":
      return engines.dns(job.domain);
    default: {
      // Exhaustiveness guard: adding a kind to CHILD_SCAN_KINDS without wiring
      // it here is a type error rather than a silently dropped scan.
      const unreachable: never = job.kind;
      throw new ScanFlowError(`Unsupported scan kind: ${String(unreachable)}`, "UNKNOWN_KIND", true);
    }
  }
}

/**
 * Enqueues the aggregator once every leg has settled.
 *
 * Safe to call from every child on every completion: the enqueue carries a
 * deterministic job id, so however many children observe "complete", BullMQ
 * keeps exactly one aggregator job.
 */
async function enqueueAggregatorIfComplete(deps: FlowDeps, job: ChildScanJob): Promise<boolean> {
  const outcomes = await deps.store.getOutcomes(job.scanId);
  if (!isScanComplete(outcomes)) return false;

  await deps.queues.aggregate.add(
    JOB_AGGREGATE,
    { scanId: job.scanId, url: job.url, email: job.email } satisfies AggregateScanJob,
    { jobId: aggregatorJobId(job.scanId), removeOnComplete: true }
  );
  return true;
}

/**
 * Parent processor: validates the target, then fans out to the child queue.
 *
 * Validation happens here, once, rather than three times in the children —
 * a scan pointed at a private address should cost one failed job, not three.
 */
export function createParentProcessor(deps: FlowDeps): Processor<ParentScanJob> {
  return async (job) => {
    const { scanId, url, email } = job.data;

    if (!scanId || typeof scanId !== "string") {
      throw new ScanFlowError("Parent job is missing scanId", "BAD_PAYLOAD", true);
    }
    if (!url || typeof url !== "string") {
      throw new ScanFlowError("Parent job is missing url", "BAD_PAYLOAD", true);
    }

    const validation = await deps.validateUrl(url);
    if (!validation.valid) {
      throw new ScanFlowError(
        `Refusing to scan '${url}': ${validation.error ?? "target failed SSRF validation"}`,
        "SSRF_REJECTED",
        true
      );
    }

    const parent: ParentScanJob = { scanId, url, email };
    const children = buildChildJobs(parent);

    const jobIds: string[] = [];
    for (const child of children) {
      await deps.queues.child.add(JOB_CHILD, child, {
        jobId: childJobId(scanId, child.kind),
        attempts: deps.childAttempts,
        backoff: { type: "exponential", delay: DEFAULT_CHILD_BACKOFF_MS },
        removeOnComplete: true,
      });
      jobIds.push(childJobId(scanId, child.kind));
    }

    return { scanId, childJobIds: jobIds };
  };
}

/**
 * Child processor: runs one leg, records its terminal outcome, and kicks the
 * aggregator if that was the last leg outstanding.
 *
 * Retry policy lives entirely here rather than in BullMQ's own settings,
 * because the interesting decision is what gets *recorded*. A leg that will be
 * retried records nothing — the store must not show a failed leg while the
 * queue is still working on it. Only on the final attempt is the failure
 * written, which is what lets a scan with one dead leg still aggregate.
 */
export function createChildProcessor(deps: FlowDeps): Processor<ChildScanJob> {
  return async (job): Promise<ChildOutcome> => {
    const data = job.data;
    if (!data || typeof data.scanId !== "string" || typeof data.kind !== "string") {
      throw new ScanFlowError("Child job is missing scanId or kind", "BAD_PAYLOAD", true);
    }
    if (!CHILD_SCAN_KINDS.includes(data.kind)) {
      throw new ScanFlowError(`Unsupported scan kind '${data.kind}'`, "UNKNOWN_KIND", true);
    }

    const child = data as ChildScanJob;
    const maxAttempts = job.opts?.attempts ?? deps.childAttempts;
    const attempts = (job.attemptsMade ?? 0) + 1;
    const isFinalAttempt = attempts >= maxAttempts;

    let outcome: ChildOutcome;
    try {
      const result = await withTimeout(runChildEngine(deps.engines, child), deps.childTimeoutMs, child.kind);

      if (child.kind === "lighthouse") {
        outcome = { kind: "lighthouse", ok: true, result: result as PerformanceResult, attempts, completedAt: deps.now().toISOString() };
      } else if (child.kind === "security") {
        outcome = { kind: "security", ok: true, result: result as SecurityScanResult, attempts, completedAt: deps.now().toISOString() };
      } else {
        outcome = { kind: "dns", ok: true, result: result as DnsResult, attempts, completedAt: deps.now().toISOString() };
      }
    } catch (err) {
      if (!isFinalAttempt) {
        // Transient: record nothing and let the queue retry.
        throw err;
      }
      outcome = {
        kind: child.kind,
        ok: false,
        error: errorMessage(err),
        attempts,
        completedAt: deps.now().toISOString(),
      };
    }

    await deps.store.recordOutcome(child.scanId, outcome);
    await enqueueAggregatorIfComplete(deps, child);
    return outcome;
  };
}

/**
 * Aggregator processor: folds outcomes into a report and delivers it once.
 *
 * The `claimAggregation` guard runs *before* delivery, so a retried aggregator
 * that crashed mid-send is not resent by the next attempt. Without it a job
 * that failed after the send but before the ack would email the customer twice.
 */
export function createAggregatorProcessor(deps: FlowDeps): Processor<AggregateScanJob> {
  return async (job): Promise<FullAuditReport | null> => {
    const { scanId, url, email } = job.data;
    if (!scanId || typeof scanId !== "string") {
      throw new ScanFlowError("Aggregator job is missing scanId", "BAD_PAYLOAD", true);
    }

    const claimed = await deps.store.claimAggregation(scanId);
    if (!claimed) return null;

    const outcomes = await deps.store.getOutcomes(scanId);
    const report = aggregateScan({ scanId, url, email, outcomes, now: deps.now() });

    await deps.deliverReport(report);
    return report;
  };
}

/** The three processors plus the shared deps they were built from. */
export function createProcessors(deps: FlowDeps): {
  parent: Processor<ParentScanJob>;
  child: Processor<ChildScanJob>;
  aggregator: Processor<AggregateScanJob>;
} {
  return {
    parent: createParentProcessor(deps),
    child: createChildProcessor(deps),
    aggregator: createAggregatorProcessor(deps),
  };
}

// ---------------------------------------------------------------------------
// BullMQ adapter
// ---------------------------------------------------------------------------

export interface ScanFlowOptions {
  connection: ConnectionOptions;
  engines: ScanEngines;
  store: ScanStore;
  validateUrl: UrlValidator;
  deliverReport: ReportSink;
  parentQueueName?: string;
  childQueueName?: string;
  aggregateQueueName?: string;
  /** Workers per queue. Children default higher — they are the slow legs. */
  parentConcurrency?: number;
  childConcurrency?: number;
  aggregateConcurrency?: number;
  childAttempts?: number;
  childTimeoutMs?: number;
  /** Injected for deterministic tests; defaults to the wall clock. */
  now?: () => Date;
  /** Injected for deterministic tests; defaults to a random UUID. */
  idFactory?: () => string;
}

export interface ScanFlow {
  /** Validates nothing — validation happens in the parent worker. Returns scanId. */
  enqueueScan(request: ScanRequest): Promise<string>;
  enqueueAggregator(job: AggregateScanJob): Promise<void>;
  parentProcessor: Processor<ParentScanJob>;
  childProcessor: Processor<ChildScanJob>;
  aggregatorProcessor: Processor<AggregateScanJob>;
  close(): Promise<void>;
}

/** Narrows BullMQ's `Queue` to the `QueuePort` the flow depends on. */
export function createQueuePort(queue: Queue): QueuePort {
  return {
    async add(name, data, opts) {
      return queue.add(name, data, opts);
    },
  };
}

/**
 * Maps a processor's rejection onto BullMQ's error contract. `permanent` maps
 * to `UnrecoverableError`, which stops the queue from retrying a failure that
 * cannot resolve itself.
 */
function toWorkerError(err: unknown): Error {
  if (err instanceof ScanFlowError && err.permanent) return new UnrecoverableError(err.message);
  return err instanceof Error ? err : new Error(errorMessage(err));
}

function wrap<T>(processor: Processor<T>) {
  return async (job: { data: T; attemptsMade?: number; opts?: { attempts?: number } }): Promise<unknown> => {
    try {
      return await processor(job as JobLike<T>);
    } catch (err) {
      throw toWorkerError(err);
    }
  };
}

/**
 * Wires the flow onto a real Redis-backed BullMQ. This is the only place that
 * constructs queues and workers; the logic above is transport-independent so it
 * can be tested without a Redis server.
 */
export function createScanFlow(options: ScanFlowOptions): ScanFlow {
  const connection = options.connection;
  const now = options.now ?? (() => new Date());
  const idFactory = options.idFactory ?? (() => randomUUID());

  const parentQueue = new Queue(options.parentQueueName ?? SCAN_QUEUE, { connection });
  const childQueue = new Queue(options.childQueueName ?? CHILD_QUEUE, { connection });
  const aggregateQueue = new Queue(options.aggregateQueueName ?? AGGREGATE_QUEUE, { connection });

  const deps: FlowDeps = {
    engines: options.engines,
    store: options.store,
    queues: {
      parent: createQueuePort(parentQueue),
      child: createQueuePort(childQueue),
      aggregate: createQueuePort(aggregateQueue),
    },
    validateUrl: options.validateUrl,
    deliverReport: options.deliverReport,
    childAttempts: options.childAttempts ?? DEFAULT_CHILD_ATTEMPTS,
    childTimeoutMs: options.childTimeoutMs ?? DEFAULT_CHILD_TIMEOUT_MS,
    now,
  };

  const processors = createProcessors(deps);

  const workers: Worker[] = [
    new Worker(parentQueue.name, wrap(processors.parent), {
      connection,
      concurrency: options.parentConcurrency ?? 5,
    }),
    new Worker(childQueue.name, wrap(processors.child), {
      connection,
      concurrency: options.childConcurrency ?? 10,
    }),
    new Worker(aggregateQueue.name, wrap(processors.aggregator), {
      connection,
      concurrency: options.aggregateConcurrency ?? 5,
    }),
  ];

  return {
    async enqueueScan(request) {
      const scanId = request.scanId ?? idFactory();
      await deps.queues.parent.add(
        JOB_PARENT,
        { scanId, url: request.url, email: request.email } satisfies ParentScanJob,
        { jobId: parentJobId(scanId), removeOnComplete: true }
      );
      return scanId;
    },

    async enqueueAggregator(job) {
      await deps.queues.aggregate.add(JOB_AGGREGATE, job, {
        jobId: aggregatorJobId(job.scanId),
        removeOnComplete: true,
      });
    },

    parentProcessor: processors.parent,
    childProcessor: processors.child,
    aggregatorProcessor: processors.aggregator,

    async close() {
      await Promise.all(workers.map((worker) => worker.close()));
      await Promise.all([parentQueue.close(), childQueue.close(), aggregateQueue.close()]);
    },
  };
}