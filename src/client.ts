import { extractProgramIds, INFRA_PROGRAMS } from "./extract.js";
import type {
  AnalyzeBeforeSignOptions,
  ContractAnalysis,
  GuardClientOptions,
  LookalikeResult,
  SignAdvice,
  Verdict,
} from "./types.js";

const DEFAULT_BASE_URL = "https://api.solsentry.app";
const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_BLOCK_THRESHOLD = 80;

const VERDICT_RANK: Record<Verdict, number> = {
  safe: 0,
  unknown: 1,
  caution: 2,
  dangerous: 3,
};

function worstVerdict(a: Verdict, b: Verdict): Verdict {
  return VERDICT_RANK[a] >= VERDICT_RANK[b] ? a : b;
}

export class GuardError extends Error {
  readonly status?: number;
  readonly detail?: string;
  constructor(message: string, status?: number, detail?: string) {
    super(message);
    this.name = "GuardError";
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Thin client over the SolSentry pre-signing API.
 *
 * ```ts
 * const guard = new SolSentryGuard();
 * const advice = await guard.analyzeBeforeSign(tx);
 * if (advice.shouldBlock) showWarning(advice.summary);
 * ```
 */
export class SolSentryGuard {
  private readonly baseUrl: string;
  private readonly clientId?: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: GuardClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.clientId = options.clientId;
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const f = options.fetch ?? globalThis.fetch;
    if (typeof f !== "function") {
      throw new GuardError(
        "No fetch implementation available — pass options.fetch or run on Node 18+/a browser.",
      );
    }
    this.fetchImpl = f.bind(globalThis);
  }

  /** Analyze a single program/mint/wallet address. */
  async analyzeProgram(address: string): Promise<ContractAnalysis> {
    return this.get<ContractAnalysis>(
      `/v1/contract-analysis/${encodeURIComponent(address)}`,
    );
  }

  /** Address-poisoning check: is `destination` a lookalike of a prior contact? */
  async checkLookalike(
    destination: string,
    contacts: string[],
  ): Promise<LookalikeResult> {
    const q = new URLSearchParams({
      destination,
      contacts: contacts.join(","),
    });
    return this.get<LookalikeResult>(`/v1/lookalike-check?${q.toString()}`);
  }

  /**
   * Extract every program a transaction touches, score each, and return a
   * single aggregated verdict. Infra programs are skipped by default to save
   * credits (they always resolve "safe" server-side).
   */
  async analyzeBeforeSign(
    tx: unknown,
    options: AnalyzeBeforeSignOptions = {},
  ): Promise<SignAdvice> {
    const blockThreshold = options.blockThreshold ?? DEFAULT_BLOCK_THRESHOLD;
    const skipInfra = options.skipInfra ?? true;

    const all = extractProgramIds(tx);
    const programs = skipInfra
      ? all.filter((p) => !INFRA_PROGRAMS.has(p))
      : all;

    if (programs.length === 0) {
      return {
        verdict: "safe",
        risk_score: 0,
        shouldBlock: false,
        reports: [],
        programs: [],
        summary:
          all.length === 0
            ? "No programs found in transaction."
            : "Only known infrastructure programs — nothing to flag.",
      };
    }

    const reports = await Promise.all(
      programs.map((p) => this.analyzeProgram(p)),
    );

    let verdict: Verdict = "safe";
    let risk = 0;
    for (const r of reports) {
      verdict = worstVerdict(verdict, r.verdict);
      if (r.risk_score > risk) risk = r.risk_score;
    }
    const shouldBlock = verdict === "dangerous" || risk >= blockThreshold;

    return {
      verdict,
      risk_score: risk,
      shouldBlock,
      reports,
      programs,
      summary: buildSummary(verdict, risk, reports),
    };
  }

  private async get<T>(path: string): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const headers: Record<string, string> = { Accept: "application/json" };
    if (this.clientId) headers["X-Client-ID"] = this.clientId;
    if (this.apiKey) headers["Authorization"] = `Bearer ${this.apiKey}`;

    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: "GET",
        headers,
        signal: controller.signal,
      });
    } catch (err) {
      if ((err as Error).name === "AbortError") {
        throw new GuardError(`Request timed out after ${this.timeoutMs}ms`);
      }
      throw new GuardError(`Network error: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }

    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = undefined;
    }

    if (!res.ok) {
      const detail =
        body && typeof body === "object"
          ? ((body as { detail?: string; error?: string }).detail ??
            (body as { error?: string }).error)
          : undefined;
      throw new GuardError(`SolSentry API ${res.status}`, res.status, detail);
    }
    return body as T;
  }
}

function buildSummary(
  verdict: Verdict,
  risk: number,
  reports: ContractAnalysis[],
): string {
  const worst =
    reports.find((r) => r.verdict === verdict && r.risk_score === risk) ??
    reports[0];
  const label = worst?.known_label ?? worst?.address?.slice(0, 8) ?? "program";
  const detail = (worst?.explanation || label).replace(/\s*\.\s*$/, "");
  switch (verdict) {
    case "dangerous":
      return `DANGEROUS (risk ${risk}/100): ${detail}. Do not sign.`;
    case "caution":
      return `CAUTION (risk ${risk}/100): ${detail}. Review before signing.`;
    case "unknown":
      return `UNVERIFIED (risk ${risk}/100): ${label} is not a recognized program. Proceed carefully.`;
    default:
      return "All programs recognized as safe.";
  }
}
