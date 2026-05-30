// Public types for @solsentry/guard.
// Mirrors the JSON returned by the SolSentry REST API
// (/v1/contract-analysis, /v1/lookalike-check). Kept hand-written so the
// SDK has zero runtime dependencies.

export type Verdict = "safe" | "caution" | "dangerous" | "unknown";

/** Response of GET /v1/contract-analysis/{address}. */
export interface ContractAnalysis {
  address: string;
  /** program | mint | wallet | unknown */
  kind: string;
  /** Canonical name if the address is recognized (e.g. "Jupiter Aggregator v6"). */
  known_label: string | null;
  /** infra | exchange | drainer | ... */
  known_category: string | null;
  /** 0-100, higher = more dangerous to sign. */
  risk_score: number;
  verdict: Verdict;
  /** Machine-readable risk flags, e.g. ["KNOWN_DRAINER", "MINT_AUTHORITY_ACTIVE"]. */
  flags: string[];
  authorities: Record<string, unknown>;
  extensions: Record<string, unknown>;
  /** Plain-language summary, suitable to show in a signing modal. */
  explanation: string;
  fetched_at: number;
  /** Server-reported latency. Present on live responses. */
  latency_ms?: number;
}

/** One match from GET /v1/lookalike-check. */
export interface LookalikeFinding {
  contact: string;
  similarity: number;
  reason: string;
}

/** Response of GET /v1/lookalike-check. */
export interface LookalikeResult {
  destination: string;
  is_lookalike: boolean;
  findings: LookalikeFinding[];
}

export interface GuardClientOptions {
  /** API base URL. Defaults to https://api.solsentry.app */
  baseUrl?: string;
  /** Optional client identifier, sent as X-Client-ID (used for usage attribution). */
  clientId?: string;
  /** Optional x402 / admin token, sent as Authorization: Bearer <token>. */
  apiKey?: string;
  /** Per-request timeout in ms. Default 8000. */
  timeoutMs?: number;
  /** Inject a fetch implementation (tests, non-global-fetch runtimes). */
  fetch?: typeof fetch;
}

/** Aggregated verdict for an entire transaction. */
export interface SignAdvice {
  /** Worst verdict across every analyzed program/account. */
  verdict: Verdict;
  /** Max risk_score across all reports. */
  risk_score: number;
  /** True when verdict is "dangerous" or risk_score >= blockThreshold. */
  shouldBlock: boolean;
  /** Per-address reports that contributed to the decision. */
  reports: ContractAnalysis[];
  /** Distinct program IDs that were analyzed. */
  programs: string[];
  /** Human-readable one-liner summarizing the decision. */
  summary: string;
}

export interface AnalyzeBeforeSignOptions {
  /** risk_score at/above which shouldBlock becomes true. Default 80. */
  blockThreshold?: number;
  /**
   * Skip addresses already known to be infra (System, Token, ATA, Compute
   * Budget, etc) to save credits. Default true.
   */
  skipInfra?: boolean;
}
