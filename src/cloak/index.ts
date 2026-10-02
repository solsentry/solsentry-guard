// Optional entrypoint: @solsentry/guard/cloak
//
// Risk-check a recipient with SolSentry, and only if it passes, send privately
// through Cloak (deposit into the shielded pool, then one full withdrawal to the
// recipient). `@cloak.dev/sdk` is an OPTIONAL peer dependency: it is imported
// lazily, only when a real (non-dry-run) send is executed.

import { SolSentryGuard } from "../client.js";
import type {
  ContractAnalysis,
  LookalikeResult,
  OperatorProfile,
} from "../types.js";

export const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
export const CLOAK_PRODUCTION_RELAY_URL = "https://api.cloak.ag";

export type CloakMint = "SOL" | "USDC";
export type RecipientDecision = "allow" | "warn" | "block";

export interface RecipientPolicy {
  /** risk_score at/above which the recipient is blocked. Default 80. */
  blockThreshold?: number;
  /** Prior contacts of the sender; enables the address-poisoning (lookalike) check. */
  contacts?: string[];
  /** Treat "caution" / "unknown" as blocking too. Default false (warn only). */
  strict?: boolean;
  /** What to do when the SolSentry API is unreachable. Default "block" (fail closed). */
  onCheckError?: "block" | "warn";
}

export interface RecipientVerdict {
  decision: RecipientDecision;
  /** Machine-readable reasons, e.g. ["KNOWN_DRAINER", "LOOKALIKE"]. */
  reasons: string[];
  /** Human-readable explanation. */
  explanation: string;
  risk_score: number | null;
  analysis?: ContractAnalysis;
  lookalike?: LookalikeResult;
}

export interface SenderVerdict extends RecipientVerdict {
  /** Operator profile of the sender, when fetched. */
  operator?: OperatorProfile;
  /**
   * First-funding lookup (1 hop, via Solana RPC). "unknown" = no signal (fresh wallet,
   * long history, or no plain funding transfer found); it is not an error.
   */
  funding?: FundingLookup;
  /** The upstream funder that was screened, if one was found. */
  funder?: { address: string; depth: number; decision: RecipientDecision; reasons: string[] };
}

/** Minimal structural view of the parts of `@cloak.dev/sdk` used here. */
export interface CloakSdk {
  CLOAK_PROGRAM_ID: unknown;
  NATIVE_SOL_MINT: unknown;
  createCloakRpc(endpoint: string): unknown;
  createUtxo(amount: bigint, owner: unknown, mint?: unknown): Promise<unknown>;
  createZeroUtxo(mint?: unknown): Promise<unknown>;
  generateUtxoKeypair(): Promise<unknown>;
  transact(params: unknown, options: unknown): Promise<CloakTxResult>;
  fullWithdraw(
    inputs: unknown[],
    recipient: unknown,
    options: unknown,
  ): Promise<CloakTxResult>;
  serializeUtxo(utxo: unknown): Uint8Array;
}

export interface CloakTxResult {
  signature: string;
  outputUtxos: Array<{ amount: bigint }>;
  merkleTree?: unknown;
}

export interface PersistedNote {
  stage: "deposit" | "withdraw";
  /** Signature of the transaction that created this note. */
  signature: string;
  /** serializeUtxo() output, hex. deserializeUtxo() turns it back into a spendable note. */
  utxoHex: string;
}

export interface GuardedPrivateSendOptions {
  recipient: string;
  /** Base units: lamports for SOL, 1e-6 for USDC. */
  amount: bigint;
  mint: CloakMint;
  /** Cloak KeyPairSigner (e.g. from `signerFromSecretKey`). Not needed for dryRun. */
  signer?: { address: unknown } & Record<string, unknown>;
  /** Pre-built Cloak RPC. Alternative: `rpcUrl`. */
  connection?: unknown;
  rpcUrl?: string;
  solsentry?: { apiBase?: string; apiKey?: string; clientId?: string };
  policy?: RecipientPolicy;
  /**
   * REQUIRED for a real send. Called with every note that holds value right after
   * the deposit lands (before the withdrawal) and again with any withdrawal change.
   * Throwing here aborts before the withdrawal.
   */
  persistUtxos?: (notes: PersistedNote[]) => void | Promise<void>;
  /** Risk-check only; nothing is built, signed or sent. */
  dryRun?: boolean;
  /** Inject the SDK (tests). Defaults to a lazy import of `@cloak.dev/sdk`. */
  cloak?: CloakSdk;
  /** Inject a guard client (tests). */
  guard?: Pick<SolSentryGuard, "analyzeProgram" | "checkLookalike"> &
    Partial<Pick<SolSentryGuard, "getOperator">>;
  /**
   * Opt-in inbound check (source of funds) on the sender, run BEFORE any Cloak
   * import or deposit. Default false. Uses `sender` or, if absent, `signer.address`.
   */
  checkSender?: boolean;
  /** Sender address for the inbound check (needed for dryRun, where there is no signer). */
  sender?: string;
}

export interface GuardedPrivateSendResult {
  verdict: RecipientVerdict;
  status: "sent" | "blocked" | "dry-run";
  /** Which party caused a "blocked" status. Absent for recipient blocks. */
  side?: "sender" | "recipient";
  /** Inbound verdict, present only when `checkSender` was on. */
  senderVerdict?: SenderVerdict;
  /** True if the send was executed (sent) or would be allowed (dry-run). */
  allowed: boolean;
  depositSig?: string;
  withdrawSig?: string;
  explorerUrls?: { deposit: string; withdraw: string };
  /** Notes persisted through `persistUtxos`. */
  outputUtxos?: PersistedNote[];
  explanation: string;
}

/** Thrown when Cloak fails AFTER the deposit landed. `notes` are the recovery material. */
export class CloakSendError extends Error {
  readonly depositSig?: string;
  readonly notes: PersistedNote[];
  readonly verdict: RecipientVerdict;
  readonly originalError: unknown;
  constructor(
    message: string,
    verdict: RecipientVerdict,
    notes: PersistedNote[],
    originalError: unknown,
    depositSig?: string,
  ) {
    super(message);
    this.name = "CloakSendError";
    this.verdict = verdict;
    this.notes = notes;
    this.originalError = originalError;
    this.depositSig = depositSig;
  }
}

type GuardLike = Pick<SolSentryGuard, "analyzeProgram" | "checkLookalike">;

const BLOCK_FLAGS = ["KNOWN_DRAINER", "KNOWN_MALICIOUS", "KNOWN_SCAM", "DRAINER"];

function explorer(sig: string): string {
  return `https://solscan.io/tx/${sig}`;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** Step 1 on its own: risk-check a recipient. Never touches Cloak. */
export async function checkRecipient(
  recipient: string,
  policy: RecipientPolicy,
  guard: GuardLike,
): Promise<RecipientVerdict> {
  const threshold = policy.blockThreshold ?? 80;
  const failClosed = (policy.onCheckError ?? "block") === "block";
  let analysis: ContractAnalysis;
  try {
    analysis = await guard.analyzeProgram(recipient);
  } catch (err) {
    return {
      decision: failClosed ? "block" : "warn",
      reasons: ["CHECK_FAILED"],
      explanation: `Risk check unavailable (${(err as Error).message}); ${
        failClosed ? "not sending (fail closed)" : "proceeding with a warning"
      }.`,
      risk_score: null,
    };
  }

  const reasons: string[] = [];
  let block = false;
  const category = (analysis.known_category ?? "").toLowerCase();
  const flags = (analysis.flags ?? []).map((f) => f.toUpperCase());
  const hardFlags = flags.filter((f) => BLOCK_FLAGS.includes(f));

  if (category === "drainer" || hardFlags.length > 0) {
    block = true;
    reasons.push(...(hardFlags.length > 0 ? hardFlags : ["KNOWN_DRAINER"]));
  }
  if (analysis.verdict === "dangerous" || analysis.risk_score >= threshold) {
    block = true;
    if (reasons.length === 0) reasons.push("HIGH_RISK");
  }

  let lookalike: LookalikeResult | undefined;
  if (policy.contacts && policy.contacts.length > 0) {
    try {
      lookalike = await guard.checkLookalike(recipient, policy.contacts);
      if (lookalike.is_lookalike) {
        block = true;
        reasons.push("LOOKALIKE");
      }
    } catch {
      if (failClosed) {
        block = true;
        reasons.push("CHECK_FAILED");
      }
    }
  }

  let warn = false;
  if (!block) {
    if (analysis.verdict === "caution") {
      warn = true;
      reasons.push("CAUTION");
    } else if (analysis.verdict === "unknown") {
      warn = true;
      reasons.push("UNVERIFIED");
    }
    if (warn && policy.strict) block = true;
  }

  const decision: RecipientDecision = block ? "block" : warn ? "warn" : "allow";
  const detail = analysis.explanation || analysis.known_label || recipient;
  return {
    decision,
    reasons,
    explanation:
      decision === "block"
        ? `Blocked: ${detail}`
        : decision === "warn"
          ? `Warning: ${detail}`
          : "No risk signals found for the recipient.",
    risk_score: analysis.risk_score,
    analysis,
    lookalike,
  };
}

type SenderGuardLike = Pick<
  SolSentryGuard,
  "analyzeProgram" | "getOperator"
>;

export const DEFAULT_SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com";
const SIG_PAGE = 1000;
const MAX_SIG_PAGES = 5;

export type FundingLookup =
  | { status: "found"; funder: string; depth: 1; signature: string }
  | { status: "unknown"; reason: "NO_HISTORY" | "HISTORY_TOO_LONG" | "NO_FUNDING_TRANSFER" };

export interface SenderCheckOptions {
  /** Solana JSON-RPC endpoint for the first-funder lookup. Default: public mainnet-beta. */
  rpcUrl?: string;
  /** Inject fetch (tests). */
  fetch?: typeof fetch;
}

async function rpcCall<T>(f: typeof fetch, url: string, method: string, params: unknown[]): Promise<T> {
  const res = await f(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`Solana RPC ${method} HTTP ${res.status}`);
  const body = (await res.json()) as { result?: T; error?: { message?: string } };
  if (body.error) throw new Error(`Solana RPC ${method}: ${body.error.message ?? "error"}`);
  return body.result as T;
}

interface ParsedIx {
  program?: string;
  parsed?: { type?: string; info?: Record<string, unknown> };
  [k: string]: unknown;
}

/**
 * Find the wallet's FIRST funder: the source of the earliest system transfer /
 * createAccount that credits it. One hop only; bounded to 5 pages of signatures.
 * Throws on RPC errors.
 */
export async function findFirstFunder(
  wallet: string,
  opts: SenderCheckOptions = {},
): Promise<FundingLookup> {
  const f = (opts.fetch ?? globalThis.fetch).bind(globalThis) as typeof fetch;
  const url = opts.rpcUrl ?? DEFAULT_SOLANA_RPC_URL;
  let before: string | undefined;
  let last: Array<{ signature: string; err: unknown }> = [];
  let exhausted = false;
  for (let page = 0; page < MAX_SIG_PAGES; page++) {
    const cfg: Record<string, unknown> = { limit: SIG_PAGE };
    if (before) cfg.before = before;
    const sigs = await rpcCall<Array<{ signature: string; err: unknown }>>(
      f, url, "getSignaturesForAddress", [wallet, cfg],
    );
    if (sigs.length === 0) {
      exhausted = true;
      break;
    }
    last = sigs;
    if (sigs.length < SIG_PAGE) {
      exhausted = true;
      break;
    }
    before = (sigs[sigs.length - 1] as { signature: string }).signature;
  }
  if (last.length === 0) return { status: "unknown", reason: "NO_HISTORY" };
  if (!exhausted) return { status: "unknown", reason: "HISTORY_TOO_LONG" };

  // Newest-first list: the oldest successful signature is the last one with err == null.
  const oldest = [...last].reverse().find((s) => s.err == null);
  if (!oldest) return { status: "unknown", reason: "NO_FUNDING_TRANSFER" };
  const tx = await rpcCall<{
    transaction?: { message?: { instructions?: ParsedIx[] } };
    meta?: { innerInstructions?: Array<{ instructions: ParsedIx[] }> } | null;
  } | null>(f, url, "getTransaction", [
    oldest.signature,
    { encoding: "jsonParsed", maxSupportedTransactionVersion: 0 },
  ]);
  const ixs: ParsedIx[] = [
    ...(tx?.transaction?.message?.instructions ?? []),
    ...(tx?.meta?.innerInstructions ?? []).flatMap((i) => i.instructions),
  ];
  for (const ix of ixs) {
    if (ix.program !== "system" || !ix.parsed) continue;
    const info = ix.parsed.info ?? {};
    if (ix.parsed.type === "transfer" && info.destination === wallet && typeof info.source === "string") {
      return { status: "found", funder: info.source, depth: 1, signature: oldest.signature };
    }
    if (ix.parsed.type === "createAccount" && info.newAccount === wallet && typeof info.source === "string") {
      return { status: "found", funder: info.source, depth: 1, signature: oldest.signature };
    }
  }
  return { status: "unknown", reason: "NO_FUNDING_TRANSFER" };
}

interface WalletScreen {
  block: boolean;
  warn: boolean;
  reasons: string[];
  detail: string;
  risk_score: number;
  analysis: ContractAnalysis;
  operator: OperatorProfile;
}

/** Steps 1+2 for one wallet: contract analysis, then operator profile. Throws on API error. */
async function screenWallet(
  wallet: string,
  threshold: number,
  guard: SenderGuardLike,
): Promise<WalletScreen> {
  const analysis = await guard.analyzeProgram(wallet);
  const operator = await guard.getOperator(wallet);
  const reasons: string[] = [];
  let block = false;
  let warn = false;

  const category = (analysis.known_category ?? "").toLowerCase();
  const hardFlags = (analysis.flags ?? [])
    .map((f) => f.toUpperCase())
    .filter((f) => BLOCK_FLAGS.includes(f));
  if (category === "drainer" || hardFlags.length > 0) {
    block = true;
    reasons.push(...(hardFlags.length > 0 ? hardFlags : ["KNOWN_DRAINER"]));
  }
  if (analysis.verdict === "dangerous" || analysis.risk_score >= threshold) {
    block = true;
    if (reasons.length === 0) reasons.push("HIGH_RISK");
  }
  if (!block && analysis.verdict === "caution") {
    warn = true;
    reasons.push("CAUTION");
  }

  // Operator profile. Only CRITICAL/HIGH/MEDIUM and confirmed_rugs carry signal;
  // LOW / UNKNOWN / missing are "no signal".
  const level = (operator.risk_level ?? "").toUpperCase();
  const rugs = Number(operator.confirmed_rugs ?? 0) || 0;
  if (level === "CRITICAL" || level === "HIGH" || rugs >= 2) {
    block = true;
    reasons.push("OPERATOR_HIGH_RISK");
  } else if (level === "MEDIUM" || rugs === 1) {
    warn = true;
    reasons.push("OPERATOR_MEDIUM_RISK");
  }

  return {
    block,
    warn,
    reasons,
    detail: analysis.explanation || analysis.known_label || wallet,
    risk_score: analysis.risk_score,
    analysis,
    operator,
  };
}

/**
 * Inbound check: is the sender (and whoever funded it) flagged? Never touches Cloak.
 * Fails closed on any API error unless `policy.onCheckError === "warn"`.
 */
export async function checkSender(
  sender: string,
  policy: RecipientPolicy,
  guard: SenderGuardLike,
  senderOpts: SenderCheckOptions = {},
): Promise<SenderVerdict> {
  const threshold = policy.blockThreshold ?? 80;
  const failClosed = (policy.onCheckError ?? "block") === "block";
  try {
    const self = await screenWallet(sender, threshold, guard);
    const reasons = [...self.reasons];
    let block = self.block;
    let warn = self.warn;
    let detail = self.detail;

    // Skip the RPC lookup when the sender is already blocked on its own.
    const funding = self.block ? undefined : await findFirstFunder(sender, senderOpts);
    let funder: SenderVerdict["funder"];
    if (funding?.status === "found") {
      const depth = funding.depth;
      const f = await screenWallet(funding.funder, threshold, guard);
      const decision: RecipientDecision = f.block ? "block" : f.warn ? "warn" : "allow";
      funder = { address: funding.funder, depth, decision, reasons: f.reasons };
      if (f.block) {
        block = true;
        reasons.push("FUNDED_BY_FLAGGED");
        detail = `funded by flagged wallet ${funding.funder} at depth ${depth} (${f.reasons.join(", ")})`;
      } else if (f.warn) {
        warn = true;
        reasons.push("FUNDED_BY_CAUTION");
        if (!self.block) detail = `funded by wallet ${funding.funder} at depth ${depth} with warnings (${f.reasons.join(", ")})`;
      }
    }
    if (!block && warn && policy.strict) block = true;

    const decision: RecipientDecision = block ? "block" : warn ? "warn" : "allow";
    return {
      decision,
      reasons,
      explanation:
        decision === "block"
          ? `Blocked: ${detail}`
          : decision === "warn"
            ? `Warning: ${detail}`
            : "No risk signals found for the sender or its source of funds.",
      risk_score: self.risk_score,
      analysis: self.analysis,
      operator: self.operator,
      funding,
      funder,
    };
  } catch (err) {
    return {
      decision: failClosed ? "block" : "warn",
      reasons: ["CHECK_FAILED"],
      explanation: `Sender check unavailable (${(err as Error).message}); ${
        failClosed ? "not sending (fail closed)" : "proceeding with a warning"
      }.`,
      risk_score: null,
    };
  }
}

/**
 * Risk-check the recipient, then (if allowed and not dryRun) deposit into the Cloak
 * pool and fully withdraw to the recipient. One deposit, one full withdrawal.
 */
export async function guardedPrivateSend(
  opts: GuardedPrivateSendOptions,
): Promise<GuardedPrivateSendResult> {
  const guard: GuardLike =
    opts.guard ??
    new SolSentryGuard({
      baseUrl: opts.solsentry?.apiBase,
      apiKey: opts.solsentry?.apiKey,
      clientId: opts.solsentry?.clientId ?? "guard-cloak",
    });

  // Opt-in inbound check: runs before anything else and before any Cloak import.
  let senderVerdict: SenderVerdict | undefined;
  if (opts.checkSender) {
    const sender = opts.sender ?? (opts.signer ? String(opts.signer.address) : undefined);
    if (!sender) throw new Error("checkSender needs `sender` or a signer with an address.");
    const rpcUrl = opts.rpcUrl ?? (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.SOLANA_RPC_URL ?? DEFAULT_SOLANA_RPC_URL;
    if (!opts.dryRun && !opts.rpcUrl) {
      throw new Error("rpcUrl is required for a real send with checkSender (first-funder lookup).");
    }
    senderVerdict = await checkSender(
      sender,
      opts.policy ?? {},
      guard as unknown as SenderGuardLike,
      { rpcUrl },
    );
    if (senderVerdict.decision === "block") {
      return {
        verdict: senderVerdict,
        senderVerdict,
        side: "sender",
        status: "blocked",
        allowed: false,
        explanation: `${senderVerdict.explanation} Cloak was not called; no funds moved.`,
      };
    }
  }

  const verdict = await checkRecipient(opts.recipient, opts.policy ?? {}, guard);

  if (verdict.decision === "block") {
    return {
      verdict,
      senderVerdict,
      side: "recipient",
      status: "blocked",
      allowed: false,
      explanation: `${verdict.explanation} Cloak was not called; no funds moved.`,
    };
  }
  if (opts.dryRun) {
    return {
      verdict,
      senderVerdict,
      status: "dry-run",
      allowed: true,
      explanation: `${verdict.explanation} Dry run: nothing was built or sent.`,
    };
  }

  // Real send: validate everything before the first on-chain action.
  const persist = opts.persistUtxos;
  const signer = opts.signer;
  if (!persist) {
    throw new Error("persistUtxos is required for a real send (notes are your money).");
  }
  if (!signer) throw new Error("signer is required for a real send.");
  if (!opts.connection && !opts.rpcUrl) {
    throw new Error("Pass connection or rpcUrl for a real send.");
  }
  if (opts.amount <= 0n) throw new Error("amount must be positive.");

  const cloak: CloakSdk =
    opts.cloak ?? ((await import("@cloak.dev/sdk")) as unknown as CloakSdk);
  const connection = opts.connection ?? cloak.createCloakRpc(opts.rpcUrl as string);
  const mint = opts.mint === "SOL" ? cloak.NATIVE_SOL_MINT : USDC_MINT;
  const base = {
    connection,
    programId: cloak.CLOAK_PROGRAM_ID,
    relayUrl: CLOAK_PRODUCTION_RELAY_URL,
    depositorKeypair: signer,
    walletPublicKey: signer.address,
  };
  const serialize = (stage: PersistedNote["stage"], r: CloakTxResult) =>
    r.outputUtxos
      .filter((u) => u.amount > 0n)
      .map<PersistedNote>((u) => ({
        stage,
        signature: r.signature,
        utxoHex: toHex(cloak.serializeUtxo(u)),
      }));

  const owner = await cloak.generateUtxoKeypair();
  const output = await cloak.createUtxo(opts.amount, owner, mint);
  const deposited = await cloak.transact(
    {
      inputUtxos: [await cloak.createZeroUtxo(mint)],
      outputUtxos: [output],
      externalAmount: opts.amount,
      depositor: signer.address,
    },
    base,
  );

  // The deposit is on chain; its note exists only in this process. Persist now.
  const depositNotes = serialize("deposit", deposited);
  try {
    await persist(depositNotes);
  } catch (err) {
    throw new CloakSendError(
      "Deposit landed but persisting the note failed; withdrawal NOT attempted. Recover from notes.",
      verdict,
      depositNotes,
      err,
      deposited.signature,
    );
  }

  let withdrawn: CloakTxResult;
  try {
    withdrawn = await cloak.fullWithdraw(deposited.outputUtxos, opts.recipient, {
      ...base,
      cachedMerkleTree: deposited.merkleTree,
    });
  } catch (err) {
    throw new CloakSendError(
      `Withdrawal failed after deposit ${deposited.signature}; funds remain shielded. Use the saved notes to recover.`,
      verdict,
      depositNotes,
      err,
      deposited.signature,
    );
  }

  const withdrawNotes = serialize("withdraw", withdrawn);
  if (withdrawNotes.length > 0) await persist(withdrawNotes);

  return {
    verdict,
    senderVerdict,
    status: "sent",
    allowed: true,
    depositSig: deposited.signature,
    withdrawSig: withdrawn.signature,
    explorerUrls: {
      deposit: explorer(deposited.signature),
      withdraw: explorer(withdrawn.signature),
    },
    outputUtxos: [...depositNotes, ...withdrawNotes],
    explanation: verdict.explanation,
  };
}
