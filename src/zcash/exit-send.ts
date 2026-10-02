// Pure helpers for examples/zcash-exit-send.ts (Solana SOL -> Zcash ZEC via NEAR Intents
// 1Click). No signing and no keys here: arg parsing, quote validation, refusal rules and
// a status poller. `fetch` and `sleep` are injectable so everything is testable offline.

export const ONECLICK_BASE = "https://1click.chaindefuser.com";
export const SOL_ASSET = "nep141:sol.omft.near";
export const ZEC_ASSET = "nep141:zec.omft.near";
export const SLIPPAGE_BPS = 100;
/** Refuse to send when fewer than this many ms remain on the quote deadline. */
export const MIN_DEADLINE_MARGIN_MS = 3 * 60_000;
export const POLL_INTERVAL_MS = 15_000;
export const POLL_MAX_MS = 10 * 60_000;

export interface ExitSendArgs {
  address: string;
  /** Lamports to send (exact input). */
  amount: bigint;
  send: boolean;
  allowTransparent: boolean;
  checkSender: boolean;
  /** Pubkey to use as refundTo / sender when there is no keypair (dry runs). */
  sender?: string;
}

export const USAGE =
  "Usage: zcash-exit-send.ts <zcash-address> <lamports> [--send] [--allow-transparent] [--check-sender] [--sender <solana-pubkey>]  (default: dry run)";

export function parseExitSendArgs(argv: string[]): ExitSendArgs {
  const sIdx = argv.indexOf("--sender");
  const sender = sIdx >= 0 ? argv[sIdx + 1] : undefined;
  if (sIdx >= 0 && (!sender || sender.startsWith("--"))) throw new Error("--sender needs a pubkey");
  const known = new Set(["--send", "--allow-transparent", "--check-sender", "--sender"]);
  const unknown = argv.filter((a) => a.startsWith("--") && !known.has(a));
  if (unknown.length) throw new Error(`Unknown flag: ${unknown[0]}. ${USAGE}`);
  const pos = argv.filter((a, i) => !a.startsWith("--") && !(sIdx >= 0 && i === sIdx + 1));
  const [address, amountArg, extra] = pos;
  if (!address || !amountArg || extra !== undefined) throw new Error(USAGE);
  if (!/^[1-9]\d*$/.test(amountArg)) throw new Error("amount must be a positive integer of lamports");
  return {
    address,
    amount: BigInt(amountArg),
    send: argv.includes("--send"),
    allowTransparent: argv.includes("--allow-transparent"),
    checkSender: argv.includes("--check-sender"),
    sender,
  };
}

/** Result of the destination gate. Never proceeds on block. */
export function destinationGate(
  verdict: { decision: "allow" | "warn" | "block"; note: string },
  allowTransparent: boolean,
): { proceed: true } | { proceed: false; reason: string } {
  if (verdict.decision === "block") return { proceed: false, reason: `blocked: ${verdict.note}` };
  if (verdict.decision === "warn" && !allowTransparent) {
    return { proceed: false, reason: `${verdict.note} Re-run with --allow-transparent to accept the transparent leg.` };
  }
  return { proceed: true };
}

export interface ExitQuote {
  depositAddress: string;
  depositMemo?: string;
  amountIn: string;
  amountOut: string;
  minAmountOut: string;
  deadline: string;
  timeEstimate?: number;
  /** The request as 1Click echoed it back; absent when the response omits it. */
  quoteRequest?: EchoedRequest;
}

export interface EchoedRequest {
  recipient?: string;
  refundTo?: string;
  amount?: string;
  originAsset?: string;
  destinationAsset?: string;
}

function echoed(json: unknown): EchoedRequest | undefined {
  const r = (json as { quoteRequest?: Record<string, unknown> } | null)?.quoteRequest;
  if (!r || typeof r !== "object") return undefined;
  const str = (v: unknown) => (typeof v === "string" ? v : undefined);
  return {
    recipient: str(r.recipient),
    refundTo: str(r.refundTo),
    amount: str(r.amount),
    originAsset: str(r.originAsset),
    destinationAsset: str(r.destinationAsset),
  };
}

const isDigits = (v: unknown): v is string => typeof v === "string" && /^\d+$/.test(v);

function amounts(q: Record<string, unknown>) {
  for (const k of ["amountIn", "amountOut", "minAmountOut"] as const) {
    if (!isDigits(q[k])) throw new Error(`1Click quote field ${k} missing or not an integer string`);
  }
  return {
    amountIn: q.amountIn as string,
    amountOut: q.amountOut as string,
    minAmountOut: q.minAmountOut as string,
    timeEstimate: typeof q.timeEstimate === "number" ? q.timeEstimate : undefined,
  };
}

function quoteObject(json: unknown): Record<string, unknown> {
  const q = (json as { quote?: Record<string, unknown> } | null)?.quote;
  if (!q || typeof q !== "object") throw new Error("1Click response has no `quote` object");
  return q;
}

/** Validate a real (dry:false) 1Click quote. Throws on anything unexpected. */
export function validateQuoteResponse(json: unknown): ExitQuote {
  const q = quoteObject(json);
  const depositAddress = q.depositAddress;
  if (typeof depositAddress !== "string" || depositAddress.length < 32 || depositAddress.length > 44) {
    throw new Error("1Click quote has no valid Solana depositAddress");
  }
  if (typeof q.deadline !== "string" || Number.isNaN(Date.parse(q.deadline))) {
    throw new Error("1Click quote has no valid deadline");
  }
  return {
    depositAddress,
    depositMemo: typeof q.depositMemo === "string" && q.depositMemo ? q.depositMemo : undefined,
    deadline: q.deadline,
    quoteRequest: echoed(json),
    ...amounts(q),
  };
}

/** A dry quote has no depositAddress/deadline; keep only the amounts. */
export function validateDryQuote(json: unknown): ExitQuote {
  return { depositAddress: "", deadline: "", quoteRequest: echoed(json), ...amounts(quoteObject(json)) };
}

/** 1Click reports the route minimum only in the error text: "try at least 14719409". */
export function parseRouteMinimum(message: unknown): bigint | undefined {
  if (typeof message !== "string") return undefined;
  const m = /too low[^]*?at least (\d+)/i.exec(message);
  return m ? BigInt(m[1] as string) : undefined;
}

export type QuoteResult =
  | { ok: true; quote: ExitQuote; raw: unknown }
  | { ok: false; status: number; message: string; routeMinimum?: bigint };

export function oneClickHeaders(jwt?: string): Record<string, string> {
  const h: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
    // The public endpoint sits behind a bot filter that rejects clients with no User-Agent.
    "User-Agent": "solsentry-guard-example/0.0.1",
  };
  if (jwt) h.Authorization = `Bearer ${jwt}`;
  return h;
}

export function buildQuoteBody(p: {
  address: string;
  amount: bigint;
  refundTo: string;
  dry: boolean;
  now?: number;
}): Record<string, unknown> {
  return {
    dry: p.dry,
    swapType: "EXACT_INPUT",
    slippageTolerance: SLIPPAGE_BPS,
    originAsset: SOL_ASSET,
    depositType: "ORIGIN_CHAIN",
    destinationAsset: ZEC_ASSET,
    amount: p.amount.toString(),
    refundTo: p.refundTo,
    refundType: "ORIGIN_CHAIN",
    recipient: p.address,
    recipientType: "DESTINATION_CHAIN",
    deadline: new Date((p.now ?? Date.now()) + 30 * 60_000).toISOString(),
  };
}

async function readJson(res: Response): Promise<unknown> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

const msgOf = (j: unknown): string =>
  typeof j === "string"
    ? j
    : (((j as { message?: unknown } | null)?.message as string | undefined) ?? JSON.stringify(j));

/** POST /v0/quote. dry:false quotes carry a depositAddress and are strictly validated. */
export async function requestQuote(
  f: typeof fetch,
  base: string,
  headers: Record<string, string>,
  body: Record<string, unknown>,
): Promise<QuoteResult> {
  const res = await f(`${base}/v0/quote`, { method: "POST", headers, body: JSON.stringify(body) });
  const json = await readJson(res);
  if (!res.ok) {
    const message = msgOf(json);
    return { ok: false, status: res.status, message, routeMinimum: parseRouteMinimum(message) };
  }
  return { ok: true, raw: json, quote: body.dry === true ? validateDryQuote(json) : validateQuoteResponse(json) };
}

/** Refusal rules applied right before signing. Returns the reasons it must NOT send. */
export function sendRefusals(p: {
  quote: ExitQuote;
  requested: bigint;
  /** What we asked for: the echoed quoteRequest must match all of it. */
  expected: { recipient: string; refundTo: string };
  routeMinimum?: bigint;
  now?: number;
}): string[] {
  const out: string[] = [];
  const { quote } = p;
  if (!quote.depositAddress) out.push("quote has no deposit address (it was a dry quote)");
  if (BigInt(quote.amountIn) !== p.requested) {
    out.push(`quote amountIn ${quote.amountIn} differs from requested ${p.requested}`);
  }
  if (p.routeMinimum !== undefined && BigInt(quote.amountIn) < p.routeMinimum) {
    out.push(`amount ${quote.amountIn} is below the route minimum ${p.routeMinimum}`);
  }
  const er = quote.quoteRequest;
  if (!er) {
    out.push("quote response does not echo quoteRequest; cannot verify recipient and refund address");
  } else {
    const chk = (name: string, got: string | undefined, want: string) => {
      if (got !== want) out.push(`echoed ${name} ${got ?? "(missing)"} does not match expected ${want}`);
    };
    chk("recipient", er.recipient, p.expected.recipient);
    chk("refundTo", er.refundTo, p.expected.refundTo);
    chk("originAsset", er.originAsset, SOL_ASSET);
    chk("destinationAsset", er.destinationAsset, ZEC_ASSET);
    chk("amount", er.amount, p.requested.toString());
  }
  if (BigInt(quote.minAmountOut) <= 0n) out.push("minAmountOut is zero");
  if (quote.depositMemo) out.push("deposit requires a memo; a plain transfer cannot carry it");
  const left = Date.parse(quote.deadline) - (p.now ?? Date.now());
  if (!(left >= MIN_DEADLINE_MARGIN_MS)) out.push("quote deadline is too close or already passed");
  return out;
}

export const TERMINAL_STATUSES = ["SUCCESS", "REFUNDED", "FAILED"] as const;

export interface StatusSnapshot {
  status: string;
  destinationTxHashes: { hash: string; explorerUrl?: string }[];
  refundReason?: string;
  raw: unknown;
}

export async function getStatus(
  f: typeof fetch,
  base: string,
  headers: Record<string, string>,
  depositAddress: string,
): Promise<StatusSnapshot> {
  const res = await f(`${base}/v0/status?depositAddress=${encodeURIComponent(depositAddress)}`, { headers });
  const json = await readJson(res);
  if (!res.ok) throw new Error(`1Click status HTTP ${res.status}: ${msgOf(json)}`);
  const j = json as {
    status?: unknown;
    swapDetails?: { destinationChainTxHashes?: unknown; refundReason?: unknown };
  };
  if (typeof j.status !== "string") throw new Error("1Click status response has no status");
  const dest = Array.isArray(j.swapDetails?.destinationChainTxHashes)
    ? (j.swapDetails.destinationChainTxHashes as unknown[])
    : [];
  return {
    status: j.status,
    destinationTxHashes: dest.filter(
      (d): d is { hash: string; explorerUrl?: string } =>
        typeof (d as { hash?: unknown } | null)?.hash === "string",
    ),
    refundReason: typeof j.swapDetails?.refundReason === "string" ? j.swapDetails.refundReason : undefined,
    raw: json,
  };
}

/** Poll until a terminal status or timeout. Transient errors are reported and retried. */
export async function pollStatus(opts: {
  fetch: typeof fetch;
  base: string;
  headers: Record<string, string>;
  depositAddress: string;
  intervalMs?: number;
  maxMs?: number;
  sleep?: (ms: number) => Promise<void>;
  onTick?: (s: StatusSnapshot | { error: string }) => void;
}): Promise<{ final: StatusSnapshot | null; timedOut: boolean; last?: StatusSnapshot }> {
  const interval = opts.intervalMs ?? POLL_INTERVAL_MS;
  const max = opts.maxMs ?? POLL_MAX_MS;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  let last: StatusSnapshot | undefined;
  for (let waited = 0; ; waited += interval) {
    try {
      last = await getStatus(opts.fetch, opts.base, opts.headers, opts.depositAddress);
      opts.onTick?.(last);
      if ((TERMINAL_STATUSES as readonly string[]).includes(last.status)) {
        return { final: last, timedOut: false, last };
      }
    } catch (e) {
      opts.onTick?.({ error: (e as Error).message });
    }
    if (waited + interval > max) return { final: null, timedOut: true, last };
    await sleep(interval);
  }
}

/** Optional: tell 1Click the deposit tx hash so it can verify early. Best effort. */
export async function submitDepositTx(
  f: typeof fetch,
  base: string,
  headers: Record<string, string>,
  txHash: string,
  depositAddress: string,
): Promise<{ ok: boolean; status: number }> {
  const res = await f(`${base}/v0/deposit/submit`, {
    method: "POST",
    headers,
    body: JSON.stringify({ txHash, depositAddress }),
  });
  return { ok: res.ok, status: res.status };
}
