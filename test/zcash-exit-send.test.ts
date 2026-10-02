import { describe, expect, it, vi } from "vitest";
import {
  buildQuoteBody,
  destinationGate,
  getStatus,
  parseExitSendArgs,
  parseRouteMinimum,
  pollStatus,
  requestQuote,
  sendRefusals,
  validateQuoteResponse,
  type ExitQuote,
} from "../src/zcash/exit-send.js";

const DEPOSIT = "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pKo4ps";
const goodQuote = (over: Record<string, unknown> = {}) => ({
  quote: {
    depositAddress: DEPOSIT,
    amountIn: "50000000",
    amountOut: "423276",
    minAmountOut: "419043",
    deadline: new Date(Date.now() + 25 * 60_000).toISOString(),
    ...over,
  },
});
const resp = (body: unknown, status = 200) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), { status });

describe("parseExitSendArgs", () => {
  it("defaults to dry run", () => {
    const a = parseExitSendArgs(["t1abc", "50000000"]);
    expect(a).toMatchObject({ address: "t1abc", amount: 50000000n, send: false, allowTransparent: false });
  });
  it("parses flags in any position", () => {
    const a = parseExitSendArgs(["--send", "t1abc", "--sender", "PK", "50000000", "--allow-transparent", "--check-sender"]);
    expect(a).toMatchObject({ send: true, allowTransparent: true, checkSender: true, sender: "PK", amount: 50000000n });
  });
  it("rejects bad input", () => {
    expect(() => parseExitSendArgs(["t1abc"])).toThrow(/Usage/);
    expect(() => parseExitSendArgs(["t1abc", "0"])).toThrow(/positive integer/);
    expect(() => parseExitSendArgs(["t1abc", "1.5"])).toThrow(/positive integer/);
    expect(() => parseExitSendArgs(["t1abc", "5", "--sned"])).toThrow(/Unknown flag/);
    expect(() => parseExitSendArgs(["t1abc", "5", "--sender"])).toThrow(/--sender needs/);
    expect(() => parseExitSendArgs(["a", "5", "6"])).toThrow(/Usage/);
  });
});

describe("destinationGate", () => {
  it("stops on block always", () => {
    expect(destinationGate({ decision: "block", note: "bad" }, true)).toMatchObject({ proceed: false });
  });
  it("stops on warn unless --allow-transparent", () => {
    expect(destinationGate({ decision: "warn", note: "t-leg" }, false)).toMatchObject({ proceed: false });
    expect(destinationGate({ decision: "warn", note: "t-leg" }, true)).toEqual({ proceed: true });
  });
  it("allows shielded", () => {
    expect(destinationGate({ decision: "allow", note: "ok" }, false)).toEqual({ proceed: true });
  });
});

describe("validateQuoteResponse", () => {
  it("accepts a good quote", () => {
    expect(validateQuoteResponse(goodQuote())).toMatchObject({ depositAddress: DEPOSIT, amountIn: "50000000" });
  });
  it("rejects malformed quotes", () => {
    expect(() => validateQuoteResponse({})).toThrow(/no `quote`/);
    expect(() => validateQuoteResponse(goodQuote({ depositAddress: undefined }))).toThrow(/depositAddress/);
    expect(() => validateQuoteResponse(goodQuote({ amountIn: "abc" }))).toThrow(/amountIn/);
    expect(() => validateQuoteResponse(goodQuote({ minAmountOut: undefined }))).toThrow(/minAmountOut/);
    expect(() => validateQuoteResponse(goodQuote({ deadline: "soon" }))).toThrow(/deadline/);
  });
});

describe("parseRouteMinimum", () => {
  it("reads the minimum from the 1Click error text", () => {
    expect(parseRouteMinimum("Amount is too low for bridge, try at least 14719409")).toBe(14719409n);
    expect(parseRouteMinimum("recipient is not valid")).toBeUndefined();
  });
});

describe("requestQuote", () => {
  const body = buildQuoteBody({ address: "t1abc", amount: 50000000n, refundTo: "PK", dry: false });
  it("body matches the SOL -> ZEC route", () => {
    expect(body).toMatchObject({
      dry: false,
      originAsset: "nep141:sol.omft.near",
      destinationAsset: "nep141:zec.omft.near",
      slippageTolerance: 100,
      refundTo: "PK",
      recipient: "t1abc",
      amount: "50000000",
    });
  });
  it("returns a validated quote and sends the User-Agent", async () => {
    const f = vi.fn(async () => resp(goodQuote()));
    const r = await requestQuote(f as never, "https://x", { "User-Agent": "ua" }, body);
    expect(r.ok).toBe(true);
    const init = (f.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect((init.headers as Record<string, string>)["User-Agent"]).toBe("ua");
    expect(JSON.parse(init.body as string).dry).toBe(false);
  });
  it("surfaces the route minimum on a too-low error", async () => {
    const f = vi.fn(async () => resp({ message: "Amount is too low for bridge, try at least 14719409" }, 400));
    const r = await requestQuote(f as never, "https://x", {}, body);
    expect(r).toMatchObject({ ok: false, status: 400, routeMinimum: 14719409n });
  });
  it("dry quote needs no deposit address", async () => {
    const f = vi.fn(async () => resp({ quote: { amountIn: "5", amountOut: "4", minAmountOut: "3" } }));
    const r = await requestQuote(f as never, "https://x", {}, { ...body, dry: true });
    expect(r).toMatchObject({ ok: true, quote: { depositAddress: "" } });
  });
});

describe("sendRefusals", () => {
  const q = (o: Partial<ExitQuote> = {}): ExitQuote => ({ ...validateQuoteResponse(goodQuote()), ...o });
  it("passes a clean quote", () => {
    expect(sendRefusals({ quote: q(), requested: 50000000n, routeMinimum: 14719409n })).toEqual([]);
  });
  it("refuses amount mismatch, below minimum, memo, stale or dry quote", () => {
    expect(sendRefusals({ quote: q(), requested: 49999999n }).join()).toMatch(/differs/);
    expect(sendRefusals({ quote: q({ amountIn: "100" }), requested: 100n, routeMinimum: 14719409n }).join()).toMatch(/route minimum/);
    expect(sendRefusals({ quote: q({ depositMemo: "1" }), requested: 50000000n }).join()).toMatch(/memo/);
    expect(
      sendRefusals({ quote: q({ deadline: new Date(Date.now() + 60_000).toISOString() }), requested: 50000000n }).join(),
    ).toMatch(/deadline/);
    expect(sendRefusals({ quote: q({ depositAddress: "" }), requested: 50000000n }).join()).toMatch(/dry quote/);
    expect(sendRefusals({ quote: q({ minAmountOut: "0" }), requested: 50000000n }).join()).toMatch(/minAmountOut/);
  });
});

describe("status polling", () => {
  const st = (status: string, extra: Record<string, unknown> = {}) => resp({ status, swapDetails: extra });
  it("reads destination hashes", async () => {
    const f = vi.fn(async () => st("SUCCESS", { destinationChainTxHashes: [{ hash: "abc", explorerUrl: "u" }] }));
    const s = await getStatus(f as never, "https://x", {}, DEPOSIT);
    expect(s.destinationTxHashes).toEqual([{ hash: "abc", explorerUrl: "u" }]);
  });
  it("polls until terminal, tolerating a transient error", async () => {
    const seq = [resp("nope", 502), st("PENDING_DEPOSIT"), st("PROCESSING"), st("SUCCESS")];
    const f = vi.fn(async () => seq.shift() as Response);
    const sleep = vi.fn(async () => {});
    const r = await pollStatus({ fetch: f as never, base: "https://x", headers: {}, depositAddress: DEPOSIT, sleep });
    expect(r.final?.status).toBe("SUCCESS");
    expect(f).toHaveBeenCalledTimes(4);
    expect(sleep).toHaveBeenCalledTimes(3);
  });
  it("times out after maxMs and reports the last status", async () => {
    const f = vi.fn(async () => st("PENDING_DEPOSIT"));
    const sleep = vi.fn(async () => {});
    const r = await pollStatus({
      fetch: f as never, base: "https://x", headers: {}, depositAddress: DEPOSIT,
      intervalMs: 15_000, maxMs: 45_000, sleep,
    });
    expect(r.timedOut).toBe(true);
    expect(r.last?.status).toBe("PENDING_DEPOSIT");
    expect(f).toHaveBeenCalledTimes(4);
  });
  it("stops on REFUNDED", async () => {
    const f = vi.fn(async () => st("REFUNDED", { refundReason: "PARTIAL_DEPOSIT" }));
    const r = await pollStatus({ fetch: f as never, base: "https://x", headers: {}, depositAddress: DEPOSIT, sleep: async () => {} });
    expect(r.final).toMatchObject({ status: "REFUNDED", refundReason: "PARTIAL_DEPOSIT" });
  });
});
