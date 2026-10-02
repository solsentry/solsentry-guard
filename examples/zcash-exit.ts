// Zcash exit dry run: classify the destination, then (optionally) fetch a 1Click
// QUOTE only. Nothing is signed, deposited or sent; the quote is requested with
// `dry: true`, so no deposit address is created.
//
//   npx tsx examples/zcash-exit.ts <zcash-address> [amount] [--origin sol|zec-spl] [--no-quote]
//
// amount is in base units of the origin asset (default: 0.05 SOL = 50000000, or
// 0.002 ZEC = 200000 for zec-spl). Env: ONECLICK_JWT (optional bearer token),
// ONECLICK_BASE (default https://1click.chaindefuser.com), REFUND_TO (a Solana
// address; only used as a placeholder in a dry quote).
// Output: one JSON document on stdout.

import { checkZcashExit } from "../src/zcash/index.js";

const ASSETS = {
  sol: { id: "nep141:sol.omft.near", defaultAmount: "50000000" },
  "zec-spl": {
    id: "1cs_v1:sol:spl:A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS",
    defaultAmount: "200000",
  },
} as const;
const ZEC_NATIVE = "nep141:zec.omft.near";

async function main() {
  const args = process.argv.slice(2);
  const flag = (n: string) => args.includes(n);
  const originIdx = args.indexOf("--origin");
  const origin = (originIdx >= 0 ? args[originIdx + 1] : "sol") as keyof typeof ASSETS;
  if (!(origin in ASSETS)) throw new Error("--origin must be sol or zec-spl");
  const positional = args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--origin");
  const [address, amountArg] = positional;
  if (!address) throw new Error("Usage: zcash-exit.ts <zcash-address> [amount] [--origin sol|zec-spl] [--no-quote]");

  const verdict = checkZcashExit(address);
  const out: Record<string, unknown> = {
    address,
    verdict: {
      decision: verdict.decision,
      reasons: verdict.reasons,
      note: verdict.note,
      kind: verdict.destination?.kind ?? null,
      network: verdict.destination?.network ?? null,
      traceability: verdict.destination?.traceability ?? null,
      receivers: verdict.destination?.receivers.map((r) => r.name) ?? [],
    },
  };

  if (verdict.decision === "block") {
    out.quote = { skipped: "destination blocked" };
  } else if (flag("--no-quote")) {
    out.quote = { skipped: "--no-quote" };
  } else {
    const base = process.env.ONECLICK_BASE ?? "https://1click.chaindefuser.com";
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
      // The public endpoint sits behind a bot filter that rejects clients with no User-Agent.
      "User-Agent": "solsentry-guard-example/0.0.1",
    };
    if (process.env.ONECLICK_JWT) headers.Authorization = `Bearer ${process.env.ONECLICK_JWT}`;
    const body = {
      dry: true, // quote only: no deposit address, nothing to fund
      swapType: "EXACT_INPUT",
      slippageTolerance: 100, // bps
      originAsset: ASSETS[origin].id,
      depositType: "ORIGIN_CHAIN",
      destinationAsset: ZEC_NATIVE,
      amount: amountArg ?? ASSETS[origin].defaultAmount,
      refundTo: process.env.REFUND_TO ?? "So11111111111111111111111111111111111111112",
      refundType: "ORIGIN_CHAIN",
      recipient: address,
      recipientType: "DESTINATION_CHAIN",
      deadline: new Date(Date.now() + 30 * 60_000).toISOString(),
    };
    try {
      const res = await fetch(`${base}/v0/quote`, { method: "POST", headers, body: JSON.stringify(body) });
      const text = await res.text();
      let json: unknown = text;
      try {
        json = JSON.parse(text);
      } catch {
        /* keep raw text */
      }
      out.quote = res.ok
        ? { ok: true, response: json }
        : { ok: false, status: res.status, response: json, hint: res.status === 401 ? "needs ONECLICK_JWT" : undefined };
    } catch (e) {
      out.quote = { ok: false, error: (e as Error).message };
    }
  }
  console.log(JSON.stringify(out, null, 2));
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
