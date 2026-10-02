// Solana -> Zcash exit through NEAR Intents 1Click. DRY BY DEFAULT.
//
//   npx tsx examples/zcash-exit-send.ts <zcash-address> <lamports>                # dry: gate + dry quote only
//   npx tsx examples/zcash-exit-send.ts <zcash-address> <lamports> --send         # REAL mainnet transfer
//
// Flags: --allow-transparent  accept a destination with a transparent leg (default: stop)
//        --check-sender       run the inbound check on the signer pubkey first
//        --sender <pubkey>    pubkey for refundTo / --check-sender when no KEYPAIR_PATH (dry runs)
// Env:   SOLANA_RPC_URL, KEYPAIR_PATH (JSON byte array; read ONLY with --send, or to derive the
//        pubkey), optional ONECLICK_JWT, ONECLICK_BASE, SOLSENTRY_API_BASE, SOLSENTRY_API_KEY.
//
// Flow: checkZcashExit -> [checkSender] -> 1Click quote (dry:true without --send, dry:false with
// it) -> refusal rules -> --send: transfer exactly amountIn lamports to the deposit address,
// confirm, tell 1Click the tx hash (optional call) -> poll /v0/status every 15 s, up to 10 min.
// The keypair is never printed. Output: one JSON line per step on stdout.

import { readFileSync } from "node:fs";
import {
  appendTransactionMessageInstruction,
  address,
  assertIsTransactionWithBlockhashLifetime,
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  createTransactionMessage,
  getSignatureFromTransaction,
  lamports,
  pipe,
  sendTransactionWithoutConfirmingFactory,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
} from "@solana/kit";
import { getTransferSolInstruction } from "@solana-program/system";
import { SolSentryGuard } from "../src/client.js";
import { checkSender, DEFAULT_SOLANA_RPC_URL } from "../src/cloak/index.js";
import { checkZcashExit } from "../src/zcash/index.js";
import {
  buildQuoteBody,
  destinationGate,
  ONECLICK_BASE,
  oneClickHeaders,
  parseExitSendArgs,
  pollStatus,
  requestQuote,
  sendRefusals,
  submitDepositTx,
} from "../src/zcash/exit-send.js";

const say = (step: string, data: Record<string, unknown>) =>
  console.log(JSON.stringify({ step, ...data }, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function main() {
  const args = parseExitSendArgs(process.argv.slice(2));
  const base = process.env.ONECLICK_BASE ?? ONECLICK_BASE;
  const headers = oneClickHeaders(process.env.ONECLICK_JWT);
  const rpcUrl = process.env.SOLANA_RPC_URL ?? DEFAULT_SOLANA_RPC_URL;

  // 1. Destination gate (offline).
  const verdict = checkZcashExit(args.address);
  say("destination", { decision: verdict.decision, reasons: verdict.reasons, note: verdict.note });
  const gate = destinationGate(verdict, args.allowTransparent);
  if (!gate.proceed) {
    say("stopped", { reason: gate.reason });
    process.exit(2);
  }

  // Signer: only needed for --send, or to derive a pubkey when KEYPAIR_PATH is set.
  let signer: Awaited<ReturnType<typeof createKeyPairSignerFromBytes>> | undefined;
  if (process.env.KEYPAIR_PATH) {
    signer = await createKeyPairSignerFromBytes(
      Uint8Array.from(JSON.parse(readFileSync(process.env.KEYPAIR_PATH, "utf8")) as number[]),
    );
  }
  if (args.send && !signer) throw new Error("--send needs KEYPAIR_PATH");
  const pubkey = signer ? String(signer.address) : args.sender;
  if (args.send && args.sender && args.sender !== pubkey) {
    throw new Error("--sender does not match the KEYPAIR_PATH pubkey; drop --sender for --send");
  }

  // 2. Optional inbound check on the signer (fail-closed: any error blocks).
  if (args.checkSender) {
    if (!pubkey) throw new Error("--check-sender needs KEYPAIR_PATH or --sender <pubkey>");
    const guard = new SolSentryGuard({
      baseUrl: process.env.SOLSENTRY_API_BASE,
      apiKey: process.env.SOLSENTRY_API_KEY,
    });
    const sv = await checkSender(pubkey, {}, guard, { rpcUrl });
    say("sender", { sender: pubkey, decision: sv.decision, reasons: sv.reasons, explanation: sv.explanation });
    if (sv.decision === "block") {
      say("stopped", { reason: sv.explanation });
      process.exit(2);
    }
  }

  // 3. Quote. Dry (no deposit address) unless --send.
  const refundTo = pubkey ?? "So11111111111111111111111111111111111111112";
  const q = await requestQuote(
    fetch,
    base,
    headers,
    buildQuoteBody({ address: args.address, amount: args.amount, refundTo, dry: !args.send }),
  );
  if (!q.ok) {
    say("quote", {
      ok: false,
      status: q.status,
      message: q.message,
      routeMinimum: q.routeMinimum,
      hint: q.status === 401 ? "needs ONECLICK_JWT" : undefined,
    });
    process.exit(1);
    return;
  }
  const { quote } = q;
  say("quote", { ok: true, dry: !args.send, ...quote, refundTo });

  if (!args.send) {
    say("dry-run", { note: "Nothing signed or sent. Re-run with --send for the real transfer." });
    return;
  }

  // 4. Refusals, then sign + send + confirm.
  const refusals = sendRefusals({ quote, requested: args.amount });
  if (refusals.length) {
    say("refused", { reasons: refusals });
    process.exit(2);
  }
  const rpc = createSolanaRpc(rpcUrl);
  const { value: blockhash } = await rpc.getLatestBlockhash({ commitment: "confirmed" }).send();
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(signer as NonNullable<typeof signer>, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(blockhash, m),
    (m) =>
      appendTransactionMessageInstruction(
        getTransferSolInstruction({
          source: signer as NonNullable<typeof signer>,
          destination: address(quote.depositAddress),
          amount: lamports(BigInt(quote.amountIn)),
        }),
        m,
      ),
  );
  const signed = await signTransactionMessageWithSigners(message);
  assertIsTransactionWithBlockhashLifetime(signed);
  const signature = getSignatureFromTransaction(signed);
  say("signed", { signature, solscan: `https://solscan.io/tx/${signature}` });
  await sendTransactionWithoutConfirmingFactory({ rpc })(signed, { commitment: "confirmed" });

  // Confirm by HTTP polling (no websocket needed); stop at blockhash expiry.
  let confirmed = false;
  for (let i = 0; i < 60 && !confirmed; i++) {
    const { value } = await rpc.getSignatureStatuses([signature]).send();
    const s = value[0];
    if (s?.err) throw new Error(`Transfer failed on-chain: ${JSON.stringify(s.err, (_k, v) => (typeof v === "bigint" ? v.toString() : v))}`);
    if (s && (s.confirmationStatus === "confirmed" || s.confirmationStatus === "finalized")) confirmed = true;
    else await sleep(2000);
  }
  if (!confirmed) {
    say("unconfirmed", { signature, solscan: `https://solscan.io/tx/${signature}`, note: "Not confirmed in 2 min; check the explorer before retrying. Do NOT re-send." });
    process.exit(1);
  }
  say("confirmed", { signature, solscan: `https://solscan.io/tx/${signature}` });

  // Optional "submit deposit tx" call: speeds up detection. Failure is not fatal.
  try {
    const sub = await submitDepositTx(fetch, base, headers, signature, quote.depositAddress);
    say("submit-deposit", sub);
  } catch (e) {
    say("submit-deposit", { ok: false, error: (e as Error).message });
  }

  // 5. Poll status.
  const res = await pollStatus({
    fetch,
    base,
    headers,
    depositAddress: quote.depositAddress,
    sleep,
    onTick: (s) =>
      say("status", "error" in s ? { error: s.error } : { status: s.status, destination: s.destinationTxHashes }),
  });
  say("final", {
    status: res.final?.status ?? res.last?.status ?? "UNKNOWN",
    timedOut: res.timedOut,
    destinationTxHashes: (res.final ?? res.last)?.destinationTxHashes ?? [],
    refundReason: (res.final ?? res.last)?.refundReason,
    depositAddress: quote.depositAddress,
    note: res.timedOut ? "Still not final after 10 min; keep checking /v0/status for the deposit address." : undefined,
  });
}

main().catch((e) => {
  console.log(JSON.stringify({ step: "error", error: e instanceof Error ? e.message : String(e) }));
  process.exit(1);
});
