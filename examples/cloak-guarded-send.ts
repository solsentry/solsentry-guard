// Guarded private send: SolSentry pre-check on the recipient, then Cloak.
//
//   npx tsx examples/cloak-guarded-send.ts <recipient> <lamports>          # dry run (default)
//   npx tsx examples/cloak-guarded-send.ts <recipient> <lamports> --send   # REAL mainnet send
//
// Env: SOLANA_RPC_URL, KEYPAIR_PATH (file path; only read with --send),
//      optional SOLSENTRY_API_BASE, SOLSENTRY_API_KEY, NOTES_DIR (default ./cloak-notes).
// Output: one JSON document on stdout.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { guardedPrivateSend, type PersistedNote } from "../src/cloak/index.js";

async function main() {
  const args = process.argv.slice(2);
  const real = args.includes("--send");
  const [recipient, lamportsArg] = args.filter((a) => !a.startsWith("--"));
  if (!recipient || !lamportsArg) {
    throw new Error(
      "Usage: cloak-guarded-send.ts <recipient> <lamports> [--send]  (default: dry run)",
    );
  }
  const amount = BigInt(lamportsArg);
  const solsentry = {
    apiBase: process.env.SOLSENTRY_API_BASE,
    apiKey: process.env.SOLSENTRY_API_KEY,
  };

  if (!real) {
    const res = await guardedPrivateSend({
      recipient,
      amount,
      mint: "SOL",
      dryRun: true,
      solsentry,
    });
    console.log(JSON.stringify(res, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
    return;
  }

  const rpcUrl = process.env.SOLANA_RPC_URL;
  const keypairPath = process.env.KEYPAIR_PATH;
  if (!rpcUrl || !keypairPath) throw new Error("Set SOLANA_RPC_URL and KEYPAIR_PATH");
  const { signerFromSecretKey } = await import("@cloak.dev/sdk");
  const signer = await signerFromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(keypairPath, "utf8")) as number[]),
  );

  const dir = process.env.NOTES_DIR ?? "./cloak-notes";
  mkdirSync(dir, { recursive: true });
  const persistUtxos = (notes: PersistedNote[]) => {
    notes.forEach((n, i) =>
      writeFileSync(join(dir, `${n.stage}-${n.signature}-${i}.note.hex`), n.utxoHex, {
        mode: 0o600,
      }),
    );
  };

  const res = await guardedPrivateSend({
    recipient,
    amount,
    mint: "SOL",
    signer: signer as never,
    rpcUrl,
    solsentry,
    persistUtxos,
  });
  console.log(JSON.stringify(res, null, 2));
}

main().catch((e) => {
  const extra =
    e && typeof e === "object" && "notes" in e
      ? { depositSig: (e as { depositSig?: string }).depositSig, notes: (e as { notes: unknown }).notes }
      : {};
  console.log(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e), ...extra }));
  process.exit(1);
});
