# @solsentry/guard

> RugCheck tells you a fire is burning. SolSentry tells you who lit it.

Pre-signing risk checks for Solana transactions. `@solsentry/guard` lets wallets
and apps ask who they are about to trust before the signature is sent.

Thin, dependency-free client over the public SolSentry API. Works in browsers,
extensions, and Node 18+.

## Live references

- API stats: `https://api.solsentry.app/v1/stats`
- Package: `https://www.npmjs.com/package/@solsentry/guard`
- GitHub org: `https://github.com/solsentry`

## Install

```bash
npm install @solsentry/guard
```

## Quick start

```ts
import { SolSentryGuard } from "@solsentry/guard";

const guard = new SolSentryGuard();
const advice = await guard.analyzeBeforeSign(tx);

if (advice.shouldBlock) {
  showWarning(advice.summary);
}
```

## What it does

- scores the programs touched by a transaction
- returns a single aggregated verdict before signing
- supports single-program checks and lookalike detection
- uses `https://api.solsentry.app` as the backing intelligence layer

## Options

```ts
new SolSentryGuard({
  baseUrl: "https://api.solsentry.app",
  clientId: "my-wallet",
  apiKey: "...",
  timeoutMs: 8000,
});
```

## Private send with a pre-check (Cloak)

Optional entrypoint `@solsentry/guard/cloak`. [Cloak](https://docs.cloak.ag) hides who paid
whom on Solana mainnet; this adds the missing step of checking who is *receiving* before any
funds enter the shielded pool. The core package stays dependency-free: `@cloak.dev/sdk` is an
optional peer dependency (install it only if you use this entrypoint).

```ts
import { guardedPrivateSend } from "@solsentry/guard/cloak";

const res = await guardedPrivateSend({
  recipient,
  amount: 50_000_000n, // lamports (SOL) or base units (USDC)
  mint: "SOL",
  signer,              // Cloak signer, e.g. signerFromSecretKey(...)
  rpcUrl,
  persistUtxos: (notes) => saveSomewhereSafe(notes), // required for a real send
  policy: { contacts: knownContacts }, // optional: address-poisoning check
});
// res.status: "blocked" | "sent" ; res.verdict.reasons explains why
```

- The recipient is checked first. Known drainers, high-risk addresses and (with `contacts`)
  lookalikes are blocked and Cloak is never called. Other findings return a warning; set
  `policy.strict` to block those too. If the check cannot run, the send is blocked by default.
- If allowed: one deposit, then one full withdrawal to the recipient (no change note).
  The deposit note is passed to `persistUtxos` before the withdrawal starts. If Cloak fails
  after the deposit, a `CloakSendError` carries the saved notes for recovery.
- `dryRun: true` runs only the risk check; nothing is built or sent.
- CLI example (dry run by default, real mainnet send only with `--send`):
  `npx tsx examples/cloak-guarded-send.ts <recipient> <lamports> [--send]`
  (`SOLANA_RPC_URL`, `KEYPAIR_PATH` are read only for `--send`).

## Inbound check (source of funds)

The Cloak module can also screen the *sender* before any funds enter the shielded pool.
`checkSender(sender, policy, guard)` returns the same `{ decision, reasons, explanation }`
shape as the recipient check:

1. the sender address itself (contract analysis: known drainers, high risk score);
2. the sender as an operator (`/v1/operator/{wallet}`): CRITICAL/HIGH risk or 2+ confirmed
   rugs blocks, MEDIUM or 1 confirmed rug warns;
3. the source of funds, one hop only: the sender's first funding transfer is found over
   Solana JSON-RPC (oldest signature, bounded to 5 pages of history; `rpcUrl` option or
   `SOLANA_RPC_URL`, default public mainnet-beta; `rpcUrl` is required for a real send).
   The funder is then screened with steps 1 and 2. A flagged funder blocks with
   `FUNDED_BY_FLAGGED` (depth 1); a funder with warnings warns. This is the wallet's first
   funding transfer, not a full multi-hop trace. If the wallet has more than 5 pages of
   history, is fresh, or has no plain funding transfer, funding is "unknown": no signal,
   not an error.

If any lookup (SolSentry API or RPC) fails or times out, the check follows `policy.onCheckError` (default `"block"`,
fail closed).

```ts
const res = await guardedPrivateSend({
  recipient, amount, mint: "SOL", signer, rpcUrl, persistUtxos,
  checkSender: true, // opt-in, default false; runs before any Cloak import or deposit
});
// res.status === "blocked" && res.side === "sender" -> nothing moved
```

Dry run from the CLI (no signer needed):
`npx tsx examples/cloak-guarded-send.ts <recipient> <lamports> --check-sender <address>`.

## Zcash exit

Optional entrypoint `@solsentry/guard/zcash`. Offline, zero dependencies, no network calls. For a
Solana-to-Zcash exit (for example private swap to the ZEC SPL token, then a cross-chain route to
native ZEC), it checks the destination address before anything is sent.

```ts
import { checkZcashExit, classifyZcashAddress } from "@solsentry/guard/zcash";

const v = checkZcashExit(address);
// v.decision: "block" | "warn" | "allow"; v.reasons; v.note; v.destination
```

| Destination | Decision | Meaning |
|---|---|---|
| Not a valid address (bad checksum, truncated, wrong type) | `block` | Funds sent to a mistyped address cannot be recovered. |
| Shielded only (`zs1`, or `u1` with Sapling/Orchard receivers only) | `allow` | No public trail after exit: value, sender and recipient are not published on Zcash. |
| Transparent leg (`t1`/`t3`, or `u1` with a transparent receiver) | `warn` | Destination is publicly traceable on Zcash. |

- Unified addresses are decoded per ZIP-316 (bech32m, F4Jumble, receiver typecodes).
- Scope: this classifies the address type only. It says nothing about who controls the address,
  and it does not cover the Solana side or the cross-chain route.
- `classifyZcashAddress(address)` returns `{ kind, network, receivers, hasTransparentLeg, traceability }`
  and throws `ZcashAddressError` on invalid input.
- Dry run (classifies, then requests a quote only; never signs or sends):
  `npx tsx examples/zcash-exit.ts <zcash-address> [amount] [--origin sol|zec-spl] [--no-quote]`

## Development

```bash
npm install
npm test
npm run build
```

## Notes

- Precision is auditable per-mint at `/v1/predictions/{mint}` (live).

## License

MIT
