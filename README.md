# @solsentry/guard

Pre-signing risk checks for Solana transactions. Show users **who they're about
to trust, before they sign** — not just whether a token is rugging.

Thin, dependency-free client over the [SolSentry](https://solsentry.app) API.
Works in browsers, extensions (MV3), and Node 18+.

> RugCheck tells you a fire is burning. SolSentry tells you who lit it.

## Install

```bash
npm install @solsentry/guard
```

## Quick start

```ts
import { SolSentryGuard } from "@solsentry/guard";

const guard = new SolSentryGuard();

// Right before wallet.signTransaction(tx):
const advice = await guard.analyzeBeforeSign(tx);

if (advice.shouldBlock) {
  showWarning(advice.summary); // "DANGEROUS (risk 100/100): Known drainer. Do not sign."
}
```

`tx` can be a `@solana/web3.js` `Transaction`, a `VersionedTransaction`, an
array of base58 program IDs, or `{ programIds: string[] }`. The SDK extracts
every program the transaction touches, scores each one, and returns a single
aggregated verdict (worst-case across all programs). Known infrastructure
programs (System, Token, ATA, …) are skipped to save credits.

### SignAdvice

```ts
interface SignAdvice {
  verdict: "safe" | "caution" | "dangerous" | "unknown";
  risk_score: number;   // 0-100, max across analyzed programs
  shouldBlock: boolean; // verdict === "dangerous" || risk_score >= blockThreshold (default 80)
  reports: ContractAnalysis[];
  programs: string[];   // distinct program IDs analyzed
  summary: string;      // one-line, ready for a signing modal
}
```

## Single-address check

```ts
const report = await guard.analyzeProgram("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
// { known_label: "Jupiter Aggregator v6", verdict: "caution", risk_score: 20,
//   flags: ["UPGRADABLE"], explanation: "...", ... }
```

## Address-poisoning check

Catch lookalike destination addresses before a transfer:

```ts
const result = await guard.checkLookalike(destination, recentContacts);
if (result.is_lookalike) {
  warn(`Destination resembles a prior contact — possible address poisoning.`);
}
```

## Options

```ts
new SolSentryGuard({
  baseUrl: "https://api.solsentry.app", // default
  clientId: "my-wallet",                 // sent as X-Client-ID for usage attribution
  apiKey: "...",                          // sent as Authorization: Bearer (paid tiers / x402)
  timeoutMs: 8000,                        // per-request, default 8s
  fetch: customFetch,                     // inject for tests / non-global-fetch runtimes
});
```

`analyzeBeforeSign(tx, { blockThreshold, skipInfra })`:
- `blockThreshold` — risk score at/above which `shouldBlock` is true (default `80`)
- `skipInfra` — skip well-known infra programs (default `true`)

## Errors

Failed requests throw `GuardError` with `.status` and `.detail` from the API.
Network failures and timeouts also surface as `GuardError`.

## Development

```bash
npm install
npm test        # vitest
npm run build   # tsc -> dist/
```

## License

MIT
