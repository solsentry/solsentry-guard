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
