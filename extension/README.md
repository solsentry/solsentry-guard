# SolSentry Guard — Chrome Extension (MV3)

Pre-signing risk checks for Solana transactions, inside your browser.

Hooks into Phantom / Solflare / Backpack right before `signTransaction` and
shows a modal if the transaction touches a known drainer, lookalike address,
or otherwise dangerous program.

Powered by [`@solsentry/guard`](https://www.npmjs.com/package/@solsentry/guard).

## Status

**Scaffold only.** Created 2026-05-31. Not yet shipped to Chrome Web Store.

Build steps below assume Vite + `@crxjs/vite-plugin` once wired (see TODO).

## Layout

```
extension/
├── manifest.json              MV3 manifest
├── src/
│   ├── background/index.ts    Service worker — instantiates SolSentryGuard, caches verdicts
│   ├── content/index.ts       Content script — bridges page <-> background
│   ├── injected/index.ts      Injected into page — monkey-patches window.solana.signTransaction
│   ├── popup/index.html       Popup UI (toggle, recent verdicts)
│   ├── popup/popup.ts
│   └── shared/messages.ts     Typed messages between contexts
├── public/icons/              16/32/48/128 PNG icons (TODO)
└── scripts/build.mjs          Build entry (TODO: pick vite/esbuild/tsup)
```

## Architecture

```
 ┌────────────────┐   postMessage   ┌────────────────┐   chrome.runtime   ┌──────────────────┐
 │  injected.js   │ ───────────────▶│  content.js    │ ──────────────────▶│  background SW   │
 │  (page world)  │                 │ (isolated)     │                    │  SolSentryGuard  │
 │  hooks         │                 │  bridge        │                    │  cache + API     │
 │  window.solana │◀─── verdict ────│                │◀──── advice ───────│                  │
 └────────────────┘                 └────────────────┘                    └──────────────────┘
         ▲                                                                          │
         │ if shouldBlock: render modal, await user choice                          │
         │                                                                          │
         └──────────────────────── analyzeBeforeSign(tx) ───────────────────────────┘
```

## Hook strategy

`injected.ts` runs in the page world (not isolated content script) so it can
mutate `window.solana`. On every signTransaction call:

1. Serialize tx → send to content script via `window.postMessage`
2. Content script forwards to background via `chrome.runtime.sendMessage`
3. Background calls `guard.analyzeBeforeSign(tx)`
4. If `shouldBlock`, injected.ts renders a modal (Shadow DOM, no site CSS bleed)
   and only resolves the original signTransaction promise if user confirms

## TODO before first publish

- [ ] Wire build (Vite + `@crxjs/vite-plugin` recommended)
- [ ] Icons 16/32/48/128 (use SolSentry logo)
- [ ] Privacy policy URL (must be public)
- [ ] Screenshots for store listing (5)
- [ ] Test against Phantom, Solflare, Backpack — confirm injection timing
- [ ] Rate-limit / cache strategy (avoid hammering api.solsentry.app per page)
- [ ] Decide monetization v1: free w/ rate limit (recommended) vs API key vs x402
- [ ] Telemetry opt-in (anonymous verdict counts, no addresses)
- [ ] CSP review — extension can't load remote scripts under MV3

## Permissions justification (for Chrome Web Store review)

- `storage`: cache verdicts locally to reduce API load
- `activeTab`: read page context only when user clicks popup
- `host_permissions` `https://api.solsentry.app/*`: API calls to the risk service

We do NOT request `<all_urls>` host_permissions. Content scripts use
`<all_urls>` match because Solana dApps live across the web, but no remote
code is executed.

## Monetization decision (pending)

| Option | Friction | Tracking | Revenue | Recommended for |
|---|---|---|---|---|
| Free + rate-limit per IP | none | weak | $0 | v1 launch |
| API key per user | high | strong | optional | v2 |
| x402 per call | high | per-tx | yes | "Pro" tier later |
