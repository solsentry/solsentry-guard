# Releasing `@solsentry/guard`

## TL;DR — first/manual publish (the one that works today)

The npm account publishes with a **WebAuthn security key** for 2FA, which has **no typeable 6‑digit OTP**. So token‑based CI publish hits `npm error code EOTP`, and `--otp=<code>` is impossible. The reliable path is a **manual publish via web login** from an interactive terminal:

```bash
cd solsentry-guard
npm ci
npm run build          # produces dist/ (published files = dist + README)
npm login --auth-type=web   # prints a browser link → authenticate with the security key
npm publish --access public # at the OTP step prints an auth/cli link → confirm in browser
# success looks like:  + @solsentry/guard@0.0.1
```

Must be run in a **real interactive terminal** — a non‑interactive shell can't open the browser for the web‑OTP and will fail with `EOTP`.

Bump the version in `package.json` before re-publishing (npm rejects re-publishing an existing version).

## Things that do NOT work (don't waste time)

- **CI publish with an `NPM_TOKEN` secret** → `EOTP`. Granular tokens and classic *Publish* tokens did not bypass 2FA on this account; unchecking "Require 2FA for write actions" did not help; removing `--provenance` did not help.
- **OIDC trusted publishing for the FIRST publish** → not possible: npm requires the package to already exist before a trusted publisher can be configured (unlike PyPI). See <https://docs.npmjs.com/trusted-publishers/>.

## Future: token‑free CI releases via OIDC (now that the package exists)

1. npmjs.com → `@solsentry/guard` → **Settings → Trusted Publisher** → add **GitHub Actions**: org `solsentry`, repo `solsentry-guard`, workflow `publish.yml`.
2. In `.github/workflows/publish.yml`: ensure `permissions: id-token: write`, upgrade npm to **≥ 11.5.1** (`npm i -g npm@latest`), drop `NODE_AUTH_TOKEN`/`NPM_TOKEN`, and (optionally) re‑add `--provenance` (works automatically under OIDC).
3. Push a `v*` tag → publishes with no token and no OTP.
