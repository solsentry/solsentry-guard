import { describe, expect, it, vi } from "vitest";
import { SolSentryGuard } from "../src/client.js";
import { checkSender, guardedPrivateSend, type CloakSdk } from "../src/cloak/index.js";

const SENDER = "Sender11111111111111111111111111111111111111";
const FUNDER = "Funder11111111111111111111111111111111111111";
const RECIP = "Recip1ent1111111111111111111111111111111111";

type Json = Record<string, unknown>;
const safe: Json = {
  address: "x", kind: "wallet", known_label: null, known_category: null,
  risk_score: 0, verdict: "safe", flags: [], authorities: {}, extensions: {},
  explanation: "ok", fetched_at: 0,
};
const noOp: Json = { known: false, risk_level: "UNKNOWN", confirmed_rugs: 0 };
const noFunder: Json = { found_payer: "", found_at_depth: -1, status: "inconclusive", path: [] };

interface Spec {
  analysis?: Record<string, Json>;
  operator?: Record<string, Json>;
  follow?: Json;
  fail?: RegExp;
}

function mkGuard(spec: Spec = {}) {
  const fetchMock = vi.fn(async (url: string | URL | Request) => {
    const u = String(url);
    if (spec.fail?.test(u)) throw new Error("boom");
    const w = decodeURIComponent(u.split("/").pop() as string);
    let body: Json;
    if (u.includes("/v1/contract-analysis/")) body = { ...safe, ...(spec.analysis?.[w] ?? {}) };
    else if (u.includes("/v1/operator/")) body = { wallet: w, ...noOp, ...(spec.operator?.[w] ?? {}) };
    else if (u.includes("/v1/reverse-follow/")) body = spec.follow ?? noFunder;
    else throw new Error("unexpected " + u);
    return new Response(JSON.stringify(body), { status: 200 });
  });
  const guard = new SolSentryGuard({ baseUrl: "http://api.test", fetch: fetchMock as never });
  return { guard, fetchMock };
}

const funded = (depth = 1): Json => ({
  found_payer: FUNDER, found_at_depth: depth, status: "found", path: [],
});

describe("checkSender", () => {
  it("allows a clean sender with no funder found (inconclusive)", async () => {
    const { guard } = mkGuard();
    const v = await checkSender(SENDER, {}, guard);
    expect(v.decision).toBe("allow");
    expect(v.reasons).toEqual([]);
  });

  it("blocks on a KNOWN_DRAINER sender", async () => {
    const { guard } = mkGuard({ analysis: { [SENDER]: { known_category: "drainer", flags: ["KNOWN_DRAINER"] } } });
    const v = await checkSender(SENDER, {}, guard);
    expect(v.decision).toBe("block");
    expect(v.reasons).toContain("KNOWN_DRAINER");
  });

  it("blocks on risk_score >= threshold", async () => {
    const { guard } = mkGuard({ analysis: { [SENDER]: { risk_score: 90 } } });
    expect((await checkSender(SENDER, {}, guard)).decision).toBe("block");
    expect((await checkSender(SENDER, { blockThreshold: 95 }, guard)).decision).toBe("allow");
  });

  it.each([
    [{ risk_level: "CRITICAL" }],
    [{ risk_level: "HIGH" }],
    [{ confirmed_rugs: 2 }],
  ])("blocks on operator signal %j", async (op) => {
    const { guard } = mkGuard({ operator: { [SENDER]: op } });
    const v = await checkSender(SENDER, {}, guard);
    expect(v.decision).toBe("block");
    expect(v.reasons).toContain("OPERATOR_HIGH_RISK");
  });

  it.each([[{ risk_level: "MEDIUM" }], [{ confirmed_rugs: 1 }]])(
    "warns on operator signal %j (blocks when strict)",
    async (op) => {
      const { guard } = mkGuard({ operator: { [SENDER]: op } });
      expect((await checkSender(SENDER, {}, guard)).decision).toBe("warn");
      expect((await checkSender(SENDER, { strict: true }, guard)).decision).toBe("block");
    },
  );

  it("treats LOW as no signal", async () => {
    const { guard } = mkGuard({ operator: { [SENDER]: { risk_level: "LOW" } } });
    expect((await checkSender(SENDER, {}, guard)).decision).toBe("allow");
  });

  it("blocks FUNDED_BY_FLAGGED and reports depth", async () => {
    const { guard } = mkGuard({
      follow: funded(2),
      operator: { [FUNDER]: { risk_level: "HIGH", confirmed_rugs: 3 } },
    });
    const v = await checkSender(SENDER, {}, guard);
    expect(v.decision).toBe("block");
    expect(v.reasons).toContain("FUNDED_BY_FLAGGED");
    expect(v.explanation).toContain("depth 2");
    expect(v.funder?.address).toBe(FUNDER);
  });

  it("blocks when the funder is a known drainer", async () => {
    const { guard } = mkGuard({
      follow: funded(1),
      analysis: { [FUNDER]: { flags: ["KNOWN_DRAINER"] } },
    });
    expect((await checkSender(SENDER, {}, guard)).reasons).toContain("FUNDED_BY_FLAGGED");
  });

  it("warns when the funder only has warning signals", async () => {
    const { guard } = mkGuard({ follow: funded(1), operator: { [FUNDER]: { risk_level: "MEDIUM" } } });
    const v = await checkSender(SENDER, {}, guard);
    expect(v.decision).toBe("warn");
    expect(v.reasons).toContain("FUNDED_BY_CAUTION");
  });

  it.each([/contract-analysis/, /operator/, /reverse-follow/])(
    "API error on %s fails closed by default, warns with onCheckError=warn",
    async (re) => {
      const { guard } = mkGuard({ fail: re });
      const closed = await checkSender(SENDER, {}, guard);
      expect(closed.decision).toBe("block");
      expect(closed.reasons).toEqual(["CHECK_FAILED"]);
      expect((await checkSender(SENDER, { onCheckError: "warn" }, guard)).decision).toBe("warn");
    },
  );

  it("fails closed when the funder lookup errors", async () => {
    const { guard } = mkGuard({ follow: funded(1), fail: new RegExp(FUNDER) });
    expect((await checkSender(SENDER, {}, guard)).decision).toBe("block");
  });
});

describe("guardedPrivateSend checkSender", () => {
  const cloakSpy = () => ({
    CLOAK_PROGRAM_ID: "P", NATIVE_SOL_MINT: "S",
    createCloakRpc: vi.fn(), generateUtxoKeypair: vi.fn(), createUtxo: vi.fn(),
    createZeroUtxo: vi.fn(), transact: vi.fn(), fullWithdraw: vi.fn(), serializeUtxo: vi.fn(),
  });

  it("blocked sender: side=sender, Cloak never touched, recipient not checked", async () => {
    const { guard, fetchMock } = mkGuard({ operator: { [SENDER]: { risk_level: "CRITICAL" } } });
    const cloak = cloakSpy();
    const res = await guardedPrivateSend({
      recipient: RECIP, amount: 1000n, mint: "SOL", signer: { address: SENDER },
      rpcUrl: "http://rpc", persistUtxos: vi.fn(), cloak: cloak as unknown as CloakSdk,
      guard, checkSender: true,
    });
    expect(res.status).toBe("blocked");
    expect(res.side).toBe("sender");
    expect(res.allowed).toBe(false);
    for (const fn of Object.values(cloak)) if (typeof fn === "function") expect(fn).not.toHaveBeenCalled();
    expect(fetchMock.mock.calls.some((c) => String(c[0]).includes(RECIP))).toBe(false);
  });

  it("does not import @cloak.dev/sdk when the sender is blocked (no cloak injected)", async () => {
    const { guard } = mkGuard({ analysis: { [SENDER]: { flags: ["KNOWN_DRAINER"] } } });
    const res = await guardedPrivateSend({
      recipient: RECIP, amount: 1000n, mint: "SOL", signer: { address: SENDER },
      rpcUrl: "http://rpc", persistUtxos: vi.fn(), guard, checkSender: true,
    });
    expect(res.status).toBe("blocked");
    expect(res.side).toBe("sender");
  });

  it("fail-closed API error blocks on the sender side", async () => {
    const { guard } = mkGuard({ fail: /operator/ });
    const res = await guardedPrivateSend({
      recipient: RECIP, amount: 1000n, mint: "SOL", sender: SENDER, dryRun: true, guard, checkSender: true,
    });
    expect(res.status).toBe("blocked");
    expect(res.side).toBe("sender");
  });

  it("allowed sender proceeds to the recipient check (dry run)", async () => {
    const { guard } = mkGuard();
    const res = await guardedPrivateSend({
      recipient: RECIP, amount: 1000n, mint: "SOL", sender: SENDER, dryRun: true, guard, checkSender: true,
    });
    expect(res.status).toBe("dry-run");
    expect(res.senderVerdict?.decision).toBe("allow");
  });

  it("default (checkSender off) never calls operator or reverse-follow", async () => {
    const { guard, fetchMock } = mkGuard();
    await guardedPrivateSend({ recipient: RECIP, amount: 1000n, mint: "SOL", dryRun: true, guard });
    expect(fetchMock.mock.calls.every((c) => String(c[0]).includes("contract-analysis"))).toBe(true);
  });
});
