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

interface Spec {
  analysis?: Record<string, Json>;
  operator?: Record<string, Json>;
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
    else throw new Error("unexpected " + u);
    return new Response(JSON.stringify(body), { status: 200 });
  });
  const guard = new SolSentryGuard({ baseUrl: "http://api.test", fetch: fetchMock as never });
  return { guard, fetchMock };
}

interface RpcSpec {
  pages?: number;      // number of full 1000-sig pages before the final page
  lastPage?: number;   // size of the final page (default 3)
  txIx?: Json[];       // instructions of the oldest tx
  oldestErr?: boolean;
  fail?: boolean;
}
function mkRpc(spec: RpcSpec = {}) {
  const calls: string[] = [];
  let page = 0;
  const f = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    const req = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
    calls.push(req.method);
    if (spec.fail) throw new Error("rpc down");
    let result: unknown;
    if (req.method === "getSignaturesForAddress") {
      const full = spec.pages ?? 0;
      const size = page < full ? 1000 : (spec.lastPage ?? 3);
      const arr = Array.from({ length: size }, (_, i) => ({
        signature: `sig${page}_${i}`,
        err: spec.oldestErr && page >= full && i === size - 1 ? { InstructionError: 1 } : null,
      }));
      page++;
      result = arr;
    } else if (req.method === "getTransaction") {
      result = { transaction: { message: { instructions: spec.txIx ?? [] } }, meta: null };
    }
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), { status: 200 });
  });
  return { f: f as unknown as typeof fetch, calls };
}
const transferIx = (src: string, dst: string): Json => ({
  program: "system", parsed: { type: "transfer", info: { source: src, destination: dst, lamports: 5 } },
});
const fundedRpc = (extra: RpcSpec = {}) => mkRpc({ txIx: [transferIx(FUNDER, SENDER)], ...extra });

describe("checkSender", () => {
  it("allows a clean sender with a clean funder", async () => {
    const { guard } = mkGuard();
    const v = await checkSender(SENDER, {}, guard, { fetch: fundedRpc().f });
    expect(v.decision).toBe("allow");
    expect(v.reasons).toEqual([]);
    expect(v.funding).toMatchObject({ status: "found", funder: FUNDER, depth: 1 });
  });

  it("blocks on a KNOWN_DRAINER sender", async () => {
    const { guard } = mkGuard({ analysis: { [SENDER]: { known_category: "drainer", flags: ["KNOWN_DRAINER"] } } });
    const v = await checkSender(SENDER, {}, guard, { fetch: mkRpc().f });
    expect(v.decision).toBe("block");
    expect(v.reasons).toContain("KNOWN_DRAINER");
  });

  it("blocks on risk_score >= threshold", async () => {
    const { guard } = mkGuard({ analysis: { [SENDER]: { risk_score: 90 } } });
    expect((await checkSender(SENDER, {}, guard, { fetch: mkRpc().f })).decision).toBe("block");
    expect((await checkSender(SENDER, { blockThreshold: 95 }, guard, { fetch: mkRpc().f })).decision).toBe("allow");
  });

  it.each([
    [{ risk_level: "CRITICAL" }],
    [{ risk_level: "HIGH" }],
    [{ confirmed_rugs: 2 }],
  ])("blocks on operator signal %j", async (op) => {
    const { guard } = mkGuard({ operator: { [SENDER]: op } });
    const v = await checkSender(SENDER, {}, guard, { fetch: mkRpc().f });
    expect(v.decision).toBe("block");
    expect(v.reasons).toContain("OPERATOR_HIGH_RISK");
  });

  it.each([[{ risk_level: "MEDIUM" }], [{ confirmed_rugs: 1 }]])(
    "warns on operator signal %j (blocks when strict)",
    async (op) => {
      const { guard } = mkGuard({ operator: { [SENDER]: op } });
      expect((await checkSender(SENDER, {}, guard, { fetch: mkRpc().f })).decision).toBe("warn");
      expect((await checkSender(SENDER, { strict: true }, guard, { fetch: mkRpc().f })).decision).toBe("block");
    },
  );

  it("treats LOW as no signal", async () => {
    const { guard } = mkGuard({ operator: { [SENDER]: { risk_level: "LOW" } } });
    expect((await checkSender(SENDER, {}, guard, { fetch: mkRpc().f })).decision).toBe("allow");
  });

  it("blocks FUNDED_BY_FLAGGED and reports depth 1", async () => {
    const { guard } = mkGuard({ operator: { [FUNDER]: { risk_level: "HIGH", confirmed_rugs: 3 } } });
    const v = await checkSender(SENDER, {}, guard, { fetch: fundedRpc().f });
    expect(v.decision).toBe("block");
    expect(v.reasons).toContain("FUNDED_BY_FLAGGED");
    expect(v.explanation).toContain("depth 1");
    expect(v.funder?.address).toBe(FUNDER);
  });

  it("blocks when the funder is a known drainer", async () => {
    const { guard } = mkGuard({ analysis: { [FUNDER]: { flags: ["KNOWN_DRAINER"] } } });
    const v = await checkSender(SENDER, {}, guard, { fetch: fundedRpc().f });
    expect(v.reasons).toContain("FUNDED_BY_FLAGGED");
  });

  it("recognises a createAccount funding instruction", async () => {
    const { guard } = mkGuard({ operator: { [FUNDER]: { risk_level: "CRITICAL" } } });
    const rpc = mkRpc({
      txIx: [{ program: "system", parsed: { type: "createAccount", info: { source: FUNDER, newAccount: SENDER } } }],
    });
    expect((await checkSender(SENDER, {}, guard, { fetch: rpc.f })).reasons).toContain("FUNDED_BY_FLAGGED");
  });

  it("warns when the funder only has warning signals", async () => {
    const { guard } = mkGuard({ operator: { [FUNDER]: { risk_level: "MEDIUM" } } });
    const v = await checkSender(SENDER, {}, guard, { fetch: fundedRpc().f });
    expect(v.decision).toBe("warn");
    expect(v.reasons).toContain("FUNDED_BY_CAUTION");
  });

  it("paginates backwards and takes the oldest signature", async () => {
    const { guard } = mkGuard();
    const rpc = fundedRpc({ pages: 2, lastPage: 5 });
    const v = await checkSender(SENDER, {}, guard, { fetch: rpc.f });
    expect(rpc.calls.filter((c) => c === "getSignaturesForAddress")).toHaveLength(3);
    expect(v.funding).toMatchObject({ status: "found", signature: "sig2_4" });
  });

  it(">5 pages of history -> funding unknown, no signal, allow", async () => {
    const { guard } = mkGuard();
    const rpc = fundedRpc({ pages: 10 });
    const v = await checkSender(SENDER, {}, guard, { fetch: rpc.f });
    expect(rpc.calls.filter((c) => c === "getSignaturesForAddress")).toHaveLength(5);
    expect(rpc.calls).not.toContain("getTransaction");
    expect(v.decision).toBe("allow");
    expect(v.funding).toEqual({ status: "unknown", reason: "HISTORY_TOO_LONG" });
  });

  it("no funding transfer in the first tx -> unknown, allow", async () => {
    const { guard } = mkGuard();
    const v = await checkSender(SENDER, {}, guard, { fetch: mkRpc({ txIx: [transferIx(SENDER, FUNDER)] }).f });
    expect(v.decision).toBe("allow");
    expect(v.funding).toEqual({ status: "unknown", reason: "NO_FUNDING_TRANSFER" });
  });

  it("empty history (fresh wallet) -> unknown, allow", async () => {
    const { guard } = mkGuard();
    const v = await checkSender(SENDER, {}, guard, { fetch: mkRpc({ lastPage: 0 }).f });
    expect(v.decision).toBe("allow");
    expect(v.funding).toEqual({ status: "unknown", reason: "NO_HISTORY" });
  });

  it("RPC error: fails closed by default, warns with onCheckError=warn", async () => {
    const { guard } = mkGuard();
    const rpc = mkRpc({ fail: true });
    const closed = await checkSender(SENDER, {}, guard, { fetch: rpc.f });
    expect(closed.decision).toBe("block");
    expect(closed.reasons).toEqual(["CHECK_FAILED"]);
    expect((await checkSender(SENDER, { onCheckError: "warn" }, guard, { fetch: rpc.f })).decision).toBe("warn");
  });

  it.each([/contract-analysis/, /operator/])(
    "API error on %s fails closed by default, warns with onCheckError=warn",
    async (re) => {
      const { guard } = mkGuard({ fail: re });
      const closed = await checkSender(SENDER, {}, guard, { fetch: mkRpc().f });
      expect(closed.decision).toBe("block");
      expect(closed.reasons).toEqual(["CHECK_FAILED"]);
      expect((await checkSender(SENDER, { onCheckError: "warn" }, guard, { fetch: mkRpc().f })).decision).toBe("warn");
    },
  );

  it("fails closed when the funder's own lookup errors", async () => {
    const { guard } = mkGuard({ fail: new RegExp(FUNDER) });
    expect((await checkSender(SENDER, {}, guard, { fetch: fundedRpc().f })).decision).toBe("block");
  });

  it("does not hit the RPC when the sender is already blocked", async () => {
    const { guard } = mkGuard({ operator: { [SENDER]: { risk_level: "CRITICAL" } } });
    const rpc = mkRpc();
    await checkSender(SENDER, {}, guard, { fetch: rpc.f });
    expect(rpc.calls).toEqual([]);
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
    vi.stubGlobal("fetch", mkRpc().f);
    const res = await guardedPrivateSend({
      recipient: RECIP, amount: 1000n, mint: "SOL", sender: SENDER, dryRun: true, guard, checkSender: true,
    });
    expect(res.status).toBe("dry-run");
    expect(res.senderVerdict?.decision).toBe("allow");
    vi.unstubAllGlobals();
  });

  it("real send with checkSender requires rpcUrl", async () => {
    const { guard } = mkGuard();
    await expect(
      guardedPrivateSend({
        recipient: RECIP, amount: 1000n, mint: "SOL", signer: { address: SENDER },
        persistUtxos: vi.fn(), guard, checkSender: true,
      }),
    ).rejects.toThrow(/rpcUrl/);
  });

  it("default (checkSender off) never calls operator or RPC", async () => {
    const { guard, fetchMock } = mkGuard();
    await guardedPrivateSend({ recipient: RECIP, amount: 1000n, mint: "SOL", dryRun: true, guard });
    expect(fetchMock.mock.calls.every((c) => String(c[0]).includes("contract-analysis"))).toBe(true);
  });
});
