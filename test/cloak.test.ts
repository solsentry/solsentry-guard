import { describe, expect, it, vi } from "vitest";
import {
  CLOAK_PRODUCTION_RELAY_URL,
  CloakSendError,
  guardedPrivateSend,
  type CloakSdk,
} from "../src/cloak/index.js";
import type { ContractAnalysis } from "../src/types.js";

const RECIPIENT = "Recip1ent1111111111111111111111111111111111";

function analysis(over: Partial<ContractAnalysis> = {}): ContractAnalysis {
  return {
    address: RECIPIENT,
    kind: "wallet",
    known_label: null,
    known_category: null,
    risk_score: 0,
    verdict: "safe",
    flags: [],
    authorities: {},
    extensions: {},
    explanation: "ok",
    fetched_at: 0,
    ...over,
  };
}

function mkGuard(a: ContractAnalysis) {
  return {
    analyzeProgram: vi.fn(async () => a),
    checkLookalike: vi.fn(async () => ({
      destination: RECIPIENT,
      is_lookalike: false,
      findings: [],
    })),
  };
}

function mkCloak() {
  const calls: string[] = [];
  const dep = { amount: 1000n, tag: "dep" };
  const cloak = {
    CLOAK_PROGRAM_ID: "PROG",
    NATIVE_SOL_MINT: "SOLMINT",
    createCloakRpc: vi.fn(() => "RPC"),
    generateUtxoKeypair: vi.fn(async () => "OWNER"),
    createUtxo: vi.fn(async (amount: bigint) => ({ amount })),
    createZeroUtxo: vi.fn(async () => ({ amount: 0n })),
    transact: vi.fn(async () => {
      calls.push("transact");
      return { signature: "DEPSIG", outputUtxos: [dep], merkleTree: "TREE" };
    }),
    fullWithdraw: vi.fn(async () => {
      calls.push("fullWithdraw");
      return { signature: "WDSIG", outputUtxos: [{ amount: 0n }] };
    }),
    serializeUtxo: vi.fn(() => new Uint8Array([1, 2, 255])),
  };
  return { cloak: cloak as unknown as CloakSdk & typeof cloak, calls, dep };
}

const signer = { address: "SENDER" };

describe("guardedPrivateSend", () => {
  it("blocked recipient never calls Cloak", async () => {
    const { cloak } = mkCloak();
    const persist = vi.fn();
    const res = await guardedPrivateSend({
      recipient: RECIPIENT,
      amount: 1000n,
      mint: "SOL",
      signer,
      rpcUrl: "http://rpc",
      cloak,
      persistUtxos: persist,
      guard: mkGuard(
        analysis({
          known_category: "drainer",
          flags: ["KNOWN_DRAINER"],
          verdict: "dangerous",
          risk_score: 99,
        }),
      ),
    });
    expect(res.status).toBe("blocked");
    expect(res.allowed).toBe(false);
    expect(res.verdict.reasons).toContain("KNOWN_DRAINER");
    expect(cloak.transact).not.toHaveBeenCalled();
    expect(cloak.fullWithdraw).not.toHaveBeenCalled();
    expect(cloak.createCloakRpc).not.toHaveBeenCalled();
    expect(persist).not.toHaveBeenCalled();
  });

  it("blocks a lookalike when contacts are given", async () => {
    const { cloak } = mkCloak();
    const guard = mkGuard(analysis());
    guard.checkLookalike.mockResolvedValue({
      destination: RECIPIENT,
      is_lookalike: true,
      findings: [{ contact: "X", similarity: 0.9, reason: "prefix/suffix" }],
    });
    const res = await guardedPrivateSend({
      recipient: RECIPIENT,
      amount: 1000n,
      mint: "SOL",
      signer,
      rpcUrl: "http://rpc",
      cloak,
      persistUtxos: vi.fn(),
      guard,
      policy: { contacts: ["X"] },
    });
    expect(res.status).toBe("blocked");
    expect(res.verdict.reasons).toContain("LOOKALIKE");
    expect(cloak.transact).not.toHaveBeenCalled();
  });

  it("fails closed when the risk check errors", async () => {
    const { cloak } = mkCloak();
    const guard = mkGuard(analysis());
    guard.analyzeProgram.mockRejectedValue(new Error("down"));
    const res = await guardedPrivateSend({
      recipient: RECIPIENT,
      amount: 1000n,
      mint: "SOL",
      cloak,
      guard,
    });
    expect(res.status).toBe("blocked");
    expect(res.verdict.reasons).toContain("CHECK_FAILED");
    expect(cloak.transact).not.toHaveBeenCalled();
  });

  it("allowed recipient: deposit then withdraw, right amounts and relayUrl", async () => {
    const { cloak, calls, dep } = mkCloak();
    const res = await guardedPrivateSend({
      recipient: RECIPIENT,
      amount: 5000n,
      mint: "SOL",
      signer,
      rpcUrl: "http://rpc",
      cloak,
      persistUtxos: vi.fn(),
      guard: mkGuard(analysis()),
    });
    expect(res.status).toBe("sent");
    expect(calls).toEqual(["transact", "fullWithdraw"]);
    expect(cloak.createUtxo).toHaveBeenCalledWith(5000n, "OWNER", "SOLMINT");
    const [params, tOpts] = cloak.transact.mock.calls[0] as unknown as [
      Record<string, unknown>,
      Record<string, unknown>,
    ];
    expect(params.externalAmount).toBe(5000n);
    expect(tOpts.relayUrl).toBe(CLOAK_PRODUCTION_RELAY_URL);
    const [inputs, to, wOpts] = cloak.fullWithdraw.mock.calls[0] as unknown as [
      unknown[],
      string,
      Record<string, unknown>,
    ];
    expect(inputs).toEqual([dep]);
    expect(to).toBe(RECIPIENT);
    expect(wOpts.relayUrl).toBe(CLOAK_PRODUCTION_RELAY_URL);
    expect(wOpts.cachedMerkleTree).toBe("TREE");
    expect(res.depositSig).toBe("DEPSIG");
    expect(res.withdrawSig).toBe("WDSIG");
    expect(res.explorerUrls?.withdraw).toContain("WDSIG");
  });

  it("persists the deposit note before the withdrawal runs and before returning", async () => {
    const { cloak, calls } = mkCloak();
    const persist = vi.fn((_n: unknown) => {
      calls.push("persist");
    });
    const res = await guardedPrivateSend({
      recipient: RECIPIENT,
      amount: 1000n,
      mint: "SOL",
      signer,
      rpcUrl: "http://rpc",
      cloak,
      persistUtxos: persist,
      guard: mkGuard(analysis()),
    });
    expect(calls).toEqual(["transact", "persist", "fullWithdraw"]);
    expect(persist).toHaveBeenCalledTimes(1);
    expect(res.outputUtxos).toEqual([
      { stage: "deposit", signature: "DEPSIG", utxoHex: "0102ff" },
    ]);
  });

  it("surfaces saved notes when the withdrawal fails after the deposit", async () => {
    const { cloak } = mkCloak();
    cloak.fullWithdraw.mockRejectedValue(new Error("401"));
    const persist = vi.fn();
    const err = await guardedPrivateSend({
      recipient: RECIPIENT,
      amount: 1000n,
      mint: "SOL",
      signer,
      rpcUrl: "http://rpc",
      cloak,
      persistUtxos: persist,
      guard: mkGuard(analysis()),
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CloakSendError);
    const e = err as CloakSendError;
    expect(e.depositSig).toBe("DEPSIG");
    expect(e.notes).toHaveLength(1);
    expect(e.notes[0]?.utxoHex).toBe("0102ff");
    expect(persist).toHaveBeenCalledTimes(1);
  });

  it("refuses a real send without persistUtxos, before any Cloak call", async () => {
    const { cloak } = mkCloak();
    await expect(
      guardedPrivateSend({
        recipient: RECIPIENT,
        amount: 1000n,
        mint: "SOL",
        signer,
        rpcUrl: "http://rpc",
        cloak,
        guard: mkGuard(analysis()),
      }),
    ).rejects.toThrow(/persistUtxos/);
    expect(cloak.transact).not.toHaveBeenCalled();
  });

  it("dryRun does no Cloak call", async () => {
    const { cloak } = mkCloak();
    const res = await guardedPrivateSend({
      recipient: RECIPIENT,
      amount: 1000n,
      mint: "USDC",
      dryRun: true,
      cloak,
      guard: mkGuard(analysis({ verdict: "caution", risk_score: 40 })),
    });
    expect(res.status).toBe("dry-run");
    expect(res.verdict.decision).toBe("warn");
    for (const fn of Object.values(cloak)) {
      if (typeof fn === "function" && "mock" in fn) {
        expect((fn as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
      }
    }
  });
});
