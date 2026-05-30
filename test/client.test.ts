import { describe, expect, it, vi } from "vitest";
import { GuardError, SolSentryGuard } from "../src/client.js";
import type { ContractAnalysis } from "../src/types.js";

const JUP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const DRAINER = "Dr4inerXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const SYSTEM = "11111111111111111111111111111111";

function report(over: Partial<ContractAnalysis>): ContractAnalysis {
  return {
    address: JUP,
    kind: "program",
    known_label: null,
    known_category: null,
    risk_score: 0,
    verdict: "unknown",
    flags: [],
    authorities: {},
    extensions: {},
    explanation: "",
    fetched_at: 0,
    ...over,
  };
}

/** Build a fetch stub that returns a JSON body keyed by address in the URL. */
function fakeFetch(
  byAddress: Record<string, { status?: number; body: unknown }>,
) {
  return vi.fn(async (url: string | URL | Request) => {
    const u = typeof url === "string" ? url : url.toString();
    const hit = Object.entries(byAddress).find(([addr]) => u.includes(addr));
    const { status = 200, body } = hit
      ? hit[1]
      : { status: 404, body: { error: "not found" } };
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    }) as Response;
  });
}

describe("analyzeProgram", () => {
  it("fetches and returns a typed report", async () => {
    const fetchImpl = fakeFetch({
      [JUP]: { body: report({ verdict: "safe", known_label: "Jupiter" }) },
    });
    const guard = new SolSentryGuard({
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const r = await guard.analyzeProgram(JUP);
    expect(r.known_label).toBe("Jupiter");
    expect(r.verdict).toBe("safe");
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("sends X-Client-ID and Authorization when configured", async () => {
    const fetchImpl = fakeFetch({ [JUP]: { body: report({}) } });
    const guard = new SolSentryGuard({
      fetch: fetchImpl as unknown as typeof fetch,
      clientId: "wallet-x",
      apiKey: "secret",
    });
    await guard.analyzeProgram(JUP);
    const init = fetchImpl.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Client-ID"]).toBe("wallet-x");
    expect(headers["Authorization"]).toBe("Bearer secret");
  });

  it("throws GuardError with status + detail on non-2xx", async () => {
    const fetchImpl = fakeFetch({
      [JUP]: {
        status: 400,
        body: { error: "invalid address", detail: "base58 32-44" },
      },
    });
    const guard = new SolSentryGuard({
      fetch: fetchImpl as unknown as typeof fetch,
    });
    await expect(guard.analyzeProgram(JUP)).rejects.toMatchObject({
      name: "GuardError",
      status: 400,
      detail: "base58 32-44",
    });
  });

  it("times out via AbortController", async () => {
    const slow = vi.fn(
      (_url: unknown, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(Object.assign(new Error("aborted"), { name: "AbortError" })),
          );
        }),
    );
    const guard = new SolSentryGuard({
      fetch: slow as unknown as typeof fetch,
      timeoutMs: 10,
    });
    await expect(guard.analyzeProgram(JUP)).rejects.toBeInstanceOf(GuardError);
  });
});

describe("analyzeBeforeSign", () => {
  it("skips infra programs and returns safe with no fetches", async () => {
    const fetchImpl = fakeFetch({});
    const guard = new SolSentryGuard({
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const advice = await guard.analyzeBeforeSign([SYSTEM]);
    expect(advice.verdict).toBe("safe");
    expect(advice.shouldBlock).toBe(false);
    expect(advice.programs).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("aggregates worst verdict + max risk across programs", async () => {
    const fetchImpl = fakeFetch({
      [JUP]: { body: report({ address: JUP, verdict: "safe", risk_score: 5 }) },
      [DRAINER]: {
        body: report({
          address: DRAINER,
          verdict: "dangerous",
          risk_score: 100,
          known_label: "Known Drainer",
          explanation: "Known drainer. Do not sign.",
          flags: ["KNOWN_DRAINER"],
        }),
      },
    });
    const guard = new SolSentryGuard({
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const advice = await guard.analyzeBeforeSign([JUP, DRAINER]);
    expect(advice.verdict).toBe("dangerous");
    expect(advice.risk_score).toBe(100);
    expect(advice.shouldBlock).toBe(true);
    expect(advice.reports).toHaveLength(2);
    expect(advice.summary).toContain("DANGEROUS");
  });

  it("blocks on risk_score >= threshold even when verdict is caution", async () => {
    const fetchImpl = fakeFetch({
      [JUP]: { body: report({ verdict: "caution", risk_score: 85 }) },
    });
    const guard = new SolSentryGuard({
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const advice = await guard.analyzeBeforeSign([JUP], { blockThreshold: 80 });
    expect(advice.shouldBlock).toBe(true);
  });

  it("does not block a caution below threshold", async () => {
    const fetchImpl = fakeFetch({
      [JUP]: { body: report({ verdict: "caution", risk_score: 40 }) },
    });
    const guard = new SolSentryGuard({
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const advice = await guard.analyzeBeforeSign([JUP], { blockThreshold: 80 });
    expect(advice.shouldBlock).toBe(false);
    expect(advice.verdict).toBe("caution");
  });

  it("reports empty transaction as safe", async () => {
    const fetchImpl = fakeFetch({});
    const guard = new SolSentryGuard({
      fetch: fetchImpl as unknown as typeof fetch,
    });
    const advice = await guard.analyzeBeforeSign([]);
    expect(advice.verdict).toBe("safe");
    expect(advice.summary).toContain("No programs");
  });
});

describe("checkLookalike", () => {
  it("passes destination + contacts as query params", async () => {
    const fetchImpl = fakeFetch({
      Dest: {
        body: { destination: "Dest", is_lookalike: false, findings: [] },
      },
    });
    const guard = new SolSentryGuard({
      fetch: fetchImpl as unknown as typeof fetch,
    });
    await guard.checkLookalike("Dest", ["A", "B"]);
    const u = fetchImpl.mock.calls[0][0] as string;
    expect(u).toContain("destination=Dest");
    expect(u).toContain("contacts=A%2CB");
  });
});
