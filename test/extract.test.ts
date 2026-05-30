import { describe, expect, it } from "vitest";
import { extractProgramIds, INFRA_PROGRAMS } from "../src/extract.js";

const JUP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const SYSTEM = "11111111111111111111111111111111";

describe("extractProgramIds", () => {
  it("reads a plain array of base58 strings", () => {
    expect(extractProgramIds([JUP, SYSTEM])).toEqual([JUP, SYSTEM]);
  });

  it("dedupes repeated ids", () => {
    expect(extractProgramIds([JUP, JUP, JUP])).toEqual([JUP]);
  });

  it("drops non-base58 garbage", () => {
    expect(extractProgramIds(["not a key", "", JUP])).toEqual([JUP]);
  });

  it("reads { programIds }", () => {
    expect(extractProgramIds({ programIds: [JUP] })).toEqual([JUP]);
  });

  it("reads a legacy Transaction shape with pubkey-like programId", () => {
    const tx = {
      instructions: [
        { programId: { toBase58: () => JUP } },
        { programId: { toBase58: () => SYSTEM } },
      ],
    };
    expect(extractProgramIds(tx).sort()).toEqual([JUP, SYSTEM].sort());
  });

  it("reads a VersionedTransaction shape via programIdIndex", () => {
    const tx = {
      message: {
        staticAccountKeys: [
          { toBase58: () => "SoMeWaLLeT1111111111111111111111111111111111" },
          { toBase58: () => JUP },
        ],
        compiledInstructions: [{ programIdIndex: 1 }],
      },
    };
    expect(extractProgramIds(tx)).toEqual([JUP]);
  });

  it("ignores out-of-range programIdIndex", () => {
    const tx = {
      message: {
        staticAccountKeys: [{ toBase58: () => JUP }],
        compiledInstructions: [{ programIdIndex: 9 }],
      },
    };
    expect(extractProgramIds(tx)).toEqual([]);
  });

  it("returns [] for junk input", () => {
    expect(extractProgramIds(null)).toEqual([]);
    expect(extractProgramIds(42)).toEqual([]);
    expect(extractProgramIds({})).toEqual([]);
  });

  it("INFRA_PROGRAMS mirrors the canonical server set", () => {
    expect(INFRA_PROGRAMS.has(SYSTEM)).toBe(true);
    expect(
      INFRA_PROGRAMS.has("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
    ).toBe(true);
    expect(INFRA_PROGRAMS.has(JUP)).toBe(false);
  });
});
