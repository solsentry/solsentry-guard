import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ZcashAddressError,
  blake2b,
  checkZcashExit,
  classifyZcashAddress,
  decodeUnifiedAddress,
  encodeSaplingAddress,
  encodeTransparentAddress,
  encodeUnifiedAddress,
  f4jumble,
  f4jumbleInv,
  sha256,
} from "../src/zcash/index.js";

// Same synthetic vectors as tests/test_zcash_ua.py: deterministic filler bytes, never real keys.
const bytes = (n: number, f: (i: number) => number) => Uint8Array.from({ length: n }, (_, i) => f(i));
const SAPLING: [number, Uint8Array] = [0x02, bytes(43, (i) => i)];
const ORCHARD: [number, Uint8Array] = [0x03, bytes(43, (i) => (i * 7) % 256)];
const P2PKH: [number, Uint8Array] = [0x00, bytes(20, (i) => i)];
const P2SH: [number, Uint8Array] = [0x01, bytes(20, (i) => (i * 3) % 256)];

// Produced by the Python reference encoder (clients/zcash_ua.py) from the vectors above.
const PY_UA_SAPLING_ORCHARD =
  "u1vx20s84w8ftt6khk5sxe29ntzs9xewfpv0aq7tv4q22l8nsnsv4t6rgk99yz09jfwpehrh0g3epctps9d6revznsp5qpcrprwnzdpegar4dqjkwvzkenq5w3uy9zahgy40pwlvrwa8cwwjsg7juy7tl8wa8yelntnyen2tcadskx43qp";
const PY_UA_P2PKH_SAPLING_ORCHARD =
  "u1mnxnhs4shwlc0sqqn2mgdv8hp3emmu0jjv73cefg3wz26zj3wwdcjmr4ase75hkj9rlf0d45v8h5pjnesjxlnl3avr3gh4f3qnrw6ajf8wz3qz4xk9pld9c9qzmfn9r3z5u86qrvyljutraqtqv5l9s8rf0tyqf60y7veg3s4ustq9zudna4d96ns5qzueczscfd6atl5cvvk3ncrt7";
const PY_UTEST_SAPLING =
  "utest1ra864p6wk82ce53gq4wmrqe8yyggvs6dg3vr2uhdprk9qm7ye9dswgj7ksn48d3tgnhvr6pkaqm9es96fez0ma6hsq3jdggm7vxscrf5";

describe("hash primitives", () => {
  it("blake2b matches node blake2b512 when unpersonalized", () => {
    for (const len of [0, 3, 127, 128, 129, 300]) {
      const msg = bytes(len, (i) => (i * 13 + len) % 256);
      const want = createHash("blake2b512").update(msg).digest();
      expect(Buffer.from(blake2b(msg, 64, new Uint8Array(0))).toString("hex")).toBe(want.toString("hex"));
    }
  });
  it("blake2b personalization matches the Python hashlib output", () => {
    const person = Uint8Array.from([...new TextEncoder().encode("UA_F4Jumble_G"), 1, 2, 3]);
    const out = blake2b(bytes(200, (i) => i), 64, person);
    expect(Buffer.from(out).toString("hex")).toBe(
      "00af0717ae9a461359a6caf38784cd1b748a415b13b7f36554c852847dbfe320b180197048479b93137a7b1ad2cf35bb97dd69eba55e4ee844d6da3a11cfda1c",
    );
  });
  it("sha256 matches node", () => {
    for (const len of [0, 1, 55, 56, 64, 119, 1000]) {
      const msg = bytes(len, (i) => (i * 5 + 1) % 256);
      expect(Buffer.from(sha256(msg)).toString("hex")).toBe(createHash("sha256").update(msg).digest("hex"));
    }
  });
  it("f4jumble round-trips across the length split and is not the identity", () => {
    for (const length of [48, 127, 128, 129, 400]) {
      const m = bytes(length, (i) => (i * 31 + length) % 256);
      expect(f4jumbleInv(f4jumble(m))).toEqual(m);
    }
    const m = bytes(64, (i) => i);
    expect(f4jumble(m)).not.toEqual(m);
  });
});

describe("unified addresses", () => {
  it.each([
    [[SAPLING]],
    [[SAPLING, ORCHARD]],
    [[P2PKH, SAPLING, ORCHARD]],
    [[P2SH, ORCHARD]],
  ])("encode/decode round trip %#", (receivers) => {
    const ua = decodeUnifiedAddress(encodeUnifiedAddress(receivers));
    expect(ua.network).toBe("mainnet");
    expect(ua.receivers.map((r) => r.typecode)).toEqual(receivers.map(([tc]) => tc));
    expect(ua.receivers.map((r) => Array.from(r.data))).toEqual(receivers.map(([, d]) => Array.from(d)));
  });

  it("encoder output is byte-identical to the Python reference", () => {
    expect(encodeUnifiedAddress([SAPLING, ORCHARD])).toBe(PY_UA_SAPLING_ORCHARD);
    expect(encodeUnifiedAddress([P2PKH, SAPLING, ORCHARD])).toBe(PY_UA_P2PKH_SAPLING_ORCHARD);
    expect(encodeUnifiedAddress([SAPLING], "utest")).toBe(PY_UTEST_SAPLING);
  });

  it("decodes Python-produced addresses", () => {
    expect(classifyZcashAddress(PY_UA_SAPLING_ORCHARD).traceability).toBe("shielded-only");
    expect(classifyZcashAddress(PY_UA_P2PKH_SAPLING_ORCHARD).hasTransparentLeg).toBe(true);
  });

  it("shielded-only has no transparent leg; names are right", () => {
    const d = classifyZcashAddress(encodeUnifiedAddress([SAPLING, ORCHARD]));
    expect(d).toMatchObject({ kind: "unified", network: "mainnet", hasTransparentLeg: false, traceability: "shielded-only" });
    expect(d.receivers.map((r) => r.name)).toEqual(["sapling", "orchard"]);
  });

  it("transparent receiver is detected", () => {
    const d = classifyZcashAddress(encodeUnifiedAddress([P2PKH, ORCHARD]));
    expect(d.hasTransparentLeg).toBe(true);
    expect(d.traceability).toBe("public");
    expect(d.receivers.map((r) => r.transparent)).toEqual([true, false]);
  });

  it("testnet hrp is labelled", () => {
    expect(classifyZcashAddress(encodeUnifiedAddress([SAPLING], "utest")).network).toBe("testnet");
  });

  it("uppercase decodes the same", () => {
    const addr = encodeUnifiedAddress([SAPLING, ORCHARD]);
    expect(decodeUnifiedAddress(addr.toUpperCase()).receivers.map((r) => r.typecode)).toEqual([2, 3]);
  });

  it("unknown typecode survives and is not transparent", () => {
    const [r] = decodeUnifiedAddress(encodeUnifiedAddress([[0x7f, new Uint8Array(8).fill(0x11)]])).receivers;
    expect(r?.name).toBe("unknown_0x7f");
    expect(r?.known).toBe(false);
    expect(r?.transparent).toBe(false);
  });

  it("rejects truncated, flipped, mixed-case, wrong-hrp, wrong-length", () => {
    const addr = encodeUnifiedAddress([SAPLING, ORCHARD]);
    expect(() => decodeUnifiedAddress(addr.slice(0, -4))).toThrow(/checksum/);
    const flipped = addr.slice(0, -1) + (addr.endsWith("q") ? "p" : "q");
    expect(() => decodeUnifiedAddress(flipped)).toThrow(/checksum/);
    expect(() => decodeUnifiedAddress(addr.slice(0, 5).toUpperCase() + addr.slice(5))).toThrow(/mixed case/);
    const body = addr.split("1")[1];
    expect(() => decodeUnifiedAddress("zs1" + body)).toThrow(ZcashAddressError);
    expect(() => decodeUnifiedAddress(encodeUnifiedAddress([[0x02, new Uint8Array(20)]]))).toThrow(/expected 43B/);
  });
});

describe("transparent and Sapling", () => {
  const h20 = bytes(20, (i) => i + 1);
  it("t1 / t3 are public", () => {
    const t1 = encodeTransparentAddress(h20, "p2pkh");
    const t3 = encodeTransparentAddress(h20, "p2sh");
    expect(t1.startsWith("t1")).toBe(true);
    expect(t3.startsWith("t3")).toBe(true);
    for (const a of [t1, t3]) {
      expect(classifyZcashAddress(a)).toMatchObject({ kind: "transparent", network: "mainnet", hasTransparentLeg: true, traceability: "public" });
    }
    expect(classifyZcashAddress(t1).receivers[0]?.name).toBe("p2pkh");
    expect(classifyZcashAddress(t3).receivers[0]?.name).toBe("p2sh");
  });
  it("testnet t-addresses", () => {
    expect(classifyZcashAddress(encodeTransparentAddress(h20, "p2pkh", "testnet")).network).toBe("testnet");
    expect(classifyZcashAddress(encodeTransparentAddress(h20, "p2sh", "testnet")).network).toBe("testnet");
  });
  it("rejects a t-address with a corrupted checksum", () => {
    const t1 = encodeTransparentAddress(h20);
    const bad = t1.slice(0, -1) + (t1.endsWith("2") ? "3" : "2");
    expect(() => classifyZcashAddress(bad)).toThrow(/checksum/);
  });
  it("Sapling zs1 is shielded-only", () => {
    const zs = encodeSaplingAddress(bytes(43, (i) => (i * 5) % 256));
    expect(zs.startsWith("zs1")).toBe(true);
    expect(classifyZcashAddress(zs)).toMatchObject({ kind: "sapling", network: "mainnet", hasTransparentLeg: false, traceability: "shielded-only" });
    expect(() => classifyZcashAddress(zs.slice(0, -3))).toThrow(ZcashAddressError);
  });
});

describe("malformed inputs", () => {
  it.each(["", "   ", "u1", "not-an-address", "u1" + "q".repeat(10), "t1", "t1abc", "zs1qqqq", "0x1234", "So11111111111111111111111111111111111111112"])(
    "classify throws on %j",
    (bad) => {
      expect(() => classifyZcashAddress(bad)).toThrow(ZcashAddressError);
    },
  );
});

describe("checkZcashExit verdict mapping", () => {
  it("invalid -> block", () => {
    for (const bad of ["", "garbage", "u1" + "q".repeat(10)]) {
      const v = checkZcashExit(bad);
      expect(v.decision).toBe("block");
      expect(v.reasons).toEqual(["INVALID_ADDRESS"]);
      expect(v.destination).toBeNull();
    }
  });
  it("shielded-only (UA and Sapling) -> allow", () => {
    for (const a of [encodeUnifiedAddress([SAPLING, ORCHARD]), encodeSaplingAddress(bytes(43, (i) => i))]) {
      const v = checkZcashExit(a);
      expect(v.decision).toBe("allow");
      expect(v.reasons).toContain("SHIELDED_ONLY");
      expect(v.note).toMatch(/no public trail after exit/);
    }
  });
  it("transparent leg (t-addr and UA with t receiver) -> warn", () => {
    for (const a of [encodeTransparentAddress(bytes(20, (i) => i)), encodeUnifiedAddress([P2PKH, ORCHARD])]) {
      const v = checkZcashExit(a);
      expect(v.decision).toBe("warn");
      expect(v.reasons).toContain("TRANSPARENT_LEG");
      expect(v.note).toMatch(/publicly traceable on Zcash/);
    }
  });
  it("testnet is flagged", () => {
    expect(checkZcashExit(encodeUnifiedAddress([SAPLING], "utest")).reasons).toEqual(["TESTNET", "SHIELDED_ONLY"]);
  });
});
