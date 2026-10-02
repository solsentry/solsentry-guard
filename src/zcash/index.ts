// Optional entrypoint: @solsentry/guard/zcash
//
// Offline Zcash destination classifier + exit verdict. Pure TypeScript, zero
// dependencies, no network, no key material. Port of the SolSentry unified-address
// decoder (ZIP 316: bech32m + F4Jumble + typecodes), plus transparent (t1/t3) and
// Sapling (zs1) recognition.
//
// What it can and cannot say: it classifies the DESTINATION ADDRESS only. A
// shielded-only destination publishes no value, sender, recipient or link between
// the two ends of the shielded transfer; a transparent destination is a public
// address on the Zcash chain. It does not assess the recipient's reputation.

// ───────────────────────── types ─────────────────────────

export type ZcashNetwork = "mainnet" | "testnet";
export type ZcashAddressKind = "transparent" | "sapling" | "unified";
export type ZcashTraceability = "public" | "shielded-only";

export interface ZcashReceiver {
  typecode: number;
  name: string;
  data: Uint8Array;
  transparent: boolean;
  known: boolean;
}

export interface ZcashDestination {
  kind: ZcashAddressKind;
  network: ZcashNetwork;
  receivers: ZcashReceiver[];
  hasTransparentLeg: boolean;
  traceability: ZcashTraceability;
}

export class ZcashAddressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ZcashAddressError";
  }
}

export const TYPECODES: Record<number, { name: string; length: number }> = {
  0x00: { name: "p2pkh", length: 20 },
  0x01: { name: "p2sh", length: 20 },
  0x02: { name: "sapling", length: 43 },
  0x03: { name: "orchard", length: 43 },
};

// ───────────────────────── hashing ─────────────────────────

const MASK64 = (1n << 64n) - 1n;
const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const rotr = (x: bigint, n: bigint) => ((x >> n) | (x << (64n - n))) & MASK64;

function readLE64(b: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i] ?? 0);
  return v;
}

/** BLAKE2b with a 16-byte personalization (RFC 7693 param block). No key, no salt. */
export function blake2b(input: Uint8Array, outLen: number, person: Uint8Array): Uint8Array {
  if (outLen < 1 || outLen > 64) throw new RangeError("blake2b outLen must be 1..64");
  if (person.length > 16) throw new RangeError("blake2b person must be <= 16 bytes");
  const param = new Uint8Array(64);
  param[0] = outLen;
  param[2] = 1; // fanout
  param[3] = 1; // depth
  param.set(person, 48);
  const h = IV.map((iv, i) => iv ^ readLE64(param, i * 8));

  const compress = (block: Uint8Array, t: bigint, last: boolean) => {
    const m: bigint[] = [];
    for (let i = 0; i < 16; i++) m.push(readLE64(block, i * 8));
    const v = [...h, ...IV];
    v[12] = (v[12] as bigint) ^ (t & MASK64);
    if (last) v[14] = (v[14] as bigint) ^ MASK64;
    const G = (a: number, b: number, c: number, d: number, x: bigint, y: bigint) => {
      v[a] = ((v[a] as bigint) + (v[b] as bigint) + x) & MASK64;
      v[d] = rotr((v[d] as bigint) ^ (v[a] as bigint), 32n);
      v[c] = ((v[c] as bigint) + (v[d] as bigint)) & MASK64;
      v[b] = rotr((v[b] as bigint) ^ (v[c] as bigint), 24n);
      v[a] = ((v[a] as bigint) + (v[b] as bigint) + y) & MASK64;
      v[d] = rotr((v[d] as bigint) ^ (v[a] as bigint), 16n);
      v[c] = ((v[c] as bigint) + (v[d] as bigint)) & MASK64;
      v[b] = rotr((v[b] as bigint) ^ (v[c] as bigint), 63n);
    };
    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r % 10] as number[];
      const mm = (i: number) => m[s[i] as number] as bigint;
      G(0, 4, 8, 12, mm(0), mm(1));
      G(1, 5, 9, 13, mm(2), mm(3));
      G(2, 6, 10, 14, mm(4), mm(5));
      G(3, 7, 11, 15, mm(6), mm(7));
      G(0, 5, 10, 15, mm(8), mm(9));
      G(1, 6, 11, 12, mm(10), mm(11));
      G(2, 7, 8, 13, mm(12), mm(13));
      G(3, 4, 9, 14, mm(14), mm(15));
    }
    for (let i = 0; i < 8; i++) h[i] = (h[i] as bigint) ^ (v[i] as bigint) ^ (v[i + 8] as bigint);
  };

  let off = 0;
  while (input.length - off > 128) {
    compress(input.subarray(off, off + 128), BigInt(off + 128), false);
    off += 128;
  }
  const last = new Uint8Array(128);
  last.set(input.subarray(off));
  compress(last, BigInt(input.length), true);

  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    let w = h[i] as bigint;
    for (let j = 0; j < 8; j++) {
      out[i * 8 + j] = Number(w & 0xffn);
      w >>= 8n;
    }
  }
  return out.slice(0, outLen);
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** Plain SHA-256 (only used for the base58check checksum of t-addresses). */
export function sha256(data: Uint8Array): Uint8Array {
  const rotr32 = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  const padded = new Uint8Array(((data.length + 9 + 63) >> 6) << 6);
  padded.set(data);
  padded[data.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor((data.length * 8) / 0x100000000));
  dv.setUint32(padded.length - 4, (data.length * 8) >>> 0);
  const H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15] as number;
      const b = w[i - 2] as number;
      const s0 = rotr32(a, 7) ^ rotr32(a, 18) ^ (a >>> 3);
      const s1 = rotr32(b, 17) ^ rotr32(b, 19) ^ (b >>> 10);
      w[i] = ((w[i - 16] as number) + s0 + (w[i - 7] as number) + s1) >>> 0;
    }
    const s = H.slice();
    let [a, b, c, d, e, f, g, hh] = s as [number, number, number, number, number, number, number, number];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + (SHA256_K[i] as number) + (w[i] as number)) >>> 0;
      const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    const add = [a, b, c, d, e, f, g, hh];
    for (let i = 0; i < 8; i++) H[i] = ((H[i] as number) + (add[i] as number)) >>> 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i] as number);
  return out;
}

// ───────────────────────── bech32 / bech32m ─────────────────────────

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;

function polymod(values: number[]): number {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ (gen[i] as number)) >>> 0;
  }
  return chk;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function bech32Decode(addr: string): { hrp: string; data: number[]; variant: "bech32" | "bech32m" } {
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) throw new ZcashAddressError("mixed case");
  const a = addr.toLowerCase();
  const pos = a.lastIndexOf("1");
  if (pos < 1 || pos + 7 > a.length) throw new ZcashAddressError("no bech32 separator (truncated?)");
  const hrp = a.slice(0, pos);
  const data: number[] = [];
  for (const c of a.slice(pos + 1)) {
    const idx = CHARSET.indexOf(c);
    if (idx < 0) throw new ZcashAddressError(`invalid bech32 char '${c}'`);
    data.push(idx);
  }
  const pm = polymod([...hrpExpand(hrp), ...data]);
  if (pm === BECH32M_CONST) return { hrp, data: data.slice(0, -6), variant: "bech32m" };
  if (pm === BECH32_CONST) return { hrp, data: data.slice(0, -6), variant: "bech32" };
  throw new ZcashAddressError("bech32 checksum invalid (truncated or corrupt)");
}

function bech32Encode(hrp: string, data: number[], constant: number): string {
  const pm = (polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ constant) >>> 0;
  const cs: number[] = [];
  for (let i = 0; i < 6; i++) cs.push((pm >>> (5 * (5 - i))) & 31);
  return hrp + "1" + [...data, ...cs].map((d) => CHARSET[d]).join("");
}

function convertBits(data: ArrayLike<number>, from: number, to: number, pad: boolean): number[] | null {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << to) - 1;
  for (let i = 0; i < data.length; i++) {
    const value = data[i] as number;
    if (value < 0 || value >> from) return null;
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      ret.push((acc >> bits) & maxv);
    }
    acc &= (1 << bits) - 1; // only the low `bits` bits matter; keeps acc small
  }
  if (pad) {
    if (bits) ret.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || (acc << (to - bits)) & maxv) {
    return null;
  }
  return ret;
}

// ───────────────────────── F4Jumble (ZIP 316) ─────────────────────────

const enc = new TextEncoder();

function hF4(i: number, u: Uint8Array, lL: number): Uint8Array {
  const person = new Uint8Array([...enc.encode("UA_F4Jumble_H"), i, 0, 0]);
  return blake2b(u, lL, person);
}

function gF4(i: number, u: Uint8Array, lR: number): Uint8Array {
  const out = new Uint8Array(Math.ceil(lR / 64) * 64);
  for (let j = 0; j * 64 < lR; j++) {
    const person = new Uint8Array([...enc.encode("UA_F4Jumble_G"), i, j & 0xff, (j >> 8) & 0xff]);
    out.set(blake2b(u, 64, person), j * 64);
  }
  return out.slice(0, lR);
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = (a[i] as number) ^ (b[i] as number);
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function split(len: number): [number, number] {
  const lL = Math.min(64, len >> 1);
  return [lL, len - lL];
}

export function f4jumble(message: Uint8Array): Uint8Array {
  const [lL, lR] = split(message.length);
  const a = message.slice(0, lL);
  const b = message.slice(lL);
  const x = xor(b, gF4(0, a, lR));
  const y = xor(a, hF4(0, x, lL));
  const d = xor(x, gF4(1, y, lR));
  const c = xor(y, hF4(1, d, lL));
  return concat(c, d);
}

export function f4jumbleInv(message: Uint8Array): Uint8Array {
  const [lL, lR] = split(message.length);
  const c = message.slice(0, lL);
  const d = message.slice(lL);
  const y = xor(c, hF4(1, d, lL));
  const x = xor(d, gF4(1, y, lR));
  const a = xor(y, hF4(0, x, lL));
  const b = xor(x, gF4(0, a, lR));
  return concat(a, b);
}

// ───────────────────────── compactsize ─────────────────────────

function readCompactSize(buf: Uint8Array, i: number): [number, number] {
  if (i >= buf.length) throw new ZcashAddressError("truncated receiver list");
  const v = buf[i] as number;
  if (v < 253) return [v, i + 1];
  const width = v === 253 ? 2 : v === 254 ? 4 : 8;
  if (i + 1 + width > buf.length) throw new ZcashAddressError("truncated compactsize");
  let n = 0;
  for (let k = width - 1; k >= 0; k--) n = n * 256 + (buf[i + 1 + k] as number);
  if (!Number.isSafeInteger(n)) throw new ZcashAddressError("compactsize too large");
  return [n, i + 1 + width];
}

function writeCompactSize(value: number): number[] {
  if (value < 253) return [value];
  if (value <= 0xffff) return [253, value & 0xff, value >> 8];
  return [254, value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff];
}

// ───────────────────────── unified addresses ─────────────────────────

const PADDING_LEN = 16;
const UA_NETWORKS: Record<string, ZcashNetwork> = { u: "mainnet", utest: "testnet" };

export interface UnifiedAddress {
  hrp: string;
  network: ZcashNetwork;
  receivers: ZcashReceiver[];
}

const hex2 = (n: number) => n.toString(16).padStart(2, "0");

export function decodeUnifiedAddress(addr: string): UnifiedAddress {
  const { hrp, data, variant } = bech32Decode(addr.trim());
  const network = UA_NETWORKS[hrp];
  if (!network) throw new ZcashAddressError(`hrp '${hrp}' is not a unified address`);
  if (variant !== "bech32m") throw new ZcashAddressError("unified addresses use bech32m");
  const raw = convertBits(data, 5, 8, false);
  if (!raw) throw new ZcashAddressError("invalid 5->8 bit padding");
  if (raw.length <= PADDING_LEN) throw new ZcashAddressError("payload shorter than the padding block");
  const unjumbled = f4jumbleInv(Uint8Array.from(raw));
  const padding = unjumbled.slice(-PADDING_LEN);
  const expected = new Uint8Array(PADDING_LEN);
  expected.set(enc.encode(hrp));
  if (padding.some((v, i) => v !== expected[i])) throw new ZcashAddressError("padding mismatch");

  const body = unjumbled.slice(0, -PADDING_LEN);
  const receivers: ZcashReceiver[] = [];
  let i = 0;
  while (i < body.length) {
    let typecode: number;
    let length: number;
    [typecode, i] = readCompactSize(body, i);
    [length, i] = readCompactSize(body, i);
    if (i + length > body.length) throw new ZcashAddressError("receiver overruns the payload");
    const value = body.slice(i, i + length);
    i += length;
    const known = TYPECODES[typecode];
    if (known && length !== known.length) {
      throw new ZcashAddressError(`receiver 0x${hex2(typecode)} has ${length}B, expected ${known.length}B`);
    }
    receivers.push({
      typecode,
      name: known ? known.name : `unknown_0x${hex2(typecode)}`,
      data: value,
      transparent: typecode === 0x00 || typecode === 0x01,
      known: !!known,
    });
  }
  if (receivers.length === 0) throw new ZcashAddressError("no receivers");
  return { hrp, network, receivers };
}

/** Encode receivers as a unified address. For tests / synthetic fixtures only. */
export function encodeUnifiedAddress(
  receivers: Array<[number, Uint8Array]>,
  hrp: "u" | "utest" = "u",
): string {
  if (receivers.length === 0) throw new ZcashAddressError("no receivers");
  const parts: number[] = [];
  for (const [tc, data] of receivers) parts.push(...writeCompactSize(tc), ...writeCompactSize(data.length), ...data);
  const padding = new Uint8Array(PADDING_LEN);
  padding.set(enc.encode(hrp));
  const jumbled = f4jumble(concat(Uint8Array.from(parts), padding));
  return bech32Encode(hrp, convertBits(jumbled, 8, 5, true) as number[], BECH32M_CONST);
}

// ───────────────────────── transparent + Sapling ─────────────────────────

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const idx = B58.indexOf(c);
    if (idx < 0) throw new ZcashAddressError(`invalid base58 char '${c}'`);
    n = n * 58n + BigInt(idx);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes]);
}

function base58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  return "1".repeat(zeros) + s;
}

// 2-byte version prefixes of Zcash transparent addresses.
const T_PREFIXES: Record<string, { network: ZcashNetwork; typecode: 0 | 1 }> = {
  "1cb8": { network: "mainnet", typecode: 0 }, // t1
  "1cbd": { network: "mainnet", typecode: 1 }, // t3
  "1d25": { network: "testnet", typecode: 0 }, // tm
  "1cba": { network: "testnet", typecode: 1 }, // t2
};

function decodeTransparent(addr: string): ZcashDestination {
  const raw = base58Decode(addr);
  if (raw.length !== 26) throw new ZcashAddressError(`transparent address has ${raw.length}B, expected 26B`);
  const payload = raw.slice(0, 22);
  const check = sha256(sha256(payload)).slice(0, 4);
  if (check.some((v, i) => v !== raw[22 + i])) throw new ZcashAddressError("base58check checksum invalid");
  const prefix = hex2(payload[0] as number) + hex2(payload[1] as number);
  const info = T_PREFIXES[prefix];
  if (!info) throw new ZcashAddressError(`unknown transparent version prefix 0x${prefix}`);
  return {
    kind: "transparent",
    network: info.network,
    receivers: [
      {
        typecode: info.typecode,
        name: TYPECODES[info.typecode]?.name ?? "transparent",
        data: payload.slice(2),
        transparent: true,
        known: true,
      },
    ],
    hasTransparentLeg: true,
    traceability: "public",
  };
}

const SAPLING_HRPS: Record<string, ZcashNetwork> = { zs: "mainnet", ztestsapling: "testnet" };

function decodeSapling(addr: string): ZcashDestination {
  const { hrp, data, variant } = bech32Decode(addr);
  const network = SAPLING_HRPS[hrp];
  if (!network) throw new ZcashAddressError(`hrp '${hrp}' is not a Sapling address`);
  if (variant !== "bech32") throw new ZcashAddressError("Sapling addresses use bech32");
  const raw = convertBits(data, 5, 8, false);
  if (!raw || raw.length !== 43) throw new ZcashAddressError("Sapling address must carry 43 bytes");
  return {
    kind: "sapling",
    network,
    receivers: [{ typecode: 0x02, name: "sapling", data: Uint8Array.from(raw), transparent: false, known: true }],
    hasTransparentLeg: false,
    traceability: "shielded-only",
  };
}

/** Encode a transparent address from a 20-byte hash. For tests / synthetic fixtures only. */
export function encodeTransparentAddress(
  hash160: Uint8Array,
  type: "p2pkh" | "p2sh" = "p2pkh",
  network: ZcashNetwork = "mainnet",
): string {
  const prefix =
    network === "mainnet"
      ? type === "p2pkh"
        ? [0x1c, 0xb8]
        : [0x1c, 0xbd]
      : type === "p2pkh"
        ? [0x1d, 0x25]
        : [0x1c, 0xba];
  const payload = Uint8Array.from([...prefix, ...hash160]);
  return base58Encode(concat(payload, sha256(sha256(payload)).slice(0, 4)));
}

/** Encode a Sapling address from 43 bytes. For tests / synthetic fixtures only. */
export function encodeSaplingAddress(data43: Uint8Array, network: ZcashNetwork = "mainnet"): string {
  return bech32Encode(
    network === "mainnet" ? "zs" : "ztestsapling",
    convertBits(data43, 8, 5, true) as number[],
    BECH32_CONST,
  );
}

// ───────────────────────── public API ─────────────────────────

/**
 * Classify a Zcash destination offline. Throws ZcashAddressError when the string
 * is not a decodable t-address / Sapling / unified address.
 */
export function classifyZcashAddress(address: string): ZcashDestination {
  const a = (address ?? "").trim();
  if (!a) throw new ZcashAddressError("empty address");
  const lower = a.toLowerCase();
  if (/^t[123m]/.test(a)) return decodeTransparent(a);
  if (lower.startsWith("utest1") || lower.startsWith("u1")) {
    const ua = decodeUnifiedAddress(a);
    const hasTransparentLeg = ua.receivers.some((r) => r.transparent);
    return {
      kind: "unified",
      network: ua.network,
      receivers: ua.receivers,
      hasTransparentLeg,
      traceability: hasTransparentLeg ? "public" : "shielded-only",
    };
  }
  if (lower.startsWith("zs1") || lower.startsWith("ztestsapling1")) return decodeSapling(a);
  throw new ZcashAddressError("not a recognised Zcash address (expected t1/t3, zs1 or u1)");
}

export type ZcashExitDecision = "allow" | "warn" | "block";

export interface ZcashExitVerdict {
  decision: ZcashExitDecision;
  /** Machine-readable reasons: INVALID_ADDRESS, SHIELDED_ONLY, TRANSPARENT_LEG, TESTNET. */
  reasons: string[];
  /** Human-readable explanation. */
  note: string;
  destination: ZcashDestination | null;
}

/**
 * Guard verdict for exiting funds to a Zcash address.
 *  - undecodable address            -> block
 *  - shielded-only destination      -> allow (no public trail after exit)
 *  - destination with a t-leg       -> warn  (publicly traceable on Zcash)
 * Only the destination's address type is assessed, not who controls it.
 */
export function checkZcashExit(address: string): ZcashExitVerdict {
  let dest: ZcashDestination;
  try {
    dest = classifyZcashAddress(address);
  } catch (e) {
    return {
      decision: "block",
      reasons: ["INVALID_ADDRESS"],
      note: `Not a valid Zcash address: ${(e as Error).message}. Funds sent to a mistyped address cannot be recovered.`,
      destination: null,
    };
  }
  const reasons: string[] = [];
  if (dest.network === "testnet") reasons.push("TESTNET");
  if (dest.hasTransparentLeg) {
    reasons.push("TRANSPARENT_LEG");
    return {
      decision: "warn",
      reasons,
      note:
        dest.kind === "unified"
          ? "Destination is publicly traceable on Zcash: this unified address includes a transparent receiver."
          : "Destination is publicly traceable on Zcash: transparent addresses show balances and transfers on any explorer.",
      destination: dest,
    };
  }
  reasons.push("SHIELDED_ONLY");
  return {
    decision: "allow",
    reasons,
    note: "Shielded-only destination: no public trail after exit (value, sender and recipient are not published on Zcash).",
    destination: dest,
  };
}
