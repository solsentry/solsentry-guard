// Program-ID extraction from a Solana transaction, without depending on
// @solana/web3.js. We duck-type the few shapes the SDK accepts:
//
//   1. A web3.js legacy `Transaction`        (has .instructions[].programId)
//   2. A web3.js `VersionedTransaction`      (has .message.staticAccountKeys +
//                                              compiledInstructions[].programIdIndex)
//   3. A plain array of base58 program-id strings
//   4. A plain `{ programIds: string[] }` object
//
// Anything with a `.toBase58()` / `.toString()` is coerced to base58.

/** Base58 alphabet (Bitcoin/Solana). */
const B58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

// Mirror of the server's clients/contract_analyzer.py:_INFRA_PROGRAMS — these
// short-circuit to verdict "safe" server-side, so skipping them client-side
// saves a credit per call without changing the outcome. Keep in sync.
export const INFRA_PROGRAMS = new Set<string>([
  "11111111111111111111111111111111", // System Program
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token Program
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", // Token-2022 Program
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", // Associated Token Program
  "ComputeBudget111111111111111111111111111111", // Compute Budget Program
  "Stake11111111111111111111111111111111111111", // Stake Program
  "Vote111111111111111111111111111111111111111", // Vote Program
  "BPFLoaderUpgradeab1e11111111111111111111111", // BPF Loader Upgradeable
  "BPFLoader2111111111111111111111111111111111", // BPF Loader v2
]);

function coerce(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value === "string") return B58.test(value) ? value : null;
  const obj = value as { toBase58?: () => string; toString?: () => string };
  if (typeof obj.toBase58 === "function") {
    const s = obj.toBase58();
    return B58.test(s) ? s : null;
  }
  if (typeof obj.toString === "function") {
    const s = obj.toString();
    return B58.test(s) ? s : null;
  }
  return null;
}

interface LegacyTx {
  instructions?: Array<{ programId?: unknown }>;
}

interface VersionedTx {
  message?: {
    staticAccountKeys?: unknown[];
    compiledInstructions?: Array<{ programIdIndex?: number }>;
  };
}

/**
 * Extract the distinct base58 program IDs referenced by a transaction.
 * Tolerant of mixed/unknown inputs — returns whatever it can resolve.
 */
export function extractProgramIds(tx: unknown): string[] {
  const out = new Set<string>();

  // Form 3: array of strings / pubkeys
  if (Array.isArray(tx)) {
    for (const item of tx) {
      const id = coerce(item);
      if (id) out.add(id);
    }
    return [...out];
  }

  if (tx && typeof tx === "object") {
    // Form 4: { programIds: [...] }
    const maybe = tx as { programIds?: unknown[] };
    if (Array.isArray(maybe.programIds)) {
      for (const item of maybe.programIds) {
        const id = coerce(item);
        if (id) out.add(id);
      }
    }

    // Form 1: legacy Transaction
    const legacy = tx as LegacyTx;
    if (Array.isArray(legacy.instructions)) {
      for (const ix of legacy.instructions) {
        const id = coerce(ix?.programId);
        if (id) out.add(id);
      }
    }

    // Form 2: VersionedTransaction
    const v = tx as VersionedTx;
    const keys = v.message?.staticAccountKeys;
    const cix = v.message?.compiledInstructions;
    if (Array.isArray(keys) && Array.isArray(cix)) {
      for (const ix of cix) {
        const idx = ix?.programIdIndex;
        if (typeof idx === "number" && idx >= 0 && idx < keys.length) {
          const id = coerce(keys[idx]);
          if (id) out.add(id);
        }
      }
    }
  }

  return [...out];
}
