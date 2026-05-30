// Sketch: gate a Solana wallet-adapter signature behind a SolSentry check.
// Not wired into the build — illustrative usage for a dApp/extension.
import { useCallback } from "react";
import { useWallet } from "@solana/wallet-adapter-react";
import { Connection, Transaction } from "@solana/web3.js";
import { SolSentryGuard } from "@solsentry/guard";

const guard = new SolSentryGuard({ clientId: "my-dapp" });

export function useGuardedSend(connection: Connection) {
  const { sendTransaction, publicKey } = useWallet();

  return useCallback(
    async (tx: Transaction) => {
      // Inspect every program the tx touches BEFORE asking the user to sign.
      const advice = await guard.analyzeBeforeSign(tx);

      if (advice.shouldBlock) {
        // Replace with your own modal. advice.summary is one human-readable line;
        // advice.reports has the per-program detail (flags, explanation).
        const proceed = window.confirm(
          `⚠️ SolSentry: ${advice.summary}\n\nSign anyway?`,
        );
        if (!proceed) throw new Error("Blocked by SolSentry guard");
      }

      if (!publicKey) throw new Error("Wallet not connected");
      return sendTransaction(tx, connection);
    },
    [connection, sendTransaction, publicKey],
  );
}
