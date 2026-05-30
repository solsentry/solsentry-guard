// Run: node examples/node.mjs
// Demonstrates analyzeBeforeSign against the live SolSentry API using a plain
// list of program IDs (no @solana/web3.js needed).
import { SolSentryGuard } from "../dist/index.js";

const guard = new SolSentryGuard({ clientId: "guard-example" });

// A transaction touching Jupiter v6 + System + ATA (the infra ones are skipped).
const programIds = [
  "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
  "11111111111111111111111111111111",
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
];

const advice = await guard.analyzeBeforeSign({ programIds });

console.log("programs analyzed:", advice.programs);
console.log("verdict:", advice.verdict, "risk:", advice.risk_score);
console.log("shouldBlock:", advice.shouldBlock);
console.log("summary:", advice.summary);
