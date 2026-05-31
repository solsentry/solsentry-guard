import type { SignAdvice } from "@solsentry/guard";

export type Msg =
  | { type: "ANALYZE_TX"; id: string; programIds: string[] }
  | { type: "ANALYZE_TX_RESULT"; id: string; advice?: SignAdvice; error?: string }
  | { type: "GET_RECENT" }
  | { type: "GET_RECENT_RESULT"; items: RecentEntry[] }
  | { type: "TOGGLE_ENABLED"; enabled: boolean };

export interface RecentEntry {
  ts: number;
  origin: string;
  verdict: SignAdvice["verdict"];
  risk_score: number;
  shouldBlock: boolean;
  summary: string;
  programs: string[];
}

export const PAGE_BRIDGE_EVENT = "__solsentry_guard_bridge__";
