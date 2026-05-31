import { SolSentryGuard } from "@solsentry/guard";
import type { Msg, RecentEntry } from "../shared/messages.js";

const guard = new SolSentryGuard({
  clientId: "chrome-extension",
});

const CACHE_TTL_MS = 5 * 60 * 1000;
const RECENT_CAP = 50;
const cache = new Map<string, { advice: unknown; expires: number }>();

async function loadRecent(): Promise<RecentEntry[]> {
  const { recent = [] } = await chrome.storage.local.get("recent");
  return recent as RecentEntry[];
}

async function pushRecent(entry: RecentEntry) {
  const recent = await loadRecent();
  recent.unshift(entry);
  if (recent.length > RECENT_CAP) recent.length = RECENT_CAP;
  await chrome.storage.local.set({ recent });
}

async function isEnabled(): Promise<boolean> {
  const { enabled = true } = await chrome.storage.local.get("enabled");
  return enabled as boolean;
}

chrome.runtime.onMessage.addListener((msg: Msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "ANALYZE_TX") {
      if (!(await isEnabled())) {
        sendResponse({ type: "ANALYZE_TX_RESULT", id: msg.id });
        return;
      }
      const key = msg.programIds.slice().sort().join("|");
      const hit = cache.get(key);
      let advice;
      if (hit && hit.expires > Date.now()) {
        advice = hit.advice;
      } else {
        try {
          advice = await guard.analyzeBeforeSign({ programIds: msg.programIds });
          cache.set(key, { advice, expires: Date.now() + CACHE_TTL_MS });
        } catch (err) {
          sendResponse({
            type: "ANALYZE_TX_RESULT",
            id: msg.id,
            error: err instanceof Error ? err.message : String(err),
          });
          return;
        }
      }
      const a = advice as Awaited<ReturnType<typeof guard.analyzeBeforeSign>>;
      await pushRecent({
        ts: Date.now(),
        origin: sender.origin ?? sender.tab?.url ?? "unknown",
        verdict: a.verdict,
        risk_score: a.risk_score,
        shouldBlock: a.shouldBlock,
        summary: a.summary,
        programs: a.programs,
      });
      sendResponse({ type: "ANALYZE_TX_RESULT", id: msg.id, advice: a });
    } else if (msg.type === "GET_RECENT") {
      sendResponse({ type: "GET_RECENT_RESULT", items: await loadRecent() });
    } else if (msg.type === "TOGGLE_ENABLED") {
      await chrome.storage.local.set({ enabled: msg.enabled });
      sendResponse({ ok: true });
    }
  })();
  return true;
});
