import type { Msg, RecentEntry } from "../shared/messages.js";

const enabledEl = document.getElementById("enabled") as HTMLInputElement;
const recentEl = document.getElementById("recent")!;

async function init() {
  const { enabled = true } = await chrome.storage.local.get("enabled");
  enabledEl.checked = enabled;
  enabledEl.addEventListener("change", async () => {
    await chrome.runtime.sendMessage<Msg>({
      type: "TOGGLE_ENABLED",
      enabled: enabledEl.checked,
    });
  });

  const res = await chrome.runtime.sendMessage<Msg>({ type: "GET_RECENT" });
  render(res.items ?? []);
}

function render(items: RecentEntry[]) {
  if (!items.length) {
    recentEl.innerHTML = '<div class="empty">No recent verdicts yet.</div>';
    return;
  }
  recentEl.innerHTML = items
    .slice(0, 20)
    .map(
      (it) => `
        <div class="item">
          <span class="verdict ${it.verdict}">${it.verdict}</span>
          <span style="font-size:11px;color:#666;">risk ${it.risk_score}</span>
          <div class="summary">${escape(it.summary)}</div>
          <div class="origin">${escape(originHost(it.origin))} · ${timeAgo(it.ts)}</div>
        </div>
      `,
    )
    .join("");
}

function escape(s: string) {
  return s.replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" })[c]!);
}

function originHost(o: string) {
  try {
    return new URL(o).host;
  } catch {
    return o;
  }
}

function timeAgo(ts: number) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

init();
