import { extractProgramIds } from "@solsentry/guard";
import { PAGE_BRIDGE_EVENT } from "../shared/messages.js";

declare global {
  interface Window {
    solana?: any;
  }
}

let nextId = 1;
function call(programIds: string[]): Promise<any> {
  const id = String(nextId++);
  return new Promise((resolve) => {
    const handler = (event: MessageEvent) => {
      const d = event.data;
      if (!d || d.__source !== PAGE_BRIDGE_EVENT) return;
      if (d.type !== "ANALYZE_TX_RESULT" || d.id !== id) return;
      window.removeEventListener("message", handler);
      resolve(d.advice);
    };
    window.addEventListener("message", handler);
    window.postMessage(
      { __source: PAGE_BRIDGE_EVENT, type: "ANALYZE_TX", id, programIds },
      "*",
    );
  });
}

function renderBlockModal(summary: string): Promise<boolean> {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    host.style.cssText = "position:fixed;inset:0;z-index:2147483647;";
    const shadow = host.attachShadow({ mode: "closed" });
    shadow.innerHTML = `
      <style>
        .backdrop{position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}
        .card{background:#0a0a0a;color:#fafafa;border:1px solid #1f1f1f;border-radius:12px;padding:24px;max-width:480px;}
        h2{margin:0 0 8px;font-size:18px;color:#ff4d4d;}
        p{margin:0 0 16px;line-height:1.5;color:#cfcfcf;}
        .actions{display:flex;gap:8px;justify-content:flex-end;}
        button{padding:8px 14px;border-radius:8px;border:1px solid #1f1f1f;background:#1f1f1f;color:#fafafa;cursor:pointer;font-size:13px;}
        button.danger{background:#ff4d4d;color:#0a0a0a;border-color:#ff4d4d;}
      </style>
      <div class="backdrop">
        <div class="card">
          <h2>SolSentry Guard — DANGEROUS</h2>
          <p>${summary.replace(/[<>]/g, "")}</p>
          <div class="actions">
            <button id="cancel">Cancel signing</button>
            <button id="proceed" class="danger">Sign anyway</button>
          </div>
        </div>
      </div>
    `;
    document.documentElement.appendChild(host);
    shadow.getElementById("cancel")!.addEventListener("click", () => {
      host.remove();
      resolve(false);
    });
    shadow.getElementById("proceed")!.addEventListener("click", () => {
      host.remove();
      resolve(true);
    });
  });
}

function wrap(provider: any) {
  if (!provider || provider.__solsentryWrapped) return provider;
  const origSign = provider.signTransaction?.bind(provider);
  const origSignAll = provider.signAllTransactions?.bind(provider);

  if (origSign) {
    provider.signTransaction = async (tx: any) => {
      try {
        const programIds = extractProgramIds(tx);
        if (programIds.length) {
          const advice = await call(programIds);
          if (advice?.shouldBlock) {
            const proceed = await renderBlockModal(advice.summary);
            if (!proceed) throw new Error("Cancelled by SolSentry Guard");
          }
        }
      } catch (err) {
        if (err instanceof Error && err.message.includes("SolSentry Guard")) throw err;
      }
      return origSign(tx);
    };
  }

  if (origSignAll) {
    provider.signAllTransactions = async (txs: any[]) => {
      try {
        const programIds = txs.flatMap((tx) => extractProgramIds(tx));
        if (programIds.length) {
          const advice = await call([...new Set(programIds)]);
          if (advice?.shouldBlock) {
            const proceed = await renderBlockModal(advice.summary);
            if (!proceed) throw new Error("Cancelled by SolSentry Guard");
          }
        }
      } catch (err) {
        if (err instanceof Error && err.message.includes("SolSentry Guard")) throw err;
      }
      return origSignAll(txs);
    };
  }

  provider.__solsentryWrapped = true;
  return provider;
}

if (window.solana) wrap(window.solana);

let _solana = window.solana;
Object.defineProperty(window, "solana", {
  configurable: true,
  get() {
    return _solana;
  },
  set(v) {
    _solana = wrap(v);
  },
});
