import { PAGE_BRIDGE_EVENT, type Msg } from "../shared/messages.js";

const url = chrome.runtime.getURL("injected/index.js");
const script = document.createElement("script");
script.src = url;
script.type = "module";
(document.head || document.documentElement).appendChild(script);
script.onload = () => script.remove();

window.addEventListener("message", async (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data.__source !== PAGE_BRIDGE_EVENT) return;

  if (data.type === "ANALYZE_TX") {
    const response = await chrome.runtime.sendMessage<Msg>({
      type: "ANALYZE_TX",
      id: data.id,
      programIds: data.programIds,
    });
    window.postMessage(
      { __source: PAGE_BRIDGE_EVENT, type: "ANALYZE_TX_RESULT", id: data.id, ...response },
      "*",
    );
  }
});
