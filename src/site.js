import { establishPrimitive } from "./webkit.js";
import { installWindowP } from "./utils/mem.js";

const output = document.getElementById("console");

function writeLog(message, type = "log", replace = false) {
  let line = replace ? output.lastElementChild : null;
  if (!line) {
    line = document.createElement("div");
    output.appendChild(line);
  }
  let marker = "*";
  if (type === "error") marker = "-";
  if (type === "info" || type === "success") marker = "+";
  line.textContent = `[${marker}] ${message}`;
  line.className = type === "log" ? "" : "log-" + type;
  /* keep the console bounded during long retry loops */
  while (output.childElementCount > 400)
    output.removeChild(output.firstElementChild);
  output.scrollTop = output.scrollHeight;
}

function writeEvent(name, detail, type) {
  writeLog(detail == null || detail === "" ? name : `${name}: ${detail}`,
    type || (name === "Failed" ? "error" : "log"));
}

window.writeLog = writeLog;
window.jb = { mark: writeEvent };

/* Kick off the PS5 storage cache immediately: elfldr AND pldmgr (plus the
 * kexp shellcode) are mirrored into localStorage the moment the page opens,
 * before any exploit stage runs - so repeat runs need zero network. */
function preloadSiteData() {
  if (!window.PS5PayloadCache || !window.PS5PayloadCache.preloadAll) return;
  Promise.resolve(window.PS5PayloadCache.preloadAll(writeLog)).catch(() => {});
}

/* Best-effort offline caching of the site itself: a service worker keeps
 * every page asset inside the PS5 webkit cache so the page opens instantly
 * and keeps working without the network. Plain-http hosting has no service
 * worker support - there the localStorage payload cache + HTTP cache
 * headers still apply. */
function registerServiceWorker() {
  try {
    if (!navigator.serviceWorker) return;
    navigator.serviceWorker.register("./sw.js")
      .then(() => writeLog("site cached to the PS5 webkit (service worker active)", "info"))
      .catch(() => {});
  } catch (e) { /* unsupported - ignore */ }
}

const OFFSETS_CACHE_DAYS = 7;

/* Offsets are cached in PS5 browser storage (localStorage) so repeat runs and
 * offline runs do not need the network. A stale cache is refreshed in the
 * background window below; if the network fetch fails we fall back to cache. */
function offsetsCacheFresh(entry) {
  if (!entry || !entry.time) return false;
  const age = Date.now() - entry.time;
  return age >= 0 && age < OFFSETS_CACHE_DAYS * 24 * 60 * 60 * 1000;
}

async function loadOffsets(fw) {
  const key = "relapse:offsets:" + fw;
  let entry = null;
  try {
    entry = JSON.parse(localStorage.getItem(key) || "null");
  } catch (e) { /* storage unavailable */ }

  if (offsetsCacheFresh(entry) && entry.text) {
    const script = document.createElement("script");
    script.textContent = entry.text;
    document.body.appendChild(script);
    writeLog(`offsets FW ${fw} loaded from PS5 storage cache`, "info");
    return;
  }

  let text = null;
  try {
    const response = await fetch(`offsets/${fw}.js`);
    if (!response.ok)
      throw new Error(`offsets/${fw}.js returned HTTP ${response.status}`);
    text = await response.text();
  } catch (e) {
    if (entry && entry.text) {
      writeLog(`offsets fetch failed (${e.message}) - using stale PS5 storage cache`, "info");
      text = entry.text;
    } else {
      throw e;
    }
  }

  const script = document.createElement("script");
  script.textContent = text;
  document.body.appendChild(script);

  if (typeof window.KRW !== "object" || !window.KRW) {
    const cached = entry && entry.text;
    if (cached) {
      writeLog(`offsets FW ${fw} look wrong - falling back to cached copy`, "info");
      document.body.removeChild(script);
      const fallback = document.createElement("script");
      fallback.textContent = cached;
      document.body.appendChild(fallback);
      if (typeof window.KRW !== "object")
        throw new Error(`offsets/${fw}.js did not define window.KRW`);
    } else {
      throw new Error(`offsets/${fw}.js did not define window.KRW`);
    }
  }

  try {
    localStorage.setItem(key, JSON.stringify({ time: Date.now(), text }));
    writeLog(`offsets FW ${fw} cached to PS5 storage for offline runs`, "info");
  } catch (e) { /* storage full or unavailable - HTTP cache still applies */ }
}

async function getPrimitive() {
  writeLog("Starting WebKit exploit");
  const primitive = installWindowP(await establishPrimitive(writeEvent));
  if (!primitive || typeof primitive.read8 !== "function")
    throw new Error("Memory primitive unavailable");

  writeLog("ARW ready", "success");
  return primitive;
}

function getWebKitBase() {
  const ctor = globalThis.__ps5NativeCtor;
  if (typeof ctor !== "number" || typeof OFFSET_wk_host_constructor_candidates === "undefined")
    throw new Error("WebKit base inputs are unavailable");

  for (const offset of OFFSET_wk_host_constructor_candidates) {
    const base = ctor - offset;
    if (base >= 0x800000000 && base < 0x900000000 && base % 0x4000 === 0)
      return base;
  }

  throw new Error("WebKit base not found");
}

/* ------------------------------------------------------------------
 * Page boot. Nothing here runs the exploit: the chain waits for the
 * Start button (or a payload card tap, which queues + auto-starts).
 * ------------------------------------------------------------------ */
async function initPage() {
  if (window.RelapseUI) window.RelapseUI.init();

  const rejection = window.firmware.rejection();
  if (rejection) throw new Error(rejection);

  writeLog("Credits: Sonic_Iso, Jordy, ntfargo, ufm42, Dr. Yenyen, TheFlow, SlidyBat, Flatz, cow, nhk, bollarz, Sleirsgoevy, EchoStretch, EarthOnion", "info");
  preloadSiteData();
  registerServiceWorker();
  writeLog(`Agent: ${navigator.userAgent}`, "info");
  writeLog(`Firmware: ${window.fw_str}`, "info");
  await loadOffsets(window.fw_str);

  const versions = window.PS5_PAYLOAD_ENTRIES || {};
  writeLog("Payloads: kexp v" + ((versions.kexp || {}).version || "2026-05-25") +
    " runs first, elfldr v" + ((versions.elfldr || {}).version || "13.60") +
    " starts on port 9021, pldmgr v" + ((versions.pldmgr || {}).version || "0.6.3") +
    " is injected straight into it (all saved to PS5 storage)", "info");
  writeLog("press Start Jailbreak - or tap any payload to jailbreak and send it in one go", "info");

  if (window.RelapseUI) window.RelapseUI.setState("idle");
}

/* The start button / payload-card entry point. Runs the full chain:
 * webkit exploit -> kernel exploit -> elfldr -> pldmgr (or the queued
 * payloads). main() flips the session to "ready" when the loader is up. */
window.startExploit = async function () {
  const session = window.RelapseSession;
  if (!session || session.state === "starting" || session.state === "running")
    return;
  if (session.state === "ready") {
    writeLog("the payload loader is already up - just tap a payload", "info");
    return;
  }

  try {
    session.state = "starting";
    if (window.RelapseUI) {
      window.RelapseUI.showExploitScreen();
      window.RelapseUI.setState("starting");
    }
    const primitive = await getPrimitive();
    writeLog(`WebKit base: 0x${getWebKitBase().toString(16)}`, "info");
    session.state = "running";
    if (window.RelapseUI) window.RelapseUI.setState("running");
    await import("./relapse_exploit.js");
    await main(primitive);
  } catch (error) {
    session.state = "failed";
    if (window.RelapseUI)
      window.RelapseUI.setState("failed",
        error instanceof Error ? error.message : String(error));
    writeLog(error instanceof Error ? error.message : String(error), "error");
    writeLog("press Retry to run the jailbreak again", "info");
  }
};

initPage().catch((error) => {
  if (window.RelapseUI)
    window.RelapseUI.setState("failed",
      error instanceof Error ? error.message : String(error));
  writeLog(error instanceof Error ? error.message : String(error), "error");
});
