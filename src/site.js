/* Relapse site boot - classic script (loaded last by the bootstrap in
 * index.html) so the page stays loadable from PS5 localStorage on plain-http
 * hosts, where module imports cannot be served from storage.
 *
 * Page boot does NOT run the exploit: the chain waits for the Start button
 * (or a payload card tap, which queues + auto-starts). */
(function () {
"use strict";

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

/* Kick off the PS5 storage cache immediately: the kexp shellcode and elfldr
 * are mirrored into localStorage the moment the page opens - before any
 * exploit stage runs - so repeat runs need zero network. */
function preloadSiteData() {
  if (!window.PS5PayloadCache || !window.PS5PayloadCache.preloadAll) return;
  Promise.resolve(window.PS5PayloadCache.preloadAll(writeLog)).catch(() => {});
}

/* Service workers only exist on secure origins (https / localhost). On a
 * self-hosted plain-http origin (e.g. http://<pc-ip>:12423) the bootstrap in
 * index.html mirrors every site asset into PS5 localStorage instead and
 * serves the next visit straight from it - report which mode is active. */
function swCapableOrigin() {
  return location.protocol === "https:" ||
    location.hostname === "127.0.0.1" ||
    location.hostname === "localhost" ||
    location.hostname === "[::1]";
}

function reportCacheMode() {
  const port = location.port || (location.protocol === "https:" ? "443" : "80");
  const mode = window.__RELAPSE_CACHE_STATE__;
  if (mode === "offline")
    writeLog("site served from the PS5 offline copy on port " + port +
      " - no server contact needed", "info");
  else if (mode === "populating")
    writeLog("saving this site to the PS5 (port " + port +
      ") - it will open without the server from now on", "info");
}

function registerServiceWorker() {
  if (!swCapableOrigin()) {
    reportCacheMode();
    return;
  }
  try {
    if (!navigator.serviceWorker) {
      reportCacheMode();
      return;
    }
    navigator.serviceWorker.register("./sw.js")
      .then(() => writeLog("site cached to the PS5 webkit (service worker active)", "info"))
      .catch(() => reportCacheMode());
  } catch (e) { /* unsupported - the bootstrap cache still applies */ }
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
  const primitive = window.RelapseMem.installWindowP(
    await window.RelapseWebKit.establishPrimitive(writeEvent));
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
  /* "served by your PS5" badge + console line when sitesrv (port 12423)
   * is the host - the webkit-autoloader end state. */
  if (window.PS5SiteCache && window.PS5SiteCache.bootBanner)
    window.PS5SiteCache.bootBanner();
  writeLog(`Agent: ${navigator.userAgent}`, "info");
  writeLog(`Firmware: ${window.fw_str}`, "info");
  await loadOffsets(window.fw_str);

  const versions = window.PS5_PAYLOAD_ENTRIES || {};
  writeLog("Payloads: kexp v" + ((versions.kexp || {}).version || "2026-05-25") +
    " runs first, elfldr v" + ((versions.elfldr || {}).version || "13.60") +
    " is the only thing auto-loaded (port 9021, saved to PS5 storage)", "info");
  writeLog("press Start Jailbreak - or tap any payload to jailbreak and send it in one go", "info");

  if (window.RelapseUI) window.RelapseUI.setState("idle");
}

/* The start button / payload-card entry point. Runs the full chain:
 * webkit exploit -> kernel exploit -> elfldr. Nothing is auto-sent after
 * that - main() flips the session to "ready" and every payload (pldmgr
 * included, from the evoX catalog) is one tap away in the manager. */
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
})();
