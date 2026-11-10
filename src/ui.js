/* Relapse UI - WebKitty-inspired initial screen + exploit screen with the
 * built-in payload manager.
 *
 * Plain script (no imports) so it evaluates before site.js and works in the
 * PS5 webkit without module support in the UI layer. Everything it needs:
 *   - window.PS5_PAYLOAD_CATALOG  (src/payload_catalog.js, embedded list)
 *   - window.startExploit         (set by src/site.js - starts the chain)
 *   - window.RelapseDeliver       (set by src/main.js after elfldr is up)
 *   - window.writeLog             (set by src/site.js)
 *
 * Card clicks before the jailbreak queue the payload and auto-start the
 * exploit; once the loader is up, src/main.js flushes the queue. After that
 * every click delivers straight through the live ROP session.
 */
(function () {
  "use strict";

  /* session registry - main.js fills in p/chain and flips state to "ready" */
  window.RelapseSession = window.RelapseSession || {
    state: "idle", /* idle | starting | running | ready | failed */
    pending: [],   /* {type:"catalog", entry} | {type:"custom", name, bytes} */
    p: null,
    chain: null,
  };

  var TABS = [
    { id: "all", label: "All" },
    { id: "homebrew", label: "Homebrew" },
    { id: "tools", label: "Tools" },
    { id: "loaders", label: "Loaders" },
    { id: "servers", label: "Servers" },
    { id: "debug", label: "Debug" },
    { id: "custom", label: "Custom" },
  ];

  var GROUP_COLORS = {
    homebrew: "#22c55e",
    tools: "#22d3ee",
    loaders: "#a78bfa",
    servers: "#60a5fa",
    debug: "#fb923c",
  };

  /* same mapping the build script uses, applied to entries fetched live */
  var PATH_CATEGORY = {
    "ps5_audio_utility": "PS5 Audio Utility", "PS5_Activation": "PS5 Activation",
    "PS5_Beta": "PS5 Beta", "PS5_Cheat": "PS5 Cheat", "ps5_dns": "PS5 Dns",
    "ps5_emulator": "PS5 Emulator", "ps5_fan": "PS5 Fan",
    "ps5_file_explorer": "PS5 File Explorer", "ps5_freeshop": "PS5 Freeshop",
    "ps5_game_dump": "PS5 Game Dump", "ps5_hen_loader": "PS5 HEN Loader",
    "ps5_kstuff": "PS5 Kstuff", "ps5_linux": "PS5 Linux",
    "ps5_pad_utility": "PS5 Pad Utility", "ps5_pkg_tool": "PS5 Pkg Tool",
    "ps5_remote": "PS5 Remote", "PS5_Overlay": "PS5 Overlay",
    "ps5_sdk_debug": "PS5 Sdk Debug", "ps5_server": "PS5 Server",
    "ps5_themes-avatars": "PS5 Themes-Avatars", "ps5_utility": "PS5 Utility",
    "ps5_video_player": "PS5 Video Player",
    "ps5-webkit-autoloader": "Ps5-Webkit-Autoloader",
  };
  var CATEGORY_GROUP = {
    "PS5 Emulator": "homebrew", "PS5 Video Player": "homebrew",
    "PS5 Audio Utility": "homebrew", "PS5 Themes-Avatars": "homebrew",
    "PS5 Freeshop": "homebrew", "PS5 Saves": "homebrew",
    "PS5 Cheat": "homebrew", "PS5 Remote": "homebrew",
    "PS5 Activation": "homebrew", "PS5 Utility": "tools",
    "PS5 Pad Utility": "tools", "PS5 Fan": "tools",
    "PS5 File Explorer": "tools", "PS5 Pkg Tool": "tools",
    "PS5 Dns": "tools", "PS5 Game Dump": "tools",
    "PS5 HEN Loader": "loaders", "PS5 Kstuff": "loaders",
    "PS5 Overlay": "loaders", "Ps5-Webkit-Autoloader": "loaders",
    "PS5 Beta": "loaders", "PS5 Linux": "loaders",
    "PS5 Server": "servers", "PS5 Sdk Debug": "debug",
  };
  var FALLBACK_DESC = "R\u00e9cup\u00e9r\u00e9 depuis le stockage local (Interne / Fallback)";
  var EVOX_BASE = "https://nexgen999.github.io/evoX-CoreOS/";

  var activeTab = "all";
  var searchQuery = "";
  var searchTimer = null;
  var started = false;

  function byId(id) { return document.getElementById(id); }
  function say(message, type) {
    if (typeof window.writeLog === "function") window.writeLog(message, type || "log");
  }
  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function catalog() {
    return (window.PS5_PAYLOAD_CATALOG && window.PS5_PAYLOAD_CATALOG.entries) || [];
  }

  /* ------------------------------------------------------------------ */
  /* tabs + cards                                                         */
  /* ------------------------------------------------------------------ */

  function renderTabs() {
    var tabs = byId("tabs");
    if (!tabs) return;
    var counts = { all: catalog().length };
    catalog().forEach(function (e) { counts[e.group] = (counts[e.group] || 0) + 1; });
    tabs.textContent = "";
    TABS.forEach(function (tab) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "tab" + (activeTab === tab.id ? " active" : "");
      button.textContent = tab.label + (counts[tab.id] ? " (" + counts[tab.id] + ")" : "");
      button.onclick = function () {
        activeTab = tab.id;
        renderTabs();
        renderCards();
      };
      tabs.appendChild(button);
    });
  }

  function cardBadge(entry) {
    var color = GROUP_COLORS[entry.group] || "#94a3b8";
    return '<span class="badge" style="color:' + color + ";border-color:" + color + '">' +
      escapeHtml(entry.category) + "</span>";
  }

  function makeCard(entry) {
    var card = document.createElement("button");
    card.type = "button";
    card.className = "card";
    card.setAttribute("aria-label", "Send payload " + entry.name);
    card.innerHTML =
      '<div class="card-head">' +
        '<div><div class="card-name">' + escapeHtml(entry.name) + "</div>" +
        '<div class="card-version">' + escapeHtml(entry.version || "") + "</div></div>" +
        cardBadge(entry) +
      "</div>" +
      '<div class="card-desc">' + escapeHtml(entry.description || "") + "</div>" +
      '<div class="card-foot">via evoX-CoreOS &middot; tap to send</div>';
    card.onclick = function () { onCardClick(entry, card); };
    return card;
  }

  function renderCards() {
    var wrap = byId("cards-wrap");
    var custom = byId("custom-panel");
    if (!wrap) return;

    if (activeTab === "custom") {
      wrap.classList.add("hidden");
      if (custom) custom.classList.remove("hidden");
      return;
    }
    if (custom) custom.classList.add("hidden");
    wrap.classList.remove("hidden");

    var query = searchQuery;
    var visible = catalog().filter(function (e) {
      if (activeTab !== "all" && e.group !== activeTab) return false;
      if (!query) return true;
      return (e.name + " " + (e.version || "") + " " + (e.category || "") + " " +
        (e.description || "")).toLowerCase().indexOf(query) !== -1;
    });

    wrap.textContent = "";
    if (visible.length === 0) {
      var note = document.createElement("div");
      note.className = "empty-note";
      note.textContent = searchQuery
        ? "No payload matches \"" + searchQuery + "\"."
        : "No payloads in this category.";
      wrap.appendChild(note);
      return;
    }
    var fragment = document.createDocumentFragment();
    visible.forEach(function (entry) { fragment.appendChild(makeCard(entry)); });
    wrap.appendChild(fragment);
  }

  /* ------------------------------------------------------------------ */
  /* delivery dispatch                                                    */
  /* ------------------------------------------------------------------ */

  function queueAndMaybeStart(item, label) {
    var session = window.RelapseSession;
    if (!session) return;
    if (session.state === "ready" && window.RelapseDeliver) {
      /* race: the session flipped to ready between the card check and here */
      if (item.type === "custom")
        window.RelapseDeliver.customPayload(item.name, item.bytes);
      else
        window.RelapseDeliver.catalogPayload(item.entry);
      return;
    }
    session.pending.push(item);
    if (session.state === "starting" || session.state === "running") {
      say(label + " queued - it is sent the moment the payload loader is up", "info");
      return;
    }
    say(label + " queued - starting the jailbreak...", "info");
    if (typeof window.startExploit === "function") window.startExploit();
  }

  function onCardClick(entry, card) {
    var session = window.RelapseSession;
    if (session && session.state === "ready" && window.RelapseDeliver) {
      var promise;
      try {
        promise = window.RelapseDeliver.catalogPayload(entry);
      } catch (e) {
        say(entry.name + " could not be sent: " + (e && e.message ? e.message : e), "error");
        return;
      }
      if (promise && typeof promise.finally === "function") {
        card.classList.add("busy");
        promise.finally(function () { card.classList.remove("busy"); });
      }
      return;
    }
    queueAndMaybeStart({ type: "catalog", entry: entry }, entry.name);
  }

  function sendCustom() {
    var input = byId("custom-file");
    var file = input && input.files && input.files[0];
    if (!file) {
      say("choose a .elf payload file first", "error");
      return;
    }
    var reader = new FileReader();
    reader.onload = function () {
      var bytes = new Uint8Array(reader.result);
      var session = window.RelapseSession;
      if (session && session.state === "ready" && window.RelapseDeliver) {
        var promise;
        try {
          promise = window.RelapseDeliver.customPayload(file.name, bytes);
        } catch (e) {
          say(file.name + " could not be sent: " + (e && e.message ? e.message : e), "error");
          return;
        }
        if (promise && typeof promise.finally === "function") promise.finally(function () {});
        return;
      }
      queueAndMaybeStart({ type: "custom", name: file.name, bytes: bytes }, file.name);
    };
    reader.onerror = function () {
      say("could not read " + file.name, "error");
    };
    reader.readAsArrayBuffer(file);
  }

  /* ------------------------------------------------------------------ */
  /* state machine visuals                                                */
  /* ------------------------------------------------------------------ */

  var PILL_TEXT = {
    idle: "ready to start", starting: "starting...", running: "exploit running",
    ready: "payload loader ready", failed: "failed",
  };

  function setState(next, detail) {
    var session = window.RelapseSession;
    if (session) session.state = next;

    var pill = byId("state-pill");
    if (pill) {
      var text = PILL_TEXT[next] || next;
      if (next === "failed" && detail) text += " - " + detail;
      if (text.length > 64) text = text.slice(0, 61) + "...";
      pill.textContent = text;
      pill.className = "pill " + next;
    }

    var startBtn = byId("start-btn");
    if (startBtn) {
      if (next === "starting" || next === "running") {
        startBtn.disabled = true;
        startBtn.textContent = "Jailbreak running...";
      } else if (next === "ready") {
        startBtn.disabled = true;
        startBtn.textContent = "Jailbreak complete";
      } else {
        startBtn.disabled = false;
        startBtn.textContent = next === "failed" ? "Retry Jailbreak" : "Start Jailbreak";
      }
    }

    var runBtn = byId("run-btn");
    if (runBtn) {
      if (next === "ready" || next === "starting" || next === "running") {
        runBtn.classList.add("hidden");
      } else {
        runBtn.classList.remove("hidden");
        runBtn.disabled = next === "starting" || next === "running";
      }
    }

    var fw = byId("initial-fw");
    if (fw) {
      if (next === "failed") {
        fw.textContent = detail || "startup failed";
        fw.className = "bad";
      } else if (window.fw_str) {
        fw.textContent = "Firmware " + window.fw_str + " \u00b7 supported";
        fw.className = "ok";
      }
    }

    var fwLabel = byId("fw-label");
    if (fwLabel && window.fw_str) fwLabel.textContent = "FW " + window.fw_str;

    var hint = byId("payload-hint");
    if (hint) {
      if (next === "ready")
        hint.textContent = "elfldr is listening on port 9021 - tap any payload to send it to the PS5";
      else if (next === "starting" || next === "running")
        hint.textContent = "jailbreak running - queued payloads are sent automatically once the loader is up";
      else
        hint.textContent = "tap a payload to jailbreak and send it in one go (or press Start Jailbreak first)";
    }
  }

  function showExploitScreen() {
    if (started) return;
    started = true;
    var initial = byId("initial-screen");
    var exploit = byId("exploit-screen");
    if (initial) initial.classList.add("hidden");
    if (exploit) exploit.classList.remove("hidden");
  }

  /* ------------------------------------------------------------------ */
  /* live catalog refresh (embedded copy stays the offline fallback)      */
  /* ------------------------------------------------------------------ */

  function normalizeLiveEntry(raw, index) {
    var url = raw.url || (EVOX_BASE + raw.local_path);
    var category = raw.category;
    if (!category) {
      var prefix = (raw.local_path || "").split("/")[1];
      category = PATH_CATEGORY[prefix] || "PS5 Utility";
    }
    var desc = raw.description && raw.description !== FALLBACK_DESC
      ? raw.description
      : category + " payload, hosted by evoX-CoreOS";
    return {
      id: "live" + index,
      name: raw.name,
      version: raw.version || "",
      category: category,
      group: CATEGORY_GROUP[category] || "tools",
      description: desc,
      filename: raw.filename || "payload.elf",
      url: url,
      sha256: raw.checksum || "",
    };
  }

  function refreshCatalog() {
    var meta = window.PS5_PAYLOAD_CATALOG;
    if (!meta || !meta.sourceUrl || typeof fetch !== "function") return;
    var controller = null;
    var timer = setTimeout(function () {
      if (controller && typeof controller.abort === "function") controller.abort();
    }, 8000);
    fetch(meta.sourceUrl).then(function (response) {
      if (!response.ok) throw new Error("HTTP " + response.status);
      return response.json();
    }).then(function (data) {
      clearTimeout(timer);
      if (!data || !data.payloads || !data.payloads.length) return;
      var entries = data.payloads.map(normalizeLiveEntry);
      if (entries.length === catalog().length &&
          JSON.stringify(entries) === JSON.stringify(catalog())) return;
      meta.entries = entries;
      meta.count = entries.length;
      say("payload catalog refreshed from evoX-CoreOS (" + entries.length + " payloads)", "info");
      renderTabs();
      renderCards();
    }).catch(function () {
      clearTimeout(timer);
      /* offline or blocked - the embedded catalog keeps serving */
    });
  }

  /* ------------------------------------------------------------------ */
  /* init                                                                 */
  /* ------------------------------------------------------------------ */

  function init() {
    renderTabs();
    renderCards();

    var search = byId("payload-search");
    if (search) {
      search.oninput = function () {
        var value = search.value;
        if (searchTimer) clearTimeout(searchTimer);
        searchTimer = setTimeout(function () {
          searchQuery = value.trim().toLowerCase();
          renderCards();
        }, 120);
      };
    }

    var startBtn = byId("start-btn");
    if (startBtn) startBtn.onclick = function () { startExploit(); };
    var psStart = byId("ps-start");
    if (psStart) psStart.onclick = function () { startExploit(); };
    var runBtn = byId("run-btn");
    if (runBtn) runBtn.onclick = function () { startExploit(); };
    var customSend = byId("custom-send");
    if (customSend) customSend.onclick = sendCustom;

    setState("idle");
    refreshCatalog();
  }

  function startExploit() {
    if (typeof window.startExploit === "function") window.startExploit();
  }

  window.RelapseUI = {
    init: init,
    setState: setState,
    showExploitScreen: showExploitScreen,
  };
})();
