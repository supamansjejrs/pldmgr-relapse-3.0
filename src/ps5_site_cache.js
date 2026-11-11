/* PS5 site cache - the webkit-autoloader flow for this site, on port 12423.
 *
 * One tap on "Cache site to PS5" (payload manager) writes the whole website
 * to console storage (/data/relapse-site) through ROP syscalls - the browser
 * process is root and sandbox-escaped at that point, so open/write/close/
 * mkdir work exactly like the socket writes in src/inject.js do. The sitesrv
 * payload then serves that folder on the console itself
 * (http://localhost:12423), fully offline, and after every jailbreak this
 * module starts it again from console storage through elfldr's file: URI
 * hand-over - no PC, no internet, nothing external.
 *
 * Everything is DOM-optional so the module also runs inside the Node test
 * harness (scripts/test_ps5_cache.mjs) with mocked p/chain.
 */
(function () {
"use strict";

var DOCROOT = "/data/relapse-site";
var SITE_PORT = 12423;
var SITESRV_REL = "payloads/sitesrv.elf";
var SITESRV_URI = "file:" + DOCROOT + "/" + SITESRV_REL;

/* FreeBSD open(2) flags: O_WRONLY|O_CREAT|O_TRUNC */
var OPEN_FLAGS = 0x1 | 0x200 | 0x400;
var FILE_MODE = 420;  /* 0644 */
var DIR_MODE = 493;   /* 0755 */
var WRITE_CHUNK = 0x40000; /* 256 KiB per write syscall, like inject.js */

/* syscall numbers - defined by src/utils/syscalls.js in the page, by the
 * test harness in Node; keep the fallbacks identical either way. */
var N_OPEN = (typeof SYS_OPEN !== "undefined") ? SYS_OPEN : 0x005;
var N_WRITE = (typeof SYS_WRITE !== "undefined") ? SYS_WRITE : 0x004;
var N_CLOSE = (typeof SYS_CLOSE !== "undefined") ? SYS_CLOSE : 0x006;
var N_MKDIR = (typeof SYS_MKDIR !== "undefined") ? SYS_MKDIR : 0x088;

function hasSyscall(p, number) {
  return !!(p && p.syscalls && p.syscalls[number]);
}

/* Same contract as inject.js: a thrown error is flattened into a bogus
 * negative return the loops can retry or report. */
async function safeSyscall(chain, number) {
  var args = Array.prototype.slice.call(arguments, 2);
  try {
    return await chain.syscall.apply(chain, [number].concat(args));
  } catch (e) {
    return { low: 0xfffffff6, hi: 0 }; /* -10 (fake errno) */
  }
}

/* True when this very page is being served by sitesrv on the console. */
function isPs5Served() {
  try {
    return typeof location !== "undefined" &&
      (location.hostname === "localhost" || location.hostname === "127.0.0.1") &&
      location.port === String(SITE_PORT);
  } catch (e) {
    return false;
  }
}

function human(bytes) {
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + " MB";
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + " KB";
  return bytes + " B";
}

function utf8Bytes(str) {
  if (typeof TextEncoder !== "undefined" && TextEncoder)
    return new Uint8Array(new TextEncoder().encode(str));
  var out = [];
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
  }
  return new Uint8Array(out);
}

/* Site asset bytes. Text assets come from the localStorage mirror when it
 * is populated (works fully offline on a plain-http host), else from the
 * network. Binaries resolve through the payload cache (embedded base64 ->
 * localStorage -> network), so elfldr/kexp/sitesrv never need the network
 * once the page has opened on this origin. */
async function fetchText(path) {
  if (typeof window !== "undefined" && window.__RELAPSE_ASSET_TEXT__) {
    var stored = window.__RELAPSE_ASSET_TEXT__(path);
    if (typeof stored === "string" && stored.length) return stored;
  }
  var response = await fetch(path);
  if (!response.ok) throw new Error(path + " returned HTTP " + response.status);
  return await response.text();
}

async function fetchBinary(path) {
  var response = await fetch(path);
  if (!response.ok) throw new Error(path + " returned HTTP " + response.status);
  return new Uint8Array(await response.arrayBuffer());
}

/* Payload-registry name for a payloads/ path ("payloads/sitesrv.elf" ->
 * "sitesrv"), so cacheSite reuses the embedded copies instead of fetching. */
function registryNameFor(relPath) {
  var reg = (typeof window !== "undefined" && window.PS5_PAYLOAD_ENTRIES) || {};
  var rel = relPath.replace(/^\.\//, "");
  for (var name in reg)
    if (reg[name] && reg[name].fallbackUrl === rel) return name;
  return null;
}

async function resolveBinary(relPath, say) {
  var name = registryNameFor(relPath);
  if (name && typeof window !== "undefined" && window.PS5PayloadCache &&
      window.PS5PayloadCache.resolve) {
    try {
      return await window.PS5PayloadCache.resolve(window.PS5_PAYLOAD_ENTRIES[name], say);
    } catch (e) { /* fall through to a plain fetch */ }
  }
  return await fetchBinary(relPath);
}

/* The canonical file list lives in src/site_files.js (generated). */
function fileList() {
  var meta = (typeof window !== "undefined" && window.SITE_FILES) ||
    { text: [], binaries: [] };
  var files = [];
  ((meta.text || []).concat(meta.binaries || [])).forEach(function (path) {
    files.push({ path: path, binary: /\.(elf|bin)$/i.test(path) });
  });
  return files;
}

function ps5Path(relPath) {
  return DOCROOT + "/" + relPath.replace(/^\.\//, "");
}

/* Every parent directory of an absolute path: /a/b/c.js -> /a, /a/b. */
function parentDirs(absPath) {
  var out = [];
  var parts = absPath.split("/");
  parts.pop(); /* the file name */
  var current = "";
  for (var i = 1; i < parts.length; i++) {
    current += "/" + parts[i];
    out.push(current);
  }
  return out;
}

/* mkdir -p every parent directory of the file list (EEXIST is ignored). */
async function ensureDirs(p, chain, files, say) {
  var dirs = {};
  files.forEach(function (file) {
    parentDirs(ps5Path(file.path)).forEach(function (dir) { dirs[dir] = 1; });
  });
  var list = Object.keys(dirs).sort();
  for (var i = 0; i < list.length; i++) {
    var ptr = p.stringify(list[i]);
    var rv = (await safeSyscall(chain, N_MKDIR, ptr, DIR_MODE)).low | 0;
    if (rv !== 0 && rv !== -17)
      say("mkdir " + list[i] + " -> errno " + (-rv) + " (continuing)", "info");
  }
}

/* open(O_CREAT|O_TRUNC) -> chunked write() -> close(). Throws with the
 * exact stage + errno on failure. */
async function writeFileBytes(p, chain, relPath, bytes) {
  var path = ps5Path(relPath);
  var pathPtr = p.stringify(path);
  var fd = (await safeSyscall(chain, N_OPEN, pathPtr, OPEN_FLAGS, FILE_MODE)).low | 0;
  if (fd < 0)
    throw new Error("open " + path + " failed (errno " + (-fd) + ")");

  var source = p.read8(p.leakval(bytes).add32(0x10));
  var offset = 0;
  while (offset < bytes.length) {
    var length = Math.min(WRITE_CHUNK, bytes.length - offset);
    var written = (await safeSyscall(chain, N_WRITE, fd, source.add32(offset), length)).low | 0;
    if (written > 0) { offset += written; continue; }
    await safeSyscall(chain, N_CLOSE, fd);
    throw new Error("write " + path + " failed at " + offset + "/" +
      bytes.length + " bytes (errno " + (-written) + ")");
  }
  await safeSyscall(chain, N_CLOSE, fd);
  return bytes.length;
}

/* Write every site file to console storage. Offset files are aggregated
 * into one log line (40 of them); everything else reports per file. */
async function cacheSite(p, chain, say) {
  var s = say || function () {};

  var numbers = [N_OPEN, N_WRITE, N_CLOSE, N_MKDIR];
  for (var n = 0; n < numbers.length; n++)
    if (!hasSyscall(p, numbers[n]))
      throw new Error("this firmware does not expose the file syscalls needed to cache the site (open/write/close/mkdir)");

  var files = fileList();
  if (!files.length)
    throw new Error("the site file list is empty - src/site_files.js is missing");

  /* sitesrv itself must be resolvable first: without it the cache would be
   * a folder the console can never serve. */
  var sitesrvBytes = await resolveBinary(SITESRV_REL, s);
  if (!sitesrvBytes || sitesrvBytes.length < 0x40)
    throw new Error("sitesrv.elf is missing on this host - build it (sitesrv-src/README.md), put it in payloads/, redeploy the site, then try again");

  s("caching " + files.length + " site files to " + DOCROOT + " on the PS5...", "info");
  await ensureDirs(p, chain, files, s);

  var count = 0, total = 0, failures = 0, quietCount = 0, quietBytes = 0;
  for (var i = 0; i < files.length; i++) {
    var file = files[i];
    var bytes = null;
    try {
      if (file.path === "./" + SITESRV_REL) {
        bytes = sitesrvBytes;
      } else if (file.binary) {
        bytes = await resolveBinary(file.path, s);
      } else {
        bytes = utf8Bytes(await fetchText(file.path));
      }
      var size = await writeFileBytes(p, chain, file.path, bytes);
      count++; total += size;
      if (/^\.\/offsets\//.test(file.path)) {
        quietCount++; quietBytes += size; /* logged as one line below */
      } else {
        s("wrote " + ps5Path(file.path) + " (" + human(size) + ")", "info");
      }
    } catch (e) {
      failures++;
      s("failed to cache " + file.path + ": " +
        (e && e.message ? e.message : e), "error");
    }
  }
  if (quietCount)
    s("wrote " + quietCount + " firmware offset files (" + human(quietBytes) + ")", "info");

  if (failures)
    throw new Error(count + " files cached, " + failures +
      " failed - tap Cache site to PS5 again to retry the rest");
  s("site cached to the PS5: " + count + " files, " + human(total) +
    " -> " + DOCROOT, "success");
  return { files: count, bytes: total };
}

/* Start (or confirm) sitesrv on the console. Already-served pages short-
 * circuit; otherwise the loader is asked to spawn sitesrv.elf from console
 * storage through the file: URI hand-over. */
async function startSitesrv(p, chain, say) {
  var s = say || function () {};
  var inject = (typeof window !== "undefined" && window.RelapseInject) || null;
  if (!inject || !inject.sendUriToLoader)
    throw new Error("the delivery module is unavailable (src/inject.js did not run)");

  if (isPs5Served()) {
    s("this page is already served by your PS5 - sitesrv on port " + SITE_PORT, "success");
    return true;
  }

  if (await inject.probePort(p, chain, SITE_PORT, 4000)) {
    s("sitesrv is already running - the PS5 serves this site on http://localhost:" + SITE_PORT + "/", "success");
    return true;
  }

  var fd;
  try {
    fd = await inject.sendUriToLoader(p, chain, SITESRV_URI, {
      name: "sitesrv", say: s,
    });
  } catch (e) {
    s("could not hand sitesrv to the ELF loader: " +
      (e && e.message ? e.message : e), "error");
    s("tap Cache site to PS5 once (it installs sitesrv.elf to " + DOCROOT +
      ") - after that this starts itself after every jailbreak", "info");
    return false;
  }

  /* Fail fast when elfldr rejects the URI (file missing): its error line
   * arrives on this socket almost immediately, long before a port probe
   * would give up. A quiet 2.5s drain also captures the startup line of a
   * successful spawn, which then shows up in the console. */
  var drained = [];
  await inject.drainPayloadStdout(p, chain, fd, "sitesrv", function (line, type) {
    drained.push(line);
    s(line, type);
  }, 2500);
  if (drained.some(function (line) { return /\[elfldr\.elf\] Error/i.test(line); })) {
    s("sitesrv is not cached on the PS5 yet - tap Cache site to PS5 once to install it", "error");
    return false;
  }

  if (await inject.probePort(p, chain, SITE_PORT, 45000)) {
    s("the PS5 is now serving this site on http://localhost:" + SITE_PORT + "/", "success");
    return true;
  }

  s("sitesrv did not come up on port " + SITE_PORT +
    " - it is probably not cached on the PS5 yet (tap Cache site to PS5 once)", "error");
  return false;
}

async function cacheAndStart(p, chain, say) {
  var s = say || function () {};
  await cacheSite(p, chain, s);
  return await startSitesrv(p, chain, s);
}

/* Visual "you are on the PS5 copy" state, called from src/site.js init. */
function bootBanner() {
  if (typeof document === "undefined" || !isPs5Served()) return;
  var badge = document.querySelector(".brand-badge");
  if (badge) {
    badge.textContent = "served by your PS5 · port " + SITE_PORT;
    badge.style.borderColor = "rgba(74,222,128,.55)";
    badge.style.color = "#4ade80";
  }
  if (typeof window !== "undefined" && typeof window.writeLog === "function")
    window.writeLog("this page is served by your PS5 - sitesrv on port " +
      SITE_PORT + ", files from " + DOCROOT, "success");
}

window.PS5SiteCache = {
  docroot: DOCROOT,
  port: SITE_PORT,
  sitesrvUri: SITESRV_URI,
  isPs5Served: isPs5Served,
  cacheSite: cacheSite,
  startSitesrv: startSitesrv,
  cacheAndStart: cacheAndStart,
  bootBanner: bootBanner,
};
})();
