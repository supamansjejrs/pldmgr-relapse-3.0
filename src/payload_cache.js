/* PS5 payload cache - single source of truth for every binary the exploit
 * auto-loads (elfldr and the kexp shellcode - nothing else runs on its own;
 * every manager payload arrives from the evoX-CoreOS catalog).
 *
 * Resolution order (cache-first, network-last):
 *   1. PS5 localStorage (survives reloads; written the moment the page opens)
 *   2. base64 copy embedded in src/payload_data.js (arrives with the site)
 *   3. network fetch of payloads/<file> (written back to localStorage)
 *
 * preloadAll() is called as soon as the page opens - before the exploit
 * stages - so both binaries are saved to PS5 storage immediately.
 */
(function () {
  "use strict";

  const REGISTRY = [
    { name: "kexp", version: "2026-05-25", fallbackUrl: "payloads/kexp_2026_05_25.bin", cacheKey: "relapse:payload:kexp:2026-05-25" },
    { name: "elfldr", version: "13.60", fallbackUrl: "payloads/elfldr-ps5-1360.elf", cacheKey: "relapse:payload:elfldr:13.60" },
  ];
  window.PS5_PAYLOAD_ENTRIES = {};
  for (const entry of REGISTRY) window.PS5_PAYLOAD_ENTRIES[entry.name] = entry;

  function metaFor(name) {
    return (window.PS5_PAYLOADS && window.PS5_PAYLOADS.meta && window.PS5_PAYLOADS.meta[name]) || null;
  }

  function b64ToBytes(b64) {
    const raw = atob(b64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes;
  }

  function bytesToBase64(bytes) {
    let binary = "";
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK)
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    return btoa(binary);
  }

  async function sha256Hex(bytes) {
    if (!window.crypto || !window.crypto.subtle || !window.crypto.subtle.digest) return null;
    try {
      const digest = await window.crypto.subtle.digest("SHA-256", bytes);
      return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch (e) {
      return null;
    }
  }

  function isElf(bytes) {
    return bytes.length > 0x40 && bytes[0] === 0x7f && bytes[1] === 0x45 &&
      bytes[2] === 0x4c && bytes[3] === 0x46;
  }

  /* Validate decoded bytes against the embedded meta: exact byte count, ELF
   * magic where applicable, sha256 when the platform can compute it (plain
   * http hosting has no crypto.subtle - count + magic still apply). */
  async function validate(name, bytes) {
    const meta = metaFor(name);
    if (meta && bytes.length !== meta.bytes) return false;
    if (name !== "kexp" && !isElf(bytes)) return false;
    if (meta && meta.sha256) {
      const sha = await sha256Hex(bytes);
      if (sha && sha !== meta.sha256) return false;
    }
    return true;
  }

  function readCache(entry) {
    try {
      return JSON.parse(localStorage.getItem(entry.cacheKey) || "null");
    } catch (e) {
      return null;
    }
  }

  function cacheLooksValid(entry, cached) {
    if (!cached || typeof cached.b64 !== "string" || cached.b64.length < 16) return false;
    const meta = metaFor(entry.name);
    if (meta && cached.bytes !== meta.bytes) return false;
    if (meta && meta.sha256 && cached.sha && cached.sha !== meta.sha256) return false;
    return true;
  }

  /* Persist one payload. Accepts {b64} (no decode needed - the embedded copy
   * is stored as-is) or {bytes} (network download). */
  function writeCache(entry, source, say) {
    try {
      const b64 = source.b64 || bytesToBase64(source.bytes);
      const meta = metaFor(entry.name);
      const size = meta ? meta.bytes : (source.bytes ? source.bytes.length : b64.length);
      localStorage.setItem(entry.cacheKey, JSON.stringify({
        b64: b64,
        bytes: meta ? meta.bytes : size,
        sha: meta ? meta.sha256 : null,
        time: Date.now(),
      }));
      if (say) say(entry.name + " v" + entry.version + " saved to PS5 storage (" + size + " bytes)", "info");
      return true;
    } catch (e) {
      if (say) say("PS5 storage is full - " + entry.name + " keeps using its in-memory copy", "info");
      return false;
    }
  }

  async function fetchBytes(entry) {
    const response = await fetch(entry.fallbackUrl);
    if (!response.ok) throw new Error(entry.fallbackUrl + " returned HTTP " + response.status);
    return new Uint8Array(await response.arrayBuffer());
  }

  /* Immediately mirror every payload into localStorage. Called at page open,
   * before the exploit runs. Already-cached entries are detected by meta
   * comparison only - no decode - so repeat loads stay instant. */
  async function preloadAll(say) {
    for (const entry of REGISTRY) {
      try {
        const cached = readCache(entry);
        if (cacheLooksValid(entry, cached)) {
          if (say) say(entry.name + " v" + entry.version + " already in PS5 storage", "info");
          continue;
        }
        const b64 = window.PS5_PAYLOADS && window.PS5_PAYLOADS.b64 && window.PS5_PAYLOADS.b64[entry.name];
        if (b64) {
          writeCache(entry, { b64: b64 }, say);
          continue;
        }
        const bytes = await fetchBytes(entry);
        if (await validate(entry.name, bytes)) writeCache(entry, { bytes: bytes }, say);
      } catch (e) {
        if (say) say(entry.name + " preload failed: " + (e && e.message ? e.message : e), "info");
      }
    }
  }

  /* Cache-first resolver used by the exploit stages. */
  async function resolve(entry, say) {
    const cached = readCache(entry);
    if (cacheLooksValid(entry, cached)) {
      try {
        const bytes = b64ToBytes(cached.b64);
        if (await validate(entry.name, bytes)) {
          if (say) say(entry.name + " v" + entry.version + " loaded from PS5 storage cache", "info");
          return bytes;
        }
      } catch (e) { /* corrupt entry - fall through to embedded copy */ }
    }

    const b64 = window.PS5_PAYLOADS && window.PS5_PAYLOADS.b64 && window.PS5_PAYLOADS.b64[entry.name];
    if (b64) {
      const bytes = b64ToBytes(b64);
      if (!(await validate(entry.name, bytes)))
        throw new Error(entry.name + " embedded copy failed validation");
      if (say) say(entry.name + " v" + entry.version + " loaded from the site bundle", "info");
      writeCache(entry, { b64: b64 }, say);
      return bytes;
    }

    const bytes = await fetchBytes(entry);
    if (!(await validate(entry.name, bytes)))
      throw new Error(entry.name + " download failed validation");
    writeCache(entry, { bytes: bytes }, say);
    return bytes;
  }

  window.PS5PayloadCache = { preloadAll: preloadAll, resolve: resolve, b64ToBytes: b64ToBytes };
})();
