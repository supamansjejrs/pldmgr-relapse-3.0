/* Payload delivery - direct socket injection into the ELF loader.
 *
 * The kernel exploit leaves the browser process with root privileges, the
 * sandbox escaped and a working ROP chain (relapse_exploit.js already runs
 * socket/read/write syscalls through it). That is everything needed to do
 * exactly what the documented `nc -q0 <ps5> 9021 < payload.elf` does, without
 * touching the browser network stack at all - no mixed-content blocking on
 * https pages, no reliance on the loader's sceHttp client, no webkit quirks.
 *
 * The elfldr wire protocol (ps5-payload-dev socksrv.c, verified line by
 * line): the loader peeks the first four bytes of every connection.
 * 0x464c457f ("\x7fELF") is a raw ELF upload - elfldr_read() receives the
 * exact byte counts it derives from the ELF header (e_shoff/e_shnum, then
 * the tail up to the last section end) with MSG_WAITALL, so the payload is
 * spawned the moment those bytes have arrived; the connection is NOT closed
 * and becomes the payload's stdin/stdout/stderr (SO_NOSIGPIPE is set on it,
 * so the payload survives the page closing).
 *
 * Ordering guarantee: nothing in this module runs before the kernel exploit
 * (main.js calls it only after runKernelExploit finished and elfldr is up).
 *
 * Classic script (loaded by the bootstrap in index.html): exposes
 * window.RelapseInject so main.js can call it without a module import. */
(function () {
"use strict";

const INJECT_AF_INET = 2;
const INJECT_SOCK_STREAM = 1;
const INJECT_SHUT_WR = 1;
const INJECT_O_NONBLOCK = 0x4;
const INJECT_F_SETFL = 4;
const INJECT_EAGAIN = 35;

const INJECT_CONNECT_WINDOW_MS = 60000;
const INJECT_CONNECT_RETRY_MS = 600;
const INJECT_WRITE_ATTEMPTS = 3;
const INJECT_CHUNK = 0x40000; /* 256 KiB per write syscall */
const INJECT_PROBE_WINDOW_MS = 45000;
const INJECT_PROBE_RETRY_MS = 800;
const INJECT_DRAIN_POLL_MS = 250;
const INJECT_DRAIN_LINE_LIMIT = 10;
const INJECT_DRAIN_MAX_MS = 10 * 60 * 1000;

function injectSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function hasSyscall(p, number) {
  return !!(p && p.syscalls && p.syscalls[number]);
}

/* The ROP chain itself can throw (worker hiccup, launch timeout). Syscalls
 * are expected to return negative errno instead, so any thrown error is
 * flattened into a bogus negative return the loops below simply retry - a
 * transient stall must never take the delivery down with an exception. */
async function safeSyscall(chain, number, ...args) {
  try {
    return await chain.syscall(number, ...args);
  } catch (e) {
    return new int64(0xfffffff6, 0); /* -10 (fake errno) - retryable */
  }
}

/* sockaddr_in { sin_len=16, AF_INET, htons(port), 127.0.0.1 } */
function sockaddrIn(p, port, ip) {
  const octets = ip || [127, 0, 0, 1];
  const sa = p.malloc(16, 1);
  for (let i = 0; i < 16; i++) p.write1(sa.add32(i), 0);
  p.write1(sa.add32(0), 16);
  p.write1(sa.add32(1), INJECT_AF_INET);
  p.write1(sa.add32(2), (port >> 8) & 0xff);
  p.write1(sa.add32(3), port & 0xff);
  for (let i = 0; i < 4; i++) p.write1(sa.add32(4 + i), octets[i] & 0xff);
  return sa;
}

/* Connects to 127.0.0.1:port, retrying until the deadline (elfldr takes a
 * moment after the kernel loader returns before its listener is up). */
async function connectLoopback(p, chain, port, deadline, say) {
  const sa = sockaddrIn(p, port);
  let lastRv = 0;
  while (Date.now() < deadline) {
    const fd = (await safeSyscall(chain, SYS_SOCKET, INJECT_AF_INET, INJECT_SOCK_STREAM, 0)).low | 0;
    if (fd >= 0) {
      const rv = (await safeSyscall(chain, SYS_CONNECT, fd, sa, 16)).low | 0;
      if (rv === 0) return fd;
      lastRv = rv;
      await safeSyscall(chain, SYS_CLOSE, fd);
    }
    await injectSleep(INJECT_CONNECT_RETRY_MS);
  }
  if (say && lastRv) say("connect to 127.0.0.1:" + port + " keeps failing (errno " + (-lastRv) + ")", "info");
  return -1;
}

/* Streams the whole ELF into the socket. The blocking socket accepts full
 * chunks; partial writes (signals, short socket buffers) just advance the
 * cursor, so the loop converges no matter how the kernel splits it.
 * onProgress(sent, total) fires after every advance for UI progress lines. */
async function writeAllToSocket(p, chain, fd, bytes, say, onProgress) {
  const source = p.read8(p.leakval(bytes).add32(0x10));
  const total = bytes.length;
  let offset = 0;
  while (offset < total) {
    const length = Math.min(INJECT_CHUNK, total - offset);
    const written = (await safeSyscall(chain, SYS_WRITE, fd, source.add32(offset), length)).low | 0;
    if (written > 0) {
      offset += written;
      if (onProgress) {
        try { onProgress(offset, total); } catch (e) { /* progress is cosmetic */ }
      }
      continue;
    }
    if (written === 0)
      throw new Error("the ELF loader closed the connection at " + offset + "/" + total + " bytes");
    throw new Error("socket write failed with errno " + -written + " at " + offset + "/" + total + " bytes");
  }
  if (say) say("payload bytes streamed to the ELF loader (" + total + " bytes)", "info");
}

/* Is anything listening on 127.0.0.1:port? Used both to detect a payload
 * that is already running (e.g. a daemon with a dashboard port) and to
 * confirm a freshly injected one. */
async function probePort(p, chain, port, windowMs) {
  const deadline = Date.now() + windowMs;
  const sa = sockaddrIn(p, port);
  while (Date.now() < deadline) {
    const fd = (await safeSyscall(chain, SYS_SOCKET, INJECT_AF_INET, INJECT_SOCK_STREAM, 0)).low | 0;
    if (fd >= 0) {
      const rv = (await safeSyscall(chain, SYS_CONNECT, fd, sa, 16)).low | 0;
      await safeSyscall(chain, SYS_CLOSE, fd);
      if (rv === 0) return true;
    }
    await injectSleep(INJECT_PROBE_RETRY_MS);
  }
  return false;
}

/* Reads the payload's stdout from the injection socket and mirrors the first
 * lines into the on-screen log - visible proof that the payload is alive.
 * The socket is made non-blocking first so a quiet stdout can never stall
 * the ROP worker; without fcntl the socket is simply left open (its send
 * buffer is far larger than a daemon's startup log). */
async function drainPayloadStdout(p, chain, fd, name, say, windowMs) {
  let drainable = false;
  if (hasSyscall(p, SYS_FCNTL)) {
    const rv = (await safeSyscall(chain, SYS_FCNTL, fd, INJECT_F_SETFL, INJECT_O_NONBLOCK)).low | 0;
    drainable = rv === 0;
  }
  if (!drainable) return;

  const buffer = p.malloc(0x400, 1);
  const window = Date.now() + (windowMs || INJECT_DRAIN_MAX_MS);
  let pending = "";
  let lines = 0;

  while (Date.now() < window && lines < INJECT_DRAIN_LINE_LIMIT) {
    const n = (await safeSyscall(chain, SYS_READ, fd, buffer, 0x400)).low | 0;
    if (n > 0) {
      const data = buffer.backing.subarray(0, n);
      for (let i = 0; i < n && lines < INJECT_DRAIN_LINE_LIMIT; i++) {
        const byte = data[i];
        if (byte === 0x0a) {
          const line = pending.trim();
          pending = "";
          if (line) {
            say(name + ": " + line, "info");
            lines++;
          }
          continue;
        }
        if (byte >= 0x20 && byte < 0x7f) pending += String.fromCharCode(byte);
      }
      continue;
    }
    if (n === 0) break; /* connection closed */
    if ((n | 0) !== -INJECT_EAGAIN) break; /* unexpected socket error */
    await injectSleep(INJECT_DRAIN_POLL_MS);
  }
}

/* Hand a URI to the ELF loader instead of raw bytes - the loader's other
 * wire format (ps5-payload-dev socksrv.c): a connection whose first four
 * bytes are "file" (or "http") is read line-by-line as a URI, then
 * uri_get_content() fetches it and the payload is spawned with this socket
 * as stdio. `file:/data/relapse-site/payloads/sitesrv.elf` is what starts
 * the on-console site server after every jailbreak - no bytes flow from the
 * page, the loader reads console storage directly. Returns the socket fd
 * (the spawned payload's stdout) for draining. */
async function sendUriToLoader(p, chain, uri, options) {
  const opts = options || {};
  const say = opts.say || (() => {});
  const name = opts.name || "payload";
  const loaderPort = opts.loaderPort || 9021;
  const connectWindowMs = opts.connectWindowMs || INJECT_CONNECT_WINDOW_MS;

  for (const number of [SYS_SOCKET, SYS_CONNECT, SYS_WRITE, SYS_CLOSE])
    if (!hasSyscall(p, number))
      throw new Error("this firmware does not expose the socket syscalls needed for the URI hand-over");
  if (typeof uri !== "string" || !uri.length)
    throw new Error("no URI to hand over");

  say("handing " + name + " to the ELF loader over 127.0.0.1:" + loaderPort + " (uri: " + uri + ")", "info");

  const deadline = Date.now() + connectWindowMs;
  const fd = await connectLoopback(p, chain, loaderPort, deadline, say);
  if (fd < 0)
    throw new Error("nothing answered on 127.0.0.1:" + loaderPort + " - the ELF loader is not up");

  /* one line, newline-terminated: that is exactly what payload_readuri() reads */
  const bytes = new Uint8Array(uri.length + 1);
  for (let i = 0; i < uri.length; i++) bytes[i] = uri.charCodeAt(i) & 0xff;
  bytes[uri.length] = 0x0a;

  try {
    await writeAllToSocket(p, chain, fd, bytes, say, opts.onProgress);
  } catch (e) {
    await safeSyscall(chain, SYS_CLOSE, fd);
    throw e;
  }

  if (hasSyscall(p, SYS_SHUTDOWN))
    await safeSyscall(chain, SYS_SHUTDOWN, fd, INJECT_SHUT_WR);
  return fd;
}

/* Fallback A - browser-HTTP hand-over through the loader's mini HTTP server
 * (`GET /?uri=<payload url>`). Fire-and-forget: elfldr answers with valid
 * HTTP 200 headers immediately, so no-cors fetch/img results say nothing
 * about the outcome; deliveryViaSocket's port probe remains the judge. */
async function beaconHandover(target, say) {
  const url = "http://127.0.0.1:9021/?uri=" + encodeURIComponent(target);
  try {
    await fetch(url, { mode: "no-cors" }).catch(() => {});
    const img = new Image();
    img.onload = img.onerror = () => {};
    img.src = url + "&cb=" + Date.now();
    img.style.display = "none";
    (document.body || document.documentElement).appendChild(img);
    if (say) say("also asked the ELF loader to pull the payload from this site (browser HTTP fallback)", "info");
  } catch (e) { /* blocked - the port probe decides the outcome */ }
}

/* Fallback B - a tappable link for a fully manual hand-over. Never navigates
 * the page by itself. */
function manualHandoverLink(target, name, say) {
  try {
    const output = document.getElementById("console");
    const line = document.createElement("div");
    const anchor = document.createElement("a");
    anchor.href = "http://127.0.0.1:9021/?uri=" + encodeURIComponent(target);
    anchor.textContent = "[tap here to hand " + name + " to the ELF loader manually]";
    anchor.style.color = "#7fd0ff";
    line.appendChild(anchor);
    output.appendChild(line);
    if (say) say("the loader also keeps listening on port 9021 for a manual hand-over", "info");
  } catch (e) { /* console element unavailable */ }
}

/* Injects `bytes` (a Uint8Array holding a full ELF) into the ELF loader on
 * 127.0.0.1:loaderPort. Returns the open socket fd whose stdout stream the
 * payload now writes to, or throws with the exact stage that failed. */
async function injectPayloadBytes(p, chain, bytes, options) {
  const opts = options || {};
  const say = opts.say || (() => {});
  const name = opts.name || "payload";
  const version = opts.version || "";
  const loaderPort = opts.loaderPort || 9021;
  const connectWindowMs = opts.connectWindowMs || INJECT_CONNECT_WINDOW_MS;
  const writeAttempts = opts.writeAttempts || INJECT_WRITE_ATTEMPTS;
  const onProgress = typeof opts.onProgress === "function" ? opts.onProgress : null;
  const label = name + (version ? " v" + version : "");

  for (const number of [SYS_SOCKET, SYS_CONNECT, SYS_WRITE, SYS_CLOSE])
    if (!hasSyscall(p, number))
      throw new Error("this firmware does not expose the socket syscalls needed for the direct hand-over");
  if (!bytes || bytes.length < 0x40)
    throw new Error("payload bytes are missing");

  say("handing " + label + " to the ELF loader over 127.0.0.1:" + loaderPort + " (direct socket)", "info");

  const deadline = Date.now() + connectWindowMs;
  let lastError = null;

  for (let attempt = 1; attempt <= writeAttempts; attempt++) {
    const fd = await connectLoopback(p, chain, loaderPort, deadline, say);
    if (fd < 0)
      throw new Error("nothing answered on 127.0.0.1:" + loaderPort + " - the ELF loader is not up");

    try {
      await writeAllToSocket(p, chain, fd, bytes, say, onProgress);
    } catch (e) {
      lastError = e;
      await safeSyscall(chain, SYS_CLOSE, fd);
      say("hand-over attempt " + attempt + "/" + writeAttempts + " failed: " +
          (e && e.message ? e.message : e), "info");
      await injectSleep(INJECT_CONNECT_RETRY_MS);
      continue;
    }

    /* EOF for any reader that waits for one; the loader has already received
     * every byte it needs at this point (MSG_WAITALL exact counts). */
    if (hasSyscall(p, SYS_SHUTDOWN))
      await safeSyscall(chain, SYS_SHUTDOWN, fd, INJECT_SHUT_WR);
    return fd;
  }

  throw lastError || new Error("the ELF loader did not take the payload");
}

/* Full delivery used for daemons with a known port: skip when the daemon is
 * already running, else inject, mirror its stdout, and confirm the port
 * answers (e.g. a payload dashboard). */
async function deliverViaLoader(p, chain, bytes, options) {
  const opts = options || {};
  const say = opts.say || (() => {});
  const name = opts.name || "payload";
  const version = opts.version || "";
  const label = name + (version ? " v" + version : "");
  const dashboardPort = opts.dashboardPort || 8084;
  const probeWindowMs = opts.probeWindowMs || INJECT_PROBE_WINDOW_MS;

  if (await probePort(p, chain, dashboardPort, opts.alreadyRunningProbeMs || 4000)) {
    say(label + " is already running (dashboard answering on port " + dashboardPort + ")", "success");
    return true;
  }

  const fd = await injectPayloadBytes(p, chain, bytes, opts);

  if (await probePort(p, chain, dashboardPort, probeWindowMs)) {
    drainPayloadStdout(p, chain, fd, name, say, opts.drainWindowMs); /* fire and forget */
    return true;
  }

  say("the ELF loader took the payload but the dashboard on port " + dashboardPort +
      " is not answering yet", "error");
  return false;
}

window.RelapseInject = {
  injectPayloadBytes: injectPayloadBytes,
  sendUriToLoader: sendUriToLoader,
  deliverViaLoader: deliverViaLoader,
  beaconHandover: beaconHandover,
  manualHandoverLink: manualHandoverLink,
  probePort: probePort,
  drainPayloadStdout: drainPayloadStdout,
};
})();
