/**
 * aletheia-sandbox core: run untrusted agent code against a frozen capability,
 * and nothing else.
 *
 * This is the generalized form of the pattern first proven in Code Atlas's
 * `atlas_exec`: ONE programmable tool instead of N fixed ones. The caller hands
 * in a `Capability` — a namespace plus a map of host methods — and the sandbox
 * exposes exactly that inside a V8 isolate. The agent writes code that calls the
 * capability and returns a value; it cannot do anything the capability does not
 * offer.
 *
 * The security is the jail, not the capability's shape:
 *   - a V8 isolate (isolated-vm): a separate heap with NO Node bindings, so
 *     `require`, `import`, `process`, `fetch`, filesystem and the host scope do
 *     not exist inside it;
 *   - the ONLY thing injected is one host reference; a trusted bootstrap consumes
 *     it, builds the frozen namespace object, and blanks the global handle before
 *     a line of agent code runs, so agent code can call the capability but cannot
 *     name the reference behind it;
 *   - every host call is checked against the capability's own method set (an
 *     allowlist): a method that is not in the map does not exist;
 *   - all data crosses the boundary as JSON strings — the isolate never holds a
 *     live reference to a host object, connection, or credential;
 *   - results are serialized and size-checked INSIDE the isolate before being
 *     copied out, so a huge return cannot blow the host heap;
 *   - an isolate memory cap and a wall-clock timeout bound in-isolate compute,
 *     and a per-call host deadline bounds each (possibly async) capability call,
 *     since an isolate timeout does not fire while the isolate is parked awaiting
 *     the host.
 *
 * Capability methods may be async (e.g. a database round-trip). Inside the isolate
 * the agent calls them synchronously (`db.query(sql)`); the core bridges that to
 * the async host method and blocks the isolate until it resolves.
 *
 * Every run returns a replayable receipt: sha256(selector + code + contextHash),
 * where contextHash is a stable fingerprint of the data surface the caller passes
 * in (e.g. a database's schema + identity). Same code + same surface => same
 * receipt.
 */
import { createHash } from "node:crypto";
import ivm from "isolated-vm";

export type HostMethod = (...args: unknown[]) => unknown | Promise<unknown>;

export interface Capability {
  /** The object name the agent calls, e.g. "db" or "atlas". Must be a valid identifier. */
  namespace: string;
  /** method name -> host function. Sync or async; must return JSON-serializable data. */
  methods: Record<string, HostMethod>;
}

export interface SandboxLimits {
  /** Wall-clock budget for in-isolate compute, ms. Does NOT cover time parked in a host call. */
  timeoutMs: number;
  /** Deadline for a single host (capability) call, ms — bounds a slow async method. */
  hostCallTimeoutMs: number;
  /** Isolate heap cap, MB. */
  memoryMb: number;
  /** Max length of agent code, chars. */
  maxCodeChars: number;
  /** Max serialized result size, bytes — enforced inside the isolate before copy-out. */
  maxResultBytes: number;
}

export const DEFAULT_LIMITS: SandboxLimits = {
  timeoutMs: 5_000,
  hostCallTimeoutMs: 15_000,
  memoryMb: 128,
  maxCodeChars: 20_000,
  maxResultBytes: 1_000_000,
};

export interface Receipt {
  selector: string;
  codeHash: string;
  contextHash: string;
  hash: string;
}

export interface ExecResult {
  ok: boolean;
  result?: unknown;
  error?: string;
  receipt: Receipt;
  note: string;
}

const sha = (s: string) => "sha256:" + createHash("sha256").update(s).digest("hex").slice(0, 16);

const IDENT = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

function bootstrap(namespace: string, methodNames: string[]): string {
  // Build the frozen namespace object. Each method forwards to the single host
  // reference via applySyncPromise (sync-looking, resolves the host's async
  // result). The host dispatches by name against the allowlist on its side.
  const entries = methodNames
    .map((m) => `${JSON.stringify(m)}: function(){ return __call(${JSON.stringify(m)}, Array.prototype.slice.call(arguments)); }`)
    .join(",\n        ");
  return `
    "use strict";
    (function(){
      const __host = __ALETHEIA_HOST__;
      const __call = (m, args) => {
        const out = __host.applySyncPromise(undefined, [m, JSON.stringify(args)]);
        return out === undefined ? undefined : JSON.parse(out);
      };
      globalThis[${JSON.stringify(namespace)}] = Object.freeze({
        ${entries}
      });
    })();
    globalThis.__ALETHEIA_HOST__ = undefined;
  `;
}

function wrapUser(code: string, maxResultBytes: number): string {
  // Async IIFE so the agent can use the (sync-looking) capability calls and a
  // top-level `return`. Serialize + size-check the result inside the isolate;
  // only the bounded JSON string is copied out.
  return `(async function(){
"use strict";
var __r = await (async function(){
${code}
})();
var __s = JSON.stringify(__r === undefined ? null : __r);
if (typeof __s !== "string") __s = "null";
if (__s.length > ${maxResultBytes}) throw new Error("result exceeds " + ${maxResultBytes} + " bytes (serialized " + __s.length + ")");
return __s;
})()`;
}

/**
 * Run agent code against a capability inside a hardened isolate.
 * Never throws for sandbox-level failures (timeout, memory, bad code, a blocked
 * or failed capability call) — those come back as { ok:false, error }. The
 * receipt is always present.
 */
export async function runInSandbox(
  capability: Capability,
  code: string,
  contextHash: string,
  limits: SandboxLimits = DEFAULT_LIMITS,
  selector = "aletheia-sandbox-v1",
): Promise<ExecResult> {
  const codeHash = sha(code);
  const receiptCore = { selector, codeHash, contextHash };
  const receipt: Receipt = { ...receiptCore, hash: sha(JSON.stringify(receiptCore)) };
  const base = {
    receipt,
    note: `Read-only sandbox: code ran in an isolate with no network, filesystem, require, or host scope — only a frozen \`${capability.namespace}\` capability. Replayable: same code + context => same receipt hash.`,
  };

  if (!IDENT.test(capability.namespace))
    return { ok: false, error: "invalid capability namespace", ...base };
  if (typeof code !== "string" || code.length === 0)
    return { ok: false, error: "empty code", ...base };
  if (code.length > limits.maxCodeChars)
    return { ok: false, error: `code exceeds ${limits.maxCodeChars} chars`, ...base };

  const allowed = new Set(Object.keys(capability.methods));

  // The one capability handed into the isolate: an async dispatcher. Every call
  // is allowlist-checked here, on the host, and bounded by a per-call deadline so
  // a hung async method (e.g. a stuck DB query) cannot park the isolate forever.
  const host = new ivm.Reference(async (method: string, argsJson: string): Promise<string | undefined> => {
    if (!allowed.has(method)) throw new Error("method not permitted: " + String(method));
    const args = JSON.parse(argsJson) as unknown[];
    const call = Promise.resolve(capability.methods[method](...args));
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, rej) => {
      timer = setTimeout(() => rej(new Error(`host call '${method}' exceeded ${limits.hostCallTimeoutMs} ms`)), limits.hostCallTimeoutMs);
    });
    try {
      const out = await Promise.race([call, deadline]);
      return out === undefined ? undefined : JSON.stringify(out);
    } finally {
      if (timer) clearTimeout(timer);
    }
  });

  const isolate = new ivm.Isolate({ memoryLimit: limits.memoryMb });
  try {
    const context = await isolate.createContext();
    await context.global.set("__ALETHEIA_HOST__", host);
    await context.eval(bootstrap(capability.namespace, [...allowed]));
    const json = (await context.eval(wrapUser(code, limits.maxResultBytes), {
      timeout: limits.timeoutMs,
      promise: true,
      copy: true,
    })) as string;
    return { ok: true, result: JSON.parse(json), ...base };
  } catch (e) {
    return { ok: false, error: String(e instanceof Error ? e.message : e), ...base };
  } finally {
    try { host.release(); } catch { /* released with the isolate */ }
    try { if (!isolate.isDisposed) isolate.dispose(); } catch { /* already disposed */ }
  }
}

/** Convenience: a stable sha256 fingerprint for any JSON-serializable surface. */
export function fingerprint(surface: unknown): string {
  return sha(JSON.stringify(surface));
}
