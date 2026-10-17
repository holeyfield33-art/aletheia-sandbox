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
 *   - an isolate memory cap and an in-isolate wall-clock timeout bound compute, a
 *     per-call host deadline bounds each (possibly async) capability call, and a
 *     WHOLE-RUN budget bounds the entire invocation — when it is exceeded the
 *     isolate is disposed (hard cancellation), so neither a loop that never calls
 *     out nor a long chain of host calls can run unbounded.
 *
 * Capability methods may be async (e.g. a database round-trip). Inside the isolate
 * the agent calls them synchronously (`db.query(sql)`); the core bridges that to
 * the async host method and blocks the isolate until it resolves.
 *
 * Every run returns a RESULT-BOUND receipt: sha256 over selector + code +
 * contextHash + resultHash, where resultHash is a hash of the actual output (or
 * the error). Two runs of the same code over the same surface that produced the
 * same result share a receipt; a run that produced a different result does not.
 * The request identity (selector+code+contextHash) is also exposed separately for
 * replay bookkeeping.
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
  /** Whole-run budget, ms: the entire invocation (compute + all host calls). When
   *  exceeded the isolate is disposed, cancelling the run. */
  runBudgetMs: number;
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
  runBudgetMs: 30_000,
  memoryMb: 128,
  maxCodeChars: 20_000,
  maxResultBytes: 1_000_000,
};

export interface Receipt {
  selector: string;
  codeHash: string;
  contextHash: string;
  /** Hash of the actual result (or of the error on failure) — makes the receipt result-bound. */
  resultHash: string;
  /** Identity of the request alone (selector+code+contextHash), independent of the result. */
  requestHash: string;
  /** The binding hash over selector+code+contextHash+resultHash. */
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
 * or failed capability call, run-budget exhaustion) — those come back as
 * { ok:false, error }. The receipt is always present and result-bound.
 */
export async function runInSandbox(
  capability: Capability,
  code: string,
  contextHash: string,
  limits: SandboxLimits = DEFAULT_LIMITS,
  selector = "aletheia-sandbox-v1",
): Promise<ExecResult> {
  const codeHash = sha(code);
  const requestHash = sha(JSON.stringify({ selector, codeHash, contextHash }));
  const mk = (outcome: { ok: boolean; result?: unknown; error?: string }): ExecResult => {
    const resultHash = outcome.ok ? sha("ok:" + JSON.stringify(outcome.result ?? null)) : sha("err:" + String(outcome.error ?? ""));
    const hash = sha(JSON.stringify({ selector, codeHash, contextHash, resultHash }));
    return {
      ok: outcome.ok,
      ...(outcome.ok ? { result: outcome.result } : { error: outcome.error }),
      receipt: { selector, codeHash, contextHash, resultHash, requestHash, hash },
      note: `Read-only sandbox: code ran in an isolate with no network, filesystem, require, or host scope — only a frozen \`${capability.namespace}\` capability. Receipt is result-bound (sha of selector+code+context+result).`,
    };
  };

  if (!IDENT.test(capability.namespace)) return mk({ ok: false, error: "invalid capability namespace" });
  if (typeof code !== "string" || code.length === 0) return mk({ ok: false, error: "empty code" });
  if (code.length > limits.maxCodeChars) return mk({ ok: false, error: `code exceeds ${limits.maxCodeChars} chars` });

  const allowed = new Set(Object.keys(capability.methods));
  const runDeadline = Date.now() + limits.runBudgetMs;

  // The one capability handed into the isolate: an async dispatcher. Every call is
  // allowlist-checked here, bounded by a per-call deadline AND by the remaining
  // whole-run budget, so neither a slow method nor a long chain can run forever.
  const host = new ivm.Reference(async (method: string, argsJson: string): Promise<string | undefined> => {
    if (!allowed.has(method)) throw new Error("method not permitted: " + String(method));
    const remaining = runDeadline - Date.now();
    if (remaining <= 0) throw new Error(`run budget exceeded (${limits.runBudgetMs} ms)`);
    const args = JSON.parse(argsJson) as unknown[];
    const call = Promise.resolve(capability.methods[method](...args));
    const perCall = Math.min(limits.hostCallTimeoutMs, remaining);
    // If the remaining whole-run budget is the binding constraint (shorter than the
    // per-call timeout), label the cutoff as a budget exhaustion, not a slow call.
    const budgetBound = remaining < limits.hostCallTimeoutMs;
    const deadlineMsg = budgetBound
      ? `run budget exceeded (${limits.runBudgetMs} ms)`
      : `host call '${method}' exceeded ${perCall} ms`;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, rej) => {
      timer = setTimeout(() => rej(new Error(deadlineMsg)), perCall);
    });
    try {
      const out = await Promise.race([call, deadline]);
      return out === undefined ? undefined : JSON.stringify(out);
    } finally {
      if (timer) clearTimeout(timer);
    }
  });

  const isolate = new ivm.Isolate({ memoryLimit: limits.memoryMb });
  // Hard cancellation: if the whole-run budget elapses, dispose the isolate. This
  // kills a tight in-isolate loop that never calls out (the in-isolate timeout
  // would also catch that) AND a run stuck across host calls.
  let budgetTimer: ReturnType<typeof setTimeout> | undefined = setTimeout(() => {
    try { if (!isolate.isDisposed) isolate.dispose(); } catch { /* already gone */ }
  }, limits.runBudgetMs);
  try {
    const context = await isolate.createContext();
    await context.global.set("__ALETHEIA_HOST__", host);
    await context.eval(bootstrap(capability.namespace, [...allowed]));
    const json = (await context.eval(wrapUser(code, limits.maxResultBytes), {
      timeout: limits.timeoutMs,
      promise: true,
      copy: true,
    })) as string;
    return mk({ ok: true, result: JSON.parse(json) });
  } catch (e) {
    const msg = String(e instanceof Error ? e.message : e);
    // A dispose triggered by the run-budget timer surfaces as an isolate-disposed error.
    const budgetHit = Date.now() >= runDeadline || /isolate (is|was) disposed/i.test(msg);
    return mk({ ok: false, error: budgetHit && /dispos/i.test(msg) ? `run budget exceeded (${limits.runBudgetMs} ms)` : msg });
  } finally {
    if (budgetTimer) { clearTimeout(budgetTimer); budgetTimer = undefined; }
    try { host.release(); } catch { /* released with the isolate */ }
    try { if (!isolate.isDisposed) isolate.dispose(); } catch { /* already disposed */ }
  }
}

/** Convenience: a stable sha256 fingerprint for any JSON-serializable surface. */
export function fingerprint(surface: unknown): string {
  return sha(JSON.stringify(surface));
}
