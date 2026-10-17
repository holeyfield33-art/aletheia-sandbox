/**
 * Core sandbox proof, with a MOCK async capability (no database needed). The core
 * must run agent code against the frozen capability and return real data, bridge
 * ASYNC host methods synchronously, be reproducible, and hold the jail on every
 * vector: no ambient authority, host ref unreachable, only allowlisted methods
 * exist, in-isolate timeout + per-call host deadline + memory + result caps, and
 * fail-closed on bad/oversized code.
 */
import assert from "node:assert";
import { runInSandbox, DEFAULT_LIMITS, fingerprint, type Capability } from "../src/core/sandbox.js";

// A mock read-only capability: an async "query" (simulates a DB round-trip), a
// sync "schema", and a "hang" that never resolves (to exercise the host deadline).
const rows = [{ id: 1, name: "a" }, { id: 2, name: "b" }, { id: 3, name: "a" }];
let counterState = 0;
const cap: Capability = {
  namespace: "db",
  methods: {
    query: async (sql: unknown) => { await new Promise((r) => setTimeout(r, 5)); return { sql, rows }; },
    schema: () => ({ tables: ["users", "orders"] }),
    hang: () => new Promise(() => { /* never resolves */ }),
    sleep: async (ms: unknown) => { await new Promise((r) => setTimeout(r, Number(ms))); return Number(ms); },
    counter: () => ++counterState, // same code can yield different results → tests result-binding
  },
};
const CTX = fingerprint({ db: "mock", schema: "v1" });
const run = (code: string, limits = DEFAULT_LIMITS) => runInSandbox(cap, code, CTX, limits);

const main = async () => {
  // 1) async bridge: agent calls db.query() synchronously, gets the awaited result
  const r1 = await run(`const r = db.query("select * from users"); return r.rows.length;`);
  assert.strictEqual(r1.ok, true, "async query runs");
  assert.strictEqual(r1.result, 3, "async host result crosses back into the isolate");

  // 2) a join/aggregate the agent shapes itself in one call (the value prop)
  const r2 = await run(`
    const r = db.query("select * from users");
    const byName = {};
    for (const row of r.rows) byName[row.name] = (byName[row.name] || 0) + 1;
    return { schema: db.schema().tables, counts: byName };
  `);
  assert.strictEqual(r2.ok, true, "multi-call join runs");
  assert.deepStrictEqual((r2.result as any).counts, { a: 2, b: 1 }, "agent aggregated host data itself");
  assert.deepStrictEqual((r2.result as any).schema, ["users", "orders"], "sync + async methods both work");

  // 3) reproducible receipt
  const a = await run(`return 1;`), b = await run(`return 1;`), c = await run(`return 2;`);
  assert.strictEqual(a.receipt.hash, b.receipt.hash, "same code+context => same receipt");
  assert.notStrictEqual(a.receipt.hash, c.receipt.hash, "different code => different receipt");

  // 4) JAIL: no ambient authority
  const amb = await run(`return [typeof fetch, typeof require, typeof process, typeof globalThis.process].join(",");`);
  assert.strictEqual(amb.result, "undefined,undefined,undefined,undefined", "no network/require/process in the isolate");

  // 5) JAIL: host reference unreachable; only allowlisted methods exist
  const noHost = await run(`return typeof __ALETHEIA_HOST__;`);
  assert.strictEqual(noHost.result, "undefined", "the host capability reference is not reachable");
  const surface = await run(`return Object.keys(db).sort().join(",") + "|" + typeof db.evil;`);
  assert.strictEqual(surface.result, "counter,hang,query,schema,sleep|undefined", "only the provided methods exist on the capability");

  // 6) JAIL: in-isolate wall-clock timeout kills a busy loop
  const spin = await run(`while (true) {}`, { ...DEFAULT_LIMITS, timeoutMs: 200 });
  assert.strictEqual(spin.ok, false, "busy loop is terminated");
  assert.ok(/time/i.test(spin.error || ""), "timeout reported");

  // 7) JAIL: per-call host deadline kills a hung capability call (isolate timeout
  // can't fire while parked awaiting the host — this is the backstop for that)
  const hang = await run(`return db.hang();`, { ...DEFAULT_LIMITS, hostCallTimeoutMs: 150 });
  assert.strictEqual(hang.ok, false, "a hung host call is terminated by the host deadline");
  assert.ok(/exceeded/.test(hang.error || ""), "host deadline reported");

  // 8) JAIL: oversized result capped inside the isolate before copy-out
  const huge = await run(`return "x".repeat(2_000_000);`);
  assert.strictEqual(huge.ok, false, "oversized result rejected before it reaches the host");
  assert.ok(/result exceeds/.test(huge.error || ""), "result cap named");

  // 9) memory cap kills an allocation bomb
  const bomb = await run(`const a=[]; for(;;){ a.push(new Array(1e6).fill(7)); } return a.length;`,
    { ...DEFAULT_LIMITS, memoryMb: 16, timeoutMs: 3000 });
  assert.strictEqual(bomb.ok, false, "allocation bomb terminated by the memory cap");

  // 10) bad code fails closed with a receipt
  const bad = await run(`return (((;`);
  assert.strictEqual(bad.ok, false, "syntax error returns ok:false");
  assert.ok(bad.receipt?.hash, "receipt present on failure");

  // 11) WHOLE-RUN budget cancels a tight in-isolate loop even when timeoutMs is huge
  const t0 = Date.now();
  const budgetLoop = await run(`while (true) {}`, { ...DEFAULT_LIMITS, timeoutMs: 10_000, runBudgetMs: 400 });
  assert.strictEqual(budgetLoop.ok, false, "run budget cancels the loop");
  assert.ok(/run budget|time/i.test(budgetLoop.error || ""), "budget/timeout reported");
  assert.ok(Date.now() - t0 < 3_000, "cancellation happened near the 400ms budget, not the 10s timeout");

  // 11b) WHOLE-RUN budget bounds a long CHAIN of host calls (per-call deadline is generous)
  const chain = await run(
    `for (let i = 0; i < 100; i++) { db.sleep(100); } return "done";`,
    { ...DEFAULT_LIMITS, runBudgetMs: 500, hostCallTimeoutMs: 10_000 },
  );
  assert.strictEqual(chain.ok, false, "a long chain of host calls is cut off by the whole-run budget");
  assert.ok(/run budget exceeded/.test(chain.error || ""), "run budget named");

  // 12) RESULT-BOUND receipt: same code+context but a DIFFERENT result => different
  // receipt hash, while the request identity (requestHash) stays the same.
  counterState = 0;
  const c1 = await run(`return db.counter();`);
  const c2 = await run(`return db.counter();`);
  assert.strictEqual(c1.result, 1);
  assert.strictEqual(c2.result, 2);
  assert.strictEqual(c1.receipt.requestHash, c2.receipt.requestHash, "same code+context => same request identity");
  assert.notStrictEqual(c1.receipt.resultHash, c2.receipt.resultHash, "different result => different resultHash");
  assert.notStrictEqual(c1.receipt.hash, c2.receipt.hash, "different result => different binding hash");
  // identical code AND identical result => identical everything
  const d1 = await run(`return 7;`);
  const d2 = await run(`return 7;`);
  assert.strictEqual(d1.receipt.hash, d2.receipt.hash, "same code+context+result => same receipt");
  assert.strictEqual(d1.receipt.resultHash, d2.receipt.resultHash, "same result => same resultHash");

  console.log("core.test: generalized sandbox — async + sync capability bridge, agent-shaped join, " +
    "result-bound receipt; jail holds (no ambient authority, host unreachable, allowlist-only surface, " +
    "isolate timeout + host-call deadline + whole-run budget + memory + result caps, fail-closed)");
};

main().catch((e) => { console.error(e); process.exit(1); });
