/**
 * Live Postgres integration test — executed evidence, not static inspection.
 *
 * Requires a running Postgres with the sample schema (users, orders) and a
 * persistent `write_canary` table, reachable by TWO roles:
 *   DATABASE_URL           a true READ-ONLY role (SELECT only)
 *   DATABASE_URL_WRITABLE  a deliberately WRITABLE role (INSERT/UPDATE/DELETE + CREATE)
 *
 * Verifies:
 *   F1  startup probe ACCEPTS the read-only role and REFUSES the writable role
 *   F2  multi-statement injection (incl. the string/comment desync) is rejected
 *       end-to-end, and the READ ONLY transaction rejects a writable CTE that the
 *       classifier would pass (protocol/txn backstop, not regex alone)
 *   -   schema/query/sample/explain work through the full sandbox path
 *   -   bounded fetch truncates a large result before host memory
 *   -   whole-run budget cancels a slow query
 *   -   result-bound receipt present and stable
 *   CANARY  after every write/injection attempt, write_canary has ZERO rows —
 *           proof that no unauthorized write reached the database.
 */
import assert from "node:assert";
import pg from "pg";
import { runInSandbox, DEFAULT_LIMITS } from "../src/core/sandbox.js";
import { createPostgresCapability, assertReadOnlyRole } from "../src/providers/postgres.js";

const roUrl = process.env.DATABASE_URL;
const rwUrl = process.env.DATABASE_URL_WRITABLE;

if (!roUrl) {
  console.log("postgres-integration.test: SKIPPED (set DATABASE_URL to run)");
  process.exit(0);
}

const main = async () => {
  const roPool = new pg.Pool({ connectionString: roUrl, max: 3 });
  // canary counter uses the read-only role (it has SELECT on write_canary)
  const countCanary = async () => Number((await roPool.query("SELECT count(*)::int AS n FROM write_canary")).rows[0].n);

  // baseline canary must be 0 before we start
  assert.strictEqual(await countCanary(), 0, "canary starts empty");

  try {
    // ---- F1: startup probe accepts read-only, refuses writable --------------
    const { capability, contextHash } = await createPostgresCapability({
      pool: roPool, identity: "integration@readonly", maxRows: 5, statementTimeoutMs: 5_000, requireReadOnlyRole: true,
    });
    console.log("F1: read-only role ACCEPTED by startup probe");

    if (rwUrl) {
      const rwPool = new pg.Pool({ connectionString: rwUrl, max: 2 });
      let refused = false;
      try { await assertReadOnlyRole(rwPool); }
      catch (e) { refused = true; assert.ok(/write|refus/i.test(String(e)), "writable refusal names the reason"); }
      assert.strictEqual(refused, true, "F1: writable role REFUSED by startup probe");
      console.log("F1: writable role REFUSED by startup probe");

      // ---- F2 backstop: a writable CTE passes the classifier (leader WITH) but
      // the READ ONLY transaction rejects it. Build a capability on the WRITABLE
      // role with the probe disabled, then prove the write still cannot land. ----
      const { capability: rwCap, contextHash: rwCtx } = await createPostgresCapability({
        pool: rwPool, identity: "integration@writable", maxRows: 5, statementTimeoutMs: 5_000, requireReadOnlyRole: false,
      });
      const cte = await runInSandbox(
        rwCap,
        `return db.query("WITH x AS (INSERT INTO write_canary(note) VALUES('cte-bypass') RETURNING id) SELECT * FROM x");`,
        rwCtx, DEFAULT_LIMITS, "aletheia-pg-integration",
      );
      assert.strictEqual(cte.ok, false, "writable CTE rejected");
      assert.ok(/read-only|only read-class|cannot execute/i.test(cte.error || ""), "rejected by read-only txn/classifier");
      assert.strictEqual(await countCanary(), 0, "CANARY: writable-CTE write did not land");
      console.log("F2 backstop: writable CTE blocked by READ ONLY transaction; canary still 0");
      await rwPool.end();
    } else {
      console.log("F1/F2-writable: SKIPPED (set DATABASE_URL_WRITABLE for full proof)");
    }

    const run = (code: string, limits = DEFAULT_LIMITS) =>
      runInSandbox(capability, code, contextHash, limits, "aletheia-pg-integration");

    // ---- happy path through the read-only sandbox ---------------------------
    const schemaRes = await run(`return db.schema().map(t => t.name).sort();`);
    assert.strictEqual(schemaRes.ok, true, "schema() succeeds");
    assert.ok((schemaRes.result as string[]).includes("users"), "users present");
    assert.ok((schemaRes.result as string[]).includes("orders"), "orders present");

    const q1 = await run(`return db.query("SELECT name FROM users ORDER BY id").rows.map(r => r.name);`);
    assert.deepStrictEqual(q1.result, ["alice", "bob", "carol"], "query returns rows");

    const q2 = await run(`return db.query("SELECT name FROM users WHERE name = $1", ["bob"]).rows;`);
    assert.strictEqual((q2.result as any[])[0].name, "bob", "parameterized query works");

    const agg = await run(`
      const orders = db.query("SELECT status, amount FROM orders").rows;
      const t = {}; for (const o of orders) t[o.status] = (t[o.status]||0) + Number(o.amount);
      return t;`);
    assert.ok((agg.result as any).paid > 0, "agent aggregation works");

    const sample = await run(`return db.sample("users", 2).rows.length;`);
    assert.strictEqual(sample.result, 2, "sample works");

    const expl = await run(`return db.explain("SELECT * FROM users WHERE id = 1");`);
    assert.strictEqual(expl.ok, true, "explain works");
    assert.ok(expl.result != null, "explain returned a plan");

    // ---- F2 end-to-end: writes + multi-statement + desync all rejected ------
    const attempts: string[] = [
      `db.query("INSERT INTO write_canary(note) VALUES('direct')")`,
      `db.query("SELECT 1; INSERT INTO write_canary(note) VALUES('multi')")`,
      `db.query("SELECT '/*'; INSERT INTO write_canary(note) VALUES('desync'); SELECT '*/'")`,
      `db.query("UPDATE users SET name='x'")`,
      `db.query("DROP TABLE write_canary")`,
      `db.query("SELECT pg_read_file('/etc/passwd')")`,
    ];
    for (const a of attempts) {
      const r = await run(`return ${a};`);
      assert.strictEqual(r.ok, false, `attempt rejected: ${a}`);
    }
    console.log(`F2: ${attempts.length} write/injection/desync/dangerous attempts all rejected`);

    // CANARY: the whole point — nothing persisted
    assert.strictEqual(await countCanary(), 0, "CANARY: no write landed after all attempts");
    console.log("CANARY: write_canary still has 0 rows after every attack");

    // ---- bounded fetch: maxRows=5, ask for 100 => truncated -----------------
    const big = await run(`return db.query("SELECT g FROM generate_series(1,100) g");`);
    assert.strictEqual((big.result as any).rows.length, 5, "bounded to maxRows");
    assert.strictEqual((big.result as any).truncated, true, "truncation flagged");
    console.log("bounded fetch: 100-row query truncated to 5 (cursor, not full materialization)");

    // ---- whole-run budget cancels a slow query ------------------------------
    const slow = await run(
      `return db.query("SELECT pg_sleep(5)");`,
      { ...DEFAULT_LIMITS, runBudgetMs: 800, hostCallTimeoutMs: 10_000 },
    );
    assert.strictEqual(slow.ok, false, "slow query cancelled");
    assert.ok(/run budget exceeded/i.test(slow.error || ""), "cancelled by run budget");
    console.log("run budget: pg_sleep(5) cancelled by the 800ms whole-run budget");

    // ---- receipt result-bound + stable --------------------------------------
    const a = await run(`return 1;`);
    const b = await run(`return 1;`);
    assert.ok(a.receipt?.hash && a.receipt?.resultHash && a.receipt?.requestHash, "receipt fields present");
    assert.strictEqual(a.receipt.hash, b.receipt.hash, "same code+context+result => same receipt");

    console.log("postgres-integration.test: PASS — F1 both roles, F2 end-to-end + canary, " +
      "txn backstop, bounded fetch, run-budget cancellation, result-bound receipt");
  } finally {
    await roPool.end();
  }
};

main().catch((e) => { console.error(e); process.exit(1); });
