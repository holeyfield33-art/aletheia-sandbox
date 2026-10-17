/**
 * Live Postgres integration test.
 *
 * Runs only when DATABASE_URL is set. Designed for the docker-compose
 * read-only role in this repo:
 *
 *   docker compose up -d
 *   export DATABASE_URL=postgres://readonly:readonly@localhost:5433/sandbox
 *   npm run test:integration
 *
 * Verifies:
 *   - schema / query / sample / explain work through the full sandbox path
 *   - writes are rejected by the classifier and by the READ ONLY transaction
 *   - multi-statement injection is rejected
 *   - receipt is present and stable for the same code + schema
 */
import assert from "node:assert";
import pg from "pg";
import { runInSandbox, DEFAULT_LIMITS } from "../src/core/sandbox.js";
import { createPostgresCapability } from "../src/providers/postgres.js";

const url = process.env.DATABASE_URL;

if (!url) {
  console.log("postgres-integration.test: SKIPPED (set DATABASE_URL to run)");
  process.exit(0);
}

const main = async () => {
  const pool = new pg.Pool({ connectionString: url, max: 2 });

  try {
    const { capability, contextHash } = await createPostgresCapability({
      pool,
      identity: "integration@test",
      maxRows: 100,
      statementTimeoutMs: 5_000,
    });

    const run = (code: string) =>
      runInSandbox(capability, code, contextHash, DEFAULT_LIMITS, "aletheia-pg-integration");

    // 1) schema is reachable and non-empty
    const schemaRes = await run(`return db.schema().map(t => t.name).sort();`);
    assert.strictEqual(schemaRes.ok, true, "schema() succeeds");
    const tables = schemaRes.result as string[];
    assert.ok(tables.includes("users"), "users table present");
    assert.ok(tables.includes("orders"), "orders table present");

    // 2) simple query
    const q1 = await run(`return db.query("SELECT name FROM users ORDER BY id").rows.map(r => r.name);`);
    assert.strictEqual(q1.ok, true, "query succeeds");
    assert.deepStrictEqual(q1.result, ["alice", "bob", "carol"], "expected user names");

    // 3) parameterized query
    const q2 = await run(`return db.query("SELECT name FROM users WHERE name = $1", ["bob"]).rows;`);
    assert.strictEqual(q2.ok, true, "parameterized query succeeds");
    assert.strictEqual((q2.result as any[]).length, 1);
    assert.strictEqual((q2.result as any[])[0].name, "bob");

    // 4) agent-shaped aggregation across two calls
    const agg = await run(`
      const orders = db.query("SELECT status, amount FROM orders").rows;
      const byStatus = {};
      for (const o of orders) {
        byStatus[o.status] = (byStatus[o.status] || 0) + Number(o.amount);
      }
      return byStatus;
    `);
    assert.strictEqual(agg.ok, true, "agent aggregation succeeds");
    assert.ok((agg.result as any).paid > 0, "paid total present");

    // 5) sample
    const sample = await run(`return db.sample("users", 2).rows.length;`);
    assert.strictEqual(sample.ok, true, "sample succeeds");
    assert.strictEqual(sample.result, 2);

    // 6) explain
    const expl = await run(`return db.explain("SELECT * FROM users WHERE id = 1");`);
    assert.strictEqual(expl.ok, true, "explain succeeds");
    assert.ok(expl.result != null, "explain returned a plan");

    // 7) write rejected by classifier
    const write = await run(`return db.query("INSERT INTO users (name) VALUES ('evil')");`);
    assert.strictEqual(write.ok, false, "INSERT rejected");
    assert.ok(/rejected|only read-class/i.test(write.error || ""), "classifier error");

    // 8) multi-statement injection rejected
    const multi = await run(`return db.query("SELECT 1; DROP TABLE users");`);
    assert.strictEqual(multi.ok, false, "multi-statement rejected");

    // 9) receipt present and stable
    const a = await run(`return 1;`);
    const b = await run(`return 1;`);
    assert.ok(a.receipt?.hash, "receipt present");
    assert.strictEqual(a.receipt.hash, b.receipt.hash, "same code+context => same receipt");

    console.log("postgres-integration.test: live read-only path holds " +
      "(schema/query/sample/explain, writes + multi-statement rejected, receipt stable)");
  } finally {
    await pool.end();
  }
};

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
