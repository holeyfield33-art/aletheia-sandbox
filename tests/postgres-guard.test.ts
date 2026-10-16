/**
 * Read-only guard proof (no database needed). classifyStatement is the first line
 * of defense — it must accept read-class statements, reject writes, and above all
 * reject multi-statement injection even when `;` or keywords are hidden in strings
 * or comments. (The always-rolled-back READ ONLY transaction is the actual
 * guarantee for writable-CTE / FOR UPDATE / volatile-write cases; this guard is
 * the clear early error.)
 */
import assert from "node:assert";
import { classifyStatement, isSafeIdentifier } from "../src/providers/postgres.js";

const ok = (s: string) => assert.strictEqual(classifyStatement(s).ok, true, `should allow: ${s}`);
const no = (s: string) => assert.strictEqual(classifyStatement(s).ok, false, `should reject: ${s}`);

// read-class statements allowed
ok("SELECT 1");
ok("  select * from users where name = 'a'");
ok("WITH t AS (SELECT 1) SELECT * FROM t");
ok("EXPLAIN SELECT 1");
ok("SHOW statement_timeout");
ok("TABLE users");
ok("VALUES (1),(2)");
ok("(SELECT 1)");
ok("-- a comment\nSELECT 1");
ok("/* banner */ SELECT 1");
ok("SELECT 1;");                               // single trailing semicolon is fine

// writes rejected by the leader check
no("INSERT INTO t VALUES (1)");
no("UPDATE t SET x = 1");
no("DELETE FROM t");
no("DROP TABLE t");
no("ALTER TABLE t ADD COLUMN x int");
no("CREATE TABLE t (x int)");
no("TRUNCATE t");
no("GRANT ALL ON t TO public");
no("COPY t TO PROGRAM 'sh -c evil'");
no("DO $$ BEGIN PERFORM 1; END $$");
no("");
no("   ");

// multi-statement injection rejected — the key defense
no("SELECT 1; DROP TABLE users");
no("SELECT 1;DELETE FROM users");
no("select * from t; update t set x=1");

// ...but a semicolon INSIDE a string or comment is not a second statement
ok("SELECT 'a;b' AS v");
ok("SELECT 1 -- ; DROP TABLE users");
ok("SELECT 1 /* ; DROP TABLE users */");
ok("SELECT $tag$ a ; b $tag$ AS v");
// and a real write hidden after a string-with-semicolon is still caught
no("SELECT 'a;b'; DELETE FROM t");

// identifier guard for sample()
assert.ok(isSafeIdentifier("users"));
assert.ok(isSafeIdentifier("public.users"));
assert.ok(!isSafeIdentifier("users; DROP TABLE x"));
assert.ok(!isSafeIdentifier("a b"));
assert.ok(!isSafeIdentifier("a.b.c"));
assert.ok(!isSafeIdentifier(""));
assert.ok(!isSafeIdentifier('"users"'));

console.log("postgres-guard.test: read-class allowed, writes + multi-statement injection rejected " +
  "(semicolons/keywords in strings & comments handled), identifier guard holds");
