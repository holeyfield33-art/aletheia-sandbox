/**
 * Read-only guard proof (no database needed).
 *
 * classifyStatement is defense in depth in front of the protocol-level
 * single-statement enforcement and the READ ONLY transaction. It must:
 *   - accept read-class statements
 *   - reject writes and transaction-control
 *   - reject multi-statement injection even when `;` / comment markers hide inside
 *     strings, comments, or dollar-quotes (the F2 skeleton-desync class)
 *   - reject dangerous functions (file/FS/dblink/exfil) even inside SELECT
 */
import assert from "node:assert";
import { classifyStatement, isSafeIdentifier, skeleton } from "../src/providers/postgres.js";

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
ok("SELECT 1;"); // single trailing semicolon is fine
ok("SELECT count(*) FROM orders WHERE status = 'paid'");

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
no("");
no("   ");

// transaction-control attempts rejected (not read-class leaders)
no("BEGIN");
no("COMMIT");
no("ROLLBACK");
no("SAVEPOINT s1");
no("RELEASE SAVEPOINT s1");
no("SET statement_timeout = 0");
no("SET TRANSACTION READ WRITE");
no("RESET ALL");
no("DISCARD ALL");
no("DO $$ BEGIN PERFORM 1; END $$");
no("CALL some_proc()");
no("PREPARE p AS SELECT 1");

// multi-statement injection rejected
no("SELECT 1; DROP TABLE users");
no("SELECT 1;DELETE FROM users");
no("select * from t; update t set x=1");
no("SELECT 1; SELECT 2");

// F2: `;` / comment markers hidden in strings, comments, dollar-quotes are NOT
// second statements — but a REAL second statement is still caught (no desync)
ok("SELECT 'a;b' AS v");
ok("SELECT 1 -- ; DROP TABLE users");
ok("SELECT 1 /* ; DROP TABLE users */");
ok("SELECT $tag$ a ; b $tag$ AS v");
ok("SELECT $$ ; DROP $$ AS v");
ok("SELECT 'it''s; still one string'"); // escaped quote
ok("SELECT 'a''; DELETE FROM t'"); // escaped quote keeps it one string
ok("SELECT 1 /* nested /* block */ still comment */"); // nested block comment
no("SELECT 'a;b'; DELETE FROM t"); // real 2nd statement after a string
// the exact skeleton-desync bypass that the old sequential-regex stripper let through:
no("SELECT '/*'; DROP TABLE x; SELECT '*/'");
no("SELECT 1 /* ' */ ; DROP TABLE x /* ' */"); // quote inside comment must not open a string
no("SELECT $$x$$; DROP TABLE x"); // real 2nd statement after a dollar-quote

// skeleton sanity: the desync input collapses to a form that still shows the real `;`
assert.ok(skeleton("SELECT '/*'; DROP TABLE x; SELECT '*/'").includes(";"), "skeleton preserves real statement separators");
assert.ok(!skeleton("SELECT '/* ; */'").includes(";"), "skeleton blanks separators hidden in a string");

// Razor wire: dangerous functions blocked even inside SELECT
no("SELECT pg_read_file('/etc/passwd')");
no("SELECT pg_read_binary_file('/etc/passwd')");
no("SELECT * FROM pg_ls_dir('/tmp')");
no("SELECT lo_export(123, '/tmp/out')");
no("SELECT dblink('dbname=other', 'select 1')");
no("SELECT pg_stat_file('/var/lib/postgresql')");
no("select PG_READ_FILE('/etc/passwd')"); // case insensitive

// identifier guard for sample()
assert.ok(isSafeIdentifier("users"));
assert.ok(isSafeIdentifier("public.users"));
assert.ok(!isSafeIdentifier("users; DROP TABLE x"));
assert.ok(!isSafeIdentifier("a b"));
assert.ok(!isSafeIdentifier("a.b.c"));
assert.ok(!isSafeIdentifier(""));
assert.ok(!isSafeIdentifier('"users"'));

console.log(
  "postgres-guard.test: read-class allowed; writes + txn-control + multi-statement + " +
    "string/comment/dollar-quote desync + dangerous functions rejected; identifier guard holds",
);
