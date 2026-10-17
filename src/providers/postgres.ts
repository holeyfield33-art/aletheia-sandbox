/**
 * Read-only Postgres capability for the aletheia sandbox.
 *
 * Defense in depth — the database is the backstop, the isolate is the jail, and
 * these guards are the wall + razor wire:
 *
 *   1. STARTUP WRITE PROBE (assertReadOnlyRole) — refuses to build the capability
 *      unless the role is provably read-only: no elevated role attributes
 *      (superuser/createdb/createrole), no INSERT/UPDATE/DELETE/TRUNCATE privilege
 *      on any user table, and no CREATE on any persistent schema. It inspects the
 *      catalog rather than attempting a TEMP write (TEMP is granted to PUBLIC, so
 *      a TEMP probe proves nothing about persistent write). Any unexpected error
 *      FAILS CLOSED — the server refuses to start rather than assume read-only.
 *   2. PROTOCOL-LEVEL SINGLE STATEMENT — user SQL runs through the extended query
 *      protocol (pg-cursor / named prepared statement), so Postgres itself rejects
 *      "cannot insert multiple commands into a prepared statement". This does not
 *      depend on regex classification.
 *   3. READ ONLY TRANSACTION — every statement runs inside `BEGIN ... READ ONLY`,
 *      always rolled back. Postgres rejects writes (writable CTEs, FOR UPDATE,
 *      volatile write functions) regardless of the role.
 *   4. CLASSIFIER (classifyStatement) — defense in depth: a single-pass tokenizer
 *      strips strings/comments/dollar-quotes without the regex desync bug, then
 *      requires a read-class leader and blocks a denylist of dangerous functions.
 *   5. BOUNDED FETCH — rows are read through a cursor up to a cap, so a huge result
 *      set is never fully materialized in host memory.
 *   6. SET LOCAL statement_timeout bounds query time.
 *
 * The capability object the agent receives has no write method and never holds the
 * connection string — credentials stay on the host side of the sandbox boundary.
 */
import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import Cursor from "pg-cursor";
import { fingerprint, type Capability } from "../core/sandbox.js";

export interface PostgresProviderOptions {
  /** A node-postgres Pool. Authenticate it as a READ-ONLY role, or point at a replica. */
  pool: Pool;
  /** A label for the target in receipts/logs — NOT the connection string. */
  identity: string;
  /** Max rows returned to the agent per query (bounded via cursor). Default 10_000. */
  maxRows?: number;
  /** Per-statement timeout in ms, applied as SET LOCAL statement_timeout. Default 10_000. */
  statementTimeoutMs?: number;
  /** If true (default), probe the role at startup and refuse to build if it can write. */
  requireReadOnlyRole?: boolean;
}

const READ_LEADERS = new Set(["select", "with", "explain", "show", "table", "values"]);

/** Functions that can read the filesystem, talk to other servers, or otherwise
 *  escape the data surface even from inside a SELECT. */
const DANGEROUS_FUNCTIONS = [
  "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "pg_logfile_rotate",
  "lo_import", "lo_export", "lo_from_bytea", "lo_get", "lo_put", "lo_unlink",
  "dblink", "dblink_exec", "dblink_connect", "dblink_send_query", "dblink_get_result", "dblink_fdw_validator",
  "pg_execute_server_program", "copy_file", "dbms_lob",
];
const DANGEROUS_RE = new RegExp(`\\b(${DANGEROUS_FUNCTIONS.join("|")})\\s*\\(`, "i");

/**
 * Single-pass tokenizer: blank out string literals, line/block comments, and
 * dollar-quoted strings so a structural scan isn't fooled by `;` or keywords
 * hidden inside them. Unlike sequential regex replacement, this cannot desync —
 * a `/*` inside a string literal is never treated as a comment, and a `'` inside
 * a comment is never treated as a string. Block comments nest (Postgres allows
 * it). Output is used ONLY for classification, never for execution.
 */
export function skeleton(sql: string): string {
  let out = "";
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const ch = sql[i];
    const two = sql.slice(i, i + 2);

    // line comment
    if (two === "--") {
      i += 2;
      while (i < n && sql[i] !== "\n") i++;
      out += " ";
      continue;
    }
    // block comment (nesting)
    if (two === "/*") {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (sql.slice(i, i + 2) === "/*") { depth++; i += 2; }
        else if (sql.slice(i, i + 2) === "*/") { depth--; i += 2; }
        else i++;
      }
      out += " ";
      continue;
    }
    // single-quoted string (with '' escape)
    if (ch === "'") {
      i++;
      while (i < n) {
        if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; }
        if (sql[i] === "'") { i++; break; }
        i++;
      }
      out += "''";
      continue;
    }
    // dollar-quoted string: $tag$ ... $tag$  (tag is an optional identifier)
    if (ch === "$") {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*|)\$/.exec(sql.slice(i));
      if (m) {
        const tag = m[0];
        i += tag.length;
        const end = sql.indexOf(tag, i);
        i = end === -1 ? n : end + tag.length;
        out += "''";
        continue;
      }
    }
    out += ch;
    i++;
  }
  return out;
}

export interface Classification { ok: boolean; reason?: string; leader?: string; }

/**
 * Defense-in-depth statement guard (the protocol-level single-statement
 * enforcement in the execution path is the actual guarantee). Accepts a single
 * read-class statement; rejects writes, transaction control, multi-statement, and
 * dangerous functions.
 */
export function classifyStatement(sql: string): Classification {
  if (typeof sql !== "string" || !sql.trim()) return { ok: false, reason: "empty statement" };
  const sk = skeleton(sql).trim().replace(/;+\s*$/, ""); // drop trailing semicolons
  if (!sk) return { ok: false, reason: "empty statement" };
  if (sk.includes(";")) return { ok: false, reason: "multiple statements are not allowed" };

  const m = /^\(*\s*([A-Za-z]+)/.exec(sk); // allow a leading paren before SELECT
  const leader = m?.[1]?.toLowerCase();
  if (!leader || !READ_LEADERS.has(leader))
    return { ok: false, reason: `only read-class statements are allowed (got ${leader ? leader.toUpperCase() : "?"})`, leader };

  const danger = DANGEROUS_RE.exec(sk);
  if (danger) return { ok: false, reason: `dangerous function blocked: ${danger[1].toLowerCase()}()`, leader };

  return { ok: true, leader };
}

/** Conservative identifier check for `sample(table)`: optional schema.table. */
export function isSafeIdentifier(id: string): boolean {
  return typeof id === "string" && /^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*)?$/.test(id);
}

function quoteIdent(id: string): string {
  return id.split(".").map((p) => `"${p}"`).join(".");
}

class RoleCanWrite extends Error {}

/**
 * Fail-closed startup privilege validation. A role is accepted ONLY if the catalog
 * proves it cannot write persistently; any unexpected error refuses startup.
 *
 * Why catalog inspection instead of a write attempt: CREATE TEMP TABLE is granted
 * to PUBLIC, so it proves nothing about persistent write; and an INSERT-only role
 * has no CREATE, so a CREATE attempt would miss it. has_table_privilege /
 * has_schema_privilege / pg_roles cover attributes, DML grants, and DDL grants
 * together, and cannot be fooled.
 */
export async function assertReadOnlyRole(pool: Pool): Promise<void> {
  let client: PoolClient | undefined;
  try {
    client = await pool.connect();
    const attr = await client.query(
      `SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user`,
    );
    const a = attr.rows[0];
    if (a && (a.rolsuper || a.rolcreatedb || a.rolcreaterole))
      throw new RoleCanWrite("role has elevated attributes (superuser/createdb/createrole)");

    const w = await client.query(
      `SELECT count(*)::int AS n FROM information_schema.tables t
        WHERE t.table_schema NOT IN ('pg_catalog','information_schema')
          AND t.table_type = 'BASE TABLE'
          AND (has_table_privilege(format('%I.%I', t.table_schema, t.table_name), 'INSERT')
            OR has_table_privilege(format('%I.%I', t.table_schema, t.table_name), 'UPDATE')
            OR has_table_privilege(format('%I.%I', t.table_schema, t.table_name), 'DELETE')
            OR has_table_privilege(format('%I.%I', t.table_schema, t.table_name), 'TRUNCATE'))`,
    );
    if ((w.rows[0]?.n ?? 0) > 0) throw new RoleCanWrite(`role has write privilege on ${w.rows[0].n} table(s)`);

    const c = await client.query(
      `SELECT count(*)::int AS n FROM information_schema.schemata s
        WHERE s.schema_name NOT IN ('pg_catalog','information_schema','pg_toast')
          AND has_schema_privilege(s.schema_name, 'CREATE')`,
    );
    if ((c.rows[0]?.n ?? 0) > 0) throw new RoleCanWrite(`role can CREATE objects in ${c.rows[0].n} schema(s)`);
  } catch (e) {
    if (e instanceof RoleCanWrite)
      throw new Error(`aletheia-sandbox: ${e.message}. Refusing to start — use a read-only role or a replica.`);
    // Unexpected error — fail CLOSED, never assume read-only.
    throw new Error(
      `aletheia-sandbox: could not verify the role is read-only (${String(e instanceof Error ? e.message : e)}). Refusing to start.`,
    );
  } finally {
    client?.release();
  }
}

export interface QueryResult { rows: any[]; fields: { name: string }[]; truncated: boolean; rowCount: number; }

export async function createPostgresCapability(
  opts: PostgresProviderOptions,
): Promise<{ capability: Capability; contextHash: string }> {
  const maxRows = opts.maxRows ?? 10_000;
  const stmtTimeout = opts.statementTimeoutMs ?? 10_000;
  const requireReadOnly = opts.requireReadOnlyRole !== false;

  if (requireReadOnly) await assertReadOnlyRole(opts.pool);

  /** Run fn inside an always-rolled-back READ ONLY transaction with a statement timeout. */
  async function readOnly<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await opts.pool.connect();
    try {
      await client.query("BEGIN TRANSACTION READ ONLY");
      await client.query(`SET LOCAL statement_timeout = ${Number(stmtTimeout)}`);
      return await fn(client);
    } finally {
      try { await client.query("ROLLBACK"); } catch { /* connection already gone */ }
      client.release();
    }
  }

  /** Bounded read via cursor (extended protocol → single-statement enforced by
   *  Postgres; rows fetched up to the cap, never the whole set). */
  function readLimited(client: PoolClient, text: string, values: unknown[]): Promise<QueryResult> {
    return new Promise((resolve, reject) => {
      const cursor = client.query(new Cursor(text, values));
      cursor.read(maxRows + 1, (err: Error | undefined, rows: any[], result: any) => {
        if (err) { cursor.close(() => {}); reject(err); return; }
        const truncated = rows.length > maxRows;
        const out = truncated ? rows.slice(0, maxRows) : rows;
        const fields = ((result?.fields ?? []) as { name: string }[]).map((f) => ({ name: f.name }));
        cursor.close(() => resolve({ rows: out, fields, truncated, rowCount: out.length }));
      });
    });
  }

  async function loadSchema() {
    return readOnly(async (client) => {
      const cols = await client.query(
        `SELECT table_schema, table_name, column_name, data_type, is_nullable
           FROM information_schema.columns
          WHERE table_schema NOT IN ('pg_catalog','information_schema')
          ORDER BY table_schema, table_name, ordinal_position`,
      );
      const tables: Record<string, { schema: string; name: string; columns: { name: string; type: string; nullable: boolean }[] }> = {};
      for (const r of cols.rows) {
        const key = `${r.table_schema}.${r.table_name}`;
        (tables[key] ??= { schema: r.table_schema, name: r.table_name, columns: [] }).columns.push({
          name: r.column_name, type: r.data_type, nullable: r.is_nullable === "YES",
        });
      }
      return Object.values(tables);
    });
  }

  const schema = await loadSchema();
  const tableKeys = new Set(schema.map((t) => `${t.schema}.${t.name}`));
  const contextHash = fingerprint({ identity: opts.identity, schema });

  const methods = {
    /** Full column-level schema of the database. */
    schema: () => schema,

    /** Run a single read-class SQL statement with optional parameters; bounded rows. */
    query: async (sql: unknown, params?: unknown) => {
      if (typeof sql !== "string") throw new Error("query(sql, params?) expects a SQL string");
      const cls = classifyStatement(sql);
      if (!cls.ok) throw new Error("rejected: " + cls.reason);
      const values = Array.isArray(params) ? (params as unknown[]) : [];
      // Cursor path enforces single-statement at the protocol level AND bounds rows.
      return readOnly((client) => readLimited(client, sql, values));
    },

    /** Sample up to n rows from a validated table (read-only, bounded). */
    sample: async (table: unknown, n?: unknown) => {
      if (!isSafeIdentifier(String(table))) throw new Error("invalid table identifier");
      const key = String(table).includes(".") ? String(table) : `public.${table}`;
      if (!tableKeys.has(key)) throw new Error(`unknown table: ${table}`);
      const lim = Math.max(1, Math.min(Number(n) || 50, maxRows));
      return readOnly((client) => readLimited(client, `SELECT * FROM ${quoteIdent(String(table))} LIMIT ${lim}`, []));
    },

    /** EXPLAIN (FORMAT JSON) a read-class statement. Named prepared statement →
     *  Postgres rejects multiple commands at Parse (protocol-level single stmt). */
    explain: async (sql: unknown) => {
      if (typeof sql !== "string") throw new Error("explain(sql) expects a SQL string");
      const cls = classifyStatement(sql);
      if (!cls.ok) throw new Error("rejected: " + cls.reason);
      return readOnly(async (client) => {
        const text = `EXPLAIN (FORMAT JSON) ${sql}`;
        const name = "aletheia_x_" + createHash("sha256").update(text).digest("hex").slice(0, 24);
        const res = await client.query({ name, text, values: [] });
        return res.rows?.[0]?.["QUERY PLAN"] ?? res.rows;
      });
    },
  };

  return { capability: { namespace: "db", methods }, contextHash };
}
