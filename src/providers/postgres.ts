/**
 * Read-only Postgres capability for the aletheia sandbox.
 *
 * Defense in depth — the database is the backstop, not SQL string-matching:
 *   1. The pool SHOULD authenticate as a read-only role (or point at a replica).
 *      This is the guarantee that holds even if every layer above is bypassed.
 *   2. Every statement runs inside a `BEGIN ... READ ONLY` transaction that is
 *      always rolled back. A read-only transaction makes Postgres itself reject
 *      writes — including the ones a naive "is it a SELECT?" check misses:
 *      writable CTEs (`WITH x AS (INSERT ...)`), `SELECT ... FOR UPDATE`, and
 *      volatile functions that attempt to write.
 *   3. `classifyStatement` is the first line: single statement, read-class leading
 *      keyword only. It is NOT the guarantee (see 2); it gives a clear early error
 *      and blocks multi-statement injection.
 *   4. `SET LOCAL statement_timeout` bounds query time; rows returned are capped.
 *
 * The capability object the agent receives has no write method and never holds the
 * connection string — credentials stay on the host side of the sandbox boundary.
 *
 * NOTE: the live pg wiring here is written against node-postgres but has NOT been
 * integration-tested against a running server in this build (no Postgres present).
 * The pure guard (`classifyStatement`, `isSafeIdentifier`) is fully unit-tested.
 * Run the integration suite against a real read-only role before production use.
 */
import type { Pool } from "pg";
import { fingerprint, type Capability } from "../core/sandbox.js";

export interface PostgresProviderOptions {
  /** A node-postgres Pool. Authenticate it as a READ-ONLY role, or point at a replica. */
  pool: Pool;
  /** A label for the target in receipts/logs — NOT the connection string. e.g. "analytics@replica". */
  identity: string;
  /** Max rows returned to the agent per query (host memory guard). Default 10_000. */
  maxRows?: number;
  /** Per-statement timeout in ms, applied as SET LOCAL statement_timeout. Default 10_000. */
  statementTimeoutMs?: number;
}

const READ_LEADERS = new Set(["select", "with", "explain", "show", "table", "values"]);

/** Strip string/line/block comments and string + dollar-quoted literals so a
 *  structural scan isn't fooled by `;` or keywords inside them. Returns the
 *  "skeleton" used only for classification (never for execution). */
function skeleton(sql: string): string {
  let s = sql;
  s = s.replace(/\/\*[\s\S]*?\*\//g, " ");          // block comments
  s = s.replace(/--[^\n]*/g, " ");                   // line comments
  s = s.replace(/'(?:''|[^'])*'/g, "''");            // single-quoted strings
  s = s.replace(/\$([A-Za-z_]*)\$[\s\S]*?\$\1\$/g, "''"); // dollar-quoted strings
  return s;
}

export interface Classification { ok: boolean; reason?: string; leader?: string; }

/**
 * First-line statement guard (NOT the security guarantee — the read-only
 * transaction is). Accepts a single read-class statement, rejects everything else.
 */
export function classifyStatement(sql: string): Classification {
  if (typeof sql !== "string" || !sql.trim()) return { ok: false, reason: "empty statement" };
  const sk = skeleton(sql).trim().replace(/;+\s*$/, ""); // drop trailing semicolons
  if (!sk) return { ok: false, reason: "empty statement" };
  if (sk.includes(";")) return { ok: false, reason: "multiple statements are not allowed" };
  const m = /^\(*\s*([A-Za-z]+)/.exec(sk);             // allow a leading paren before SELECT
  const leader = m?.[1]?.toLowerCase();
  if (!leader || !READ_LEADERS.has(leader))
    return { ok: false, reason: `only read-class statements are allowed (got ${leader ? leader.toUpperCase() : "?"})`, leader };
  return { ok: true, leader };
}

/** A conservative identifier check for `sample(table)`: optional schema.table,
 *  each part a plain SQL identifier. Anything else is rejected rather than quoted. */
export function isSafeIdentifier(id: string): boolean {
  return typeof id === "string" && /^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*)?$/.test(id);
}

function quoteIdent(id: string): string {
  // id already validated by isSafeIdentifier; quote each part to preserve case.
  return id.split(".").map((p) => `"${p}"`).join(".");
}

/**
 * Build the read-only Postgres capability plus a context fingerprint for receipts.
 * The returned `capability` is what you pass to runInSandbox; `contextHash` folds
 * in the live schema so a receipt changes if the schema changes under the agent.
 */
export async function createPostgresCapability(
  opts: PostgresProviderOptions,
): Promise<{ capability: Capability; contextHash: string }> {
  const maxRows = opts.maxRows ?? 10_000;
  const stmtTimeout = opts.statementTimeoutMs ?? 10_000;

  // Every read runs in its own always-rolled-back READ ONLY transaction.
  async function readOnly<T>(fn: (q: (text: string, values?: unknown[]) => Promise<{ rows: any[]; fields: { name: string }[]; rowCount: number | null }>) => Promise<T>): Promise<T> {
    const client = await opts.pool.connect();
    try {
      await client.query("BEGIN TRANSACTION READ ONLY");
      await client.query(`SET LOCAL statement_timeout = ${Number(stmtTimeout)}`);
      const q = async (text: string, values?: unknown[]) => {
        const res = await client.query({ text, values });
        return { rows: res.rows, fields: (res.fields ?? []).map((f) => ({ name: f.name })), rowCount: res.rowCount };
      };
      return await fn(q);
    } finally {
      try { await client.query("ROLLBACK"); } catch { /* connection already gone */ }
      client.release();
    }
  }

  async function loadSchema() {
    return readOnly(async (q) => {
      const cols = await q(
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

  const cap = (rows: any[]) => {
    const truncated = rows.length > maxRows;
    return { rows: truncated ? rows.slice(0, maxRows) : rows, truncated, rowCount: rows.length };
  };

  const methods = {
    /** Full column-level schema of the database (comment-free, read-only). */
    schema: () => schema,

    /** Run a single read-class SQL statement with optional parameters; returns capped rows. */
    query: async (sql: unknown, params?: unknown) => {
      if (typeof sql !== "string") throw new Error("query(sql, params?) expects a SQL string");
      const cls = classifyStatement(sql);
      if (!cls.ok) throw new Error("rejected: " + cls.reason);
      const values = Array.isArray(params) ? (params as unknown[]) : undefined;
      return readOnly(async (q) => {
        const res = await q(sql, values);
        return { ...cap(res.rows), fields: res.fields };
      });
    },

    /** Sample up to n rows from a table (validated identifier, read-only). */
    sample: async (table: unknown, n?: unknown) => {
      if (!isSafeIdentifier(String(table))) throw new Error("invalid table identifier");
      const key = String(table).includes(".") ? String(table) : `public.${table}`;
      if (!tableKeys.has(key)) throw new Error(`unknown table: ${table}`);
      const lim = Math.max(1, Math.min(Number(n) || 50, maxRows));
      return readOnly(async (q) => {
        const res = await q(`SELECT * FROM ${quoteIdent(String(table))} LIMIT ${lim}`);
        return { ...cap(res.rows), fields: res.fields };
      });
    },

    /** EXPLAIN (FORMAT JSON) a read-class statement without executing its effects. */
    explain: async (sql: unknown) => {
      if (typeof sql !== "string") throw new Error("explain(sql) expects a SQL string");
      const cls = classifyStatement(sql);
      if (!cls.ok) throw new Error("rejected: " + cls.reason);
      return readOnly(async (q) => {
        const res = await q(`EXPLAIN (FORMAT JSON) ${sql}`);
        return res.rows?.[0]?.["QUERY PLAN"] ?? res.rows;
      });
    },
  };

  return { capability: { namespace: "db", methods }, contextHash };
}
