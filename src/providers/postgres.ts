/**
 * Read-only Postgres capability for the aletheia sandbox.
 *
 * Defense in depth — the database is the backstop, the isolate is the jail,
 * and these guards are the wall + razor wire:
 *
 *   1. STARTUP WRITE PROBE — createPostgresCapability refuses to build if the
 *      role can write. Fail closed. No silent weak mode.
 *   2. The pool SHOULD authenticate as a read-only role (or point at a replica).
 *      This is the guarantee that holds even if every layer above is bypassed.
 *   3. Every statement runs inside a `BEGIN ... READ ONLY` transaction that is
 *      always rolled back. Postgres itself rejects writes — including writable
 *      CTEs, SELECT ... FOR UPDATE, and volatile write functions.
 *   4. classifyStatement is the first line: single statement, read-class leader
 *      only, plus a denylist of dangerous functions (file/FS/dblink/exfil).
 *   5. SET LOCAL statement_timeout bounds query time; rows returned are capped.
 *
 * The capability object the agent receives has no write method and never holds
 * the connection string — credentials stay on the host side of the sandbox boundary.
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
  /**
   * If true (default), probe the role at startup and refuse to build the capability
   * if a write is possible. Set false only for controlled tests.
   */
  requireReadOnlyRole?: boolean;
}

const READ_LEADERS = new Set(["select", "with", "explain", "show", "table", "values"]);

/**
 * Functions that can read the filesystem, talk to other servers, or otherwise
 * escape the data surface even from inside a SELECT. Matched on the skeleton
 * (comments/strings stripped) as whole identifiers.
 */
const DANGEROUS_FUNCTIONS = [
  "pg_read_file",
  "pg_read_binary_file",
  "pg_ls_dir",
  "pg_stat_file",
  "pg_logfile_rotate",
  "lo_import",
  "lo_export",
  "lo_from_bytea",
  "lo_get",
  "lo_put",
  "lo_unlink",
  "dblink",
  "dblink_exec",
  "dblink_connect",
  "dblink_send_query",
  "dblink_get_result",
  "dblink_fdw_validator",
  "pg_execute_server_program",
  "copy_file",
  "dbms_lob",
];

const DANGEROUS_RE = new RegExp(
  `\\b(${DANGEROUS_FUNCTIONS.map((f) => f.replace(/_/g, "_")).join("|")})\\s*\\(`,
  "i",
);

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
 * First-line statement guard (NOT the sole security guarantee — the read-only
 * transaction + startup probe are). Accepts a single read-class statement,
 * rejects writes, multi-statement injection, and dangerous functions.
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

  // Razor wire: block known exfil / FS / dblink style functions even in SELECT
  const danger = DANGEROUS_RE.exec(sk);
  if (danger) {
    return {
      ok: false,
      reason: `dangerous function blocked: ${danger[1].toLowerCase()}()`,
      leader,
    };
  }

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
 * Wall: probe whether the connected role can write.
 * Tries a write inside a transaction and rolls it back.
 * If the write succeeds, the role is too powerful — fail closed.
 */
export async function assertReadOnlyRole(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    try {
      // Temporary table is a clear write. If this works, the role is not read-only.
      await client.query("CREATE TEMP TABLE aletheia_write_probe (x int)");
      // If we get here, the role can write.
      await client.query("ROLLBACK");
      throw new Error(
        "aletheia-sandbox: DATABASE_URL role can WRITE. " +
        "Refusing to start. Use a read-only role or a replica. " +
        "This is intentional — the database is the final backstop.",
      );
    } catch (e) {
      // Expected path: permission denied / read-only transaction / etc.
      const msg = String(e instanceof Error ? e.message : e);
      if (/aletheia-sandbox: DATABASE_URL role can WRITE/i.test(msg)) throw e;
      // Any other error from the probe means the write was blocked — good.
      try { await client.query("ROLLBACK"); } catch { /* ignore */ }
    }
  } finally {
    client.release();
  }
}

/**
 * Build the read-only Postgres capability plus a context fingerprint for receipts.
 * The returned `capability` is what you pass to runInSandbox; `contextHash` folds
 * in the live schema so a receipt changes if the schema changes under the agent.
 *
 * By default this probes the role and refuses to build if writes are possible.
 */
export async function createPostgresCapability(
  opts: PostgresProviderOptions,
): Promise<{ capability: Capability; contextHash: string }> {
  const maxRows = opts.maxRows ?? 10_000;
  const stmtTimeout = opts.statementTimeoutMs ?? 10_000;
  const requireReadOnly = opts.requireReadOnlyRole !== false;

  if (requireReadOnly) {
    await assertReadOnlyRole(opts.pool);
  }

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
