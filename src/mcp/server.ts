#!/usr/bin/env node
/**
 * MCP server exposing ONE tool, `db_exec`, over a read-only Postgres connection.
 *
 *   aletheia-sandbox-pg            # reads DATABASE_URL
 *   DATABASE_URL=postgres://readonly:***@host:5432/db aletheia-sandbox-pg
 *
 * The agent writes JavaScript that calls a frozen `db` capability
 * (db.schema(), db.query(sql, params?), db.sample(table, n?), db.explain(sql))
 * and returns a value. The code runs in a hardened isolate (no network, fs,
 * require, process, or host scope); every statement runs in an always-rolled-back
 * READ ONLY transaction with a statement timeout; the connection string never
 * crosses into the sandbox. Point DATABASE_URL at a READ-ONLY role or a replica.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import pg from "pg";
import { runInSandbox, DEFAULT_LIMITS } from "../core/sandbox.js";
import { createPostgresCapability } from "../providers/postgres.js";

function targetIdentity(url: string): string {
  try { const u = new URL(url); return `${u.username || "?"}@${u.hostname}:${u.port || "5432"}${u.pathname}`; }
  catch { return "postgres"; }
}

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("set DATABASE_URL (point it at a READ-ONLY role or a replica)");

  const pool = new pg.Pool({ connectionString: url, max: 4 });
  const { capability, contextHash } = await createPostgresCapability({ pool, identity: targetIdentity(url) });

  const server = new McpServer({ name: "aletheia-sandbox-pg", version: "0.1.0" });
  server.registerTool(
    "db_exec",
    {
      title: "Run read-only code against the database",
      description:
        "ONE programmable, read-only tool. Write JavaScript that calls a frozen `db` capability and `return`s a value — explore, join, aggregate, sample, and reason in a single call. " +
        "API (all read-only): db.schema() -> column-level schema; db.query(sql, params?) -> { rows, fields, rowCount, truncated } for a single read-class statement; db.sample(table, n?) -> up to n rows of a table; db.explain(sql) -> the JSON query plan. " +
        "The code runs in an isolate with NO network, filesystem, require, import, process, or host scope — only `db`. Every statement runs inside an always-rolled-back READ ONLY transaction with a statement timeout, so there is no write path (INSERT/UPDATE/DELETE/DDL and writable CTEs are rejected by Postgres itself). The connection string is never exposed. Results are size-capped and the run carries a replayable receipt. " +
        "Example: `const s = db.schema(); const big = s.find(t => t.name === 'orders'); return db.query('SELECT status, count(*) FROM orders GROUP BY 1 ORDER BY 2 DESC').rows;`",
      inputSchema: { code: z.string().describe("JavaScript body using `db` that returns a JSON-serializable value. Top-level `return` supported.") },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ code }) => {
      const res = await runInSandbox(capability, code, contextHash, DEFAULT_LIMITS, "aletheia-pg-v1");
      return { content: [{ type: "text" as const, text: JSON.stringify(res) }] };
    },
  );

  await server.connect(new StdioServerTransport());
  console.error(`aletheia-sandbox-pg ready (stdio) — target ${targetIdentity(url)}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(String(e instanceof Error ? e.message : e)); process.exit(1); });
}
