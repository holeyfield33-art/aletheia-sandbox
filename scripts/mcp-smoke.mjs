/**
 * Package smoke test: drive the INSTALLED `aletheia-sandbox-pg` binary as a real
 * MCP server over stdio — list tools, run a read, attempt a write — proving the
 * executable entry point works end to end after `npm install`.
 *
 * Run from a directory where the package is installed (node_modules/.bin present):
 *   DATABASE_URL=postgres://readonly:...@host/db node scripts/mcp-smoke.mjs
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import assert from "node:assert";
import { existsSync } from "node:fs";

const url = process.env.DATABASE_URL;
if (!url) { console.error("mcp-smoke: set DATABASE_URL (read-only role)"); process.exit(2); }

const bin = "node_modules/.bin/aletheia-sandbox-pg";
if (!existsSync(bin)) { console.error(`mcp-smoke: ${bin} not found — install the package here first`); process.exit(2); }

const transport = new StdioClientTransport({ command: "node", args: [bin], env: { ...process.env, DATABASE_URL: url } });
const client = new Client({ name: "mcp-smoke", version: "1.0.0" });

try {
  await client.connect(transport);

  const tools = await client.listTools();
  assert.ok(tools.tools.some((t) => t.name === "db_exec"), "db_exec tool is listed");

  const read = await client.callTool({ name: "db_exec", arguments: {
    code: `return db.query("SELECT name FROM users ORDER BY id").rows.map(r => r.name);`,
  } });
  const readOut = JSON.parse(read.content[0].text);
  assert.strictEqual(readOut.ok, true, "read succeeds end to end");
  assert.ok(Array.isArray(readOut.result) && readOut.result.length >= 1, "read returned rows");
  assert.ok(readOut.receipt?.hash, "receipt present");

  const write = await client.callTool({ name: "db_exec", arguments: {
    code: `return db.query("INSERT INTO write_canary(note) VALUES('via-mcp-smoke')");`,
  } });
  const writeOut = JSON.parse(write.content[0].text);
  assert.strictEqual(writeOut.ok, false, "write rejected end to end");

  console.log(`mcp-smoke: PASS — tools=[${tools.tools.map((t) => t.name).join(",")}], read=${JSON.stringify(readOut.result)}, write rejected`);
} finally {
  await client.close().catch(() => {});
}
