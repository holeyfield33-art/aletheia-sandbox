# aletheia-sandbox

**One programmable, read-only tool for agents — security in the jail, not the API.**

Instead of giving an agent *N* fixed tools (each spending context on its schema, none able to answer a query nobody pre-wrote), give it **one** tool that takes code and runs it against a frozen, read-only capability. The agent writes the exact filter / join / aggregate / traversal it needs and gets the result back — and it can do *nothing* the capability does not offer.

The guarantee is the sandbox, not the shape of the API:

- **V8 isolate** (`isolated-vm`): a separate heap with **no** Node bindings — `require`, `import`, `process`, `fetch`, filesystem and the host scope do not exist inside it.
- **Capability unreachable**: a trusted bootstrap consumes the one host reference and blanks the handle before any agent code runs. Agent code can call the capability but cannot name the reference behind it, nor the credentials it closes over.
- **Allowlist**: every host call is checked against the capability's own method set. A method that isn't in the map doesn't exist.
- **JSON boundary**: all data crosses as JSON strings. The isolate never holds a live reference to a host object, a database connection, or a credential.
- **Bounded**: an isolate memory cap, an in-isolate wall-clock timeout, a per-call host deadline (for async calls the isolate timeout can't see), and a result-size cap enforced *inside* the isolate before copy-out.
- **Replayable receipt**: every run returns `sha256(selector + code + contextHash)`. Same code over the same data surface → same receipt.

Because the capability the agent holds has **zero write paths and no credentials**, a fully prompt-injected agent's worst case is "read within limits and reason." It cannot mutate, exfiltrate, or escape.

## Core

```ts
import { runInSandbox, type Capability } from "aletheia-sandbox";

const capability: Capability = {
  namespace: "data",
  methods: {
    // sync or async; must return JSON-serializable data
    get: (id: string) => store.get(id),
    search: async (q: string) => await index.search(q),
  },
};

const res = await runInSandbox(
  capability,
  `const hits = data.search("invoices"); return hits.slice(0, 5).map(h => h.id);`,
  contextHash,              // a stable fingerprint of the data surface, for the receipt
);
// res = { ok, result, error?, receipt, note }
```

## Read-only Postgres provider

A ready capability for Postgres, exposed as an MCP server with a single `db_exec` tool.

```bash
npm run build
DATABASE_URL=postgres://readonly:***@replica.host:5432/app  node dist/mcp/server.js
```

The agent gets a frozen `db` capability:

- `db.schema()` — column-level schema (tables, columns, types, nullability)
- `db.query(sql, params?)` — a single read-class statement → `{ rows, fields, rowCount, truncated }`
- `db.sample(table, n?)` — up to *n* rows of a validated table
- `db.explain(sql)` — the JSON query plan

**Write protection is defense in depth, with the database as the backstop:**

1. Point `DATABASE_URL` at a **read-only role** or a **replica** — the guarantee that holds even if every layer above is bypassed.
2. Every statement runs inside an always-rolled-back `BEGIN TRANSACTION READ ONLY`, so Postgres itself rejects writes — including the ones a naive "is it a SELECT?" check misses: writable CTEs (`WITH x AS (INSERT …)`), `SELECT … FOR UPDATE`, volatile write functions.
3. `classifyStatement` is the first line (single statement; read-class leading keyword only; multi-statement injection rejected even when `;` hides in strings or comments) — a clear early error, **not** the guarantee.
4. `SET LOCAL statement_timeout` bounds query time; returned rows are capped.

The connection string never crosses the sandbox boundary.

> **Status.** The core and the read-only SQL guard are fully unit-tested (`npm test`). The live `pg` wiring is written against node-postgres but has **not** been integration-tested against a running server in this build — run it against a real read-only role before production, and prefer a replica or snapshot over a live primary even then.

## Design: one core, many providers

`runInSandbox` knows nothing about any specific data source — it runs code against *whatever* frozen capability you hand it. A provider is just `{ namespace, methods }` plus an allowlist. Postgres is the first; MySQL, Snowflake, BigQuery, ClickHouse, DuckDB, schema catalogs and query-history surfaces are all the same shape against the same core.

## Scripts

- `npm run build` — compile to `dist/`
- `npm run typecheck` — `tsc --noEmit`
- `npm test` — core jail suite + read-only SQL guard suite

## License

Apache-2.0
