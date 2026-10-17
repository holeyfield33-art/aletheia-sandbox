# aletheia-sandbox

**One programmable, read-only tool for agents — security in the jail, not the API.**

Give an agent a single tool that runs code against a frozen, read-only capability.
The agent writes the exact filter / join / aggregate it needs. It can do nothing the capability does not offer.

---

## Requirements

- **Node.js >= 20.**
- **A C/C++ toolchain for the `isolated-vm` native addon.** `isolated-vm` is a
  compiled V8-isolate binding; `npm install` builds it with `node-gyp` unless a
  matching prebuilt binary is available. Install the toolchain first:
  - Debian/Ubuntu: `sudo apt-get install -y python3 make g++`
  - macOS: `xcode-select --install`
  - Windows: Visual Studio "Desktop development with C++" (MSVC) + Python 3
- **Supported platforms:** Linux and macOS (x64/arm64) are tested in CI. Windows
  works with the build tools above but is not covered by CI.
- A reachable PostgreSQL (12+) and a **read-only** role or a replica.

## Install

Pre-1.0 and **not yet published to npm.** Install from source or a release tarball:

```bash
# from a built release tarball (npm pack) — ships prebuilt dist/
npm install ./aletheia-sandbox-0.1.0.tgz
# or straight from GitHub — a `prepare` script compiles dist/ on install
# (so the native toolchain above is required for the Git install)
npm install github:holeyfield33-art/aletheia-sandbox
```

This installs the `aletheia-sandbox-pg` executable into `node_modules/.bin/`.
(`npx aletheia-sandbox-pg` resolves that local binary; it is **not** on the npm
registry, so `npx -y aletheia-sandbox-pg` with a forced registry fetch will fail.)

## Give this to your agent in 60 seconds

### 1. Point at a read-only Postgres

```bash
# MUST be a READ-ONLY role or replica. The server refuses to start otherwise.
export DATABASE_URL="postgres://readonly_user:secret@host:5432/yourdb"
```

### 2. Run the MCP server

```bash
# after installing locally (see Install above):
npx aletheia-sandbox-pg
# or directly: ./node_modules/.bin/aletheia-sandbox-pg
```

### 3. Connect your agent

**Claude Desktop / Cursor-style MCP config:**

```json
{
  "mcpServers": {
    "aletheia-sandbox-pg": {
      "command": "npx",
      "args": ["aletheia-sandbox-pg"],
      "env": {
        "DATABASE_URL": "postgres://readonly_user:secret@host:5432/yourdb"
      }
    }
  }
}
```

The agent receives **one tool**: `db_exec`.
It writes JavaScript that calls a frozen `db` capability and returns a value.

```js
// Example agent code inside db_exec
const s = db.schema();
const orders = s.find(t => t.name === "orders");
return db.query("SELECT status, count(*) FROM orders GROUP BY 1 ORDER BY 2 DESC").rows;
```

---

## What the agent gets

| Method | What it does |
|--------|--------------|
| `db.schema()` | Column-level schema (tables, columns, types, nullability) |
| `db.query(sql, params?)` | Single read-class statement → `{ rows, fields, rowCount, truncated }` |
| `db.sample(table, n?)` | Up to *n* rows from a validated table |
| `db.explain(sql)` | JSON query plan |

Everything runs inside a hardened V8 isolate. The agent cannot write, cannot reach the network, filesystem, `require`, `process`, or credentials.

---

## Security model

**Jail** = V8 isolate (`isolated-vm`): separate heap, no Node bindings, no ambient authority.

**Wall + razor wire** = everything around the jail:

1. **Startup write probe** — refuses to start unless the catalog proves the role
   is read-only: no elevated role attributes, no INSERT/UPDATE/DELETE/TRUNCATE on
   any user table, no CREATE on any persistent schema. (It does **not** rely on a
   `CREATE TEMP TABLE` attempt — TEMP is granted to PUBLIC and proves nothing.)
   Any unexpected error **fails closed** — the server refuses to start.
2. **Database is the backstop** — point `DATABASE_URL` at a **read-only role** or **replica**.
3. Every statement runs inside an always-rolled-back `BEGIN TRANSACTION READ ONLY`,
   so Postgres rejects writes the classifier never sees — writable CTEs, `FOR UPDATE`, volatile writes.
4. **Protocol-level single statement** — user SQL runs through the extended query
   protocol (cursor / named prepared statement), so Postgres itself rejects
   multiple commands. This does not depend on regex classification.
5. `classifyStatement` (defense in depth) uses a single-pass tokenizer — strings,
   comments, and dollar-quotes can't desync it — then rejects non-read leaders,
   transaction control, and **dangerous functions** (`pg_read_file`, `lo_export`, `dblink`, …).
6. Capability is frozen + allowlisted; host reference is blanked before agent code runs.
7. JSON boundary — isolate never holds live host objects or credentials.
8. Caps: isolate memory, in-isolate timeout, per-call host deadline, **whole-run budget**
   (hard cancellation), result size, and **bounded row fetch** (cursor — a huge result is
   never fully materialized in host memory).
9. Every run returns a **result-bound** receipt: `sha256(selector + code + contextHash + resultHash)`,
   with the request identity (`requestHash`) exposed separately.

A fully prompt-injected agent’s worst case is “read within limits and reason.”

---

## Core library (optional)

If you want to build your own capability instead of using the Postgres MCP server:

```ts
import { runInSandbox, type Capability } from "aletheia-sandbox";

const capability: Capability = {
  namespace: "data",
  methods: {
    get: (id: string) => store.get(id),
    search: async (q: string) => await index.search(q),
  },
};

const res = await runInSandbox(
  capability,
  `const hits = data.search("invoices"); return hits.slice(0, 5).map(h => h.id);`,
  contextHash, // stable fingerprint of the data surface
);
// res = { ok, result, error?, receipt, note }
```

Any frozen `{ namespace, methods }` works. Postgres is just the first ready-made provider.

---

## Local testing with Docker

```bash
docker compose up -d
export DATABASE_URL="postgres://readonly:readonly@localhost:5433/sandbox"
npm test
npm run test:integration
```

See `docker-compose.yml` for the read-only role setup. The integration test exercises the full wall (write probe + dangerous-function denylist).

---

## Scripts

| Command | Purpose |
|---------|---------|
| `npm run build` | Compile to `dist/` |
| `npm run typecheck` | Type-check only |
| `npm test` | Core jail + SQL guard (no DB required) |
| `npm run test:integration` | Live Postgres tests (requires `DATABASE_URL`) |

---

## Status

Pre-1.0. Verified by executed tests (not static inspection):

- Core isolate, allowlist, caps, whole-run budget + cancellation, result-bound receipt — unit-tested
- Read-only SQL guard (incl. string/comment/dollar-quote desync) + dangerous-function denylist — unit-tested
- Live Postgres path, run with a real read-only **and** a real writable role: startup probe accepts
  read-only / refuses writable; writes, multi-statement injection, and a writable CTE are all rejected
  with a persistent **canary** confirming zero rows written; bounded fetch; run-budget cancellation —
  integration-tested (`DATABASE_URL` + `DATABASE_URL_WRITABLE`)
- npm-installed binary drives an end-to-end MCP `db_exec` call — package smoke-tested
- Prefer a replica or snapshot over a live primary in production

---

## License

Apache-2.0
