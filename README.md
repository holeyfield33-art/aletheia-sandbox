# aletheia-sandbox

**One programmable, read-only tool for agents — security in the jail, not the API.**

Give an agent a single tool that runs code against a frozen, read-only capability.
The agent writes the exact filter / join / aggregate it needs. It can do nothing the capability does not offer.

---

## Give this to your agent in 60 seconds

### 1. Point at a read-only Postgres

```bash
# Use a READ-ONLY role or a replica. This is the real backstop.
export DATABASE_URL="postgres://readonly_user:secret@host:5432/yourdb"
```

### 2. Run the MCP server

```bash
npx aletheia-sandbox-pg
# or after install: aletheia-sandbox-pg
```

### 3. Connect your agent

**Claude Desktop / Cursor-style MCP config:**

```json
{
  "mcpServers": {
    "aletheia-sandbox-pg": {
      "command": "npx",
      "args": ["-y", "aletheia-sandbox-pg"],
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

## Security model (defense in depth)

1. **Database is the backstop** — point `DATABASE_URL` at a **read-only role** or **replica**.
2. Every statement runs inside an always-rolled-back `BEGIN TRANSACTION READ ONLY`.
3. `classifyStatement` rejects non-read leaders and multi-statement injection early.
4. V8 isolate (`isolated-vm`): separate heap, no Node bindings, no ambient authority.
5. Capability is frozen + allowlisted; host reference is blanked before agent code runs.
6. JSON boundary — isolate never holds live host objects or credentials.
7. Caps: isolate memory, wall-clock timeout, per-call host deadline, result size, row count.
8. Every run returns a replayable receipt: `sha256(selector + code + contextHash)`.

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

See `docker-compose.yml` for the read-only role setup.

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

- Core isolate + allowlist + caps: unit-tested
- Read-only SQL guard: unit-tested
- Live Postgres path: integration test available when `DATABASE_URL` is set
- Prefer a replica or snapshot over a live primary in production

---

## License

Apache-2.0
