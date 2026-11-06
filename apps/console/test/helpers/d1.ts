// In-memory D1 stand-in on node:sqlite, applying the real migrations.
import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const MIGRATIONS = fileURLToPath(new URL("../../migrations/", import.meta.url));

class Stmt {
  constructor(
    private db: DatabaseSync,
    public sql: string,
    public args: unknown[] = [],
  ) {}
  bind(...a: unknown[]) {
    return new Stmt(this.db, this.sql, a.map((v) => (v === undefined ? null : v)));
  }
  async first<T>() {
    return (this.db.prepare(this.sql).get(...(this.args as never[])) ?? null) as T;
  }
  async all<T>() {
    return { results: this.db.prepare(this.sql).all(...(this.args as never[])) as T[] };
  }
  async run() {
    const st = this.db.prepare(this.sql);
    if (/RETURNING/i.test(this.sql)) return { meta: { changes: st.all(...(this.args as never[])).length } };
    return { meta: { changes: Number(st.run(...(this.args as never[])).changes) } };
  }
  runSync() {
    const st = this.db.prepare(this.sql);
    return /RETURNING|^\s*SELECT/i.test(this.sql) ? st.all(...(this.args as never[])) : st.run(...(this.args as never[]));
  }
}

export function makeD1() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  for (const f of readdirSync(MIGRATIONS).filter((f) => f.endsWith(".sql")).sort()) db.exec(readFileSync(MIGRATIONS + f, "utf8"));
  return {
    raw: db,
    prepare: (sql: string) => new Stmt(db, sql),
    async batch(stmts: Stmt[]) {
      db.exec("BEGIN");
      try {
        const out = stmts.map((s) => s.runSync());
        db.exec("COMMIT");
        return out;
      } catch (e) {
        db.exec("ROLLBACK");
        throw e;
      }
    },
  };
}
