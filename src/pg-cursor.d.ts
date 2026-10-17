/**
 * Minimal typed declaration for pg-cursor (which ships no types). Covers only the
 * surface this package uses: construct with text + values, read a bounded batch
 * with the 3-arg callback (rows + a result carrying fields), and close. Declared
 * with a `submit` method so an instance is structurally a node-postgres
 * Submittable and can be passed to client.query(...).
 */
declare module "pg-cursor" {
  interface CursorResultLike {
    fields: { name: string }[];
  }
  export default class Cursor<R = Record<string, unknown>> {
    constructor(text: string, values?: unknown[]);
    /** node-postgres Submittable hook — not called directly by this package. */
    submit(connection: unknown): void;
    read(
      rowCount: number,
      callback: (err: Error | undefined, rows: R[], result: CursorResultLike) => void,
    ): void;
    close(callback?: (err?: Error) => void): void;
  }
}
