/**
 * A stopped PostgreSQL container closes idle pooled clients asynchronously.
 * Absorb that transport event so the gateway can fail closed on its next
 * request instead of terminating the process.
 */
export function absorbIdlePostgresClientErrors(pool: unknown): void {
  if (
    typeof pool !== "object" ||
    pool === null ||
    !("on" in pool) ||
    typeof pool.on !== "function"
  ) {
    return;
  }

  pool.on("error", () => undefined);
}
