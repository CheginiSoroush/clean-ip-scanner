/**
 * Next.js instrumentation hook (hunt v6.5) — auto-push scheduler entry.
 *
 * The node-only implementation lives in src/lib/auto-push-node.ts and is
 * dynamically imported inside the `process.env.NEXT_RUNTIME === 'nodejs'`
 * branch — the Next.js documented pattern. Turbopack DCEs the branch from the
 * Edge bundle (node:fs / node:path / prisma are never statically reachable
 * from Edge), so boot stays clean of Edge-runtime warnings; the scheduler
 * itself still lazy-loads everything at register time.
 */

export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { startAutoPushScheduler } = await import('./lib/auto-push-node')
    startAutoPushScheduler()
  }
}
