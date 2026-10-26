/**
 * Auto-push scheduler — NODE-ONLY implementation (hunt v6.5).
 *
 * Lives in its own file per the Next.js documented instrumentation pattern:
 * src/instrumentation.ts does `if (process.env.NEXT_RUNTIME === 'nodejs')
 * { await import('./lib/auto-push-node') }`, which lets the Edge bundle drop
 * this module entirely (node:fs / node:path / prisma must never be statically
 * reachable from Edge — Turbopack's Edge lint flags even unreachable usage
 * inside instrumentation.ts itself).
 *
 * Every TICK_MS a tick checks the DnsSettings row: when autoPush is enabled
 * and the configured interval has elapsed since the last push (autoPushAt),
 * the latest hunt run's healthy IPs (db/hunt-history.json, newest first) are
 * synced to Cloudflare through the SAME core the manual push route uses
 * (syncDnsRecords → identical create/keep/delete semantics), journalled as a
 * DnsPushLog row, and autoPushAt is refreshed so the next due time moves.
 *
 * Everything is wrapped in try/catch — the scheduler must never crash the
 * server. The globalThis guard keeps dev hot-reloads from double-registering
 * the interval.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { db } from '@/lib/db'
import { CfDnsError, syncDnsRecords } from '@/lib/cf-dns'

const TICK_MS = 60_000

/** module-level in-flight guard (a CF sync can legitimately take >60 s) */
let autoPushInFlight = false

async function runAutoPushTick(): Promise<void> {
  try {
    // 1. settings row
    const row = await db.dnsSettings.findUnique({ where: { id: 1 } })
    if (!row || !row.autoPush) return

    // 2. due check: never pushed OR the configured interval has elapsed
    if (row.autoPushAt && Date.now() - row.autoPushAt.getTime() < row.autoPushMin * 60_000) return

    // 3. in-flight guard (previous tick still talking to CF)
    if (autoPushInFlight) return
    autoPushInFlight = true

    try {
      // 4. latest hunt run with healthy IPs → filter per recordType → cap
      let runs: Array<{ healthyIps?: Array<{ ip?: unknown }> }> = []
      try {
        const file = join(process.cwd(), 'db', 'hunt-history.json')
        runs = JSON.parse(readFileSync(file, 'utf8')) as Array<{
          healthyIps?: Array<{ ip?: unknown }>
        }>
      } catch {
        runs = []
      }
      const run = runs.find((r) => Array.isArray(r.healthyIps) && r.healthyIps.length > 0)
      const ips = (run?.healthyIps ?? [])
        .map((e) => (typeof e?.ip === 'string' ? e.ip.trim() : ''))
        .filter((ip) => ip !== '' && (row.recordType === 'AAAA' ? ip.includes(':') : !ip.includes(':')))
        .slice(0, row.autoPushMaxIps)

      if (ips.length === 0) {
        // nothing pushable — refresh autoPushAt so we don't hammer every tick
        await db.dnsSettings.update({ where: { id: 1 }, data: { autoPushAt: new Date() } })
        return
      }

      // 5. sync through the shared CF core
      let result: Awaited<ReturnType<typeof syncDnsRecords>>
      try {
        result = await syncDnsRecords({
          cfToken: row.cfToken,
          zoneId: row.zoneId,
          recordName: row.recordName,
          recordType: row.recordType === 'AAAA' ? 'AAAA' : 'A',
          ttl: row.ttl,
          proxied: row.proxied,
          ips,
        })
      } catch (e) {
        // list-level failure (e.g. CF auth) → journal as a failed attempt
        const errors = e instanceof CfDnsError ? e.errors : [String(e).slice(0, 300)]
        result = { ok: false, created: 0, kept: 0, removed: 0, errors }
      }

      try {
        await db.dnsPushLog.create({
          data: {
            recordName: row.recordName,
            ips: ips.join(','),
            created: result.created,
            kept: result.kept,
            removed: result.removed,
            ok: result.ok,
            detail: (result.errors.length > 0 ? result.errors.join(' | ') : 'auto-push').slice(0, 300),
          },
        })
      } catch {
        // best-effort journal — never mask the result
      }
      await db.dnsSettings.update({ where: { id: 1 }, data: { autoPushAt: new Date() } })

      // 6. one telemetry line
      if (result.ok) {
        console.log(
          `[auto-push] pushed ${ips.length} ips (created ${result.created} kept ${result.kept} removed ${result.removed})`,
        )
      } else {
        console.error(`[auto-push] push failed: ${result.errors.join(' | ')}`)
      }
    } finally {
      autoPushInFlight = false
    }
  } catch (e) {
    console.error('[auto-push] tick error:', String(e).slice(0, 300))
  }
}

/** idempotent: installs the 60 s interval exactly once per server process */
export function startAutoPushScheduler(): void {
  const g = globalThis as { __cleanIpAutoPushTimer?: boolean }
  if (g.__cleanIpAutoPushTimer) return // hot reload — already registered
  g.__cleanIpAutoPushTimer = true
  setInterval(() => {
    void runAutoPushTick()
  }, TICK_MS)
}
