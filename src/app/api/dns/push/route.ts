import { isIP } from 'node:net'
import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'
import { CfDnsError, syncDnsRecords } from '@/lib/cf-dns'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

/**
 * Cloudflare DDNS sync-push (hunt v6.3, A/AAAA since v6.4).
 *
 * POST /api/dns/push { ips: string[] } — SYNC semantics: after this call the
 * record set (type = the STORED recordType: 'A' default, 'AAAA' for IPv6) of
 * `recordName` equals EXACTLY the pushed list:
 *   • missing  → created (POST /dns_records)
 *   • matching → kept untouched
 *   • extras   → deleted (DELETE /dns_records/{id})
 *
 * v6.5 — the CF HTTP plumbing lives in src/lib/cf-dns.ts (shared with the
 * auto-push scheduler); this route keeps validation + settings read + the
 * body.recordType override + journaling.
 *
 * Every attempt (ok or failed) appends a DnsPushLog row; CF API failures log
 * ok:false and answer 502 {error}.
 */

const MAX_IPS = 10
/** strict dotted-quad IPv4 (no leading zeros beyond 0 itself) */
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

/** hunt v6.4 — type-aware IP validation ('A' → strict IPv4 dotted-quad, 'AAAA' → real IPv6 via net.isIP) */
function isValidIp(ip: string, recordType: 'A' | 'AAAA'): boolean {
  return recordType === 'AAAA' ? isIP(ip) === 6 : IPV4_RE.test(ip)
}

export async function POST(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  // ----- settings must exist FIRST — the stored recordType drives IP validation (hunt v6.4) -----
  let row: Awaited<ReturnType<typeof db.dnsSettings.findUnique>>
  try {
    row = await db.dnsSettings.findUnique({ where: { id: 1 } })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_push_dns', detail: String(e) }, { status: 500 })
  }
  if (!row) {
    return NextResponse.json({ error: 'not_configured' }, { status: 400 })
  }
  const { cfToken, zoneId, recordName, ttl, proxied } = row
  // v6.4.1 — the edited recordType may ride the body (UI validates with the
  // same value); a valid body value wins over the stored one, anything else
  // falls back to the stored settings
  let bodyOverride: 'A' | 'AAAA' | null = null

  // ----- validate the payload (never trust the client) — strict per type -----
  let body: { ips?: unknown; recordType?: unknown }
  try {
    body = (await req.json()) as { ips?: unknown; recordType?: unknown }
  } catch {
    return NextResponse.json({ error: 'invalid_body' }, { status: 400 })
  }
  if (body.recordType === 'A' || body.recordType === 'AAAA') bodyOverride = body.recordType
  const recordType = bodyOverride ?? (row.recordType === 'AAAA' ? 'AAAA' : 'A')
  const rawIps = Array.isArray(body.ips) ? body.ips.filter((ip): ip is string => typeof ip === 'string') : []
  const ips = [...new Set(rawIps.map((ip) => ip.trim()).filter((ip) => isValidIp(ip, recordType)))].slice(0, MAX_IPS)
  if (rawIps.length === 0 || ips.length === 0) {
    return NextResponse.json(
      { error: recordType === 'AAAA' ? 'invalid_ipv6' : 'invalid_ipv4' },
      { status: 400 },
    )
  }

  const logRow = async (ok: boolean, created: number, kept: number, removed: number, detail: string) => {
    try {
      await db.dnsPushLog.create({
        data: {
          recordName,
          ips: ips.join(','),
          created,
          kept,
          removed,
          ok,
          detail: detail.slice(0, 300),
        },
      })
    } catch {
      // the push journal is best-effort — never mask the API result with it
    }
  }

  try {
    const result = await syncDnsRecords({ cfToken, zoneId, recordName, recordType, ttl, proxied, ips })
    if (result.ok) {
      await logRow(true, result.created, result.kept, result.removed, '')
      return NextResponse.json({
        ok: true,
        created: result.created,
        kept: result.kept,
        removed: result.removed,
        recordName: row.recordName,
      })
    }
    await logRow(false, result.created, result.kept, result.removed, result.errors.join(' | '))
    return NextResponse.json(
      {
        ok: false,
        created: result.created,
        kept: result.kept,
        removed: result.removed,
        recordName: row.recordName,
        errors: result.errors,
      },
      { status: 502 },
    )
  } catch (e) {
    // list-level failure — same 502 shapes as before the v6.5 lib extraction
    if (e instanceof CfDnsError) {
      if (e.kind === 'unreachable') {
        await logRow(false, 0, 0, 0, 'cloudflare_unreachable')
        return NextResponse.json({ error: 'cloudflare_unreachable' }, { status: 502 })
      }
      await logRow(false, 0, 0, 0, e.errors.join(' | '))
      return NextResponse.json({ error: 'cloudflare_error', errors: e.errors }, { status: 502 })
    }
    await logRow(false, 0, 0, 0, String(e).slice(0, 300))
    return NextResponse.json({ error: 'failed_to_push_dns', detail: String(e) }, { status: 500 })
  }
}
