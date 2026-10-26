import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

/**
 * Cloudflare DDNS settings (hunt v6.3, A/AAAA since v6.4, auto-push since v6.5) —
 * single row (id=1) + push history.
 *
 * GET  → { settings: {configured, recordName?, recordType? 'A'|'AAAA', zoneId?, ttl?, proxied?, autoPush?, autoPushMin?, autoPushMaxIps?, autoPushAt?, tokenHint?, updatedAt?}, pushes: [...] }
 * PUT  ← { cfToken?, zoneId, recordName, recordType?, ttl, proxied, autoPush?, autoPushMin?, autoPushMaxIps? } → { ok, tokenHint }
 *
 * The CF API token NEVER leaves the server raw — responses carry a masked
 * `tokenHint` ('••••' + last 4). An omitted/empty token keeps the stored one.
 * v6.5 auto-push: autoPush is boolean, autoPushMin (minutes) clamps to 10..1440,
 * autoPushMaxIps clamps to 1..10; omitted fields keep the stored values.
 */

const TTL_ALLOWED = new Set([1, 300, 600, 1800, 3600, 7200])
/** lenient zone-id shape (CF issues 32-hex; we accept 16..40 hex chars) */
const ZONE_ID_RE = /^[a-f0-9]{16,40}$/i
/** hostname-ish record name (labels + dots), ≤253 chars */
const RECORD_NAME_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i
const TOKEN_MIN = 20
const TOKEN_MAX = 60

function maskToken(token: string): string {
  const last4 = token.slice(-4)
  return `••••${last4}`
}

/** hunt v6.5 — optional int field: absent/blank → fallback (stored or default), else clamped */
function clampIntField(v: unknown, lo: number, hi: number, fallback: number): number {
  if (v === undefined || v === null || v === '') return fallback
  const n = Math.round(Number(v))
  if (!Number.isFinite(n)) return fallback
  return Math.min(hi, Math.max(lo, n))
}

// GET /api/dns — settings (masked) + last 10 push-log rows (newest first)
export async function GET() {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const [row, pushes] = await Promise.all([
      db.dnsSettings.findUnique({ where: { id: 1 } }),
      db.dnsPushLog.findMany({ orderBy: { createdAt: 'desc' }, take: 10 }),
    ])
    return NextResponse.json({
      settings: row
        ? {
            configured: true,
            recordName: row.recordName,
            recordType: row.recordType === 'AAAA' ? 'AAAA' : 'A',
            zoneId: row.zoneId,
            ttl: row.ttl,
            proxied: row.proxied,
            autoPush: row.autoPush,
            autoPushMin: row.autoPushMin,
            autoPushMaxIps: row.autoPushMaxIps,
            autoPushAt: row.autoPushAt ? row.autoPushAt.toISOString() : null,
            tokenHint: maskToken(row.cfToken),
            updatedAt: row.updatedAt.toISOString(),
          }
        : { configured: false, autoPush: false, autoPushMin: 30, autoPushMaxIps: 5, autoPushAt: null },
      pushes: pushes.map((p) => ({
        id: p.id,
        recordName: p.recordName,
        ips: p.ips,
        created: p.created,
        kept: p.kept,
        removed: p.removed,
        ok: p.ok,
        detail: p.detail,
        createdAt: p.createdAt.toISOString(),
      })),
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_read_dns', detail: String(e) }, { status: 500 })
  }
}

// PUT /api/dns — upsert settings (empty cfToken = keep the stored token)
export async function PUT(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const body = (await req.json()) as {
      cfToken?: unknown
      zoneId?: unknown
      recordName?: unknown
      recordType?: unknown
      ttl?: unknown
      proxied?: unknown
      autoPush?: unknown
      autoPushMin?: unknown
      autoPushMaxIps?: unknown
    }

    const zoneId = typeof body.zoneId === 'string' ? body.zoneId.trim() : ''
    if (!ZONE_ID_RE.test(zoneId)) {
      return NextResponse.json({ error: 'invalid_zone_id' }, { status: 400 })
    }
    const recordName = typeof body.recordName === 'string' ? body.recordName.trim().toLowerCase() : ''
    if (!recordName || recordName.length > 253 || !RECORD_NAME_RE.test(recordName)) {
      return NextResponse.json({ error: 'invalid_record_name' }, { status: 400 })
    }
    // hunt v6.4 — record type: 'A' (default) or 'AAAA' (IPv6); anything else is rejected
    const recordType = body.recordType === undefined || body.recordType === null || body.recordType === ''
      ? 'A'
      : body.recordType
    if (recordType !== 'A' && recordType !== 'AAAA') {
      return NextResponse.json({ error: 'invalid_record_type' }, { status: 400 })
    }
    const ttl = Number(body.ttl)
    if (!Number.isFinite(ttl) || !TTL_ALLOWED.has(ttl)) {
      return NextResponse.json({ error: 'invalid_ttl' }, { status: 400 })
    }
    if (typeof body.proxied !== 'boolean') {
      return NextResponse.json({ error: 'invalid_proxied' }, { status: 400 })
    }

    // token rules: a non-empty string within 20..60 replaces the stored one;
    // omitted/blank KEEPS whatever is stored (single-user self-hosted tool)
    const existing = await db.dnsSettings.findUnique({ where: { id: 1 } })
    const rawToken = typeof body.cfToken === 'string' ? body.cfToken.trim() : ''
    let cfToken = rawToken
    if (rawToken === '') {
      if (!existing) {
        return NextResponse.json({ error: 'token_required' }, { status: 400 })
      }
      cfToken = existing.cfToken
    } else if (rawToken.length < TOKEN_MIN || rawToken.length > TOKEN_MAX) {
      return NextResponse.json({ error: 'invalid_token' }, { status: 400 })
    }

    // hunt v6.5 — auto-push scheduler fields (omitted → keep stored / defaults)
    const autoPush = typeof body.autoPush === 'boolean' ? body.autoPush : (existing?.autoPush ?? false)
    const autoPushMin = clampIntField(body.autoPushMin, 10, 1440, existing?.autoPushMin ?? 30)
    const autoPushMaxIps = clampIntField(body.autoPushMaxIps, 1, 10, existing?.autoPushMaxIps ?? 5)

    await db.dnsSettings.upsert({
      where: { id: 1 },
      update: { cfToken, zoneId, recordName, recordType, ttl, proxied: body.proxied, autoPush, autoPushMin, autoPushMaxIps },
      create: { id: 1, cfToken, zoneId, recordName, recordType, ttl, proxied: body.proxied, autoPush, autoPushMin, autoPushMaxIps },
    })

    return NextResponse.json({ ok: true, tokenHint: maskToken(cfToken) })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_save_dns', detail: String(e) }, { status: 500 })
  }
}
