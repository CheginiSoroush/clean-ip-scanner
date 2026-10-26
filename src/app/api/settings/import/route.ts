import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

/**
 * v6.7 — import a previously exported settings envelope (POST body = JSON).
 *
 * Envelope must be { kind:'clean-ip-scanner-settings', schemaVersion:1,
 * dns?, telegram? }. Validate-then-write: BOTH sections are fully validated
 * before ANY row is touched — a bad field anywhere means nothing is applied
 * (no partial import).
 *
 * dns:      zoneId ≤64 · recordName hostname regex (like PUT /api/dns) ·
 *           recordType 'A'|'AAAA' · ttl integer 60..86400 · proxied boolean ·
 *           autoPush boolean (absent → stored/default) ·
 *           autoPushMin clamp 10..1440 · autoPushMaxIps clamp 1..10 ·
 *           cfToken ≤200 with the PUT keep-if-empty semantics
 * telegram: chatId ≤32 · autoOnFinish boolean · botToken ≤200 (same rules)
 *
 * Token rules (identical to the PUT routes): empty/missing → KEEP the stored
 * token (400 when no row exists yet to keep), non-empty → overwrite. Token
 * values are never logged.
 */

const RECORD_NAME_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i
const ZONE_ID_MAX = 64
const RECORD_NAME_MAX = 253
const TTL_MIN = 60
const TTL_MAX = 86400
const TOKEN_MAX = 200
const CHAT_ID_MAX = 32

function invalidField(error: string, field: string) {
  return NextResponse.json({ error, field }, { status: 400 })
}

/** hunt v6.5 semantics — optional int field: absent/blank → fallback, else clamped */
function clampIntField(v: unknown, lo: number, hi: number, fallback: number): number {
  if (v === undefined || v === null || v === '') return fallback
  const n = Math.round(Number(v))
  if (!Number.isFinite(n)) return fallback
  return Math.min(hi, Math.max(lo, n))
}

interface DnsWrite {
  cfToken: string
  zoneId: string
  recordName: string
  recordType: 'A' | 'AAAA'
  ttl: number
  proxied: boolean
  autoPush: boolean
  autoPushMin: number
  autoPushMaxIps: number
}

interface TgWrite {
  botToken: string
  chatId: string
  autoOnFinish: boolean
}

export async function POST(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  let body: unknown = null
  try {
    body = await req.json()
  } catch {
    body = null
  }
  const env = body as {
    kind?: unknown
    schemaVersion?: unknown
    dns?: unknown
    telegram?: unknown
  } | null
  if (
    !env ||
    typeof env !== 'object' ||
    Array.isArray(env) ||
    env.kind !== 'clean-ip-scanner-settings' ||
    env.schemaVersion !== 1
  ) {
    return NextResponse.json({ error: 'invalid_envelope' }, { status: 400 })
  }

  const hasDns = env.dns !== undefined && env.dns !== null
  const hasTg = env.telegram !== undefined && env.telegram !== null
  if (!hasDns && !hasTg) {
    return NextResponse.json({ error: 'nothing_to_import' }, { status: 400 })
  }

  try {
    // both rows up-front — token keep-if-empty + optional-field fallbacks need them
    const [existingDns, existingTg] = await Promise.all([
      db.dnsSettings.findUnique({ where: { id: 1 } }),
      db.telegramSettings.findUnique({ where: { id: 1 } }),
    ])

    let dnsWrite: DnsWrite | null = null
    let tgWrite: TgWrite | null = null

    // ---- validate dns section (still no writes) ----
    if (hasDns) {
      const d = env.dns as Record<string, unknown>

      const zoneId = typeof d.zoneId === 'string' ? d.zoneId.trim() : ''
      if (!zoneId || zoneId.length > ZONE_ID_MAX) {
        return invalidField('invalid_dns_field', 'zoneId')
      }
      const recordName = typeof d.recordName === 'string' ? d.recordName.trim().toLowerCase() : ''
      if (!recordName || recordName.length > RECORD_NAME_MAX || !RECORD_NAME_RE.test(recordName)) {
        return invalidField('invalid_dns_field', 'recordName')
      }
      // 'A' default (like PUT) — anything else than A/AAAA is rejected
      const rawType =
        d.recordType === undefined || d.recordType === null || d.recordType === ''
          ? 'A'
          : d.recordType
      if (rawType !== 'A' && rawType !== 'AAAA') {
        return NextResponse.json({ error: 'invalid_record_type' }, { status: 400 })
      }
      const recordType = rawType as 'A' | 'AAAA'
      const ttl =
        typeof d.ttl === 'number'
          ? d.ttl
          : typeof d.ttl === 'string' && d.ttl.trim() !== ''
            ? Number(d.ttl)
            : NaN
      if (!Number.isInteger(ttl) || ttl < TTL_MIN || ttl > TTL_MAX) {
        return invalidField('invalid_dns_field', 'ttl')
      }
      if (typeof d.proxied !== 'boolean') {
        return invalidField('invalid_dns_field', 'proxied')
      }
      // hunt v6.5 fields — absent → stored/default, else clamped (PUT semantics)
      const autoPush = typeof d.autoPush === 'boolean' ? d.autoPush : (existingDns?.autoPush ?? false)
      const autoPushMin = clampIntField(d.autoPushMin, 10, 1440, existingDns?.autoPushMin ?? 30)
      const autoPushMaxIps = clampIntField(d.autoPushMaxIps, 1, 10, existingDns?.autoPushMaxIps ?? 5)

      // token: empty/missing keeps the stored one (400 if there is none yet);
      // a non-empty string ≤200 overwrites — import is more permissive than
      // PUT's 20..60 so pre-existing stores of any shape can round-trip
      const rawToken = typeof d.cfToken === 'string' ? d.cfToken.trim() : ''
      let cfToken: string
      if (rawToken === '') {
        if (!existingDns) return invalidField('invalid_dns_field', 'cfToken')
        cfToken = existingDns.cfToken
      } else if (rawToken.length > TOKEN_MAX) {
        return invalidField('invalid_dns_field', 'cfToken')
      } else {
        cfToken = rawToken
      }

      dnsWrite = {
        cfToken,
        zoneId,
        recordName,
        recordType,
        ttl,
        proxied: d.proxied,
        autoPush,
        autoPushMin,
        autoPushMaxIps,
      }
    }

    // ---- validate telegram section (still no writes) ----
    if (hasTg) {
      const t = env.telegram as Record<string, unknown>

      const chatId = typeof t.chatId === 'string' ? t.chatId.trim() : ''
      if (!chatId || chatId.length > CHAT_ID_MAX) {
        return invalidField('invalid_telegram_field', 'chatId')
      }
      if (typeof t.autoOnFinish !== 'boolean') {
        return invalidField('invalid_telegram_field', 'autoOnFinish')
      }

      const rawToken = typeof t.botToken === 'string' ? t.botToken.trim() : ''
      let botToken: string
      if (rawToken === '') {
        if (!existingTg) return invalidField('invalid_telegram_field', 'botToken')
        botToken = existingTg.botToken
      } else if (rawToken.length > TOKEN_MAX) {
        return invalidField('invalid_telegram_field', 'botToken')
      } else {
        botToken = rawToken
      }

      tgWrite = { botToken, chatId, autoOnFinish: t.autoOnFinish }
    }

    // ---- everything valid → write (dns first, like the PUT routes) ----
    if (dnsWrite) {
      await db.dnsSettings.upsert({
        where: { id: 1 },
        update: dnsWrite,
        create: { id: 1, ...dnsWrite },
      })
    }
    if (tgWrite) {
      await db.telegramSettings.upsert({
        where: { id: 1 },
        update: tgWrite,
        create: { id: 1, ...tgWrite },
      })
    }

    return NextResponse.json({ ok: true, applied: { dns: !!dnsWrite, telegram: !!tgWrite } })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_import', detail: String(e) }, { status: 500 })
  }
}
