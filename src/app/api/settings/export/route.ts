import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'
import type { SettingsExport } from '@/lib/scan-protocol'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

/**
 * v6.7 — export integration settings as a portable JSON envelope.
 *
 * GET /api/settings/export           → envelope WITHOUT token fields
 * GET /api/settings/export?tokens=1  → envelope WITH raw cfToken/botToken
 *
 * A section appears only when its settings row exists. Token fields are
 * OMITTED (never masked placeholders) unless explicitly requested — absence
 * is the honest signal, so a casually exported file cannot leak a token.
 * Token values are never logged.
 */

export async function GET(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const withTokens = req.nextUrl.searchParams.get('tokens') === '1'
    const [dns, tg] = await Promise.all([
      db.dnsSettings.findUnique({ where: { id: 1 } }),
      db.telegramSettings.findUnique({ where: { id: 1 } }),
    ])

    const out: SettingsExport = {
      kind: 'clean-ip-scanner-settings',
      schemaVersion: 1,
      exportedAt: new Date().toISOString(),
    }
    if (dns) {
      out.dns = {
        zoneId: dns.zoneId,
        recordName: dns.recordName,
        recordType: dns.recordType === 'AAAA' ? 'AAAA' : 'A',
        ttl: dns.ttl,
        proxied: dns.proxied,
        autoPush: dns.autoPush,
        autoPushMin: dns.autoPushMin,
        autoPushMaxIps: dns.autoPushMaxIps,
        ...(withTokens ? { cfToken: dns.cfToken } : {}),
      }
    }
    if (tg) {
      out.telegram = {
        chatId: tg.chatId,
        autoOnFinish: tg.autoOnFinish,
        ...(withTokens ? { botToken: tg.botToken } : {}),
      }
    }

    // pretty-printed so a direct navigation doubles as a readable file;
    // fetch()-based consumers are unaffected
    return new NextResponse(JSON.stringify(out, null, 2), {
      status: 200,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'content-disposition': 'attachment; filename="clean-ip-scanner-settings.json"',
      },
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_export', detail: String(e) }, { status: 500 })
  }
}
