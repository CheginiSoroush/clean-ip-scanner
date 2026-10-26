import { NextRequest, NextResponse } from 'next/server'
import { randomUUID } from 'node:crypto'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'
import { XRAY_PRESETS_CAP, type XrayPreset } from '@/lib/scan-protocol'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

/**
 * Xray generator template presets (v6.7) — stored as ONE generic Setting row
 * (key='xray_presets_v1', value = JSON array of XrayPreset) so no prisma
 * migration is needed.
 *
 * GET    → { presets } newest first; a missing/corrupt store is honestly an
 *          empty list (logged, never a 500 — the next mutation self-heals it)
 * POST   ← { name, host, port, protocol, transport, wsPath } → 201 { preset }
 *          | 400 { error:'invalid_preset', field }   (first offending field)
 *          | 400 { error:'duplicate_preset' }        (identical full identity)
 *          | 400 { error:'preset_limit', cap }       (XRAY_PRESETS_CAP)
 * DELETE ?id= → remove one | ?all=1 → clear all → { ok:true }
 *
 * id + createdAt are server-assigned (8-hex chars / epoch ms) — client values
 * are never trusted.
 */

const STORE_KEY = 'xray_presets_v1'

/** hostname-ish: labels + dots (same shape as the DDNS record name) */
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i
const PROTOCOLS = new Set<string>(['vless', 'vmess', 'trojan'])
const TRANSPORTS = new Set<string>(['ws', 'tcp'])
const NAME_MAX = 40
const HOST_MAX = 253
const WS_PATH_MAX = 64

function badField(field: string) {
  return NextResponse.json({ error: 'invalid_preset', field }, { status: 400 })
}

/** defensive shape check — the store is ours, but a hand-edited DB stays honest */
function isPresetShape(v: unknown): v is XrayPreset {
  if (typeof v !== 'object' || v === null) return false
  const p = v as Record<string, unknown>
  return (
    typeof p.id === 'string' &&
    p.id.length > 0 &&
    typeof p.name === 'string' &&
    typeof p.host === 'string' &&
    typeof p.port === 'number' &&
    Number.isInteger(p.port) &&
    p.port >= 1 &&
    p.port <= 65535 &&
    typeof p.protocol === 'string' &&
    PROTOCOLS.has(p.protocol) &&
    typeof p.transport === 'string' &&
    TRANSPORTS.has(p.transport) &&
    typeof p.wsPath === 'string' &&
    p.wsPath.startsWith('/') &&
    p.wsPath.length <= WS_PATH_MAX &&
    typeof p.createdAt === 'number' &&
    Number.isFinite(p.createdAt)
  )
}

/** parse the Setting row — corrupt/missing JSON is an empty list, never a throw */
function readPresets(raw: string | null | undefined): XrayPreset[] {
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) {
      console.warn('[xray-presets] corrupt store (not an array) — serving empty')
      return []
    }
    return parsed.filter(isPresetShape)
  } catch {
    console.warn('[xray-presets] corrupt store (bad JSON) — serving empty')
    return []
  }
}

async function savePresets(presets: XrayPreset[]): Promise<void> {
  const value = JSON.stringify(presets)
  await db.setting.upsert({
    where: { key: STORE_KEY },
    update: { value },
    create: { key: STORE_KEY, value },
  })
}

// GET /api/xray-presets — list (createdAt desc)
export async function GET() {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const row = await db.setting.findUnique({ where: { key: STORE_KEY } })
    const presets = readPresets(row?.value).sort((a, b) => b.createdAt - a.createdAt)
    return NextResponse.json({ presets })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_read_presets', detail: String(e) }, { status: 500 })
  }
}

// POST /api/xray-presets — validate → cap → dedupe → save
export async function POST(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  let body: {
    name?: unknown
    host?: unknown
    port?: unknown
    protocol?: unknown
    transport?: unknown
    wsPath?: unknown
  } | null = null
  try {
    body = await req.json()
  } catch {
    body = null
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return badField('body')
  }

  // 1..40 chars after trim
  const name = typeof body.name === 'string' ? body.name.trim() : ''
  if (!name || name.length > NAME_MAX) return badField('name')

  // 1..253 hostname chars, must contain a dot (or be exactly 'localhost')
  const host = typeof body.host === 'string' ? body.host.trim().toLowerCase() : ''
  if (
    !host ||
    host.length > HOST_MAX ||
    !HOSTNAME_RE.test(host) ||
    (!host.includes('.') && host !== 'localhost')
  ) {
    return badField('host')
  }

  // integer 1..65535 (numeric strings tolerated, like the other int fields)
  const port =
    typeof body.port === 'number'
      ? body.port
      : typeof body.port === 'string' && body.port.trim() !== ''
        ? Number(body.port)
        : NaN
  if (!Number.isInteger(port) || port < 1 || port > 65535) return badField('port')

  const protocol = typeof body.protocol === 'string' ? body.protocol : ''
  if (!PROTOCOLS.has(protocol)) return badField('protocol')

  const transport = typeof body.transport === 'string' ? body.transport : ''
  if (!TRANSPORTS.has(transport)) return badField('transport')

  // '/'-prefixed, ≤64 chars; defaults to '/' when tcp leaves it empty (path is
  // ignored for tcp); an empty path on ws is a real error, not a silent default
  let wsPath = typeof body.wsPath === 'string' ? body.wsPath : ''
  if (!wsPath) {
    if (transport === 'tcp') {
      wsPath = '/'
    } else {
      return badField('wsPath')
    }
  }
  if (!wsPath.startsWith('/') || wsPath.length > WS_PATH_MAX) return badField('wsPath')

  try {
    const presets = readPresets((await db.setting.findUnique({ where: { key: STORE_KEY } }))?.value)

    if (presets.length >= XRAY_PRESETS_CAP) {
      return NextResponse.json({ error: 'preset_limit', cap: XRAY_PRESETS_CAP }, { status: 400 })
    }
    const duplicate = presets.find(
      (p) =>
        p.name === name &&
        p.host === host &&
        p.port === port &&
        p.protocol === protocol &&
        p.transport === transport &&
        p.wsPath === wsPath,
    )
    if (duplicate) {
      return NextResponse.json({ error: 'duplicate_preset' }, { status: 400 })
    }

    let id = randomUUID().slice(0, 8)
    while (presets.some((p) => p.id === id)) id = randomUUID().slice(0, 8)

    const preset: XrayPreset = {
      id,
      name,
      host,
      port,
      protocol: protocol as XrayPreset['protocol'],
      transport: transport as XrayPreset['transport'],
      wsPath,
      createdAt: Date.now(),
    }
    await savePresets([...presets, preset])
    return NextResponse.json({ preset }, { status: 201 })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_save_presets', detail: String(e) }, { status: 500 })
  }
}

// DELETE /api/xray-presets?id=<8hex> | ?all=1 — remove one / clear all
export async function DELETE(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  const params = req.nextUrl.searchParams
  try {
    if (params.get('all') === '1') {
      await savePresets([])
      return NextResponse.json({ ok: true })
    }
    const id = params.get('id')?.trim() ?? ''
    if (!id || id.length > 40) {
      return NextResponse.json({ error: 'invalid_id' }, { status: 400 })
    }
    const presets = readPresets((await db.setting.findUnique({ where: { key: STORE_KEY } }))?.value)
    const idx = presets.findIndex((p) => p.id === id)
    if (idx === -1) {
      return NextResponse.json({ error: 'preset_not_found' }, { status: 404 })
    }
    presets.splice(idx, 1)
    await savePresets(presets)
    return NextResponse.json({ ok: true })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_save_presets', detail: String(e) }, { status: 500 })
  }
}
