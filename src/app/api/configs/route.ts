import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

/**
 * Saved proxy configs — the store behind the /api/sub subscription endpoint.
 *
 * POST dedupes on the `uri` unique key: SQLite has no createMany skipDuplicates,
 * so a single findMany pre-check builds the fresh set and createMany inserts it;
 * a per-item upsert fallback covers the (theoretical) insert race.
 */

const MAX_URIS = 200
const MAX_URI_LEN = 2048
const URI_PREFIX_RE = /^(vless|vmess):\/\//
const PROTO_OK = new Set(['vless', 'vmess'])

/** per-URI metadata parsed server-side so list rows show ip:port / sni / label */
function parseUriMeta(uri: string): {
  proto: 'vless' | 'vmess'
  ip: string | null
  port: number | null
  sni: string | null
  label: string | null
} {
  const proto: 'vless' | 'vmess' = uri.toLowerCase().startsWith('vmess://') ? 'vmess' : 'vless'
  if (proto === 'vless') {
    try {
      const u = new URL(uri)
      const port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : null
      return {
        proto,
        ip: u.hostname || null,
        port: port != null && Number.isFinite(port) ? port : null,
        sni: u.searchParams.get('sni'),
        label: u.hash ? decodeURIComponent(u.hash.replace(/^#/, '')).slice(0, 60) || null : null,
      }
    } catch {
      return { proto, ip: null, port: null, sni: null, label: null }
    }
  }
  // vmess:// base64 JSON ({ add, port, sni, ps, … }) — best-effort decode
  try {
    const b64 = uri.slice('vmess://'.length).replace(/-/g, '+').replace(/_/g, '/')
    const json = JSON.parse(Buffer.from(b64, 'base64').toString('utf8')) as {
      add?: unknown
      port?: unknown
      sni?: unknown
      host?: unknown
      ps?: unknown
    }
    const port = Number(json.port)
    const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null)
    const host = str(json.sni) ?? str(json.host)
    return {
      proto,
      ip: str(json.add),
      port: Number.isFinite(port) && port > 0 ? port : null,
      sni: host ? host.slice(0, 200) : null,
      label: str(json.ps)?.slice(0, 60) ?? null,
    }
  } catch {
    return { proto, ip: null, port: null, sni: null, label: null }
  }
}

// GET /api/configs?limit=200 — list saved configs (newest first, capped at 200)
export async function GET(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const limitRaw = Number(req.nextUrl.searchParams.get('limit') ?? 200)
    const limit = Number.isFinite(limitRaw) ? Math.min(200, Math.max(1, Math.floor(limitRaw))) : 200
    const rows = await db.savedConfig.findMany({
      orderBy: { createdAt: 'desc' },
      take: limit,
    })
    return NextResponse.json({
      configs: rows.map((c) => ({
        id: c.id,
        uri: c.uri,
        proto: c.proto,
        label: c.label,
        ip: c.ip,
        port: c.port,
        sni: c.sni,
        createdAt: c.createdAt.toISOString(),
      })),
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_list', detail: String(e) }, { status: 500 })
  }
}

// POST /api/configs — save URIs { uris: string[], label?, proto?, ip?, port?, sni? }
// dedupe via the unique `uri` key → { saved, duplicates, total }
export async function POST(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const body = (await req.json()) as {
      uris?: unknown
      label?: unknown
      proto?: unknown
      ip?: unknown
      port?: unknown
      sni?: unknown
    }
    const uris: string[] = Array.isArray(body.uris)
      ? body.uris
          .filter((u): u is string => typeof u === 'string')
          .map((u) => u.trim())
          .filter((u) => u.length > 0 && u.length <= MAX_URI_LEN && URI_PREFIX_RE.test(u))
          .slice(0, MAX_URIS)
      : []
    if (uris.length === 0) {
      return NextResponse.json({ error: 'invalid_uris' }, { status: 400 })
    }
    const label =
      typeof body.label === 'string' && body.label.trim() ? body.label.trim().slice(0, 60) : null
    const proto =
      typeof body.proto === 'string' && PROTO_OK.has(body.proto.trim().toLowerCase())
        ? body.proto.trim().toLowerCase()
        : null
    const ip =
      typeof body.ip === 'string' && body.ip.trim() ? body.ip.trim().slice(0, 64) : null
    const portRaw = Number(body.port)
    const port = Number.isFinite(portRaw) && portRaw > 0 && portRaw <= 65535 ? Math.floor(portRaw) : null
    const sni =
      typeof body.sni === 'string' && body.sni.trim() ? body.sni.trim().slice(0, 200) : null

    // dedupe the payload itself first (same uri twice in one request)
    const list = [...new Set(uris)]

    // one round-trip pre-check → the fresh subset (SQLite lacks skipDuplicates)
    const known = await db.savedConfig.findMany({
      where: { uri: { in: list } },
      select: { uri: true },
    })
    const knownSet = new Set(known.map((r) => r.uri))
    const fresh = list.filter((uri) => !knownSet.has(uri))

    let saved = 0
    try {
      const res = await db.savedConfig.createMany({
        data: fresh.map((uri) => {
          const meta = parseUriMeta(uri)
          return {
            uri,
            proto: proto ?? meta.proto,
            label: label ?? meta.label,
            ip: ip ?? meta.ip,
            port: port ?? meta.port,
            sni: sni ?? meta.sni,
          }
        }),
      })
      saved = res.count
    } catch {
      // rare insert race (same uri landed between check and create) — per-item upsert
      for (const uri of fresh) {
        const meta = parseUriMeta(uri)
        try {
          await db.savedConfig.upsert({
            where: { uri },
            update: {},
            create: {
              uri,
              proto: proto ?? meta.proto,
              label: label ?? meta.label,
              ip: ip ?? meta.ip,
              port: port ?? meta.port,
              sni: sni ?? meta.sni,
            },
          })
          saved += 1
        } catch {
          // genuine duplicate — counted as skipped below
        }
      }
    }

    const total = await db.savedConfig.count()
    return NextResponse.json({ saved, duplicates: list.length - saved, total })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_save', detail: String(e) }, { status: 500 })
  }
}

// DELETE /api/configs?id=<cuid> | ?all=1 — remove one / all → { remaining }
export async function DELETE(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const params = req.nextUrl.searchParams
    if (params.get('all') === '1') {
      await db.savedConfig.deleteMany({})
    } else {
      const id = params.get('id')?.trim() ?? ''
      if (!id || id.length > 40) {
        return NextResponse.json({ error: 'invalid_id' }, { status: 400 })
      }
      await db.savedConfig.deleteMany({ where: { id } })
    }
    const remaining = await db.savedConfig.count()
    return NextResponse.json({ remaining })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_delete', detail: String(e) }, { status: 500 })
  }
}
