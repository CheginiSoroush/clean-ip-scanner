import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

/** health status derived from a quick TCPing check */
export function deriveStatus(latencyMs: number, lossRate: number): 'healthy' | 'degraded' | 'dead' {
  if (latencyMs <= 0) return 'dead'
  if (lossRate > 0.3 || latencyMs > 300) return 'degraded'
  return 'healthy'
}

// GET /api/favorites — list watchlist (newest first)
export async function GET() {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const favorites = await db.favorite.findMany({
      orderBy: { addedAt: 'desc' },
      take: 200,
    })
    return NextResponse.json({
      favorites: favorites.map((f) => ({
        id: f.id,
        ip: f.ip,
        label: f.label,
        note: f.note,
        addedAt: f.addedAt.toISOString(),
        lastCheckAt: f.lastCheckAt?.toISOString() ?? null,
        lastLatencyMs: f.lastLatencyMs,
        lastLossRate: f.lastLossRate,
        lastStatus: f.lastStatus,
        checksCount: f.checksCount,
      })),
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_list', detail: String(e) }, { status: 500 })
  }
}

// POST /api/favorites — add an IP { ip: string, label?: string, note?: string }
export async function POST(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const body = await req.json()
    const ip = typeof body?.ip === 'string' ? body.ip.trim() : ''
    if (!ip || !/^[0-9a-fA-F.:]+$/.test(ip) || ip.length > 45) {
      return NextResponse.json({ error: 'invalid_ip' }, { status: 400 })
    }
    const label =
      typeof body?.label === 'string' && body.label.trim() ? body.label.trim().slice(0, 60) : null
    const note =
      typeof body?.note === 'string' && body.note.trim() ? body.note.trim().slice(0, 200) : null
    const fav = await db.favorite.upsert({
      where: { ip },
      update: { label, note: note ?? undefined },
      create: { ip, label, note },
    })
    return NextResponse.json({
      favorite: {
        id: fav.id,
        ip: fav.ip,
        label: fav.label,
        note: fav.note,
        addedAt: fav.addedAt.toISOString(),
        lastCheckAt: fav.lastCheckAt?.toISOString() ?? null,
        lastLatencyMs: fav.lastLatencyMs,
        lastLossRate: fav.lastLossRate,
        lastStatus: fav.lastStatus,
        checksCount: fav.checksCount,
      },
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_add', detail: String(e) }, { status: 500 })
  }
}

function num(v: unknown): number | null {
  const n = Number(v)
  return Number.isFinite(n) ? n : null
}

// PATCH /api/favorites — bulk health update { results: [{ ip, latencyMs, lossRate }] }
export async function PATCH(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const body = await req.json()
    const results: unknown = body?.results
    if (!Array.isArray(results) || results.length === 0) {
      return NextResponse.json({ error: 'invalid_body' }, { status: 400 })
    }
    let updated = 0
    for (const r of results.slice(0, 100)) {
      const ip = typeof r?.ip === 'string' ? r.ip.trim() : ''
      if (!ip) continue
      const latencyMs = num(r?.latencyMs) ?? 0
      const lossRate = num(r?.lossRate) ?? 1
      const status = deriveStatus(latencyMs, lossRate)
      const res = await db.favorite.updateMany({
        where: { ip },
        data: {
          lastCheckAt: new Date(),
          lastLatencyMs: latencyMs,
          lastLossRate: lossRate,
          lastStatus: status,
          checksCount: { increment: 1 },
        },
      })
      updated += res.count
    }
    return NextResponse.json({ updated })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_update', detail: String(e) }, { status: 500 })
  }
}
