import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/

/**
 * GET /api/ip-history?ip=a.b.c.d — everything we know about ONE IP over time:
 *  - every saved-scan appearance (latency / loss / speed / rank per scan)
 *  - every persisted probe verdict (per SNI host + port)
 * Powers the per-IP history dialog (timeline + lists).
 */
export async function GET(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const ip = (req.nextUrl.searchParams.get('ip') ?? '').trim()
    if (!IP_RE.test(ip) || ip.split('.').some((o) => Number(o) > 255)) {
      return NextResponse.json({ error: 'invalid_ip' }, { status: 400 })
    }

    const rows = await db.scanResult.findMany({
      where: { ip },
      include: {
        scan: {
          select: {
            id: true,
            label: true,
            preset: true,
            port: true,
            status: true,
            createdAt: true,
          },
        },
      },
      orderBy: { scan: { createdAt: 'asc' } },
      take: 60,
    })

    const probes = await db.probeResult.findMany({
      where: { ip },
      orderBy: { updatedAt: 'desc' },
      take: 30,
    })

    // append-only journal → true TLS/latency trend for this IP over time (oldest→newest)
    const trendRows = await db.probeLog.findMany({
      where: { ip, tlsMs: { not: null } },
      orderBy: { createdAt: 'desc' },
      take: 40,
    })

    return NextResponse.json({
      scans: rows.map((r) => ({
        scanId: r.scan.id,
        label: r.scan.label,
        preset: r.scan.preset,
        port: r.scan.port,
        scanStatus: r.scan.status,
        createdAt: r.scan.createdAt.toISOString(),
        latencyMs: r.latencyMs,
        sent: r.sent,
        received: r.received,
        lossRate: r.lossRate,
        downloadSpeed: r.downloadSpeed,
        uploadSpeed: r.uploadSpeed,
        totalSpeed: r.totalSpeed,
        rank: r.rank,
      })),
      probes: probes.map((p) => ({
        host: p.host,
        port: p.port,
        grade: p.grade,
        tcpMs: p.tcpMs,
        tlsMs: p.tlsMs,
        httpStatus: p.httpStatus,
        ok: p.ok,
        updatedAt: p.updatedAt.toISOString(),
      })),
      trend: trendRows
        .reverse()
        .map((l) => ({
          host: l.host,
          port: l.port,
          grade: l.grade,
          tlsMs: l.tlsMs,
          ok: l.ok,
          createdAt: l.createdAt.toISOString(),
        })),
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_ip_history', detail: String(e) }, { status: 500 })
  }
}
