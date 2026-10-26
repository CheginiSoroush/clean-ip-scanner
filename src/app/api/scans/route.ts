import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'
import type { ScanSummary } from '@/lib/scan-protocol'

export const dynamic = 'force-dynamic'

// GET /api/scans — list scan history (newest first) + per-scan result aggregates
export async function GET() {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const scans = await db.scan.findMany({
      orderBy: { createdAt: 'desc' },
      take: 50,
      include: { _count: { select: { results: true } } },
    })
    const grouped = await db.scanResult.groupBy({
      by: ['scanId'],
      _max: { totalSpeed: true },
      _avg: { latencyMs: true },
      where: { scanId: { in: scans.map((s) => s.id) } },
    })
    const aggMap = new Map(
      grouped.map((g) => [
        g.scanId,
        { bestSpeed: g._max.totalSpeed ?? 0, avgLatency: g._avg.latencyMs ?? 0 },
      ]),
    )
    return NextResponse.json({
      scans: scans.map((s) => ({
        id: s.id,
        preset: s.preset,
        label: s.label,
        port: s.port,
        pingCount: s.pingCount,
        timeoutMs: s.timeoutMs,
        concurrency: s.concurrency,
        maxIPs: s.maxIPs,
        speedTestCount: s.speedTestCount,
        totalIPs: s.totalIPs,
        scannedIPs: s.scannedIPs,
        aliveIPs: s.aliveIPs,
        speedTested: s.speedTested,
        status: s.status,
        durationMs: s.durationMs,
        createdAt: s.createdAt.toISOString(),
        resultCount: s._count.results,
        bestSpeed: aggMap.get(s.id)?.bestSpeed ?? 0,
        avgLatency: aggMap.get(s.id)?.avgLatency ?? 0,
      })),
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_list', detail: String(e) }, { status: 500 })
  }
}

function num(v: unknown, dflt: number): number {
  const n = Number(v)
  return Number.isFinite(n) ? n : dflt
}

// POST /api/scans — persist a finished scan
export async function POST(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const body = await req.json()
    const summary = body?.summary as ScanSummary | undefined
    if (!summary || !summary.config || !Array.isArray(summary.results)) {
      return NextResponse.json({ error: 'invalid_body' }, { status: 400 })
    }
    const rangesText =
      typeof body?.rangesText === 'string' ? body.rangesText.slice(0, 16_000) : ''
    const label = typeof body?.label === 'string' && body.label.trim() ? body.label.trim().slice(0, 80) : null

    const scan = await db.scan.create({
      data: {
        preset: String(summary.config.preset ?? 'custom').slice(0, 40),
        label,
        port: Math.round(num(summary.config.port, 443)),
        pingCount: Math.round(num(summary.config.pingCount, 4)),
        timeoutMs: Math.round(num(summary.config.timeoutMs, 1500)),
        concurrency: Math.round(num(summary.config.concurrency, 256)),
        maxIPs: Math.round(num(summary.config.maxIPs, 2000)),
        speedTestCount: Math.round(num(summary.config.speedTestCount, 10)),
        totalIPs: Math.round(num(summary.totalIPs, 0)),
        scannedIPs: Math.round(num(summary.scanned, 0)),
        aliveIPs: Math.round(num(summary.alive, 0)),
        speedTested: Math.round(num(summary.speedTested, 0)),
        status: summary.status === 'stopped' ? 'stopped' : summary.status === 'error' ? 'failed' : 'done',
        durationMs: Math.round(num(summary.elapsedMs, 0)),
        rangesText,
        results: {
          create: summary.results.slice(0, 200).map((r, i) => ({
            ip: String(r.ip).slice(0, 45),
            latencyMs: num(r.latencyMs, 0),
            sent: Math.round(num(r.sent, 0)),
            received: Math.round(num(r.received, 0)),
            lossRate: num(r.lossRate, 0),
            downloadSpeed: num(r.downloadSpeed, 0),
            uploadSpeed: num(r.uploadSpeed, 0),
            totalSpeed: num(r.totalSpeed, 0),
            rank: i + 1,
          })),
        },
      },
    })
    return NextResponse.json({ scan: { id: scan.id } })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_save', detail: String(e) }, { status: 500 })
  }
}
