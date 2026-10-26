import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

// GET /api/scans/[id] — scan detail with results
export async function GET(_req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const denied = await lockGuard()
  if (denied) return denied

  const { id } = await ctx.params
  try {
    const scan = await db.scan.findUnique({
      where: { id },
      include: { results: { orderBy: { rank: 'asc' } } },
    })
    if (!scan) return NextResponse.json({ error: 'not_found' }, { status: 404 })
    return NextResponse.json({
      scan: {
        id: scan.id,
        preset: scan.preset,
        label: scan.label,
        port: scan.port,
        pingCount: scan.pingCount,
        timeoutMs: scan.timeoutMs,
        concurrency: scan.concurrency,
        maxIPs: scan.maxIPs,
        speedTestCount: scan.speedTestCount,
        totalIPs: scan.totalIPs,
        scannedIPs: scan.scannedIPs,
        aliveIPs: scan.aliveIPs,
        speedTested: scan.speedTested,
        status: scan.status,
        durationMs: scan.durationMs,
        rangesText: scan.rangesText,
        createdAt: scan.createdAt.toISOString(),
        resultCount: scan.results.length,
      },
      results: scan.results.map((r) => ({
        ip: r.ip,
        latencyMs: r.latencyMs,
        sent: r.sent,
        received: r.received,
        lossRate: r.lossRate,
        downloadSpeed: r.downloadSpeed,
        uploadSpeed: r.uploadSpeed,
        totalSpeed: r.totalSpeed,
        rank: r.rank,
      })),
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_fetch', detail: String(e) }, { status: 500 })
  }
}

// DELETE /api/scans/[id]
export async function DELETE(_req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const denied = await lockGuard()
  if (denied) return denied

  const { id } = await ctx.params
  try {
    await db.scan.delete({ where: { id } })
    return NextResponse.json({ ok: true })
  } catch {
    return NextResponse.json({ error: 'not_found' }, { status: 404 })
  }
}
