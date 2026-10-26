import { NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

// GET /api/stats — aggregate dashboard stats
export async function GET() {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const [totalScans, agg, best, last] = await Promise.all([
      db.scan.count(),
      db.scan.aggregate({ _sum: { scannedIPs: true } }),
      db.scanResult.findFirst({
        orderBy: [{ totalSpeed: 'desc' }, { latencyMs: 'asc' }],
        where: { totalSpeed: { gt: 0 } },
      }),
      db.scan.findFirst({ orderBy: { createdAt: 'desc' } }),
    ])
    const totalClean = await db.scanResult.count()
    const fallbackBest = totalClean > 0 && !best ? await db.scanResult.findFirst({ orderBy: { latencyMs: 'asc' } }) : null
    const b = best ?? fallbackBest
    return NextResponse.json({
      totalScans,
      totalIPsScanned: agg._sum.scannedIPs ?? 0,
      totalCleanIPs: totalClean,
      bestIp: b
        ? { ip: b.ip, latencyMs: b.latencyMs, totalSpeed: b.totalSpeed }
        : null,
      lastScanAt: last?.createdAt.toISOString() ?? null,
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_stats', detail: String(e) }, { status: 500 })
  }
}
