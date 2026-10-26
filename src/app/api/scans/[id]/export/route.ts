import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

function fmtBps(bps: number): string {
  if (!bps || bps <= 0) return '-'
  const mb = bps / 1048576
  if (mb >= 1) return `${mb.toFixed(2)} MB/s`
  return `${(bps / 1024).toFixed(1)} KB/s`
}

// GET /api/scans/[id]/export?format=txt|csv|json
export async function GET(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const denied = await lockGuard()
  if (denied) return denied

  const { id } = await ctx.params
  const format = (req.nextUrl.searchParams.get('format') ?? 'txt').toLowerCase()

  const scan = await db.scan.findUnique({
    where: { id },
    include: { results: { orderBy: { rank: 'asc' } } },
  })
  if (!scan) return NextResponse.json({ error: 'not_found' }, { status: 404 })

  const stamp = scan.createdAt.toISOString().replace(/[:.]/g, '-').slice(0, 19)
  let body: string
  let mime: string
  let ext: string

  if (format === 'json') {
    body = JSON.stringify(
      {
        exportedAt: new Date().toISOString(),
        scan: {
          preset: scan.preset,
          port: scan.port,
          pingCount: scan.pingCount,
          timeoutMs: scan.timeoutMs,
          concurrency: scan.concurrency,
          maxIPs: scan.maxIPs,
          totalIPs: scan.totalIPs,
          scannedIPs: scan.scannedIPs,
          aliveIPs: scan.aliveIPs,
          status: scan.status,
          durationMs: scan.durationMs,
          createdAt: scan.createdAt.toISOString(),
        },
        results: scan.results.map((r) => ({
          ip: r.ip,
          latencyMs: r.latencyMs,
          lossRate: r.lossRate,
          sent: r.sent,
          received: r.received,
          downloadSpeedBps: r.downloadSpeed,
          uploadSpeedBps: r.uploadSpeed,
          totalSpeedBps: r.totalSpeed,
        })),
      },
      null,
      2,
    )
    mime = 'application/json'
    ext = 'json'
  } else if (format === 'csv') {
    const rows = [
      'ip,latency_ms,loss_rate,sent,received,download_bps,upload_bps,total_bps',
      ...scan.results.map(
        (r) =>
          `${r.ip},${r.latencyMs.toFixed(1)},${r.lossRate.toFixed(2)},${r.sent},${r.received},${r.downloadSpeed.toFixed(0)},${r.uploadSpeed.toFixed(0)},${r.totalSpeed.toFixed(0)}`,
      ),
    ]
    body = rows.join('\n')
    mime = 'text/csv'
    ext = 'csv'
  } else {
    // txt — mirrors the original tool's clean_ips.txt style
    const lines: string[] = [
      '# Clean IP Scanner — Web Edition',
      `# preset=${scan.preset} port=${scan.port} created=${scan.createdAt.toISOString()}`,
      `# found=${scan.results.length} clean IPs (scanned ${scan.scannedIPs}/${scan.totalIPs})`,
      '#',
    ]
    for (const r of scan.results) {
      lines.push(
        `${r.ip}:${scan.port}  # latency=${r.latencyMs.toFixed(0)}ms loss=${(r.lossRate * 100).toFixed(0)}% down=${fmtBps(r.downloadSpeed)} up=${fmtBps(r.uploadSpeed)}`,
      )
    }
    lines.push('#')
    lines.push('# plain list:')
    for (const r of scan.results) lines.push(r.ip)
    body = lines.join('\n')
    mime = 'text/plain'
    ext = 'txt'
  }

  return new NextResponse(body, {
    headers: {
      'Content-Type': `${mime}; charset=utf-8`,
      'Content-Disposition': `attachment; filename="clean-ips-${stamp}.${ext}"`,
    },
  })
}
