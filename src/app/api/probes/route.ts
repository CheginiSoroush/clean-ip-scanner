import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'
import type { ProbeRecordPayload } from '@/lib/scan-protocol'

export const dynamic = 'force-dynamic'

const GRADES = new Set(['excellent', 'good', 'weak', 'fail'])

function intOrNull(v: unknown): number | null {
  const n = Number(v)
  return Number.isFinite(n) && n >= 0 ? Math.round(n) : null
}

// GET /api/probes?host=<sni>[&ips=a,b,c] — recent probe verdicts for one SNI host
// GET /api/probes?all=1[&limit=150][&grade=excellent] — latest records across all hosts (history view)
export async function GET(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const host = (req.nextUrl.searchParams.get('host') ?? '').trim().toLowerCase().slice(0, 253)
    const all = req.nextUrl.searchParams.get('all') === '1'
    if (!host && !all) {
      return NextResponse.json({ error: 'invalid_host' }, { status: 400 })
    }
    const gradeParam = (req.nextUrl.searchParams.get('grade') ?? '').trim()
    const grade = GRADES.has(gradeParam) ? gradeParam : null
    const limitRaw = Number(req.nextUrl.searchParams.get('limit') ?? '150')
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(600, Math.round(limitRaw))) : 150

    if (all) {
      const probes = await db.probeResult.findMany({
        where: grade ? { grade } : {},
        orderBy: { updatedAt: 'desc' },
        take: limit,
      })
      return NextResponse.json({
        probes: probes.map((p) => ({
          ip: p.ip,
          host: p.host,
          port: p.port,
          grade: p.grade,
          tcpMs: p.tcpMs,
          tlsMs: p.tlsMs,
          httpStatus: p.httpStatus,
          ok: p.ok,
          updatedAt: p.updatedAt.toISOString(),
        })),
      })
    }

    const ipsParam = req.nextUrl.searchParams.get('ips') ?? ''
    const ips = ipsParam
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && s.length <= 45)
      .slice(0, 600)

    const probes = await db.probeResult.findMany({
      where: { host, ...(grade ? { grade } : {}), ...(ips.length > 0 ? { ip: { in: ips } } : {}) },
      orderBy: { updatedAt: 'desc' },
      take: 600,
    })
    return NextResponse.json({
      probes: probes.map((p) => ({
        ip: p.ip,
        host: p.host,
        port: p.port,
        grade: p.grade,
        tcpMs: p.tcpMs,
        tlsMs: p.tlsMs,
        httpStatus: p.httpStatus,
        ok: p.ok,
        updatedAt: p.updatedAt.toISOString(),
      })),
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_list_probes', detail: String(e) }, { status: 500 })
  }
}

// POST /api/probes — bulk upsert verdicts { probes: ProbeRecordPayload[] }
export async function POST(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const body = await req.json()
    const list: unknown = body?.probes
    if (!Array.isArray(list) || list.length === 0) {
      return NextResponse.json({ error: 'invalid_body' }, { status: 400 })
    }
    let saved = 0
    const logs: {
      ip: string
      host: string
      port: number
      grade: string
      tcpMs: number | null
      tlsMs: number | null
      ok: boolean
    }[] = []
    for (const raw of list.slice(0, 60)) {
      const p = raw as Partial<ProbeRecordPayload>
      const ip = typeof p.ip === 'string' ? p.ip.trim().slice(0, 45) : ''
      const host = typeof p.host === 'string' ? p.host.trim().toLowerCase().slice(0, 253) : ''
      const grade = typeof p.grade === 'string' && GRADES.has(p.grade) ? p.grade : null
      const port = intOrNull(p.port) ?? 443
      if (!ip || !host || !grade) continue
      const ok = p.ok === true
      logs.push({
        ip,
        host,
        port,
        grade,
        tcpMs: intOrNull(p.tcpMs),
        tlsMs: intOrNull(p.tlsMs),
        ok,
      })
      await db.probeResult.upsert({
        where: { ip_host_port: { ip, host, port } },
        update: {
          grade,
          tcpMs: intOrNull(p.tcpMs),
          tlsMs: intOrNull(p.tlsMs),
          httpStatus: intOrNull(p.httpStatus),
          ok,
        },
        create: {
          ip,
          host,
          port,
          grade,
          tcpMs: intOrNull(p.tcpMs),
          tlsMs: intOrNull(p.tlsMs),
          httpStatus: intOrNull(p.httpStatus),
          ok,
        },
      })
      saved++
    }
    // append-only journal — one row per observation so TLS trends over time exist
    if (logs.length > 0) {
      try {
        await db.probeLog.createMany({ data: logs })
      } catch {
        // journal is best-effort; verdict persistence must never fail because of it
      }
    }
    return NextResponse.json({ saved })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_save_probes', detail: String(e) }, { status: 500 })
  }
}
