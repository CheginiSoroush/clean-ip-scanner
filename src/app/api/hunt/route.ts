import { NextResponse } from 'next/server'
import fs from 'node:fs'
import path from 'node:path'
import { lockGuard } from '@/lib/lock'
import type { GoogleHuntHistoryRun } from '@/lib/scan-protocol'

export const dynamic = 'force-dynamic'

/**
 * GET /api/hunt — finished Google IP hunter runs (funnel v2).
 *
 * The scan-engine (mini-service, port 3003) appends each finished hunt to
 * db/hunt-history.json; this route serves that file read-only so the UI can
 * show past hunts + re-copy their healthy IPs. The file lives on the same
 * machine, so a direct fs read keeps the API zero-dependency (no extra
 * socket round-trip) and naturally survives engine restarts.
 */
export async function GET() {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const file = path.join(process.cwd(), 'db', 'hunt-history.json')
    if (!fs.existsSync(file)) {
      return NextResponse.json({ runs: [] })
    }
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (!Array.isArray(raw)) {
      return NextResponse.json({ runs: [] })
    }
    // defensive sanitation — engine-written but never blindly trusted
    const runs: GoogleHuntHistoryRun[] = raw
      .filter(
        (r): r is GoogleHuntHistoryRun =>
          !!r &&
          typeof r === 'object' &&
          typeof (r as GoogleHuntHistoryRun).id === 'string' &&
          typeof (r as GoogleHuntHistoryRun).tested === 'number' &&
          Array.isArray((r as GoogleHuntHistoryRun).healthyIps),
      )
      .slice(0, 30)
      .map((r) => ({
        id: r.id.slice(0, 64),
        startedAt: typeof r.startedAt === 'number' ? r.startedAt : 0,
        finishedAt: typeof r.finishedAt === 'number' ? r.finishedAt : 0,
        target: typeof r.target === 'number' ? r.target : 0,
        stopped: r.stopped === true,
        host: typeof r.host === 'string' ? r.host.slice(0, 253) : '',
        port: typeof r.port === 'number' ? r.port : 443,
        tested: r.tested,
        healthy: typeof r.healthy === 'number' ? r.healthy : 0,
        blocked: typeof r.blocked === 'number' ? r.blocked : 0,
        dead: typeof r.dead === 'number' ? r.dead : 0,
        tcpAlive: typeof r.tcpAlive === 'number' ? r.tcpAlive : 0,
        verify: typeof r.verify === 'number' ? r.verify : 0,
        healthyIps: Array.isArray(r.healthyIps) ? r.healthyIps.slice(0, 100) : [],
        provider: typeof r.provider === 'string' ? r.provider.slice(0, 16) : undefined,
        /** v7.0 — scheduler-triggered runs are flagged so the UI can badge them */
        auto: r.auto === true,
        perProvider:
          r.perProvider && typeof r.perProvider === 'object'
            ? Object.fromEntries(
                Object.entries(r.perProvider as Record<string, unknown>)
                  .slice(0, 4)
                  .filter(([, v]) => !!v && typeof v === 'object')
                  .map(([k, v]) => [
                    k,
                    {
                      tested: Number((v as Record<string, unknown>).tested) || 0,
                      healthy: Number((v as Record<string, unknown>).healthy) || 0,
                      blocked: Number((v as Record<string, unknown>).blocked) || 0,
                      dead: Number((v as Record<string, unknown>).dead) || 0,
                    },
                  ]),
              )
            : undefined,
      }))
    return NextResponse.json({ runs })
  } catch {
    return NextResponse.json({ runs: [] })
  }
}

/**
 * DELETE /api/hunt — history management (v7.2).
 *
 *   DELETE /api/hunt?id=<runId>   → removes that ONE run from
 *                                   db/hunt-history.json
 *   DELETE /api/hunt              → clears the ENTIRE history file
 *
 * The engine keeps NO in-memory copy of the history — persistHuntHistory()
 * re-reads the file before every append — so file-level deletion here is
 * authoritative and surviving runs stay deleted. The UI must confirm both
 * operations (AlertDialog) before calling; this route is intentionally
 * single-shot (no bulk id lists) to keep the blast radius obvious.
 */
export async function DELETE(request: Request) {
  const denied = await lockGuard()
  if (denied) return denied

  const url = new URL(request.url)
  const id = (url.searchParams.get('id') ?? '').trim().slice(0, 64)
  const file = path.join(process.cwd(), 'db', 'hunt-history.json')

  try {
    if (!fs.existsSync(file)) {
      // nothing stored — clearing "all" is trivially successful, a specific
      // id can never match so it is an honest 404
      if (id) return NextResponse.json({ ok: false, error: 'not_found' }, { status: 404 })
      return NextResponse.json({ ok: true, deleted: 0, remaining: 0 })
    }
    let raw: unknown
    try {
      raw = JSON.parse(fs.readFileSync(file, 'utf8'))
    } catch {
      // unreadable / corrupt JSON — same recovery stance as the GET route:
      // a clear wipes the junk to an honest empty store, a single delete of
      // an unreadable file can never match so it is an honest 404
      if (id) return NextResponse.json({ ok: false, error: 'not_found' }, { status: 404 })
      fs.writeFileSync(file, '[]')
      return NextResponse.json({ ok: true, deleted: 0, remaining: 0 })
    }
    if (!Array.isArray(raw)) {
      // valid JSON but not an array — same recovery stance
      if (id) return NextResponse.json({ ok: false, error: 'not_found' }, { status: 404 })
      fs.writeFileSync(file, '[]')
      return NextResponse.json({ ok: true, deleted: 0, remaining: 0 })
    }

    if (id) {
      const next = raw.filter((r) => r && r.id !== id)
      if (next.length === raw.length) {
        return NextResponse.json({ ok: false, error: 'not_found' }, { status: 404 })
      }
      fs.writeFileSync(file, JSON.stringify(next))
      return NextResponse.json({ ok: true, deleted: raw.length - next.length, remaining: next.length })
    }

    const deleted = raw.length
    fs.writeFileSync(file, '[]')
    return NextResponse.json({ ok: true, deleted, remaining: 0 })
  } catch {
    return NextResponse.json({ ok: false, error: 'server_error' }, { status: 500 })
  }
}
