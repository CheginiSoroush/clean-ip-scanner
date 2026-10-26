import { NextResponse } from 'next/server'
import fs from 'node:fs'
import path from 'node:path'
import { lockGuard } from '@/lib/lock'
import type { WarpEndpoint, WarpHistoryRun } from '@/lib/scan-protocol'
import { WARP_HISTORY_FOUND_CAP, WARP_HISTORY_MAX_RUNS } from '@/lib/scan-protocol'

export const dynamic = 'force-dynamic'

/**
 * GET /api/warp-history — finished WARP UDP scans (v7.4, hunt-history parity).
 *
 * The scan-engine (mini-service, port 3003) appends each finished WARP scan
 * to db/warp-history.json; this route serves that file read-only so the panel
 * can show past scans + re-copy their live endpoints. Same contract as
 * /api/hunt: direct fs read (same machine), defensive sanitation, honest
 * empty arrays for missing/corrupt stores.
 */
export async function GET() {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const file = path.join(process.cwd(), 'db', 'warp-history.json')
    if (!fs.existsSync(file)) {
      return NextResponse.json({ runs: [] })
    }
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (!Array.isArray(raw)) {
      return NextResponse.json({ runs: [] })
    }
    // defensive sanitation — engine-written but never blindly trusted
    const runs: WarpHistoryRun[] = raw
      .filter(
        (r): r is WarpHistoryRun =>
          !!r &&
          typeof r === 'object' &&
          typeof (r as WarpHistoryRun).id === 'string' &&
          typeof (r as WarpHistoryRun).tested === 'number' &&
          Array.isArray((r as WarpHistoryRun).found),
      )
      .slice(0, WARP_HISTORY_MAX_RUNS)
      .map((r) => ({
        id: r.id.slice(0, 64),
        startedAt: typeof r.startedAt === 'number' ? r.startedAt : 0,
        finishedAt: typeof r.finishedAt === 'number' ? r.finishedAt : 0,
        target: typeof r.target === 'number' ? r.target : 0,
        stopped: r.stopped === true,
        tested: r.tested,
        alive: typeof r.alive === 'number' ? r.alive : 0,
        planned: typeof r.planned === 'number' ? r.planned : 0,
        exhausted: r.exhausted === true,
        eps: typeof r.eps === 'number' ? r.eps : undefined,
        ports: Array.isArray(r.ports)
          ? r.ports.slice(0, 8).map((p) => Math.floor(Number(p)) || 0).filter((p) => p > 0)
          : [],
        ranges: Array.isArray(r.ranges)
          ? r.ranges.slice(0, 20).filter((x): x is string => typeof x === 'string').map((x) => x.slice(0, 20))
          : [],
        custom: r.custom === true,
        registered: r.registered === true,
        found: (Array.isArray(r.found) ? r.found : [])
          .slice(0, WARP_HISTORY_FOUND_CAP)
          .filter((ep): ep is WarpEndpoint => !!ep && typeof ep === 'object' && typeof ep.endpoint === 'string')
          .map((ep) => ({
            endpoint: ep.endpoint.slice(0, 23),
            ip: typeof ep.ip === 'string' ? ep.ip.slice(0, 16) : '',
            port: typeof ep.port === 'number' ? ep.port : 0,
            rttMs: typeof ep.rttMs === 'number' ? ep.rttMs : undefined,
            response: ep.response === 'handshake' || ep.response === 'cookie' ? ep.response : undefined,
            range: typeof ep.range === 'string' ? ep.range.slice(0, 20) : undefined,
            attempts: typeof ep.attempts === 'number' ? ep.attempts : undefined,
          })),
        error: typeof r.error === 'string' && r.error.length > 0 ? r.error.slice(0, 300) : undefined,
      }))
    return NextResponse.json({ runs })
  } catch {
    return NextResponse.json({ runs: [] })
  }
}

/**
 * DELETE /api/warp-history — history management (v7.4, mirrors DELETE /api/hunt).
 *
 *   DELETE /api/warp-history?id=<runId>   → removes that ONE run from
 *                                           db/warp-history.json
 *   DELETE /api/warp-history              → clears the ENTIRE history file
 *
 * The engine keeps NO in-memory copy of the history — persistWarpHistory()
 * re-reads the file before every append — so file-level deletion here is
 * authoritative and surviving runs stay deleted. The UI must confirm both
 * operations (AlertDialog) before calling; single-shot semantics (no bulk id
 * lists) keep the blast radius obvious.
 */
export async function DELETE(request: Request) {
  const denied = await lockGuard()
  if (denied) return denied

  const url = new URL(request.url)
  const id = (url.searchParams.get('id') ?? '').trim().slice(0, 64)
  const file = path.join(process.cwd(), 'db', 'warp-history.json')

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
