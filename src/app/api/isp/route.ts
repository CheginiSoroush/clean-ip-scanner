import { isIP } from 'node:net'
import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

/**
 * RIPEstat announced-prefixes proxy (hunt v6.5) — community ISP lists feed.
 *
 * GET /api/isp?asn=AS44244 →
 *   { ok, asn, name, prefixes: string[], count4, count6, cached }
 *
 * Only a hardcoded whitelist of Iranian consumer ISPs is resolvable (the UI
 * offers these as one-tap hunt-target presets). Primary source is the
 * RIPEstat Data API (api.ripe.net) with the legacy stat.ripe.net endpoint as
 * a mirror — same envelope, same data (recon-resilience pattern from v6.4).
 * Answers are cached in memory for 30 min (announced prefixes move on hour
 * scales, not seconds).
 */

/** whitelisted Iranian consumer ASNs (asn → display name) */
export const ISP_ASN_WHITELIST: Readonly<Record<string, string>> = {
  AS197207: 'MCI (همراه اول)',
  AS44244: 'Irancell (ایرانسل)',
  AS58224: 'TCI (مخابرات ایران)',
  AS31549: 'Shatel (شاتل)',
  AS57218: 'Rightel (رایتل)',
  AS44288: 'Asiatech (آسیاتک)',
  AS16322: 'ParsOnline (پارسآنلاین)',
}

const RIPESTAT_URL = 'https://api.ripe.net/data/announced-prefixes/data.json'
/** legacy RIPEstat endpoint — same envelope, acts as the mirror when api.ripe.net is unreachable */
const RIPESTAT_MIRROR_URL = 'https://stat.ripe.net/data/announced-prefixes/data.json'
const RIPESTAT_TIMEOUT_MS = 10_000
const CACHE_TTL_MS = 30 * 60 * 1000

interface IspPayload {
  ok: true
  asn: string
  name: string
  prefixes: string[]
  count4: number
  count6: number
}

/** module-level in-memory cache (key = normalized asn) */
const ispCache = new Map<string, { at: number; payload: IspPayload }>()

/** normalize the query param: trim + uppercase + bare-number → AS-prefix */
function normalizeAsn(raw: string): string {
  const asn = raw.trim().toUpperCase()
  if (/^\d+$/.test(asn)) return `AS${asn}`
  return asn
}

/** fetch + parse announced prefixes (primary → mirror); throws the last failure */
async function fetchAnnouncedPrefixes(asn: string): Promise<string[]> {
  let lastErr: unknown = new Error('ripestat_unreachable')
  for (const base of [RIPESTAT_URL, RIPESTAT_MIRROR_URL]) {
    try {
      const res = await fetch(`${base}?resource=${encodeURIComponent(asn)}`, {
        cache: 'no-store',
        signal: AbortSignal.timeout(RIPESTAT_TIMEOUT_MS),
      })
      if (!res.ok) {
        lastErr = new Error(`HTTP ${res.status}`)
        continue
      }
      let json: { data?: { prefixes?: Array<{ prefix?: unknown }> } } | null = null
      try {
        json = (await res.json()) as { data?: { prefixes?: Array<{ prefix?: unknown }> } }
      } catch {
        lastErr = new Error('unexpected_response')
        continue
      }
      const rows = Array.isArray(json?.data?.prefixes) ? (json?.data?.prefixes as Array<{ prefix?: unknown }>) : null
      if (!rows) {
        lastErr = new Error('unexpected_response')
        continue
      }
      const prefixes: string[] = []
      for (const row of rows) {
        const prefix = row && typeof row.prefix === 'string' ? row.prefix.trim() : ''
        if (!prefix) continue
        // accept anything whose network part (before '/') is a valid v4/v6 IP
        const net = prefix.split('/')[0] ?? ''
        const v = isIP(net)
        if (v !== 4 && v !== 6) continue
        prefixes.push(prefix)
      }
      return prefixes
    } catch (e) {
      lastErr = e
    }
  }
  throw lastErr
}

// GET /api/isp?asn=AS44244 — announced prefixes for a whitelisted Iranian ISP
export async function GET(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  const raw = req.nextUrl.searchParams.get('asn')
  if (!raw || raw.trim() === '') {
    return NextResponse.json({ error: 'missing_asn' }, { status: 400 })
  }
  const asn = normalizeAsn(raw)
  const name = ISP_ASN_WHITELIST[asn]
  if (!name) {
    return NextResponse.json({ error: 'unknown_asn' }, { status: 400 })
  }

  const hit = ispCache.get(asn)
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) {
    return NextResponse.json({ ...hit.payload, cached: true })
  }

  try {
    const prefixes = await fetchAnnouncedPrefixes(asn)
    let count4 = 0
    let count6 = 0
    for (const prefix of prefixes) {
      const v = isIP(prefix.split('/')[0] ?? '')
      if (v === 4) count4 += 1
      else count6 += 1
    }

    const payload: IspPayload = { ok: true, asn, name, prefixes, count4, count6 }
    ispCache.set(asn, { at: Date.now(), payload })
    return NextResponse.json({ ...payload, cached: false })
  } catch (e) {
    const detail = (e instanceof Error ? e.message : String(e)).slice(0, 200)
    return NextResponse.json({ error: 'ripestat_error', detail }, { status: 502 })
  }
}
