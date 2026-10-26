import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'

export const dynamic = 'force-dynamic'

export interface GeoInfo {
  ip: string
  countryCode: string
  country: string
  city: string
  isp: string
  asn: string
}

const ALLOWED_FIELDS = 'status,query,country,countryCode,city,isp,as'
const MAX_IPS = 100

/**
 * Server-side cache (per Next.js process) — ip-api free tier tolerates bursts,
 * but clean IPs are stable across scans, so a 24h TTL turns repeat scans into
 * zero external requests. Failed lookups are remembered for 1h only.
 */
const GEO_CACHE = new Map<string, { geo: GeoInfo | null; ts: number }>()
const GEO_TTL_OK = 24 * 60 * 60 * 1000
const GEO_TTL_MISS = 60 * 60 * 1000

/**
 * POST /api/geo — batch IP geolocation & ASN enrichment.
 * Proxies http://ip-api.com/batch (free tier: 100 IPs / request, HTTP only).
 * Body: { ips: string[] } → { geo: Record<ip, GeoInfo> }
 */
export async function POST(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const body = await req.json()
    const raw: unknown = body?.ips
    if (!Array.isArray(raw)) {
      return NextResponse.json({ error: 'invalid_body' }, { status: 400 })
    }
    const seen = new Set<string>()
    const ips: string[] = []
    for (const v of raw) {
      if (typeof v !== 'string') continue
      // light validation: v4 or v6-ish
      if (!/^[0-9a-fA-F.:]+$/.test(v)) continue
      if (seen.has(v)) continue
      seen.add(v)
      if (ips.length >= MAX_IPS) break
      ips.push(v)
    }
    if (ips.length === 0) {
      return NextResponse.json({ geo: {} })
    }

    // 1) serve whatever the in-memory cache still holds
    const now = Date.now()
    const geo: Record<string, GeoInfo> = {}
    const missing: string[] = []
    for (const ip of ips) {
      const hit = GEO_CACHE.get(ip)
      if (hit) {
        const ttl = hit.geo ? GEO_TTL_OK : GEO_TTL_MISS
        if (now - hit.ts < ttl) {
          if (hit.geo) geo[ip] = hit.geo
          continue
        }
        GEO_CACHE.delete(ip)
      }
      missing.push(ip)
    }
    if (missing.length === 0) {
      return NextResponse.json({ geo })
    }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 10_000)
    try {
      const res = await fetch(
        `http://ip-api.com/batch?fields=${ALLOWED_FIELDS}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(missing.map((ip) => ({ query: ip }))),
          signal: controller.signal,
          // ip-api free tier is HTTP-only; disable Next.js caching
          cache: 'no-store',
        },
      )
      if (!res.ok) throw new Error(`ip-api HTTP ${res.status}`)
      const text = await res.text()
      let data: Array<{
        status?: string
        query?: string
        country?: string
        countryCode?: string
        city?: string
        isp?: string
        as?: string
      }> = []
      try {
        data = JSON.parse(text)
      } catch {
        // tolerate malformed upstream payloads — result stays empty
      }
      const geo2: Record<string, GeoInfo> = {}
      for (const row of data) {
        if (!row?.query || row.status !== 'success') continue
        geo2[row.query] = {
          ip: row.query,
          countryCode: row.countryCode ?? '',
          country: row.country ?? '',
          city: row.city ?? '',
          isp: row.isp ?? '',
          asn: row.as ?? '',
        }
      }
      // 2) refill the cache — hits for 24h, misses for 1h (retry later, politely)
      const ts = Date.now()
      for (const ip of missing) {
        GEO_CACHE.set(ip, { geo: geo2[ip] ?? null, ts })
      }
      // keep the map bounded (clean-IP pools churn slowly)
      if (GEO_CACHE.size > 5000) {
        const cutoff = ts - GEO_TTL_OK
        for (const [k, v] of GEO_CACHE) {
          if (v.ts < cutoff) GEO_CACHE.delete(k)
        }
      }
      return NextResponse.json({ geo: { ...geo, ...geo2 } })
    } finally {
      clearTimeout(timer)
    }
  } catch (e) {
    return NextResponse.json(
      { error: 'geo_failed', detail: String(e) },
      { status: 502 },
    )
  }
}
