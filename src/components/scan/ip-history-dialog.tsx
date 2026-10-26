'use client'

/**
 * IpHistoryDialog — full dossier for ONE IP:
 *  - SVG timeline of latency (line) + download speed (bars) across saved scans
 *  - per-scan rows (preset, port, latency, loss, speed, rank)
 *  - persisted probe verdicts (grade per SNI host:port)
 * Data: /api/ip-history (ScanResult × Scan + ProbeResult).
 */

import { useCallback, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { faIR, enUS } from 'date-fns/locale'
import { Gauge, Loader2, Network, Radar, Timer, Copy } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { formatLatency, formatBytesPerSec } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'
import { fetchJson, countryFlag, type GeoInfo } from '@/lib/api-types'

type ProbeGrade = 'excellent' | 'good' | 'weak' | 'fail'

const GRADE_STYLES: Record<ProbeGrade, string> = {
  excellent: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  good: 'border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400',
  weak: 'border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  fail: 'border-red-500/40 bg-red-500/10 text-red-500',
}

interface ScanAppearance {
  scanId: string
  label: string
  preset: string
  port: number
  scanStatus: string
  createdAt: string
  latencyMs: number
  sent: number
  received: number
  lossRate: number
  downloadSpeed: number
  uploadSpeed: number
  totalSpeed: number
  rank: number
}

interface ProbeVerdict {
  host: string
  port: number
  grade: ProbeGrade
  tcpMs?: number | null
  tlsMs?: number | null
  httpStatus?: number | null
  ok: boolean
  updatedAt: string
}

interface TrendPoint {
  host: string
  port: number
  grade: ProbeGrade
  tlsMs?: number | null
  ok: boolean
  createdAt: string
}

export interface IpHistoryDialogProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  ip: string | null
  geo?: GeoInfo
}

/** pure-SVG timeline: latency polyline (upper band) + speed bars (lower band) */
function Timeline({ scans }: { scans: ScanAppearance[] }) {
  const { t, num } = useI18n()
  const W = 320
  const H = 132
  const PAD = 8
  const LAT_TOP = 10
  const LAT_BOTTOM = 62
  const SPD_TOP = 78
  const SPD_BOTTOM = 124

  const { latPts, spdBars, latMin, latMax, spdMax } = useMemo(() => {
    const n = scans.length
    const lats = scans.map((s) => s.latencyMs)
    const spds = scans.map((s) => s.totalSpeed)
    const latMin = Math.min(...lats)
    const latMax = Math.max(...lats)
    const spdMax = Math.max(...spds, 1)
    const x = (i: number) => (n <= 1 ? W / 2 : PAD + (i / (n - 1)) * (W - PAD * 2))
    // latency: LOWER is better → invert (best latency = highest point)
    const yLat = (v: number) =>
      latMax === latMin ? (LAT_TOP + LAT_BOTTOM) / 2 : LAT_BOTTOM - ((v - latMin) / (latMax - latMin)) * (LAT_BOTTOM - LAT_TOP)
    const latPts = scans.map((s, i) => ({ x: x(i), y: yLat(s.latencyMs), v: s.latencyMs, at: s.createdAt }))
    const bw = n <= 1 ? 24 : Math.min(24, (W - PAD * 2) / n - 3)
    const spdBars = scans.map((s, i) => ({
      x: x(i) - bw / 2,
      w: bw,
      h: s.totalSpeed > 0 ? Math.max(3, (s.totalSpeed / spdMax) * (SPD_BOTTOM - SPD_TOP)) : 0,
      v: s.totalSpeed,
      at: s.createdAt,
    }))
    return { latPts, spdBars, latMin, latMax, spdMax }
  }, [scans])

  const line = latPts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')

  return (
    <div dir="ltr">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-32 w-full" role="img" aria-label={t('iph.timeline')}>
        {/* gridlines */}
        {[LAT_TOP, (LAT_TOP + LAT_BOTTOM) / 2, LAT_BOTTOM].map((y) => (
          <line key={y} x1={PAD} x2={W - PAD} y1={y} y2={y} stroke="currentColor" strokeOpacity={0.08} strokeDasharray="3 4" />
        ))}
        {/* speed bars */}
        {spdBars.map((b, i) =>
          b.h > 0 ? (
            <rect key={i} x={b.x} y={SPD_BOTTOM - b.h} width={b.w} height={b.h} rx={1.5} className="fill-teal-500/45">
              <title>{`▲ ${b.v > 1e6 ? (b.v / 1e6).toFixed(1) : (b.v / 1e3).toFixed(0)} MB/s`}</title>
            </rect>
          ) : (
            <rect key={i} x={b.x} y={SPD_BOTTOM - 2} width={b.w} height={2} rx={1} className="fill-zinc-400/30" />
          ),
        )}
        {/* latency polyline */}
        <path d={line} fill="none" className="stroke-emerald-500" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {latPts.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r={3} className="fill-emerald-500 stroke-background" strokeWidth={1.5}>
            <title>{`${num(Math.round(p.v))} ms`}</title>
          </circle>
        ))}
      </svg>
      <div className="mt-1 flex items-center justify-between text-[9.5px] text-muted-foreground" dir="rtl">
        <span className="inline-flex items-center gap-1">
          <span className="inline-block h-0.5 w-3 rounded bg-emerald-500" aria-hidden />
          {t('iph.lat')} {num(Math.round(latMin))}–{num(Math.round(latMax))} ms
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-sm bg-teal-500/60" aria-hidden />
          {t('iph.speed')} ≤ {spdMax > 1e6 ? `${(spdMax / 1e6).toFixed(1)}` : `${Math.round(spdMax / 1e3)}`} MB/s
        </span>
      </div>
    </div>
  )
}

const TREND_DOT: Record<ProbeGrade, string> = {
  excellent: 'fill-emerald-500',
  good: 'fill-teal-500',
  weak: 'fill-amber-500',
  fail: 'fill-red-500',
}

/** pure-SVG TLS trend: one point per probe observation, oldest → newest, lower = better */
function TrendSparkline({ points }: { points: TrendPoint[] }) {
  const { t, num, dateLocale } = useI18n()
  const W = 320
  const H = 72
  const PAD = 10

  const { pts, tlsMin, tlsMax, spanDays } = useMemo(() => {
    const vals = points.map((p) => p.tlsMs ?? 0)
    const tlsMin = Math.min(...vals)
    const tlsMax = Math.max(...vals)
    const n = points.length
    const t0 = new Date(points[0].createdAt).getTime()
    const tN = new Date(points[n - 1].createdAt).getTime()
    const span = Math.max(1, tN - t0)
    const x = (i: number) => (n <= 1 ? W / 2 : PAD + (new Date(points[i].createdAt).getTime() - t0) / span * (W - PAD * 2))
    // lower TLS = better = higher point (inverted, same convention as Timeline)
    const y = (v: number) =>
      tlsMax === tlsMin ? H / 2 : PAD + ((v - tlsMin) / (tlsMax - tlsMin)) * (H - PAD * 2 - 6)
    const pts = points.map((p, i) => ({ x: x(i), y: y(p.tlsMs ?? 0), v: p.tlsMs ?? 0, grade: p.grade, at: p.createdAt, port: p.port }))
    return { pts, tlsMin, tlsMax, spanDays: Math.max(1, Math.round((tN - t0) / 86_400_000)) }
  }, [points])

  const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')
  const trendDown = pts.length > 1 && pts[pts.length - 1].v <= pts[0].v

  return (
    <div dir="ltr">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-16 w-full" role="img" aria-label={t('iph.trend.title')}>
        <line x1={PAD} x2={W - PAD} y1={PAD} y2={PAD} stroke="currentColor" strokeOpacity={0.08} strokeDasharray="3 4" />
        <line x1={PAD} x2={W - PAD} y1={H - PAD - 6} y2={H - PAD - 6} stroke="currentColor" strokeOpacity={0.08} strokeDasharray="3 4" />
        <path d={line} fill="none" className={trendDown ? 'stroke-emerald-500' : 'stroke-amber-500'} strokeWidth={1.8} strokeLinejoin="round" strokeLinecap="round" />
        {pts.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r={2.6} className={cn(TREND_DOT[p.grade], 'stroke-background')} strokeWidth={1}>
            <title>{`${num(Math.round(p.v))} ms · :${num(p.port)} · ${p.grade} · ${new Date(p.at).toLocaleDateString(dateLocale)}`}</title>
          </circle>
        ))}
      </svg>
      <div className="mt-0.5 flex items-center justify-between text-[9.5px] text-muted-foreground" dir="rtl">
        <span dir="ltr">
          {t('iph.trend.range', { min: num(Math.round(tlsMin)), max: num(Math.round(tlsMax)) })}
        </span>
        <span dir="ltr">⏱ {num(spanDays)}d · n={num(pts.length)}</span>
      </div>
    </div>
  )
}

export function IpHistoryDialog({ open, onOpenChange, ip, geo }: IpHistoryDialogProps) {
  const { t, num, dir, dateLocale } = useI18n()

  const query = useQuery({
    queryKey: ['ip-history', ip],
    queryFn: () =>
      fetchJson<{ scans: ScanAppearance[]; probes: ProbeVerdict[]; trend?: TrendPoint[] }>(
        `/api/ip-history?ip=${encodeURIComponent(ip ?? '')}`,
      ),
    enabled: open && !!ip,
    staleTime: 5_000,
  })

  const scans = query.data?.scans ?? []
  const probes = query.data?.probes ?? []
  const trend = query.data?.trend ?? []

  const stats = useMemo(() => {
    const lat = scans.map((s) => s.latencyMs)
    const spd = scans.map((s) => s.totalSpeed)
    const ranks = scans.map((s) => s.rank).filter((r) => r > 0)
    return {
      n: scans.length,
      avgLat: lat.length ? lat.reduce((a, b) => a + b, 0) / lat.length : 0,
      bestSpd: spd.length ? Math.max(...spd) : 0,
      bestRank: ranks.length ? Math.min(...ranks) : 0,
    }
  }, [scans])

  // per-IP recommended port: best verdict across every probed port for this IP
  // (excellent first, then good, lowest TLS wins; falls back to any ok probe)
  const bestPort = useMemo(() => {
    const okProbes = probes.filter((p) => p.ok)
    if (okProbes.length === 0) return null
    const ranked = [...okProbes].sort((a, b) => {
      const g = (x: ProbeGrade) => (x === 'excellent' ? 0 : x === 'good' ? 1 : x === 'weak' ? 2 : 3)
      return g(a.grade) - g(b.grade) || (a.tlsMs ?? 9_999) - (b.tlsMs ?? 9_999)
    })
    const best = ranked[0]
    return { host: best.host, port: best.port, grade: best.grade, tlsMs: best.tlsMs }
  }, [probes])

  const copyTarget = useCallback(
    (target: string) => {
      void navigator.clipboard.writeText(target).then(
        () => toast.success(target),
        () => toast.error(target),
      )
    },
    [],
  )

  const flag = geo?.countryCode ? countryFlag(geo.countryCode) : null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-w-lg flex-col overflow-hidden" dir={dir}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
              <Radar className="size-4" aria-hidden />
            </span>
            {t('iph.title')}
          </DialogTitle>
          <DialogDescription className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <span className="font-mono font-bold text-foreground" dir="ltr">
              {ip}
            </span>
            {flag ? (
              <span aria-hidden>{flag}</span>
            ) : null}
            {geo?.country ? <span dir="ltr">{geo.country}</span> : null}
            <span className="text-[10.5px]">{t('iph.desc')}</span>
          </DialogDescription>
        </DialogHeader>

        {query.isLoading ? (
          <div className="flex h-40 items-center justify-center">
            <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden />
          </div>
        ) : scans.length === 0 && probes.length === 0 && trend.length === 0 ? (
          <div className="flex h-32 items-center justify-center px-6 text-center text-xs text-muted-foreground">
            {t('iph.empty')}
          </div>
        ) : (
          <div className="scrollbar-thin -mx-1 max-h-[60vh] space-y-3 overflow-y-auto px-1">
            {/* summary chips */}
            {stats.n > 0 ? (
              <div className="grid grid-cols-3 gap-2">
                {(
                  [
                    { icon: Timer, label: t('iph.scans'), value: num(stats.n) },
                    { icon: Gauge, label: t('iph.bestSpeed'), value: stats.bestSpd > 0 ? formatBytesPerSec(stats.bestSpd) : '—' },
                    { icon: Radar, label: t('iph.avgLat'), value: `${num(Math.round(stats.avgLat))} ms` },
                  ] as const
                ).map((c) => (
                  <div key={c.label} className="rounded-lg border bg-card/50 px-2 py-1.5 text-center">
                    <c.icon className="mx-auto size-3.5 text-emerald-600 dark:text-emerald-400" aria-hidden />
                    <div className="mt-0.5 truncate text-[11.5px] font-bold" dir="ltr">
                      {c.value}
                    </div>
                    <div className="text-[9.5px] text-muted-foreground">{c.label}</div>
                  </div>
                ))}
              </div>
            ) : null}

            {/* timeline */}
            {stats.n >= 2 ? (
              <div className="rounded-lg border bg-card/40 p-2.5">
                <Timeline scans={scans} />
              </div>
            ) : null}

            {/* per-scan rows */}
            {scans.length > 0 ? (
              <div>
                <div className="mb-1 text-[11px] font-semibold text-muted-foreground">{t('iph.scanList')}</div>
                <ul className="divide-y divide-border/60 rounded-lg border" role="list">
                  {[...scans].reverse().map((s) => (
                    <li key={s.scanId} role="listitem" className="flex items-center gap-2 px-2.5 py-1.5 text-[11px]">
                      <span className="max-w-28 shrink-0 truncate font-semibold">{s.label}</span>
                      <span className="shrink-0 font-mono text-[10px] text-muted-foreground" dir="ltr">
                        :{num(s.port)}
                      </span>
                      <span className="min-w-0 flex-1 truncate text-[10px] text-muted-foreground" title={new Date(s.createdAt).toLocaleString(dateLocale)}>
                        {formatDistanceToNow(new Date(s.createdAt), { addSuffix: true, locale: dir === 'rtl' ? faIR : enUS })}
                      </span>
                      <span className="shrink-0 font-mono text-[10.5px]" dir="ltr">
                        {num(Math.round(s.latencyMs))} ms
                      </span>
                      {s.totalSpeed > 0 ? (
                        <span className="shrink-0 rounded bg-teal-500/10 px-1 font-mono text-[10px] font-semibold text-teal-600 dark:text-teal-400" dir="ltr">
                          {formatBytesPerSec(s.totalSpeed)}
                        </span>
                      ) : null}
                      {s.rank > 0 ? (
                        <span className="shrink-0 rounded bg-amber-500/10 px-1 font-mono text-[9.5px] font-bold text-amber-600 dark:text-amber-400">
                          #{num(s.rank)}
                        </span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {/* TLS trend over time (append-only journal) */}
            {trend.length >= 2 ? (
              <div>
                <div className="mb-1 text-[11px] font-semibold text-muted-foreground">{t('iph.trend.title')}</div>
                <div className="rounded-lg border bg-card/40 p-2.5">
                  <TrendSparkline points={trend} />
                </div>
              </div>
            ) : null}

            {/* probe verdicts */}
            {probes.length > 0 ? (
              <div>
                <div className="mb-1 text-[11px] font-semibold text-muted-foreground">{t('iph.probes')}</div>
                {bestPort && bestPort.port !== 443 ? (
                  <button
                    type="button"
                    onClick={() => copyTarget(`${ip}:${bestPort.port}`)}
                    aria-label={t('iph.bestPort.copy', { target: `${ip}:${bestPort.port}` })}
                    className="mb-1.5 flex w-full items-center justify-between gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1.5 text-start transition-colors hover:bg-emerald-500/18"
                  >
                    <span className="flex min-w-0 items-center gap-1.5">
                      <Network className="size-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden />
                      <span className="text-[11px] font-semibold text-emerald-600 dark:text-emerald-400">{t('iph.bestPort')}</span>
                      <span className="truncate font-mono text-[11px] text-emerald-700/90 dark:text-emerald-300/90" dir="ltr">
                        {ip}:{num(bestPort.port)} · {bestPort.tlsMs != null ? `${num(bestPort.tlsMs)} ms` : bestPort.grade}
                      </span>
                    </span>
                    <Copy className="size-3.5 shrink-0 text-emerald-600/70 dark:text-emerald-400/70" aria-hidden />
                  </button>
                ) : null}
                <div className="flex flex-wrap gap-1.5 rounded-lg border bg-card/40 p-2.5">
                  <TooltipProvider delayDuration={150}>
                    {probes.map((p) => (
                      <Tooltip key={`${p.host}:${p.port}`}>
                        <TooltipTrigger asChild>
                          <Badge variant="outline" className={cn('cursor-default gap-1 px-1.5 py-0 text-[10px]', GRADE_STYLES[p.grade])}>
                            <span dir="ltr" className="font-mono">
                              {p.host.length > 18 ? `${p.host.slice(0, 16)}…` : p.host}:{num(p.port)}
                            </span>
                            {p.tlsMs != null ? (
                              <span className="font-mono opacity-80" dir="ltr">
                                {formatLatency(p.tlsMs)}
                              </span>
                            ) : null}
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent dir="ltr" className="text-[10px]">
                          {p.tcpMs != null ? `TCP ${p.tcpMs} ms · ` : ''}TLS {p.tlsMs ?? '—'} ms
                          {p.httpStatus != null ? ` · HTTP ${p.httpStatus}` : ''}
                        </TooltipContent>
                      </Tooltip>
                    ))}
                  </TooltipProvider>
                </div>
              </div>
            ) : null}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
