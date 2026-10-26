'use client'

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import {
  ArrowUpDown,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Download,
  History,
  Loader2,
  MapPin,
  Globe,
  Zap,
  Server,
  Medal,
  Network,
  Radar,
  Share2,
  SlidersHorizontal,
  Sparkles,
  Square,
  Trophy,
  X,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { cn } from '@/lib/utils'
import { formatBytesPerSec, formatLatency, type LiveResult } from '@/lib/scan-protocol'
import { probeHostFor } from '@/lib/xray-config'
import {
  computeIpScores,
  rankScores,
  scoreBand,
  SCORE_BAND_HEX,
  SCORE_BAND_STYLES,
} from '@/lib/ip-score'
import { useScoreWeights } from '@/lib/score-weights'
import { countryFlag, fetchJson, type GeoInfo, type FavoritesResponse } from '@/lib/api-types'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'
import dynamic from 'next/dynamic'
import type { ShareMeta } from '@/components/scan/share-dialog'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Star } from 'lucide-react'
import type { XrayProbeResult } from '@/lib/scan-protocol'

// heavy recharts/dialog bundles load on demand — smaller initial JS, faster first paint
const ChartFallback = (
  <div className="flex h-44 items-center justify-center rounded-lg border bg-background/40">
    <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden />
  </div>
)
const LatencyHistogram = dynamic(
  () => import('@/components/scan/latency-histogram').then((m) => m.LatencyHistogram),
  { ssr: false, loading: () => ChartFallback },
)
const SpeedChart = dynamic(
  () => import('@/components/scan/speed-chart').then((m) => m.SpeedChart),
  { ssr: false, loading: () => ChartFallback },
)
const ScatterChart = dynamic(
  () => import('@/components/scan/scatter-chart').then((m) => m.ScatterChart),
  { ssr: false, loading: () => ChartFallback },
)
const ShareDialog = dynamic(
  () => import('@/components/scan/share-dialog').then((m) => m.ShareDialog),
  { ssr: false },
)
const XrayDialog = dynamic(
  () => import('@/components/scan/xray-dialog').then((m) => m.XrayDialog),
  { ssr: false },
)
const PortFinderDialog = dynamic(
  () => import('@/components/scan/port-finder-dialog').then((m) => m.PortFinderDialog),
  { ssr: false },
)
const ScoreTuningDialog = dynamic(
  () => import('@/components/scan/score-tuning-dialog').then((m) => m.ScoreTuningDialog),
  { ssr: false },
)
const IpHistoryDialog = dynamic(
  () => import('@/components/scan/ip-history-dialog').then((m) => m.IpHistoryDialog),
  { ssr: false },
)
const ProbeHistoryDialog = dynamic(
  () => import('@/components/scan/probe-history-dialog').then((m) => m.ProbeHistoryDialog),
  { ssr: false },
)

interface ResultsPanelProps {
  results: LiveResult[]
  running: boolean
  /** set when the finished scan was persisted via POST /api/scans */
  savedId: string | null
  /** context for the share report (preset label, scan start time…) */
  shareMeta?: ShareMeta | null
  /** preset id of the current scan — picks the default SNI in the Xray dialog */
  preset?: string
  /** TCP port used by the scan — flows into the Xray dialog configs */
  port: number
  connected: boolean
  /** engine-side Xray-style TLS probe */
  onProbe: (payload: { ip: string; port: number; host: string }) => Promise<XrayProbeResult | null>
}

type SortKey =
  | 'rank'
  | 'score'
  | 'ip'
  | 'latencyMs'
  | 'lossRate'
  | 'downloadSpeed'
  | 'uploadSpeed'
  | 'totalSpeed'

type SortDir = 'asc' | 'desc'

const COLUMNS: { key: SortKey; labelKey: DictKey; defaultDir: SortDir }[] = [
  { key: 'rank', labelKey: 'results.col.rank', defaultDir: 'asc' },
  { key: 'ip', labelKey: 'results.col.ip', defaultDir: 'asc' },
  { key: 'latencyMs', labelKey: 'results.col.latency', defaultDir: 'asc' },
  { key: 'lossRate', labelKey: 'results.col.loss', defaultDir: 'asc' },
  { key: 'downloadSpeed', labelKey: 'results.col.download', defaultDir: 'desc' },
  { key: 'uploadSpeed', labelKey: 'results.col.upload', defaultDir: 'desc' },
  { key: 'totalSpeed', labelKey: 'results.col.total', defaultDir: 'desc' },
]

const MEDAL_STYLES = [
  'border-amber-500/40 bg-amber-500/10 text-amber-500',
  'border-zinc-400/40 bg-zinc-400/10 text-zinc-400',
  'border-orange-500/40 bg-orange-500/10 text-orange-500',
]

type ProbeGrade = NonNullable<XrayProbeResult['grade']>

/** per-row batch-probe verdict chip colors (excellent → fail) */
const GRADE_STYLES: Record<ProbeGrade, string> = {
  excellent: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  good: 'border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400',
  weak: 'border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  fail: 'border-red-500/40 bg-red-500/10 text-red-500',
}

interface ProbeSummary {
  grade: ProbeGrade
  tcpMs?: number | null
  tlsMs?: number | null
  ok: boolean
  port?: number
}

const AUTO_PROBE_KEY = 'clean-ip.auto-probe'

function lossBadgeClass(lossRate: number): string {
  const pct = lossRate * 100
  if (pct < 10)
    return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
  if (pct < 30)
    return 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400'
  return 'border-red-500/30 bg-red-500/10 text-red-500'
}

export function ResultsPanel({ results, running, savedId, shareMeta, preset, port, connected, onProbe }: ResultsPanelProps) {
  const { t, num, lang, dir } = useI18n()
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({
    key: 'rank',
    dir: 'asc',
  })
  const [geoMap, setGeoMap] = useState<Record<string, GeoInfo>>({})
  const [geoLoading, setGeoLoading] = useState(false)
  const [shareOpen, setShareOpen] = useState(false)
  const [xrayOpen, setXrayOpen] = useState(false)
  const [xrayTarget, setXrayTarget] = useState<LiveResult | null>(null)
  /** port found by the port-finder, overriding the scan port in Xray configs */
  const [xrayPortOverride, setXrayPortOverride] = useState<number | null>(null)
  const [portOpen, setPortOpen] = useState(false)
  const [tuneOpen, setTuneOpen] = useState(false)
  const [phOpen, setPhOpen] = useState(false)
  const [iphOpen, setIphOpen] = useState(false)
  const [iphIp, setIphIp] = useState<string | null>(null)
  const [batch, setBatch] = useState<{ done: number; total: number } | null>(null)
  const [probeGrades, setProbeGrades] = useState<Record<string, ProbeSummary>>({})
  const [batchSize, setBatchSize] = useState(6)
  const [autoProbe, setAutoProbe] = useState<boolean>(false)
  const [hydrating, setHydrating] = useState(false)
  const batchCancelRef = useRef(false)
  const batchRunningRef = useRef(false)
  const autoProbedKeyRef = useRef<string | null>(null)
  const hydrationCancelRef = useRef<(() => void) | null>(null)

  // restore + persist the auto-probe preference
  useEffect(() => {
    try {
      setAutoProbe(window.localStorage.getItem(AUTO_PROBE_KEY) === '1')
    } catch {
      /* private mode */
    }
  }, [])
  const toggleAutoProbe = (v: boolean) => {
    setAutoProbe(v)
    try {
      window.localStorage.setItem(AUTO_PROBE_KEY, v ? '1' : '0')
    } catch {
      /* private mode */
    }
  }

  const openXray = (r: LiveResult) => {
    setXrayTarget(r)
    setXrayPortOverride(null)
    setXrayOpen(true)
  }

  // port-finder handoff: generate configs for the discovered best IP:port combo
  const handleUsePort = useCallback(
    (p: number, ip: string) => {
      setXrayPortOverride(p)
      const row: LiveResult =
        results.find((r) => r.ip === ip) ?? xrayTarget ?? { ip, latencyMs: 0, sent: 0, received: 0, lossRate: 0 }
      setXrayTarget(row)
      setXrayOpen(true)
      toast.success(t('port.use.toast', { port: num(p), ip }))
    },
    [results, xrayTarget, t, num],
  )

  // --- favorites (star) integration ---
  const qc = useQueryClient()
  const favQuery = useQuery<FavoritesResponse>({
    queryKey: ['favorites'],
    queryFn: () => fetchJson<FavoritesResponse>('/api/favorites'),
    retry: false,
  })
  const favoriteIps = useMemo(
    () => new Set((favQuery.data?.favorites ?? []).map((f) => f.ip)),
    [favQuery.data],
  )
  const toggleFav = useMutation({
    mutationFn: async ({ ip, add }: { ip: string; add: boolean }) => {
      if (add) {
        const res = await fetch('/api/favorites', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip }),
        })
        if (!res.ok) throw new Error('HTTP error')
        return res.json()
      }
      const res = await fetch(`/api/favorites/${encodeURIComponent(ip)}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('HTTP error')
      return res.json()
    },
    onSuccess: (_d, v) => {
      toast.success(
        t(v.add ? 'results.toast.fav.add' : 'results.toast.fav.remove', { ip: v.ip }),
      )
      qc.invalidateQueries({ queryKey: ['favorites'] })
    },
    onError: () => toast.error(t('results.toast.fav.error')),
  })
  const handleToggleFav = (ip: string) => {
    toggleFav.mutate({ ip, add: !favoriteIps.has(ip) })
  }

  const openIpHistory = useCallback((ip: string) => {
    setIphIp(ip)
    setIphOpen(true)
  }, [])

  // --- geo enrichment (top 100 results per request, ip-api batch) ---
  const missingGeoCount = useMemo(
    () => results.slice(0, 100).filter((r) => !geoMap[r.ip]).length,
    [results, geoMap],
  )

  // localStorage mirror under "cis-geo" — hydrated once, persisted after every
  // fetch so reloads and repeat scans fire zero external requests
  const geoStoreRef = useRef<Record<string, { d: GeoInfo; ts: number }>>({})
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem('cis-geo')
      if (!raw) return
      const store = JSON.parse(raw) as Record<string, { d: GeoInfo; ts: number }>
      geoStoreRef.current = store
      const now = Date.now()
      const fresh: Record<string, GeoInfo> = {}
      for (const [ip, v] of Object.entries(store)) {
        if (now - v.ts < 7 * 24 * 60 * 60 * 1000) fresh[ip] = v.d
      }
      if (Object.keys(fresh).length > 0) setGeoMap((prev) => ({ ...fresh, ...prev }))
    } catch {
      /* corrupt store — start clean */
    }
  }, [])

  const persistGeo = useCallback((data: Record<string, GeoInfo>) => {
    const now = Date.now()
    const store = geoStoreRef.current
    for (const [ip, info] of Object.entries(data)) store[ip] = { d: info, ts: now }
    try {
      // keep newest 800 entries
      const trimmed = Object.entries(store)
        .sort((a, b) => b[1].ts - a[1].ts)
        .slice(0, 800)
      window.localStorage.setItem('cis-geo', JSON.stringify(Object.fromEntries(trimmed)))
    } catch {
      /* storage full — non-fatal */
    }
  }, [])

  const handleGeo = async (silent = false) => {
    if (geoLoading) return
    const ips = results.slice(0, 100).map((r) => r.ip)
    if (ips.length === 0) {
      if (!silent) toast.error(t('results.toast.geo.none'))
      return
    }
    setGeoLoading(true)
    try {
      const data = await fetchJson<{ geo: Record<string, GeoInfo> }>('/api/geo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips }),
      })
      const found = Object.keys(data.geo ?? {}).length
      setGeoMap((prev) => ({ ...prev, ...data.geo }))
      persistGeo(data.geo ?? {})
      if (!silent) {
        if (found === 0) toast.warning(t('results.toast.geo.warn'))
        else toast.success(t('results.toast.geo.ok', { n: num(found) }))
      }
    } catch {
      if (!silent) toast.error(t('results.toast.geo.fail'))
    } finally {
      setGeoLoading(false)
    }
  }

  // auto-enrich once per result set: 1.2s after a scan finishes, silently
  const autoGeoRef = useRef('')
  useEffect(() => {
    if (running || results.length === 0) return
    const sig = results.slice(0, 100).map((r) => r.ip).join(',')
    if (sig === autoGeoRef.current || missingGeoCount === 0) return
    const timer = setTimeout(() => {
      autoGeoRef.current = sig
      void handleGeo(true)
    }, 1200)
    return () => clearTimeout(timer)
  }, [results, running, missingGeoCount])

  // rank: best by totalSpeed (fallback latencyMs when every speed is zero)
  const ranked = useMemo(() => {
    const hasSpeed = results.some((r) => (r.totalSpeed ?? 0) > 0)
    const sorted = [...results].sort((a, b) => {
      if (hasSpeed) {
        const at = a.totalSpeed ?? 0
        const bt = b.totalSpeed ?? 0
        if (bt !== at) return bt - at
      }
      return a.latencyMs - b.latencyMs
    })
    return sorted.map((r, i) => ({ ...r, rank: i + 1 }))
  }, [results])

  // --- geo distribution (countries + ISPs across the enriched top results) ---
  const geoStats = useMemo(() => {
    const countries = new Map<string, { code: string; name: string; n: number }>()
    const isps = new Map<string, number>()
    let enriched = 0
    for (const r of ranked.slice(0, 100)) {
      const g = geoMap[r.ip]
      if (!g) continue
      enriched += 1
      if (g.countryCode) {
        const cur = countries.get(g.countryCode)
        if (cur) cur.n += 1
        else countries.set(g.countryCode, { code: g.countryCode, name: g.country || g.countryCode, n: 1 })
      }
      const isp = (g.isp ?? '').trim()
      if (isp) isps.set(isp, (isps.get(isp) ?? 0) + 1)
    }
    return {
      enriched,
      countries: [...countries.values()].sort((a, b) => b.n - a.n).slice(0, 8),
      isps: [...isps.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4),
    }
  }, [ranked, geoMap])

  // --- smart best-IP scoring (probe grade + TLS + loss + speed + stability) ---
  const weights = useScoreWeights()
  const scoreMap = useMemo(
    () =>
      computeIpScores(ranked, probeGrades, favoriteIps, {
        bytesPerSec: formatBytesPerSec,
        latency: formatLatency,
      }, weights),
    [ranked, probeGrades, favoriteIps, weights],
  )
  const bestScores = useMemo(() => rankScores(scoreMap), [scoreMap])
  const best = bestScores[0] ?? null

  const rows = useMemo(() => {
    const arr = [...ranked]
    const { key, dir } = sort
    arr.sort((a, b) => {
      if (key === 'score') {
        const as = scoreMap[a.ip]?.score ?? -1
        const bs = scoreMap[b.ip]?.score ?? -1
        return dir === 'asc' ? as - bs : bs - as
      }
      if (key === 'ip') {
        return dir === 'asc'
          ? a.ip.localeCompare(b.ip)
          : b.ip.localeCompare(a.ip)
      }
      const av = (a[key] ?? 0) as number
      const bv = (b[key] ?? 0) as number
      return dir === 'asc' ? av - bv : bv - av
    })
    return arr
  }, [ranked, sort, scoreMap])

  const toggleSort = (key: SortKey) => {
    setSort((prev) => {
      if (prev.key === key) {
        return { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
      }
      const col = COLUMNS.find((c) => c.key === key)
      return { key, dir: col?.defaultDir ?? (key === 'score' ? 'desc' : 'asc') }
    })
  }

  const ipList = useMemo(() => ranked.map((r) => r.ip).join('\n'), [ranked])

  const handleCopy = async () => {
    if (!ipList) {
      toast.error(t('results.toast.copy.none'))
      return
    }
    try {
      await navigator.clipboard.writeText(ipList)
      toast.success(t('results.toast.copy.ok', { n: num(ranked.length) }))
    } catch {
      toast.error(t('results.toast.copy.fail'))
    }
  }

  const downloadClient = (fmt: 'txt' | 'csv' | 'json') => {
    if (ranked.length === 0) {
      toast.error(t('results.toast.export.none'))
      return
    }
    let content = ''
    let mime = 'text/plain'
    if (fmt === 'txt') {
      content = ipList
    } else if (fmt === 'csv') {
      mime = 'text/csv'
      const head =
        'ip,latency_ms,sent,received,loss_rate,download_bps,upload_bps,total_bps'
      const body = ranked
        .map((r) =>
          [
            r.ip,
            r.latencyMs.toFixed(2),
            r.sent,
            r.received,
            r.lossRate.toFixed(3),
            Math.round(r.downloadSpeed ?? 0),
            Math.round(r.uploadSpeed ?? 0),
            Math.round(r.totalSpeed ?? 0),
          ].join(',')
        )
        .join('\n')
      content = `${head}\n${body}`
    } else {
      mime = 'application/json'
      content = JSON.stringify(ranked, null, 2)
    }
    const blob = new Blob([content], { type: `${mime};charset=utf-8` })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `clean-ips.${fmt}`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    toast.success(t('results.toast.export.ok', { fmt: fmt.toUpperCase() }))
  }

  const handleExport = (fmt: 'txt' | 'csv' | 'json') => {
    if (savedId) {
      window.open(`/api/scans/${savedId}/export?format=${fmt}`, '_blank')
      return
    }
    downloadClient(fmt)
  }

  // ----- batch Xray probe: top N IPs (user-selectable), CDN default SNI, concurrency 2 -----
  const BATCH_CONCURRENCY = 2
  const probeHost = probeHostFor(preset)

  // persist verdicts so grades survive reloads (best-effort, never blocks UI)
  const saveProbeVerdicts = useCallback(
    (entries: { ip: string; res: XrayProbeResult | null }[]) => {
      const payload = entries
        .filter(({ res }) => !!res)
        .map(({ ip, res }) => ({
          ip,
          host: res?.host ?? probeHost,
          port: res?.port ?? (port || 443),
          grade: res?.grade ?? 'fail',
          tcpMs: res?.tcpMs,
          tlsMs: res?.tlsMs,
          httpStatus: res?.httpStatus,
          ok: !!res?.ok && res.grade !== 'fail',
        }))
      if (payload.length === 0) return
      void fetch('/api/probes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ probes: payload }),
      }).catch(() => undefined)
    },
    [port, probeHost],
  )

  const runBatchProbe = async () => {
    if (batchRunningRef.current) return
    if (!connected) {
      toast.error(t('xray.toast.offline'))
      return
    }
    const targets = ranked.slice(0, Math.min(batchSize, ranked.length))
    if (targets.length === 0) return
    const host = probeHost
    batchRunningRef.current = true
    batchCancelRef.current = false
    setBatch({ done: 0, total: targets.length })
    let done = 0
    let ok = 0
    for (let i = 0; i < targets.length; i += BATCH_CONCURRENCY) {
      if (batchCancelRef.current) break
      const chunk = targets.slice(i, i + BATCH_CONCURRENCY)
      const out = await Promise.all(
        chunk.map(async (r) => ({
          ip: r.ip,
          res: await onProbe({ ip: r.ip, port: port || 443, host }),
        })),
      )
      for (const { ip, res } of out) {
        done++
        const healthy = !!res?.ok && !!res.grade && res.grade !== 'fail'
        if (healthy) ok++
        setProbeGrades((prev) => ({
          ...prev,
          [ip]: { grade: res?.grade ?? 'fail', tcpMs: res?.tcpMs, tlsMs: res?.tlsMs, ok: healthy },
        }))
      }
      saveProbeVerdicts(out)
      setBatch({ done, total: targets.length })
    }
    const cancelled = batchCancelRef.current
    batchRunningRef.current = false
    setBatch(null)
    if (cancelled) {
      toast.info(t('results.batch.cancelled', { n: num(done), total: num(targets.length) }))
    } else if (ok === 0) {
      toast.warning(t('results.batch.zero'))
    } else {
      toast.success(t('results.batch.done', { ok: num(ok), total: num(targets.length) }))
    }
  }

  // latest runner for the Alt+B window-event bridge
  const runBatchRef = useRef(runBatchProbe)
  useEffect(() => {
    runBatchRef.current = runBatchProbe
  })

  useEffect(() => {
    const onEvt = () => void runBatchRef.current()
    window.addEventListener('results:batch-probe', onEvt)
    return () => window.removeEventListener('results:batch-probe', onEvt)
  }, [])

  // fresh scan → clear stale probe verdicts
  useEffect(() => {
    if (results.length === 0) {
      setProbeGrades({})
      autoProbedKeyRef.current = null
    }
  }, [results])

  // hydrate persisted verdicts for the current SNI host (grades survive reloads).
  // Debounced 600ms — during a live scan ipListKey grows every ~450ms batch and
  // without the debounce this would fire a fetch per batch.
  const ipListKey = useMemo(() => ranked.map((r) => r.ip).join(','), [ranked])
  useEffect(() => {
    if (ranked.length === 0 || !probeHost) return
    const timer = window.setTimeout(() => {
      let cancelled = false
      setHydrating(true)
      void fetchJson<{
        probes: { ip: string; port: number; grade: ProbeGrade; tcpMs?: number; tlsMs?: number; ok: boolean }[]
      }>(`/api/probes?host=${encodeURIComponent(probeHost)}`)
        .then((data) => {
          if (cancelled) return
          const known = new Set(ranked.map((r) => r.ip))
          const next: Record<string, ProbeSummary> = {}
          const RANK: Record<ProbeGrade, number> = { excellent: 0, good: 1, weak: 2, fail: 3 }
          for (const p of data.probes ?? []) {
            if (!known.has(p.ip)) continue
            const cand: ProbeSummary = {
              grade: p.grade,
              tcpMs: p.tcpMs,
              tlsMs: p.tlsMs,
              ok: p.ok,
              port: p.port,
            }
            const cur = next[p.ip]
            // same IP may hold verdicts for several ports (port-finder) — keep the BEST
            if (
              !cur ||
              RANK[cand.grade] < RANK[cur.grade] ||
              (RANK[cand.grade] === RANK[cur.grade] &&
                (cand.tlsMs ?? Infinity) < (cur.tlsMs ?? Infinity))
            ) {
              next[p.ip] = cand
            }
          }
          if (Object.keys(next).length > 0) {
            setProbeGrades((prev) => ({ ...next, ...prev }))
          }
        })
        .catch(() => undefined)
        .finally(() => {
          if (!cancelled) setHydrating(false)
        })
      hydrationCancelRef.current = () => {
        cancelled = true
      }
    }, 600)
    return () => {
      window.clearTimeout(timer)
      hydrationCancelRef.current?.()
    }
  }, [ipListKey, probeHost])

  // auto-probe right after a scan finishes (user preference, runs once per result set)
  useEffect(() => {
    if (!autoProbe || running || ranked.length === 0 || batchRunningRef.current) return
    if (Object.keys(probeGrades).length > 0) return
    if (autoProbedKeyRef.current === ipListKey) return
    autoProbedKeyRef.current = ipListKey
    const id = window.setTimeout(() => void runBatchRef.current(), 800)
    return () => window.clearTimeout(id)
  }, [autoProbe, running, ipListKey])

  const gradedHealthy = useMemo(
    () => Object.entries(probeGrades).filter(([, v]) => v.ok),
    [probeGrades],
  )

  const handleCopyBest = async () => {
    if (gradedHealthy.length === 0) {
      toast.warning(t('results.batch.copybest.none'))
      return
    }
    const sorted = [...gradedHealthy]
      .sort((a, b) => (a[1].tlsMs ?? 9999) - (b[1].tlsMs ?? 9999))
      .map(([ip]) => ip)
    try {
      await navigator.clipboard.writeText(sorted.join('\n'))
      toast.success(t('results.batch.copybest.ok', { n: num(sorted.length) }))
    } catch {
      toast.error(t('results.toast.copy.fail'))
    }
  }

  // one-click: save every healthy graded IP to the favorites watchlist
  const [favBulkPending, setFavBulkPending] = useState(false)
  const handleFavHealthy = async () => {
    if (gradedHealthy.length === 0) {
      toast.warning(t('results.batch.fav.none'))
      return
    }
    const sorted = [...gradedHealthy]
      .sort((a, b) => (a[1].tlsMs ?? 9999) - (b[1].tlsMs ?? 9999))
      .map(([ip]) => ip)
      .filter((ip) => !favoriteIps.has(ip))
    if (sorted.length === 0) {
      toast.info(t('results.batch.fav.already'))
      return
    }
    setFavBulkPending(true)
    try {
      const out = await Promise.allSettled(
        sorted.map((ip) =>
          fetch('/api/favorites', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, label: t('results.batch.fav.label') }),
          }).then((res) => {
            if (!res.ok) throw new Error('HTTP error')
          }),
        ),
      )
      const added = out.filter((r) => r.status === 'fulfilled').length
      if (added > 0) {
        toast.success(t('results.batch.fav.ok', { n: num(added) }))
        qc.invalidateQueries({ queryKey: ['favorites'] })
      } else {
        toast.error(t('results.toast.fav.error'))
      }
    } finally {
      setFavBulkPending(false)
    }
  }

  // tap-to-copy a single IP (table cell + mobile card)
  const handleCopyIp = async (ip: string) => {
    try {
      await navigator.clipboard.writeText(ip)
      toast.success(t('results.toast.copy.ok', { n: num(1) }))
    } catch {
      toast.error(t('results.toast.copy.fail'))
    }
  }

  const top3 = ranked.slice(0, 3)
  const geoSeparator = lang === 'fa' ? '، ' : ', '

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur sm:p-6">
      {/* Title */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="flex size-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="size-4" aria-hidden />
          </span>
          <h2 className="text-base font-bold">{t('results.title')}</h2>
          {ranked.length > 0 ? (
            <Badge
              variant="outline"
              className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
            >
              <span dir="ltr">{num(ranked.length)}</span> IP
            </Badge>
          ) : null}
        </div>

        {ranked.length > 0 ? (
          <div className="flex flex-wrap items-center gap-2">
            <TooltipProvider delayDuration={250}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-9 gap-1.5 border-teal-500/30 text-teal-700 hover:bg-teal-500/10 hover:text-teal-700 dark:text-teal-400 dark:hover:text-teal-300"
                    onClick={
                      batch
                        ? () => {
                            batchCancelRef.current = true
                          }
                        : () => void runBatchRef.current()
                    }
                    aria-label={t('results.batch.aria')}
                  >
                    {batch ? (
                      <>
                        <Square className="size-3.5" aria-hidden />
                        <span className="hidden sm:inline">{t('results.batch.stop')}</span>
                        <span className="font-mono text-[10px]" dir="ltr">
                          {batch.done}/{batch.total}
                        </span>
                      </>
                    ) : (
                      <>
                        <Zap className="size-3.5" aria-hidden />
                        <span className="hidden sm:inline">
                          {t('results.batch.title', { n: num(Math.min(batchSize, ranked.length)) })}
                        </span>
                        <span className="font-mono text-[10px] sm:hidden" dir="ltr">
                          ×{num(Math.min(batchSize, ranked.length))}
                        </span>
                      </>
                    )}
                  </Button>
                </TooltipTrigger>
                <TooltipContent dir={dir} className="max-w-64 text-xs">
                  <p>{t('results.batch.tip', { n: num(Math.min(batchSize, ranked.length)) })}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            {/* batch size selector (3 / 6 / 10 / 15) */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-9 gap-1 px-2 text-teal-700 dark:text-teal-400"
                  aria-label={t('results.batch.size')}
                  disabled={!!batch}
                >
                  <SlidersHorizontal className="size-3.5" aria-hidden />
                  <span className="font-mono text-[10px]" dir="ltr">
                    ×{num(batchSize)}
                  </span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start">
                {[3, 6, 10, 15].map((n) => (
                  <DropdownMenuItem
                    key={n}
                    onClick={() => setBatchSize(n)}
                    className="cursor-pointer justify-between gap-3"
                  >
                    <span className="font-mono" dir="ltr">
                      Top {n}
                    </span>
                    {batchSize === n ? <Check className="size-3.5 text-emerald-500" aria-hidden /> : null}
                  </DropdownMenuItem>
                ))}
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="cursor-pointer justify-between gap-3"
                  onClick={() => toggleAutoProbe(!autoProbe)}
                >
                  <span className="flex items-center gap-1.5 text-xs">
                    <Zap className="size-3 text-teal-500" aria-hidden />
                    {t('results.batch.autoprobe')}
                  </span>
                  {autoProbe ? <Check className="size-3.5 text-emerald-500" aria-hidden /> : null}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            {/* smart-score quick sort */}
            <TooltipProvider delayDuration={250}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className={cn(
                      'h-9 gap-1.5',
                      sort.key === 'score'
                        ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                        : 'text-emerald-700/80 dark:text-emerald-400/80',
                    )}
                    onClick={() => setSort({ key: 'score', dir: 'desc' })}
                    aria-label={t('results.smart.sort')}
                  >
                    <Sparkles className="size-3.5" aria-hidden />
                    <span className="hidden sm:inline">{t('results.smart.sort')}</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent dir={dir} className="max-w-64 text-xs">
                  <p>{t('results.smart.tip')}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            {/* score weight tuning (what-if sliders) */}
            <TooltipProvider delayDuration={250}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className={cn(
                      'h-9 gap-1.5',
                      tuneOpen
                        ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                        : 'text-emerald-700/80 dark:text-emerald-400/80',
                    )}
                    onClick={() => setTuneOpen(true)}
                    aria-label={t('tune.title')}
                  >
                    <SlidersHorizontal className="size-3.5" aria-hidden />
                    <span className="hidden sm:inline">{t('tune.title')}</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent dir={dir} className="max-w-64 text-xs">
                  <p>{t('tune.tip')}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            <TooltipProvider delayDuration={250}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-9 gap-1.5 border-teal-500/30 text-teal-700 hover:bg-teal-500/10 hover:text-teal-700 dark:text-teal-400 dark:hover:text-teal-300"
                    onClick={() => setShareOpen(true)}
                    aria-label={t('share.aria')}
                  >
                    <Share2 className="size-3.5" aria-hidden />
                    <span className="hidden sm:inline">{t('share.title')}</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent dir={dir}>
                  <p>{t('share.desc')}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            <Button
              variant="outline"
              size="sm"
              className="h-9 gap-1.5"
              onClick={() => void handleGeo(false)}
              disabled={geoLoading}
              title={t('results.geo.title')}
            >
              {geoLoading ? (
                <Loader2 className="size-3.5 animate-spin" aria-hidden />
              ) : (
                <MapPin className="size-3.5" aria-hidden />
              )}
              {geoLoading
                ? t('results.geo.updating')
                : missingGeoCount > 0
                  ? t('results.geo', { n: num(missingGeoCount) })
                  : t('results.geo.refresh')}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-9 gap-1.5"
              onClick={handleCopy}
            >
              <Copy className="size-3.5" aria-hidden />
              {t('results.copy')}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" className="h-9 gap-1.5">
                  <Download className="size-3.5" aria-hidden />
                  {t('results.export')}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {(['txt', 'csv', 'json'] as const).map((fmt) => (
                  <DropdownMenuItem
                    key={fmt}
                    onClick={() => handleExport(fmt)}
                    className="cursor-pointer justify-between gap-2"
                  >
                    <span className="font-mono" dir="ltr">
                      .{fmt}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {t(`results.export.${fmt}` as DictKey)}
                    </span>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        ) : null}
      </div>

      {/* batch probe progress */}
      {batch ? (
        <div className="mt-3 flex items-center gap-2">
          <Loader2 className="size-3.5 animate-spin text-teal-500" aria-hidden />
          <Progress
            value={Math.round((batch.done / Math.max(1, batch.total)) * 100)}
            className="h-1.5 flex-1"
          />
          <span className="font-mono text-[10px] text-muted-foreground" dir="ltr">
            {batch.done}/{batch.total}
          </span>
        </div>
      ) : null}

      {/* batch probe verdict summary */}
      {ranked.length > 0 && Object.keys(probeGrades).length > 0 ? (
        <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-teal-500/20 bg-teal-500/[0.04] px-3 py-2">
          <Zap className="size-3.5 shrink-0 text-teal-600 dark:text-teal-400" aria-hidden />
          <span className="text-[11px] font-semibold text-teal-700 dark:text-teal-300">
            {t('results.batch.summary')}
          </span>
          {hydrating ? (
            <Loader2 className="size-3 animate-spin text-teal-500" aria-hidden />
          ) : null}
          <span className="flex flex-wrap items-center gap-1">
            {(['excellent', 'good', 'weak', 'fail'] as const).map((g) => {
              const n = Object.values(probeGrades).filter((v) => v.grade === g).length
              if (n === 0) return null
              return (
                <Badge
                  key={g}
                  variant="outline"
                  className={cn('px-1.5 py-0 text-[10px]', GRADE_STYLES[g])}
                >
                  <span dir="ltr">{num(n)}</span>{' '}
                  {t(`xray.grade.${g}` as DictKey)}
                </Badge>
              )
            })}
          </span>
          <span className="ms-auto flex flex-wrap items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-[11px]"
              onClick={() => setPhOpen(true)}
              aria-label={t('ph.title')}
            >
              <History className="size-3" aria-hidden />
              <span className="hidden sm:inline">{t('ph.short')}</span>
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-[11px]"
              onClick={() => void handleCopyBest()}
            >
              <Copy className="size-3" aria-hidden />
              {t('results.batch.copybest')}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-[11px] text-amber-600 hover:text-amber-600 dark:text-amber-400"
              onClick={() => void handleFavHealthy()}
              disabled={favBulkPending}
              aria-label={t('results.batch.fav')}
            >
              {favBulkPending ? (
                <Loader2 className="size-3 animate-spin" aria-hidden />
              ) : (
                <Star className="size-3" aria-hidden />
              )}
              <span className="hidden sm:inline">{t('results.batch.fav')}</span>
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-[11px] text-muted-foreground"
              onClick={() => setProbeGrades({})}
              aria-label={t('results.batch.clear')}
            >
              <X className="size-3" aria-hidden />
              <span className="hidden sm:inline">{t('results.batch.clear')}</span>
            </Button>
          </span>
        </div>
      ) : null}

      {/* geo distribution — countries + ISPs across enriched results */}
      {ranked.length > 0 && geoStats.enriched > 0 ? (
        <div className="mt-3 rounded-lg border bg-card/40 px-3 py-2.5">
          <div className="flex items-center gap-1.5">
            <Globe className="size-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden />
            <span className="text-[11px] font-semibold">{t('results.geo.dist')}</span>
            <span className="rounded-full bg-muted px-1.5 py-0.5 text-[9.5px] font-semibold text-muted-foreground">
              {t('results.geo.count', { n: num(geoStats.enriched) })}
            </span>
            {geoLoading ? <Loader2 className="size-3 animate-spin text-emerald-500" aria-hidden /> : null}
          </div>
          {geoStats.countries.length > 0 ? (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              {geoStats.countries.map((c) => {
                const pct = Math.round((c.n / geoStats.enriched) * 100)
                return (
                  <Tooltip key={c.code}>
                    <TooltipTrigger asChild>
                      <span
                        className="inline-flex cursor-default items-center gap-1 rounded-full border bg-background/60 px-1.5 py-0.5 text-[10.5px] font-medium transition-colors hover:border-emerald-500/40"
                        dir="ltr"
                      >
                        <span aria-hidden>{countryFlag(c.code)}</span>
                        <span className="max-w-24 truncate">{c.name}</span>
                        <span className="rounded-full bg-emerald-500/10 px-1 font-bold text-emerald-600 dark:text-emerald-400">
                          {num(c.n)}
                        </span>
                      </span>
                    </TooltipTrigger>
                    <TooltipContent dir="ltr">
                      {c.name} — {num(pct)}%
                    </TooltipContent>
                  </Tooltip>
                )
              })}
            </div>
          ) : null}
          {geoStats.isps.length > 0 ? (
            <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-muted-foreground">
              <Server className="size-3 shrink-0" aria-hidden />
              {geoStats.isps.map(([name, n]) => (
                <span key={name} dir="ltr" className="inline-flex items-center gap-1">
                  <span className="max-w-40 truncate">{name}</span>
                  <span className="font-bold text-emerald-600 dark:text-emerald-400">×{num(n)}</span>
                </span>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}

      {/* smart best-IP recommendation */}
      {ranked.length > 0 && best
        ? (() => {
            const band = scoreBand(best.score)
            const ringC = 2 * Math.PI * 26
            const bestResult = ranked.find((r) => r.ip === best.ip)
            const bestProbe = probeGrades[best.ip]
            const runners = bestScores.slice(1, 3)
            return (
              <div className="relative mt-4 overflow-hidden rounded-xl border border-emerald-500/30 bg-gradient-to-l from-emerald-500/[0.08] via-teal-500/[0.04] to-transparent p-4">
                <span
                  aria-hidden
                  className="absolute inset-x-0 top-0 h-px bg-gradient-to-l from-transparent via-emerald-400/60 to-transparent"
                />
                <div className="flex flex-wrap items-center gap-3 sm:flex-nowrap">
                  {/* animated score ring */}
                  <div
                    className="relative size-14 shrink-0"
                    role="img"
                    aria-label={`${t('results.smart.col')} ${num(Math.round(best.score))}`}
                  >
                    <svg viewBox="0 0 64 64" className="size-14 -rotate-90">
                      <circle cx="32" cy="32" r="26" fill="none" strokeWidth="6" className="stroke-emerald-500/15" />
                      <circle
                        cx="32"
                        cy="32"
                        r="26"
                        fill="none"
                        strokeWidth="6"
                        strokeLinecap="round"
                        stroke={SCORE_BAND_HEX[band]}
                        strokeDasharray={ringC}
                        strokeDashoffset={ringC * (1 - best.score / 100)}
                        style={{ transition: 'stroke-dashoffset 0.7s ease, stroke 0.7s ease' }}
                      />
                    </svg>
                    <span
                      className="absolute inset-0 flex items-center justify-center font-mono text-sm font-bold"
                      style={{ color: SCORE_BAND_HEX[band] }}
                      dir="ltr"
                    >
                      {num(Math.round(best.score))}
                    </span>
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Sparkles className="size-3.5 text-emerald-600 dark:text-emerald-400" aria-hidden />
                      <span className="text-[11px] font-bold text-emerald-700 dark:text-emerald-300">
                        {t('results.smart.title')}
                      </span>
                      {bestProbe ? (
                        <span
                          className={cn(
                            'inline-flex items-center rounded-md border px-1.5 py-0 text-[10px] font-semibold',
                            GRADE_STYLES[bestProbe.grade],
                          )}
                        >
                          {t(`xray.grade.${bestProbe.grade}` as DictKey)}
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => void runBatchRef.current()}
                          disabled={!connected}
                          className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-amber-600 transition-colors hover:bg-amber-500/20 disabled:opacity-40 dark:text-amber-400"
                        >
                          <Zap className="size-2.5" aria-hidden />
                          {t('results.smart.probe.nudge')}
                        </button>
                      )}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => void handleCopyIp(best.ip)}
                        title={t('results.ip.copy', { ip: best.ip })}
                        aria-label={t('results.ip.copy', { ip: best.ip })}
                        className="font-mono text-sm font-bold tracking-tight transition-colors hover:text-emerald-600 dark:hover:text-emerald-400"
                        dir="ltr"
                      >
                        {best.ip}
                      </button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground"
                        onClick={() => void handleCopyIp(best.ip)}
                        aria-label={t('results.ip.copy', { ip: best.ip })}
                      >
                        <Copy className="size-3" aria-hidden />
                      </Button>
                      {bestResult ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 gap-1 px-2 text-[11px] text-teal-700 dark:text-teal-400"
                          onClick={() => openXray(bestResult)}
                        >
                          <Zap className="size-3" aria-hidden />
                          Xray
                        </Button>
                      ) : null}
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 gap-1 px-2 text-[11px] text-teal-700 dark:text-teal-400"
                        onClick={() => setPortOpen(true)}
                        aria-label={t('port.title')}
                        disabled={!connected}
                      >
                        <Network className="size-3" aria-hidden />
                        {t('port.banner')}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className={cn(
                          'h-7 w-7 p-0',
                          favoriteIps.has(best.ip) ? 'text-amber-400' : 'text-muted-foreground',
                        )}
                        onClick={() => handleToggleFav(best.ip)}
                        aria-label={
                          favoriteIps.has(best.ip)
                            ? t('results.fav.remove', { ip: best.ip })
                            : t('results.fav.add', { ip: best.ip })
                        }
                      >
                        <Star
                          className={cn('size-3', favoriteIps.has(best.ip) && 'fill-amber-400')}
                          aria-hidden
                        />
                      </Button>
                    </div>
                    {/* stat chips */}
                    <div className="mt-1.5 flex flex-wrap items-center gap-1 text-[10px]">
                      {[
                        { label: t('results.col.latency'), value: formatLatency(bestResult?.latencyMs ?? 0) },
                        { label: t('results.col.loss'), value: `${((bestResult?.lossRate ?? 0) * 100).toFixed(1)}%` },
                        { label: t('results.col.download'), value: formatBytesPerSec(bestResult?.downloadSpeed ?? 0) },
                        ...(bestProbe?.tlsMs != null
                          ? [{ label: 'TLS', value: formatLatency(bestProbe.tlsMs) }]
                          : []),
                      ].map((c) => (
                        <span
                          key={c.label}
                          className="inline-flex items-center gap-1 rounded-md border border-border bg-background/60 px-1.5 py-0.5"
                        >
                          <span className="text-muted-foreground">{c.label}</span>
                          <span className="font-mono font-semibold" dir="ltr">
                            {c.value}
                          </span>
                        </span>
                      ))}
                    </div>
                    {/* why chips */}
                    {best.reasons.length > 0 ? (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {best.reasons.map((rsn, i) => {
                          const key = (
                            rsn.kind === 'grade'
                              ? `results.smart.reason.${rsn.grade}`
                              : `results.smart.reason.${rsn.kind}`
                          ) as DictKey
                          const val =
                            rsn.kind === 'tls' || rsn.kind === 'loss-low' || rsn.kind === 'speed' || rsn.kind === 'latency'
                              ? rsn.label
                              : undefined
                          return (
                            <span
                              key={i}
                              className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/[0.06] px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-300"
                            >
                              <Check className="size-2.5" aria-hidden />
                              {t(key)}
                              {val ? (
                                <span dir="ltr" className="font-mono">
                                  {val}
                                </span>
                              ) : null}
                            </span>
                          )
                        })}
                      </div>
                    ) : null}
                    {/* runner-ups */}
                    {runners.length > 0 ? (
                      <div className="mt-1.5 flex flex-wrap items-center gap-1 text-[10px] text-muted-foreground">
                        <span>{t('results.smart.runners')}:</span>
                        {runners.map((alt) => (
                          <button
                            key={alt.ip}
                            type="button"
                            onClick={() => void handleCopyIp(alt.ip)}
                            className="inline-flex items-center gap-1 rounded-md border border-border bg-background/60 px-1.5 py-0.5 font-mono transition-colors hover:border-emerald-500/40 hover:text-emerald-600 dark:hover:text-emerald-400"
                            aria-label={t('results.ip.copy', { ip: alt.ip })}
                          >
                            <span dir="ltr">{alt.ip}</span>
                            <span style={{ color: SCORE_BAND_HEX[scoreBand(alt.score)] }} dir="ltr">
                              {num(Math.round(alt.score))}
                            </span>
                          </button>
                        ))}
                      </div>
                    ) : null}
                  </div>
                </div>
              </div>
            )
          })()
        : null}

      {/* Empty state */}
      {ranked.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-14 text-center">
          <span className="relative flex size-16 items-center justify-center rounded-full border border-dashed border-border bg-background/40">
            <Radar className="size-7 text-muted-foreground" aria-hidden />
            {running ? (
              <span className="absolute inset-0 animate-ping rounded-full border border-emerald-500/30" />
            ) : null}
          </span>
          <div>
            <p className="text-sm font-semibold text-foreground">
              {running ? t('results.empty.wait.title') : t('results.empty.idle.title')}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {running
                ? t('results.empty.wait.sub')
                : t('results.empty.idle.sub')}
            </p>
          </div>
        </div>
      ) : (
        <>
          {/* Podium */}
          <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
            {top3.map((r, i) => (
              <div
                key={r.ip}
                className={cn(
                  'group/podium relative overflow-hidden rounded-xl border p-4 transition-all hover:-translate-y-0.5',
                  i === 0
                    ? 'border-amber-500/40 bg-gradient-to-br from-amber-500/10 via-transparent to-emerald-500/5 shadow-[0_0_24px_-6px_rgba(245,158,11,0.35)]'
                    : 'border-border bg-background/40 hover:border-emerald-500/25',
                )}
              >
                {/* top hairline glow */}
                <span
                  aria-hidden
                  className={cn(
                    'absolute inset-x-0 top-0 h-px bg-gradient-to-l from-transparent to-transparent opacity-70',
                    i === 0 ? 'via-amber-400/60' : 'via-emerald-400/40',
                  )}
                />
                {/* animated shine sweep (CSS keyframes, reduced-motion safe) */}
                <span
                  aria-hidden
                  className={cn(
                    'podium-shine pointer-events-none absolute inset-y-0 -left-24 w-24 bg-gradient-to-r from-transparent to-transparent',
                    i === 0 ? 'via-white/25' : 'via-emerald-200/10',
                  )}
                  style={{ animationDelay: `${i * 0.9}s` }}
 />
                {i === 0 ? (
                  <span
                    aria-hidden
                    className="absolute -top-8 -end-8 size-24 rounded-full bg-amber-500/10 blur-2xl"
                  />
                ) : null}
                <div className="flex items-center justify-between gap-2">
                  <span
                    className={cn(
                      'flex size-9 items-center justify-center rounded-full border',
                      MEDAL_STYLES[i],
                    )}
                  >
                    {i === 0 ? (
                      <Trophy className="size-4" aria-hidden />
                    ) : (
                      <Medal className="size-4" aria-hidden />
                    )}
                  </span>
                  <span
                    dir="ltr"
                    className="font-mono text-sm font-bold tracking-tight"
                  >
                    {r.ip}
                  </span>
                </div>
                <div className="mt-3 grid grid-cols-2 gap-x-2 gap-y-1.5 text-[11px]">
                  <span className="text-muted-foreground">{t('results.podium.latency')}</span>
                  <span className="text-end font-mono" dir="ltr">
                    {formatLatency(r.latencyMs)}
                  </span>
                  <span className="text-muted-foreground">{t('results.podium.total')}</span>
                  <span className="text-end font-mono font-semibold text-emerald-600 dark:text-emerald-400" dir="ltr">
                    {formatBytesPerSec(r.totalSpeed ?? 0)}
                  </span>
                  <span className="text-muted-foreground">{t('results.podium.loss')}</span>
                  <span className="text-end font-mono" dir="ltr">
                    {(r.lossRate * 100).toFixed(1)}%
                  </span>
                </div>
                {/* xray probe quick action */}
                <button
                  type="button"
                  onClick={() => openXray(r)}
                  aria-label={t('xray.podium.aria', { ip: r.ip })}
                  className="absolute end-3 bottom-3 inline-flex items-center gap-1 rounded-md border border-teal-500/30 bg-teal-500/5 px-1.5 py-1 text-[10px] font-semibold text-teal-600 opacity-0 transition-all hover:bg-teal-500/15 focus-visible:opacity-100 group-hover/podium:opacity-100 dark:text-teal-400"
                >
                  <Zap className="size-3" aria-hidden />
                  Xray
                </button>
              </div>
            ))}
          </div>

          {/* Charts: latency distribution + download/upload breakdown + scatter */}
          {results.length > 0 ? (
            <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
              <LatencyHistogram results={results} />
              <SpeedChart results={results} />
              {results.some((r) => (r.totalSpeed ?? 0) > 0) ? (
                <div className="md:col-span-2">
                  <ScatterChart results={results} />
                </div>
              ) : null}
            </div>
          ) : null}

          {/* Mobile card list (<sm) — replaces the wide table on touch screens */}
          <div className="mt-5 space-y-2 sm:hidden">
            {rows.slice(0, 30).map((r) => {
              const clean = r.lossRate < 0.25 && r.latencyMs < 300
              const g = geoMap[r.ip]
              return (
                <div
                  key={r.ip}
                  className={cn(
                    'rounded-lg border bg-background/40 p-3 transition-colors',
                    clean ? 'border-emerald-500/20' : 'border-border',
                  )}
                >
                  <div className="flex items-center gap-2">
                    {r.rank <= 3 ? (
                      <span
                        className={cn(
                          'inline-flex size-6 shrink-0 items-center justify-center rounded-full border text-[10px] font-bold',
                          MEDAL_STYLES[r.rank - 1],
                        )}
                        dir="ltr"
                      >
                        {num(r.rank)}
                      </span>
                    ) : (
                      <span className="w-6 shrink-0 text-center font-mono text-[10px] text-muted-foreground" dir="ltr">
                        {num(r.rank)}
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => void handleCopyIp(r.ip)}
                      title={t('results.ip.copy', { ip: r.ip })}
                      aria-label={t('results.ip.copy', { ip: r.ip })}
                      className="min-h-9 flex-1 text-start font-mono text-xs font-bold active:text-emerald-600 dark:active:text-emerald-400"
                      dir="ltr"
                    >
                      {r.ip}
                    </button>
                    {probeGrades[r.ip] ? (
                      <span
                        className={cn(
                          'inline-flex shrink-0 items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold',
                          GRADE_STYLES[probeGrades[r.ip].grade],
                        )}
                      >
                        {t(`xray.grade.${probeGrades[r.ip].grade}` as DictKey)}
                      </span>
                    ) : null}
                    {scoreMap[r.ip] ? (
                      <button
                        type="button"
                        onClick={() => openIpHistory(r.ip)}
                        className={cn(
                          'inline-flex shrink-0 cursor-pointer items-center rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-bold transition-transform hover:scale-110',
                          SCORE_BAND_STYLES[scoreBand(scoreMap[r.ip].score)],
                        )}
                        dir="ltr"
                        title={t('results.smart.history')}
                        aria-label={`${t('results.smart.col')} ${num(Math.round(scoreMap[r.ip].score))} — ${t('results.smart.history')}`}
                      >
                        {num(Math.round(scoreMap[r.ip].score))}
                      </button>
                    ) : null}
                    <button
                      type="button"
                      onClick={() => handleToggleFav(r.ip)}
                      aria-label={
                        favoriteIps.has(r.ip)
                          ? t('results.fav.remove', { ip: r.ip })
                          : t('results.fav.add', { ip: r.ip })
                      }
                      className={cn(
                        'inline-flex size-9 shrink-0 items-center justify-center rounded-md transition-colors',
                        favoriteIps.has(r.ip) ? 'text-amber-400' : 'text-muted-foreground/40',
                      )}
                    >
                      <Star
                        className={cn('size-4', favoriteIps.has(r.ip) && 'fill-amber-400')}
                        aria-hidden
                      />
                    </button>
                    <button
                      type="button"
                      onClick={() => openXray(r)}
                      disabled={!connected}
                      aria-label={t('xray.row.aria', { ip: r.ip })}
                      className="inline-flex size-9 shrink-0 items-center justify-center rounded-md border border-teal-500/25 text-teal-600/80 disabled:opacity-40 dark:text-teal-400/80"
                    >
                      <Zap className="size-4" aria-hidden />
                    </button>
                  </div>
                  <div className="mt-2 grid grid-cols-4 gap-1.5 rounded-md bg-background/60 p-2 text-center">
                    <div>
                      <p className="text-[9px] text-muted-foreground">{t('results.col.latency')}</p>
                      <p className="font-mono text-[11px] font-semibold" dir="ltr">
                        {formatLatency(r.latencyMs)}
                      </p>
                    </div>
                    <div>
                      <p className="text-[9px] text-muted-foreground">{t('results.col.loss')}</p>
                      <p className="font-mono text-[11px] font-semibold" dir="ltr">
                        {(r.lossRate * 100).toFixed(1)}%
                      </p>
                    </div>
                    <div>
                      <p className="text-[9px] text-muted-foreground">{t('results.col.download')}</p>
                      <p className="font-mono text-[11px]" dir="ltr">
                        {formatBytesPerSec(r.downloadSpeed ?? 0)}
                      </p>
                    </div>
                    <div>
                      <p className="text-[9px] text-muted-foreground">{t('results.col.total')}</p>
                      <p
                        className="font-mono text-[11px] font-bold text-emerald-600 dark:text-emerald-400"
                        dir="ltr"
                      >
                        {formatBytesPerSec(r.totalSpeed ?? 0)}
                      </p>
                    </div>
                  </div>
                  {(g || clean) && (
                    <div className="mt-1.5 flex items-center justify-between px-0.5 text-[10px] text-muted-foreground">
                      <span className="inline-flex items-center gap-1">
                        {g ? (
                          <>
                            <span aria-hidden>{countryFlag(g.countryCode)}</span>
                            <span dir="ltr">{[g.city, g.country].filter(Boolean).join(geoSeparator) || g.countryCode}</span>
                          </>
                        ) : null}
                      </span>
                      {clean ? (
                        <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                          {t('results.badge.clean')}
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 text-zinc-500">
                          {t('results.badge.borderline')}
                        </Badge>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
            {rows.length > 30 ? (
              <p className="pt-1 text-center text-[10px] text-muted-foreground">
                {t('results.card.more')}
              </p>
            ) : null}
          </div>

          {/* Full table (sm+) */}
          <div className="scrollbar-thin mt-5 hidden max-h-96 overflow-y-auto rounded-lg border sm:block">
            <Table>
              <TableHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-8" />
                  {COLUMNS.map((col) => (
                    <Fragment key={col.key}>
                      <TableHead className="text-start">
                        <button
                          type="button"
                          onClick={() => toggleSort(col.key)}
                          className={cn(
                            'inline-flex min-h-6 items-center gap-1 text-xs font-semibold transition-colors hover:text-foreground',
                            sort.key === col.key && 'text-emerald-600 dark:text-emerald-400'
                          )}
                          aria-label={t('results.sort.aria', { col: t(col.labelKey) })}
                        >
                          {t(col.labelKey)}
                          {sort.key === col.key ? (
                            sort.dir === 'asc' ? (
                              <ChevronUp className="size-3" aria-hidden />
                            ) : (
                              <ChevronDown className="size-3" aria-hidden />
                            )
                          ) : (
                            <ArrowUpDown
                              className="size-3 opacity-40"
                              aria-hidden
                            />
                          )}
                        </button>
                      </TableHead>
                      {col.key === 'rank' ? (
                        <TableHead className="text-start">
                          <button
                            type="button"
                            onClick={() => toggleSort('score')}
                            className={cn(
                              'inline-flex min-h-6 items-center gap-1 text-xs font-semibold transition-colors hover:text-foreground',
                              sort.key === 'score' && 'text-emerald-600 dark:text-emerald-400'
                            )}
                            aria-label={t('results.sort.aria', { col: t('results.smart.col') })}
                          >
                            <Sparkles className="size-3 text-emerald-500" aria-hidden />
                            {t('results.smart.col')}
                            {sort.key === 'score' ? (
                              sort.dir === 'asc' ? (
                                <ChevronUp className="size-3" aria-hidden />
                              ) : (
                                <ChevronDown className="size-3" aria-hidden />
                              )
                            ) : null}
                          </button>
                        </TableHead>
                      ) : null}
                    </Fragment>
                  ))}
                  <TableHead className="text-start">
                    <span className="text-xs font-semibold">{t('results.col.geo')}</span>
                  </TableHead>
                  <TableHead className="text-start">
                    <span className="text-xs font-semibold">{t('results.col.status')}</span>
                  </TableHead>
                  <TableHead className="text-start">
                    <span className="text-xs font-semibold">Xray</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => {
                  const clean = r.lossRate < 0.25 && r.latencyMs < 300
                  return (
                    <TableRow
                      key={r.ip}
                      className={cn(
                        'group/row bg-gradient-to-l from-transparent via-transparent to-transparent transition-all hover:from-emerald-500/[0.03] hover:via-emerald-500/[0.05] hover:to-emerald-500/[0.03]',
                      )}
                    >
                      <TableCell>
                        <button
                          type="button"
                          onClick={() => handleToggleFav(r.ip)}
                          aria-label={
                            favoriteIps.has(r.ip)
                              ? t('results.fav.remove', { ip: r.ip })
                              : t('results.fav.add', { ip: r.ip })
                          }
                          className={cn(
                            'inline-flex size-6 items-center justify-center rounded transition-all hover:scale-110',
                            favoriteIps.has(r.ip)
                              ? 'text-amber-400'
                              : 'text-muted-foreground/30 hover:text-amber-400',
                            toggleFav.isPending && 'opacity-50'
                          )}
                        >
                          <Star
                            className={cn('size-3.5', favoriteIps.has(r.ip) && 'fill-amber-400')}
                            aria-hidden
                          />
                        </button>
                      </TableCell>
                      <TableCell className="font-mono text-xs tabular-nums">
                        {r.rank <= 3 ? (
                          <span
                            className={cn(
                              'inline-flex size-5 items-center justify-center rounded-full border text-[10px] font-bold',
                              MEDAL_STYLES[r.rank - 1],
                            )}
                            dir="ltr"
                          >
                            {num(r.rank)}
                          </span>
                        ) : (
                          num(r.rank)
                        )}
                      </TableCell>
                      {(() => {
                        const s = scoreMap[r.ip]
                        if (!s) return null
                        const band = scoreBand(s.score)
                        return (
                          <TableCell>
                            <TooltipProvider delayDuration={150}>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <button
                                    type="button"
                                    onClick={() => openIpHistory(r.ip)}
                                    className={cn(
                                      'inline-flex cursor-pointer items-center rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-bold transition-transform hover:scale-110',
                                      SCORE_BAND_STYLES[band],
                                    )}
                                    dir="ltr"
                                    aria-label={`${t('results.smart.col')} ${num(Math.round(s.score))} — ${t('results.smart.history')}`}
                                  >
                                    {num(Math.round(s.score))}
                                  </button>
                                </TooltipTrigger>
                                <TooltipContent dir={dir} className="text-xs">
                                  <p className="font-mono" dir="ltr">
                                    {t('results.smart.bd.grade')} {s.breakdown.grade} · TLS {s.breakdown.tls} ·{' '}
                                    {t('results.smart.bd.loss')} {s.breakdown.loss} · {t('results.smart.bd.speed')}{' '}
                                    {s.breakdown.speed} · {t('results.smart.bd.stab')} {s.breakdown.stab}
                                  </p>
                                  {!s.probed ? (
                                    <p className="mt-1 text-[10px] text-muted-foreground">
                                      {t('results.smart.probe.nudge')}
                                    </p>
                                  ) : null}
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          </TableCell>
                        )
                      })()}
                      <TableCell dir="ltr" className="p-0 text-left">
                        <button
                          type="button"
                          onClick={() => void handleCopyIp(r.ip)}
                          title={t('results.ip.copy', { ip: r.ip })}
                          aria-label={t('results.ip.copy', { ip: r.ip })}
                          className="w-full px-2 py-2.5 text-left font-mono text-xs font-medium transition-colors hover:text-emerald-600 hover:underline dark:hover:text-emerald-400"
                        >
                          {r.ip}
                        </button>
                      </TableCell>
                      <TableCell
                        dir="ltr"
                        className="text-left font-mono text-xs tabular-nums"
                      >
                        {formatLatency(r.latencyMs)}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={cn('px-1.5 py-0 text-[10px]', lossBadgeClass(r.lossRate))}
                        >
                          <span dir="ltr">
                            {(r.lossRate * 100).toFixed(1)}%
                          </span>
                        </Badge>
                      </TableCell>
                      <TableCell
                        dir="ltr"
                        className="text-left font-mono text-xs tabular-nums"
                      >
                        {formatBytesPerSec(r.downloadSpeed ?? 0)}
                      </TableCell>
                      <TableCell
                        dir="ltr"
                        className="text-left font-mono text-xs tabular-nums"
                      >
                        {formatBytesPerSec(r.uploadSpeed ?? 0)}
                      </TableCell>
                      <TableCell
                        dir="ltr"
                        className="text-left font-mono text-xs font-semibold tabular-nums text-emerald-600 dark:text-emerald-400"
                      >
                        {formatBytesPerSec(r.totalSpeed ?? 0)}
                      </TableCell>
                      <TableCell>
                        {(() => {
                          const g = geoMap[r.ip]
                          if (!g) {
                            return (
                              <span
                                className="text-[10px] text-muted-foreground/50"
                                title={t('results.geo.empty.title')}
                              >
                                —
                              </span>
                            )
                          }
                          const label = [g.city, g.country].filter(Boolean).join(geoSeparator)
                          return (
                            <TooltipProvider delayDuration={150}>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <span
                                    className="inline-flex cursor-default items-center gap-1 text-xs"
                                    title={label}
                                  >
                                    <span aria-hidden>{countryFlag(g.countryCode)}</span>
                                    <span className="font-mono text-[10px] text-muted-foreground" dir="ltr">
                                      {g.countryCode || '??'}
                                    </span>
                                  </span>
                                </TooltipTrigger>
                                <TooltipContent dir={dir} className="max-w-64 text-xs">
                                  <p className="font-semibold">{label || g.ip}</p>
                                  {g.isp ? <p className="mt-0.5 text-muted-foreground">{g.isp}</p> : null}
                                  {g.asn ? <p className="font-mono text-[10px] text-muted-foreground" dir="ltr">{g.asn}</p> : null}
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          )
                        })()}
                      </TableCell>
                      <TableCell>
                        {clean ? (
                          <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                            {t('results.badge.clean')}
                          </Badge>
                        ) : (
                          <Badge
                            variant="outline"
                            className="border-zinc-500/30 bg-zinc-500/10 text-zinc-500"
                          >
                            {t('results.badge.borderline')}
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          {probeGrades[r.ip] ? (
                            <TooltipProvider delayDuration={150}>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <span
                                    className={cn(
                                      'inline-flex cursor-default items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold',
                                      GRADE_STYLES[probeGrades[r.ip].grade],
                                    )}
                                  >
                                    {t(`xray.grade.${probeGrades[r.ip].grade}` as DictKey)}
                                  </span>
                                </TooltipTrigger>
                                <TooltipContent dir={dir} className="text-xs">
                                  <p className="font-mono" dir="ltr">
                                    TCP {probeGrades[r.ip].tcpMs ?? '—'}ms · TLS{' '}
                                    {probeGrades[r.ip].tlsMs ?? '—'}ms
                                  </p>
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          ) : null}
                          <TooltipProvider delayDuration={200}>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <button
                                  type="button"
                                  onClick={() => openXray(r)}
                                  disabled={!connected}
                                  aria-label={t('xray.row.aria', { ip: r.ip })}
                                  className="inline-flex size-6 items-center justify-center rounded-md border border-teal-500/25 text-teal-600/70 transition-all hover:scale-110 hover:border-teal-500/50 hover:bg-teal-500/10 hover:text-teal-600 disabled:opacity-40 dark:text-teal-400/70 dark:hover:text-teal-300"
                                >
                                  <Zap className="size-3" aria-hidden />
                                </button>
                              </TooltipTrigger>
                              <TooltipContent dir={dir} className="text-xs">
                                <p>{t('xray.row.tip')}</p>
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        </>
      )}

      <ShareDialog
        open={shareOpen}
        onOpenChange={setShareOpen}
        results={results}
        meta={shareMeta}
        savedId={savedId}
      />
      <XrayDialog
        open={xrayOpen}
        onOpenChange={setXrayOpen}
        target={xrayTarget}
        port={(xrayPortOverride ?? port) || 443}
        preset={preset}
        connected={connected}
        onProbe={onProbe}
      />
      <PortFinderDialog
        open={portOpen}
        onOpenChange={setPortOpen}
        defaultIp={best?.ip}
        ipOptions={bestScores.slice(0, 5).map((s) => s.ip)}
        host={probeHost}
        basePort={port || 443}
        connected={connected}
        onProbe={onProbe}
        onUsePort={handleUsePort}
      />
      <ScoreTuningDialog
        open={tuneOpen}
        onOpenChange={setTuneOpen}
        inputs={ranked}
        probes={probeGrades}
        favorites={favoriteIps}
      />
      <ProbeHistoryDialog open={phOpen} onOpenChange={setPhOpen} />
      <IpHistoryDialog
        open={iphOpen}
        onOpenChange={setIphOpen}
        ip={iphIp}
        geo={iphIp ? geoMap[iphIp] : undefined}
      />
    </div>
  )
}
