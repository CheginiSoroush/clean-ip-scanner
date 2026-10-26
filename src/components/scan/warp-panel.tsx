'use client'

/**
 * WarpPanel — standalone Cloudflare WARP endpoint scanner (hunt v6.2 / P3).
 *
 * Fully independent of the scan pipeline and of the Google hunter (engine-side
 * `warp:*` events): the engine registers a best-effort WARP identity, crafts a
 * real WireGuard handshake initiation packet and rotates it across the canonical
 * WARP ranges × known UDP ports. Any response datagram (92-byte type-2 handshake
 * or 64-byte type-3 cookie) marks the endpoint live.
 *
 * Legacy degrade: engines without the `warp:*` handlers never answer the
 * `warp:state` snapshot request, so `warpState` stays null — after a grace
 * deadline (longer than the hook's 8s ack timeout) the panel switches to an
 * honest "engine does not support WARP" notice with disabled controls.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import {
  ChevronDown,
  Copy,
  Download,
  Globe,
  History,
  Loader2,
  Play,
  Plane,
  Plus,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Signal,
  Square,
  Target,
  Timer,
  Trash2,
  X,
  Zap,
} from 'lucide-react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Progress } from '@/components/ui/progress'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { csvBool, csvFileStamp, csvNum, downloadCsv } from '@/lib/csv'
import type { WarpHistoryRun, WarpScanSettings, WarpScanState } from '@/lib/scan-protocol'
import { WARP_CUSTOM_RANGES_CAP, WARP_RANGE_RE, WARP_RANGES, WARP_UDP_PORTS } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'

interface WarpPanelProps {
  connected: boolean
  warpState: WarpScanState | null
  onStart: (settings?: Partial<WarpScanSettings>) => Promise<WarpScanState | null>
  onStop: () => Promise<WarpScanState | null>
  onReset: () => Promise<WarpScanState | null>
}

/** default port rotation (2408 is the WARP client default) */
const DEFAULT_PORTS: number[] = [2408, 500, 1701, 4500]
const TARGET_DEFAULT = 20
const TARGET_MIN = 1
const TARGET_MAX = 200
/** grace deadline before an always-null warpState is treated as a legacy engine (hook ack timeout = 8s) */
const LEGACY_GRACE_MS = 9500
/** v7.4 — history rows shown before «نمایش بیشتر» grows the window (+10 per click) */
const HISTORY_SHOW = 5

/** v6.6 — canonical WARP_RANGES.label → DictKey (unknown labels fall back to the raw string) */
const RANGE_LABEL_KEY: Record<string, DictKey> = {
  engage: 'warp.ranges.label.engage',
  'warp-2': 'warp.ranges.label.warp-2',
  'warp-3': 'warp.ranges.label.warp-3',
  'warp-a': 'warp.ranges.label.warp-a',
  'warp-b': 'warp.ranges.label.warp-b',
  'warp-c': 'warp.ranges.label.warp-c',
  'warp-d': 'warp.ranges.label.warp-d',
}
/** the full canonical cidr set — a selection equal to this (and no customs) sends NO ranges field */
const CANONICAL_CIDRS: string[] = WARP_RANGES.map((r) => r.cidr)

/** Persian keyboard digits → ASCII so the target input accepts both */
function toEnDigits(v: string): string {
  return v.replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 1776))
}

/** parsed + clamped target (1..200, default 20 on empty/NaN) */
function clampTarget(text: string): number {
  const n = Number(toEnDigits(text.trim()))
  if (!Number.isFinite(n)) return TARGET_DEFAULT
  return Math.min(TARGET_MAX, Math.max(TARGET_MIN, Math.round(n)))
}

/** elapsed as m:ss (or plain seconds under a minute) — same style as the hunt panel */
function fmtElapsed(ms: number): string {
  const s = Math.floor(ms / 1000)
  const m = Math.floor(s / 60)
  return m > 0 ? `${m}:${String(s % 60).padStart(2, '0')}` : `${s}s`
}

/** compact stat box for the stats row */
function WarpStat({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div
      className={cn(
        'min-w-[72px] flex-1 rounded-lg border bg-background/40 px-2 py-1.5 text-center',
        accent && 'border-emerald-500/30 bg-emerald-500/5',
      )}
    >
      <p
        className={cn(
          'font-mono text-sm font-bold leading-tight tabular-nums',
          accent && 'text-emerald-600 dark:text-emerald-400',
        )}
        dir="ltr"
      >
        {value}
      </p>
      <p className="mt-0.5 text-[10px] text-muted-foreground">{label}</p>
    </div>
  )
}

export function WarpPanel({ connected, warpState, onStart, onStop, onReset }: WarpPanelProps) {
  const { t, num, dir, dateLocale, lang } = useI18n()
  const [targetText, setTargetText] = useState(String(TARGET_DEFAULT))
  const [ports, setPorts] = useState<Set<number>>(() => new Set(DEFAULT_PORTS))
  const [busy, setBusy] = useState(false)
  // v6.6 — custom ranges editor: selection starts as the FULL canonical set (legacy-identical)
  const [rangesOpen, setRangesOpen] = useState(false)
  const [rangeSelection, setRangeSelection] = useState<Set<string>>(() => new Set(CANONICAL_CIDRS))
  const [customRanges, setCustomRanges] = useState<string[]>([])
  const [rangeInput, setRangeInput] = useState('')
  const [rangeInvalid, setRangeInvalid] = useState(false)
  // legacy-engine detection — a state that NEVER arrives after the grace deadline
  const [pastGrace, setPastGrace] = useState(false)
  // finish toasts fire exactly once per run
  const lastFinishRef = useRef<number>(0)
  // v7.4 — WARP scan history (hunt-history parity): GET /api/warp-history, newest-first
  const [histRuns, setHistRuns] = useState<WarpHistoryRun[]>([])
  const runsStampRef = useRef<string>('')

  // realtime payloads are never trusted structurally — a partial state degrades to the empty view
  const s = useMemo(() => {
    if (!warpState) return null
    if (!Array.isArray(warpState.found) || !Array.isArray(warpState.recent)) return null
    return warpState
  }, [warpState])

  const running = !!s?.running

  // legacy degrade — only once the engine had a fair chance to answer warp:state
  useEffect(() => {
    if (!connected || s) {
      setPastGrace(false)
      return
    }
    const id = window.setTimeout(() => setPastGrace(true), LEGACY_GRACE_MS)
    return () => window.clearTimeout(id)
  }, [connected, s])
  const isLegacy = connected && pastGrace && !s

  // toast on finish (target reached / stopped / error)
  useEffect(() => {
    if (!s || !s.finished || s.running) return
    const stamp = s.startedAt ?? 0
    if (lastFinishRef.current === stamp) return
    lastFinishRef.current = stamp
    if (s.error) {
      toast.error(t('warp.done.fail', { e: s.error }))
      return
    }
    if (s.stopped) toast.info(t('warp.done.stopped', { n: num(s.alive) }))
    else toast.success(t('warp.done.ok', { n: num(s.alive) }))
  }, [s, t, num])

  const copyText = useCallback(
    async (text: string, okKey: DictKey, vars?: Record<string, string | number>) => {
      try {
        await navigator.clipboard.writeText(text)
        toast.success(t(okKey, vars))
      } catch {
        toast.error(t('configs.toast.copy.fail'))
      }
    },
    [t],
  )

  const copyAll = useCallback(() => {
    if (!s || s.found.length === 0) return
    void copyText(
      s.found.map((e) => e.endpoint).join('\n'),
      'warp.found.copyall.ok',
      { n: num(s.found.length) },
    )
  }, [s, copyText, num])

  // ----- v7.4 history — best-effort fetch (never blocks the panel on it) -----
  const fetchWarpRuns = useCallback(async () => {
    try {
      const res = await fetch('/api/warp-history', { cache: 'no-store' })
      if (!res.ok) return
      const data = (await res.json()) as { runs?: WarpHistoryRun[] }
      setHistRuns(Array.isArray(data.runs) ? data.runs : [])
    } catch {
      // history is best-effort — never block the panel on it
    }
  }, [])

  // initial load + refetch once per finished run (same dedupe stamp recipe as the hunt panel)
  useEffect(() => {
    void fetchWarpRuns()
  }, [fetchWarpRuns])

  useEffect(() => {
    if (!s?.finished || s.running) return
    const stamp = `${s.startedAt ?? 0}-${s.tested}`
    if (runsStampRef.current === stamp) return
    runsStampRef.current = stamp
    void fetchWarpRuns()
  }, [s, fetchWarpRuns])

  /** v7.4 — absolute date+time of a history run, locale-aware (fa → Persian calendar + digits) */
  const fmtRunDate = useCallback(
    (ts: number) =>
      new Intl.DateTimeFormat(dateLocale, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(
        new Date(ts),
      ),
    [dateLocale],
  )

  /**
   * v7.4 — humanized duration for history rows + the detail dialog
   * (time.s/m/h units, zero parts dropped, fa joins parts with «و").
   */
  const fmtDur = useCallback(
    (ms: number): string => {
      const total = Math.max(0, Math.floor(ms / 1000))
      if (total < 60) return t('time.s', { n: num(total) })
      const h = Math.floor(total / 3600)
      const m = Math.floor((total % 3600) / 60)
      const sec = total % 60
      const joiner = lang === 'fa' ? ' و ' : ' '
      if (total < 3600) {
        return sec === 0
          ? t('time.m', { n: num(m) })
          : `${t('time.m', { n: num(m) })}${joiner}${t('time.s', { n: num(sec) })}`
      }
      return m === 0 ? t('time.h', { n: num(h) }) : `${t('time.h', { n: num(h) })}${joiner}${t('time.m', { n: num(m) })}`
    },
    [t, num, lang],
  )

  const togglePort = useCallback((p: number) => {
    setPorts((prev) => {
      const next = new Set(prev)
      if (next.has(p)) next.delete(p)
      else next.add(p)
      return next
    })
  }, [])

  // ---------- v6.6 — custom ranges editor ----------

  /** canonical toggle — same Set semantics as the port chips, capped at the engine's honest cap */
  const toggleRange = useCallback((cidr: string) => {
    setRangeSelection((prev) => {
      const next = new Set(prev)
      if (next.has(cidr)) next.delete(cidr)
      else {
        if (next.size >= WARP_CUSTOM_RANGES_CAP) {
          toast.warning(t('warp.ranges.cap', { n: WARP_CUSTOM_RANGES_CAP }))
          return prev
        }
        next.add(cidr)
      }
      return next
    })
  }, [t])

  /** validate + add a user-supplied /24 (Persian digits tolerated, strict WARP_RANGE_RE) */
  const addRange = useCallback(() => {
    const cidr = toEnDigits(rangeInput).trim()
    if (cidr === '') return
    if (!WARP_RANGE_RE.test(cidr)) {
      setRangeInvalid(true)
      toast.error(t('warp.ranges.invalid'))
      return
    }
    if (rangeSelection.has(cidr)) {
      toast.info(t('warp.ranges.dup'))
      return
    }
    if (rangeSelection.size >= WARP_CUSTOM_RANGES_CAP) {
      toast.warning(t('warp.ranges.cap', { n: WARP_CUSTOM_RANGES_CAP }))
      return
    }
    setRangeSelection((prev) => new Set(prev).add(cidr))
    setCustomRanges((prev) => [...prev, cidr])
    setRangeInput('')
    setRangeInvalid(false)
  }, [rangeInput, rangeSelection, t])

  /** remove a user-added custom entry from both the selection and the custom list */
  const removeCustom = useCallback((cidr: string) => {
    setRangeSelection((prev) => {
      const next = new Set(prev)
      next.delete(cidr)
      return next
    })
    setCustomRanges((prev) => prev.filter((c) => c !== cidr))
    setRangeInvalid(false)
  }, [])

  /**
   * v6.6 payload — send `ranges` ONLY when the selection differs from the full
   * canonical set (canonical-minus-some IS different) or custom ranges exist;
   * otherwise omit the field so the wire payload stays byte-identical to v6.2-6.5.
   * Sorted with localeCompare for deterministic engine-side sampling.
   */
  const rangesPayload = useMemo(() => {
    const canonical = new Set(CANONICAL_CIDRS)
    const differs = rangeSelection.size !== canonical.size || [...rangeSelection].some((c) => !canonical.has(c))
    if (!differs && customRanges.length === 0) return undefined
    return [...rangeSelection].sort((a, b) => a.localeCompare(b))
  }, [rangeSelection, customRanges])

  const handleStart = useCallback(async () => {
    if (!connected) {
      toast.error(t('warp.offline'))
      return
    }
    if (ports.size === 0) return
    if (rangeSelection.size === 0) return
    setBusy(true)
    try {
      const state = await onStart({
        target: clampTarget(targetText),
        // keep the canonical WARP_UDP_PORTS rotation order
        ports: WARP_UDP_PORTS.filter((p) => ports.has(p)),
        // v6.6 — omitted entirely when the selection is the untouched canonical set (legacy-safe)
        ...(rangesPayload ? { ranges: rangesPayload } : {}),
      })
      if (!state) toast.error(t('warp.offline'))
      else if (state.running) lastFinishRef.current = 0
    } finally {
      setBusy(false)
    }
  }, [connected, onStart, ports, targetText, t, rangeSelection, rangesPayload])

  const handleStop = useCallback(async () => {
    setBusy(true)
    try {
      await onStop()
    } finally {
      setBusy(false)
    }
  }, [onStop])

  const handleReset = useCallback(async () => {
    setBusy(true)
    try {
      lastFinishRef.current = 0
      await onReset()
    } finally {
      setBusy(false)
    }
  }, [onReset])

  // ---------- v7.4 — history management (search + sort + delete/clear + detail dialog) ----------
  /** id of the run whose delete-confirmation dialog is open (null = closed) — ONE shared dialog */
  const [pendingDelId, setPendingDelId] = useState<string | null>(null)
  const [delBusy, setDelBusy] = useState(false)
  const [confirmClear, setConfirmClear] = useState(false)
  const [clearBusy, setClearBusy] = useState(false)
  /** visible rows grow via «نمایش بیشتر» (reset when the search query or sort changes — in the setters, no effect flash) */
  const [histShow, setHistShow] = useState<number>(HISTORY_SHOW)
  /** the run behind the open delete dialog — feeds the date line in the description */
  const pendingDelRun = useMemo(
    () => (pendingDelId ? histRuns.find((r) => r.id === pendingDelId) ?? null : null),
    [pendingDelId, histRuns],
  )
  /** client-side search over found[].endpoint / found[].ip (case-insensitive substring; ≤30 runs ⇒ no debounce) */
  const [histQuery, setHistQuery] = useState('')
  /** 'date' = store order (already newest-first) · 'alive'/'tested' = metric desc, tie → startedAt desc */
  const [histSort, setHistSort] = useState<'date' | 'alive' | 'tested'>('date')
  /**
   * v7.5 — time-range filter (shared hist.range.* keys with the hunt history):
   * '24h'/'7d' keep runs whose startedAt is inside the window, 'all' = everything.
   * Date.now() inside the memo is fine — recomputing on state change is enough.
   */
  const [histRange, setHistRange] = useState<'all' | '24h' | '7d'>('all')
  /** the run behind the open detail dialog (null = closed) */
  const [detailRun, setDetailRun] = useState<WarpHistoryRun | null>(null)

  /**
   * v7.5 — range pass, FIRST in the pipeline (range → search → sort — pagination
   * slices downstream). A range-only empty list reuses the honest
   * «نتیجه‌ای برای «…» یافت نشد» state with the range label as the query.
   */
  const histRanged = useMemo(() => {
    const cutoff = histRange === '24h' ? Date.now() - 86_400_000 : histRange === '7d' ? Date.now() - 7 * 86_400_000 : 0
    return cutoff === 0 ? histRuns : histRuns.filter((r) => r.startedAt >= cutoff)
  }, [histRuns, histRange])

  /** search pass — empty input = pass-through */
  const histFiltered = useMemo(() => {
    const q = histQuery.trim().toLowerCase()
    if (q === '') return histRanged
    return histRanged.filter((r) =>
      r.found.some((e) => e.endpoint.toLowerCase().includes(q) || e.ip.toLowerCase().includes(q)),
    )
  }, [histRanged, histQuery])

  /** sort pass — pagination (histShow + «نمایش بیشتر») slices downstream of this */
  const histSorted = useMemo(() => {
    if (histSort === 'date') return histFiltered
    return [...histFiltered].sort((a, b) => {
      const d = histSort === 'alive' ? b.alive - a.alive : b.tested - a.tested
      return d !== 0 ? d : b.startedAt - a.startedAt
    })
  }, [histFiltered, histSort])

  const histVisible = useMemo(() => histSorted.slice(0, histShow), [histSorted, histShow])

  /** copies the full live-endpoint list of the run shown in the detail dialog (same join as the live copy-all) */
  const copyDetailEndpoints = useCallback(() => {
    if (!detailRun || detailRun.found.length === 0) return
    void copyText(
      detailRun.found.map((e) => e.endpoint).join('\n'),
      'warp.hist.detail.copyall.ok',
      { n: num(detailRun.found.length) },
    )
  }, [detailRun, copyText, num])

  /** DELETE /api/warp-history?id=… → optimistic local removal (no refetch needed) */
  const deleteRun = useCallback(async () => {
    const id = pendingDelId
    if (!id || delBusy) return
    setDelBusy(true)
    try {
      const res = await fetch(`/api/warp-history?id=${encodeURIComponent(id)}`, { method: 'DELETE' })
      const data = (res.ok ? await res.json().catch(() => null) : null) as { ok?: boolean } | null
      if (res.ok && data?.ok) {
        setHistRuns((prev) => prev.filter((r) => r.id !== id))
        setPendingDelId(null)
        toast.success(t('warp.hist.del.ok'))
      } else {
        toast.error(t('warp.hist.del.fail'))
      }
    } catch {
      toast.error(t('warp.hist.del.fail'))
    } finally {
      setDelBusy(false)
    }
  }, [pendingDelId, delBusy, t])

  /** DELETE /api/warp-history (no id) → clears the whole history file */
  const clearAllRuns = useCallback(async () => {
    if (clearBusy) return
    setClearBusy(true)
    try {
      const res = await fetch('/api/warp-history', { method: 'DELETE' })
      const data = (res.ok ? await res.json().catch(() => null) : null) as { ok?: boolean } | null
      if (res.ok && data?.ok) {
        setHistRuns([])
        setConfirmClear(false)
        toast.success(t('warp.hist.clear.ok'))
      } else {
        toast.error(t('warp.hist.clear.fail'))
      }
    } catch {
      toast.error(t('warp.hist.clear.fail'))
    } finally {
      setClearBusy(false)
    }
  }, [clearBusy, t])

  /**
   * v7.5 — history CSV export (same conventions as the hunt journal/history
   * exporters: BOM + blob plumbing via lib/csv, honest empty cells — optional
   * flags via csvBool, eps via csvNum — and no quoting: multi-value fields are
   * ';'-joined since ports/CIDRs never contain commas). Column order:
   * at_iso,at_ms,stopped,exhausted,custom,registered,tested,alive,planned,
   * alive_rate_pct,eps,ports,ranges,found_count. at_* is the run's startedAt
   * (the SAME timestamp the time-range chips filter on); alive_rate_pct is one
   * decimal, no % sign.
   */
  const exportHistoryCsv = useCallback(() => {
    if (histRuns.length === 0) return
    const rows: string[] = [
      'at_iso,at_ms,stopped,exhausted,custom,registered,tested,alive,planned,alive_rate_pct,eps,ports,ranges,found_count',
    ]
    for (const r of histRuns) {
      const rate = r.tested > 0 ? Math.round((r.alive / r.tested) * 1000) / 10 : null
      rows.push(
        [
          new Date(r.startedAt).toISOString(),
          String(r.startedAt),
          csvBool(r.stopped),
          csvBool(r.exhausted),
          csvBool(r.custom),
          csvBool(r.registered),
          String(r.tested),
          String(r.alive),
          String(r.planned),
          rate === null ? '' : String(rate),
          csvNum(r.eps),
          r.ports.join(';'),
          r.ranges.join(';'),
          String(r.found.length),
        ].join(','),
      )
    }
    downloadCsv(`warp-history-${csvFileStamp()}.csv`, rows)
    toast.success(t('warp.hist.export.ok', { n: num(histRuns.length) }))
  }, [histRuns, num, t])

  const target = clampTarget(targetText)
  const alivePct = s && s.target > 0 ? Math.min(100, Math.round((s.alive / s.target) * 100)) : 0
  const controlsDisabled = busy || !connected || isLegacy

  return (
    <div
      className="rounded-xl border border-amber-500/20 bg-card/60 p-4 backdrop-blur sm:p-6"
      id="warp-scanner"
    >
      {/* ---------- header ---------- */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="flex size-8 items-center justify-center rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-400">
            <Plane className="size-4" aria-hidden />
          </span>
          <h2 className="text-base font-bold">{t('warp.title')}</h2>
          {running ? (
            <Badge className="border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300">
              <Loader2 className="size-3 animate-spin" aria-hidden />
              {t('warp.running')}
            </Badge>
          ) : null}
          {/* registered badge — presence-gated: legacy engines without the field render nothing */}
          {s && s.registered !== undefined ? (
            s.registered ? (
              <Badge
                variant="outline"
                className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
              >
                <ShieldCheck className="size-2.5" aria-hidden />
                {t('warp.reg.ok')}
              </Badge>
            ) : (
              <Badge
                variant="outline"
                className="border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400"
              >
                <ShieldAlert className="size-2.5" aria-hidden />
                {t('warp.reg.none')}
              </Badge>
            )
          ) : null}
        </div>

        {/* start / stop / reset */}
        <div className="flex flex-wrap items-center gap-2">
          {running ? (
            <Button
              variant="outline"
              size="sm"
              className="h-9 gap-1.5 border-red-500/30 text-red-600 hover:bg-red-500/10 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
              onClick={() => void handleStop()}
              disabled={busy}
            >
              <Square className="size-3.5" aria-hidden />
              <span className="hidden sm:inline">{t('warp.stop')}</span>
            </Button>
          ) : (
            <div className="flex items-center gap-2">
              {s && (s.tested > 0 || s.found.length > 0) ? (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-9 gap-1.5 text-muted-foreground hover:text-foreground"
                  onClick={() => void handleReset()}
                  disabled={busy}
                >
                  <RotateCcw className="size-3.5" aria-hidden />
                  <span className="hidden sm:inline">{t('warp.reset')}</span>
                </Button>
              ) : null}
              <Button
                size="sm"
                className="h-9 gap-1.5 bg-amber-600 text-white hover:bg-amber-700 dark:bg-amber-500 dark:hover:bg-amber-600"
                onClick={() => void handleStart()}
                disabled={controlsDisabled || running || ports.size === 0 || rangeSelection.size === 0}
              >
                {busy ? (
                  <Loader2 className="size-3.5 animate-spin" aria-hidden />
                ) : (
                  <Play className="size-3.5" aria-hidden />
                )}
                <span className="hidden sm:inline">{t('warp.start')}</span>
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* ---------- description ---------- */}
      <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{t('warp.desc')}</p>

      {/* ---------- legacy engine degrade ---------- */}
      {isLegacy ? (
        <div
          className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2"
          role="status"
        >
          <p className="flex items-center gap-1.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300">
            <ShieldAlert className="size-3.5 shrink-0" aria-hidden />
            {t('warp.legacy')}
          </p>
        </div>
      ) : null}

      {/* ---------- settings row (target + port chips) ---------- */}
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2">
        <label className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
          <Target className="size-3.5 text-amber-500" aria-hidden />
          {t('warp.target', { n: num(target) })}
          <Input
            value={targetText}
            onChange={(e) => setTargetText(toEnDigits(e.target.value).replace(/[^\d]/g, '').slice(0, 3))}
            onBlur={() => setTargetText(String(clampTarget(targetText)))}
            type="number"
            min={TARGET_MIN}
            max={TARGET_MAX}
            dir="ltr"
            aria-label={t('warp.target.aria')}
            className="h-8 w-20 font-mono text-xs"
          />
        </label>

        <div
          className="flex flex-wrap items-center gap-1.5"
          role="group"
          aria-label={t('warp.ports')}
        >
          <TooltipProvider delayDuration={120}>
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="flex cursor-default items-center gap-1 text-[11px] font-semibold text-muted-foreground">
                  <Zap className="size-3.5 text-amber-500" aria-hidden />
                  {t('warp.ports')}
                </span>
              </TooltipTrigger>
              <TooltipContent dir={dir} className="text-[10px]">
                {t('warp.ports.tip')}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
          {WARP_UDP_PORTS.map((p) => (
            <button
              key={p}
              type="button"
              aria-pressed={ports.has(p)}
              disabled={running || isLegacy}
              onClick={() => togglePort(p)}
              className={cn(
                'flex min-h-11 items-center gap-1 rounded-md border px-2 py-1 font-mono text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60 disabled:cursor-not-allowed disabled:opacity-50',
                ports.has(p)
                  ? 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                  : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
              )}
            >
              <span dir="ltr">{num(p)}</span>
              {p === 2408 ? (
                <span className="font-sans text-[9px] font-normal opacity-80">
                  {t('warp.ports.default')}
                </span>
              ) : null}
            </button>
          ))}
        </div>
      </div>

      {/* ---------- v6.6 — custom /24 ranges (collapsible, same recipe as the hunt «هدف سفارشی منابع») ---------- */}
      <div className="mt-3 rounded-lg border border-zinc-500/30 bg-zinc-500/5">
        <button
          type="button"
          aria-expanded={rangesOpen}
          onClick={() => setRangesOpen((v) => !v)}
          className="flex min-h-11 w-full items-center justify-between gap-2 px-3 py-2 text-start transition-colors hover:bg-zinc-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-500/60"
        >
          <span className="flex items-center gap-1.5 text-[11px] font-semibold text-zinc-700 dark:text-zinc-300">
            <Globe className="size-3.5 text-zinc-500" aria-hidden />
            {t('warp.ov.title')}
            <span
              className="rounded-md border border-zinc-500/40 bg-background/60 px-1 py-0 font-mono text-[10px] text-zinc-600 dark:text-zinc-300"
              dir="ltr"
            >
              {num(rangeSelection.size)}
            </span>
          </span>
          <ChevronDown
            className={cn('size-3.5 shrink-0 text-zinc-500 transition-transform', rangesOpen && 'rotate-180')}
            aria-hidden
          />
        </button>
        {rangesOpen ? (
          <div className="space-y-2.5 border-t border-zinc-500/20 px-3 py-3">
            <p className="text-[10px] leading-relaxed text-muted-foreground">{t('warp.ov.hint')}</p>

            {/* canonical + custom chips — scrollable when the list grows */}
            <div
              className="scrollbar-thin flex max-h-40 flex-wrap items-center gap-1.5 overflow-y-auto"
              role="group"
              aria-label={t('warp.ranges.title')}
            >
              <span className="text-[10px] font-semibold text-muted-foreground">{t('warp.ranges.title')}:</span>
              {WARP_RANGES.map((r) => {
                const selected = rangeSelection.has(r.cidr)
                const labelKey = RANGE_LABEL_KEY[r.label]
                return (
                  <button
                    key={r.cidr}
                    type="button"
                    role="switch"
                    aria-checked={selected}
                    disabled={running || isLegacy}
                    onClick={() => toggleRange(r.cidr)}
                    className={cn(
                      'flex min-h-11 items-center gap-1 rounded-md border px-2 py-1 font-mono text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60 disabled:cursor-not-allowed disabled:opacity-50',
                      selected
                        ? 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                        : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                    )}
                  >
                    <span dir="ltr">{r.cidr}</span>
                    <span className="font-sans text-[9px] font-normal opacity-80">
                      {labelKey ? t(labelKey) : r.label}
                    </span>
                  </button>
                )
              })}
              {customRanges.map((cidr) => (
                <span
                  key={cidr}
                  className="flex min-h-11 items-center gap-1 rounded-md border border-teal-500/40 bg-teal-500/10 px-2 py-1 font-mono text-[11px] font-medium text-teal-700 dark:text-teal-300"
                  dir="ltr"
                >
                  {cidr}
                  <span className="font-sans text-[9px] font-normal opacity-80">{t('warp.ranges.custom')}</span>
                  <button
                    type="button"
                    onClick={() => removeCustom(cidr)}
                    aria-label={t('warp.ranges.rm.aria', { cidr })}
                    disabled={running || isLegacy}
                    className="flex size-7 items-center justify-center rounded-md text-teal-700/70 transition-colors hover:bg-teal-500/15 hover:text-teal-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 disabled:cursor-not-allowed disabled:opacity-50 dark:text-teal-300/70 dark:hover:text-teal-200"
                  >
                    <X className="size-3.5" aria-hidden />
                  </button>
                </span>
              ))}
            </div>

            {/* add row — wraps on mobile */}
            <div className="flex flex-wrap items-center gap-2">
              <Input
                value={rangeInput}
                onChange={(e) => {
                  setRangeInput(e.target.value)
                  setRangeInvalid(false)
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    addRange()
                  }
                }}
                dir="ltr"
                spellCheck={false}
                placeholder={t('warp.ranges.placeholder')}
                aria-label={`${t('warp.ov.title')} — ${t('warp.ranges.add')}`}
                disabled={running || isLegacy}
                className="h-11 w-full font-mono text-xs sm:h-9 sm:w-56"
              />
              <Button
                variant="outline"
                size="sm"
                className="h-11 gap-1.5 border-amber-500/30 px-3 text-[11px] text-amber-700 hover:bg-amber-500/10 hover:text-amber-800 dark:text-amber-400 sm:h-9"
                onClick={addRange}
                disabled={running || isLegacy}
              >
                <Plus className="size-3.5" aria-hidden />
                {t('warp.ranges.add')}
              </Button>
            </div>
            {rangeInvalid ? (
              <p role="alert" className="text-[10px] font-medium text-red-600 dark:text-red-400">
                {t('warp.ranges.invalid')}
              </p>
            ) : null}
            <p className="text-[10px] leading-relaxed text-muted-foreground">{t('warp.ranges.tip')}</p>
          </div>
        ) : null}
      </div>
      {rangeSelection.size === 0 ? (
        <p role="alert" className="mt-1.5 text-[10px] font-medium text-red-600 dark:text-red-400">
          {t('warp.ranges.empty')}
        </p>
      ) : null}

      {/* ---------- target progress ---------- */}
      {s ? (
        <div className="mt-4">
          <div className="mb-1.5 flex items-center justify-between text-xs">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <Target className="size-3.5 text-amber-500" aria-hidden />
              {num(s.alive)} / {num(s.target)}
            </span>
            <span className="flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground" dir="ltr">
              <Timer className="size-3.5" aria-hidden />
              {fmtElapsed(s.elapsedMs)}
              <span aria-hidden>·</span>
              <Signal className="size-3.5" aria-hidden />
              {num(s.epsPerSecond ?? 0)}/s
            </span>
          </div>
          <Progress
            value={alivePct}
            className="h-2"
            aria-label={`${num(s.alive)} / ${num(s.target)}`}
          />
        </div>
      ) : null}

      {/* ---------- stats row + live range/port scope chips ---------- */}
      {s ? (
        <div className="mt-3 rounded-lg border bg-background/40 p-3">
          <div className="flex flex-wrap gap-1.5 sm:gap-2">
            <WarpStat label={t('warp.stat.tested')} value={num(s.tested)} />
            <WarpStat label={t('warp.stat.alive')} value={num(s.alive)} accent />
            <WarpStat label={t('warp.stat.planned')} value={num(s.planned)} />
            <WarpStat label={t('warp.stat.eps')} value={`${num(s.epsPerSecond ?? 0)}/s`} />
          </div>
          {(s.ports.length > 0 || s.ranges.length > 0) && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] font-semibold text-muted-foreground">
                {t('warp.scope.ports')}:
              </span>
              {s.ports.map((p) => (
                <span
                  key={p}
                  className="rounded-md border border-amber-500/30 bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-amber-700 dark:text-amber-300"
                  dir="ltr"
                >
                  {num(p)}
                </span>
              ))}
              <span className="ms-1 text-[10px] font-semibold text-muted-foreground">
                {t('warp.scope.ranges')}:
              </span>
              {s.ranges.map((r) => (
                <span
                  key={r}
                  className="rounded-md border border-zinc-500/30 bg-zinc-500/5 px-1.5 py-0.5 font-mono text-[10px] text-zinc-600 dark:text-zinc-300"
                  dir="ltr"
                >
                  {r}
                </span>
              ))}
            </div>
          )}
        </div>
      ) : null}

      {/* ---------- recent probe ticker (live only) ---------- */}
      {running && s && s.recent.length > 0 ? (
        <div className="mt-3" aria-live="off">
          <p className="mb-1.5 text-[11px] font-semibold text-muted-foreground">
            {t('warp.recent.title')}
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            {s.recent.slice(-12).map((e, i) => (
              <span
                key={`${e.endpoint}-${i}`}
                className="inline-flex cursor-default items-center gap-1 rounded-md border border-zinc-500/30 bg-zinc-500/5 px-1.5 py-0.5 font-mono text-[10px] text-zinc-500 dark:text-zinc-400"
                dir="ltr"
                title={e.endpoint}
              >
                {e.endpoint}
                {e.rttMs != null ? <span className="opacity-70">{e.rttMs}ms</span> : <span aria-hidden>×</span>}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {/* ---------- found endpoints (the payload) ---------- */}
      <div className="mt-4">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <p className="text-[11px] font-semibold text-muted-foreground">
            {t('warp.found.title')}
            {s && s.found.length > 0 ? (
              <span className="ms-1.5 font-mono" dir="ltr">
                ({num(s.found.length)})
              </span>
            ) : null}
          </p>
          {s && s.found.length > 0 ? (
            <Button
              variant="outline"
              size="sm"
              className="h-7 gap-1 border-amber-500/30 px-2 text-[11px] text-amber-700 hover:bg-amber-500/10 dark:text-amber-300"
              onClick={copyAll}
            >
              <Copy className="size-3" aria-hidden />
              {t('warp.found.copyall')}
            </Button>
          ) : null}
        </div>

        {!s || s.found.length === 0 ? (
          <div className="flex h-12 items-center justify-center rounded-lg border border-dashed bg-background/40 text-[11px] text-muted-foreground">
            {t('warp.found.empty')}
          </div>
        ) : (
          <ul
            className="scrollbar-thin max-h-96 space-y-1.5 overflow-y-auto"
            aria-label={t('warp.found.title')}
          >
            {s.found.map((e) => (
              <li
                key={e.endpoint}
                className="flex items-center justify-between gap-2 rounded-lg border bg-background/50 px-2.5 py-1.5"
              >
                <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                  <span className="truncate font-mono text-xs" dir="ltr">
                    {e.endpoint}
                  </span>
                  {e.rttMs != null ? (
                    <Badge
                      variant="outline"
                      className={cn(
                        'shrink-0 px-1 text-[9px]',
                        e.rttMs <= 100
                          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                          : 'border-zinc-500/40 bg-zinc-500/10 text-zinc-500 dark:text-zinc-400',
                      )}
                      dir="ltr"
                    >
                      {e.rttMs}ms
                    </Badge>
                  ) : null}
                  {e.response ? (
                    <Badge
                      variant="outline"
                      className={cn(
                        'shrink-0 px-1 text-[9px]',
                        e.response === 'handshake'
                          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                          : 'border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400',
                      )}
                    >
                      {t(e.response === 'handshake' ? 'warp.resp.handshake' : 'warp.resp.cookie')}
                    </Badge>
                  ) : null}
                  {e.range ? (
                    <Badge
                      variant="outline"
                      className="shrink-0 border-zinc-500/40 bg-zinc-500/10 px-1 font-mono text-[8px] text-zinc-600 dark:text-zinc-400"
                      dir="ltr"
                    >
                      {e.range}
                    </Badge>
                  ) : null}
                </div>
                <button
                  type="button"
                  onClick={() => void copyText(e.endpoint, 'warp.row.copy.ok', { ep: e.endpoint })}
                  aria-label={t('warp.row.copy.aria', { ep: e.endpoint })}
                  className="inline-flex size-6 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-amber-500/10 hover:text-amber-600 dark:hover:text-amber-400"
                >
                  <Copy className="size-3" aria-hidden />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* ---------- v7.4 — WARP scan history (hunt-history parity) ---------- */}
      <div className="mt-4">
        <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
          <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <History className="size-3" aria-hidden />
            {t('warp.hist.title')}
            {histRuns.length > 0 ? (
              <span
                className="rounded-md border border-zinc-500/40 bg-background/60 px-1 py-0 font-mono text-[10px] leading-4 text-zinc-600 dark:text-zinc-300"
                dir="ltr"
              >
                {num(histRuns.length)}
              </span>
            ) : null}
          </p>
          {/* v7.5 — history CSV export + clear-all, one right-side cluster (honest: both disabled on empty history) */}
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={exportHistoryCsv}
              disabled={histRuns.length === 0}
              aria-label={t('warp.hist.export')}
              title={t('warp.hist.export')}
              className="inline-flex size-8 shrink-0 items-center justify-center self-center rounded-md text-muted-foreground transition-colors hover:bg-emerald-500/10 hover:text-emerald-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/60 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent dark:hover:text-emerald-400 sm:size-7"
            >
              <Download className="size-3.5" aria-hidden />
            </button>
            <button
              type="button"
              onClick={() => setConfirmClear(true)}
              disabled={histRuns.length === 0}
              aria-label={t('warp.hist.clear')}
              className="inline-flex h-11 items-center gap-1 rounded-md border border-red-500/40 px-2.5 text-[11px] font-medium text-red-600 transition-colors hover:bg-red-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500/60 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent dark:text-red-400 dark:hover:bg-red-500/10 sm:h-9"
            >
              <Trash2 className="size-3" aria-hidden />
              {t('warp.hist.clear')}
            </button>
          </div>
        </div>

        {/* client-side search over found[].endpoint / found[].ip (mono ltr island; ≤30 runs ⇒ no debounce) */}
        {histRuns.length > 0 ? (
          <div className="relative mb-1.5">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <input
              type="search"
              value={histQuery}
              onChange={(e) => {
                setHistQuery(e.target.value)
                setHistShow(HISTORY_SHOW)
              }}
              placeholder={t('warp.hist.search')}
              aria-label={t('warp.hist.search')}
              spellCheck={false}
              dir="ltr"
              className="h-11 w-full rounded-md border border-border bg-background/40 px-8 font-mono text-[12px] text-left text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60 [&::-webkit-search-cancel-button]:hidden sm:h-9"
            />
            {histQuery !== '' ? (
              <button
                type="button"
                onClick={() => setHistQuery('')}
                aria-label={t('warp.hist.search.clear')}
                className="absolute right-1.5 top-1/2 inline-flex size-6 -translate-y-1/2 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-red-500/10 hover:text-red-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60 dark:hover:text-red-400"
              >
                <X className="size-3.5" aria-hidden />
              </button>
            ) : null}
          </div>
        ) : null}

        {/* sort chips + v7.5 time-range chips (two segmented groups in one wrapping row;
           the range group reuses the shared «فیلتر تاریخچه» wording — hist.range.* is a
           cross-panel v7.5 feature, so no dedicated group-label key was added) */}
        {histRuns.length > 0 ? (
          <div className="mb-1.5 flex flex-wrap items-center gap-1.5">
            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={t('warp.hist.sort')}>
              {(['date', 'alive', 'tested'] as const).map((sid) => (
                <button
                  key={sid}
                  type="button"
                  aria-pressed={histSort === sid}
                  onClick={() => {
                    setHistSort(sid)
                    setHistShow(HISTORY_SHOW)
                  }}
                  className={cn(
                    'flex h-11 items-center rounded-md border px-2.5 py-1 text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60 sm:h-9',
                    histSort === sid
                      ? 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                      : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                  )}
                >
                  {t(`warp.hist.sort.${sid}`)}
                </button>
              ))}
            </div>
            {/* v7.5 — time-range chips (same amber chip recipe, in-setter histShow reset) */}
            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={t('hunt.hist.filter')}>
              <span aria-hidden className="mx-0.5 h-5 w-px shrink-0 self-center bg-border" />
              {(['24h', '7d', 'all'] as const).map((rid) => (
                <button
                  key={rid}
                  type="button"
                  aria-pressed={histRange === rid}
                  onClick={() => {
                    setHistRange(rid)
                    setHistShow(HISTORY_SHOW)
                  }}
                  className={cn(
                    'flex h-11 items-center rounded-md border px-2.5 py-1 text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60 sm:h-9',
                    histRange === rid
                      ? 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                      : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                  )}
                >
                  {t(`hist.range.${rid}`)}
                </button>
              ))}
            </div>
          </div>
        ) : null}

        {histRuns.length === 0 ? (
          <div className="flex h-12 items-center justify-center rounded-lg border border-dashed bg-background/40 text-[11px] text-muted-foreground">
            {t('warp.hist.empty')}
          </div>
        ) : histRanged.length === 0 ? (
          // v7.5 — the time range emptied the list (store still has runs): reuse the
          // honest search-empty state with the range label as the «query» — no new key
          <div className="flex h-12 items-center justify-center rounded-lg border border-dashed bg-background/40 px-3 text-center text-[11px] text-muted-foreground">
            {t('warp.hist.empty.search', { q: t(`hist.range.${histRange}`) })}
          </div>
        ) : histSorted.length === 0 ? (
          <div className="flex h-12 items-center justify-center rounded-lg border border-dashed bg-background/40 px-3 text-center text-[11px] text-muted-foreground">
            {t('warp.hist.empty.search', { q: histQuery.trim() })}
          </div>
        ) : (
          <ul className="space-y-1.5" aria-label={t('warp.hist.title')}>
            {histVisible.map((run) => {
              const rate = run.tested > 0 ? (run.alive / run.tested) * 100 : null
              return (
                <li
                  key={run.id}
                  className="flex items-center justify-between gap-2 rounded-lg border bg-background/50 px-2.5 py-1.5"
                >
                  {/* the info area is a real button opening the per-run detail dialog (action buttons stay siblings) */}
                  <button
                    type="button"
                    onClick={() => setDetailRun(run)}
                    aria-label={t('warp.hist.detail')}
                    className="flex min-w-0 flex-1 cursor-pointer flex-col items-start gap-1 rounded-md text-start transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60"
                  >
                    <span className="flex w-full flex-wrap items-center gap-1.5">
                      <span className="flex size-5 shrink-0 items-center justify-center rounded bg-amber-500/10 text-amber-600 dark:text-amber-400">
                        <History className="size-3" aria-hidden />
                      </span>
                      <span className="whitespace-nowrap text-[11px] text-muted-foreground">
                        {fmtRunDate(run.finishedAt)}
                      </span>
                      <span className="whitespace-nowrap text-[10px] text-muted-foreground">
                        · {fmtDur(run.finishedAt - run.startedAt)}
                      </span>
                      <WarpRunBadges run={run} />
                    </span>
                    <span className="flex w-full flex-wrap items-center gap-1.5">
                      <span
                        className={cn(
                          'whitespace-nowrap text-[10px] font-semibold',
                          run.alive > 0
                            ? 'text-emerald-600 dark:text-emerald-400'
                            : 'text-muted-foreground',
                        )}
                      >
                        {t('warp.hist.rows.alive', { a: num(run.alive), t: num(run.tested) })}
                        {rate !== null
                          ? ` · ${num(rate, { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%`
                          : ''}
                      </span>
                      {run.ports.length > 0 ? (
                        <span className="min-w-0 truncate font-mono text-[10px] text-muted-foreground" dir="ltr">
                          {run.ports.map((p) => num(p)).join('/')}
                        </span>
                      ) : null}
                      {run.ranges.length > 0 ? (
                        <span className="shrink-0 rounded-md border border-zinc-500/30 bg-zinc-500/5 px-1 py-0.5 text-[9px] text-zinc-600 dark:text-zinc-300">
                          {t('warp.hist.rows.ranges', { n: num(run.ranges.length) })}
                        </span>
                      ) : null}
                    </span>
                  </button>
                  <div className="flex shrink-0 items-center gap-1.5">
                    {/* per-row delete (opens the shared confirm dialog) */}
                    <TooltipProvider delayDuration={120}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => setPendingDelId(run.id)}
                            aria-label={t('warp.hist.del')}
                            className="inline-flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-red-500/10 hover:text-red-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500/60 dark:hover:text-red-400"
                          >
                            <Trash2 className="size-3" aria-hidden />
                          </button>
                        </TooltipTrigger>
                        <TooltipContent dir={dir} className="text-[10px]">
                          {t('warp.hist.del')}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </div>
                </li>
              )
            })}
          </ul>
        )}
        {/* honest «show more» (the store keeps up to 30 runs; HISTORY_SHOW caps the rows) */}
        {histSorted.length > histShow ? (
          <button
            type="button"
            onClick={() => setHistShow((n) => n + 10)}
            aria-label={t('warp.hist.more', { n: num(histSorted.length - histShow) })}
            className="mt-1.5 flex h-11 w-full items-center justify-center gap-1.5 rounded-md border border-dashed text-[11px] text-muted-foreground transition-colors hover:bg-background/70 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60 sm:h-9"
          >
            <ChevronDown className="size-3" aria-hidden />
            {t('warp.hist.more', { n: num(histSorted.length - histShow) })}
          </button>
        ) : null}
      </div>

      {/* ---------- honest environment note ---------- */}
      <p className="mt-3 flex items-start gap-1.5 text-[10px] leading-relaxed text-amber-600 dark:text-amber-400">
        <ShieldAlert className="mt-0.5 size-3 shrink-0" aria-hidden />
        {t('warp.note.udp')}
      </p>

      {/* ---------- v7.4 — per-run delete confirmation (ONE shared dialog driven by pendingDelId) ---------- */}
      <AlertDialog
        open={pendingDelId !== null}
        onOpenChange={(o) => {
          if (!o && !delBusy) setPendingDelId(null)
        }}
      >
        <AlertDialogContent dir={dir}>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('warp.hist.del.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('warp.hist.del.desc')}
              {pendingDelRun ? (
                <span className="mt-1 block text-[10px] text-muted-foreground">
                  {fmtRunDate(pendingDelRun.finishedAt)}
                </span>
              ) : null}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={delBusy}>{t('warp.hist.del.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault() // stay open while the DELETE is in flight — closed on success
                void deleteRun()
              }}
              disabled={delBusy}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              {delBusy ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : null}
              {t('warp.hist.del.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ---------- v7.4 — clear-all history confirmation ---------- */}
      <AlertDialog
        open={confirmClear}
        onOpenChange={(o) => {
          if (!o && !clearBusy) setConfirmClear(false)
        }}
      >
        <AlertDialogContent dir={dir}>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('warp.hist.clear.title')}</AlertDialogTitle>
            <AlertDialogDescription>{t('warp.hist.clear.desc', { n: num(histRuns.length) })}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={clearBusy}>{t('warp.hist.clear.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault() // stay open while the DELETE is in flight — closed on success
                void clearAllRuns()
              }}
              disabled={clearBusy}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              {clearBusy ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : null}
              {t('warp.hist.clear.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ---------- v7.4 — per-run detail dialog (badges + meta + ranges + live endpoints) ---------- */}
      <Dialog
        open={detailRun !== null}
        onOpenChange={(o) => {
          if (!o) setDetailRun(null)
        }}
      >
        <DialogContent dir={dir} className="max-h-[85dvh] max-w-lg overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <History className="size-4 text-amber-500" aria-hidden />
              {t('warp.hist.detail')}
            </DialogTitle>
            <DialogDescription>{detailRun ? fmtRunDate(detailRun.finishedAt) : null}</DialogDescription>
          </DialogHeader>
          {detailRun ? <WarpDetailBody run={detailRun} fmtDur={fmtDur} onCopyAll={copyDetailEndpoints} /> : null}
        </DialogContent>
      </Dialog>
    </div>
  )
}

/** v7.4 — the conditional badge set shared by history rows + the detail dialog (renders nothing when nothing applies) */
function WarpRunBadges({ run }: { run: WarpHistoryRun }) {
  const { t } = useI18n()
  return (
    <>
      {run.custom ? (
        <Badge
          variant="outline"
          className="shrink-0 border-teal-500/40 bg-teal-500/10 px-1 text-[8px] text-teal-600 dark:text-teal-300"
        >
          {t('warp.hist.badge.custom')}
        </Badge>
      ) : null}
      {run.registered ? (
        <Badge
          variant="outline"
          className="shrink-0 gap-0.5 border-emerald-500/40 bg-emerald-500/10 px-1 text-[8px] text-emerald-600 dark:text-emerald-400"
        >
          <ShieldCheck className="size-2" aria-hidden />
          {t('warp.hist.badge.registered')}
        </Badge>
      ) : null}
      {run.stopped ? (
        <Badge
          variant="outline"
          className="shrink-0 gap-0.5 border-amber-500/40 bg-amber-500/10 px-1 text-[8px] text-amber-700 dark:text-amber-300"
        >
          <Square className="size-2" aria-hidden />
          {t('warp.hist.badge.stopped')}
        </Badge>
      ) : null}
      {run.exhausted ? (
        <Badge
          variant="outline"
          className="shrink-0 border-zinc-500/40 bg-zinc-500/10 px-1 text-[8px] text-zinc-600 dark:text-zinc-300"
        >
          {t('warp.hist.badge.exhausted')}
        </Badge>
      ) : null}
      {run.error ? (
        <Badge
          variant="outline"
          className="shrink-0 gap-0.5 border-red-500/40 bg-red-500/10 px-1 text-[8px] text-red-600 dark:text-red-400"
        >
          <ShieldAlert className="size-2" aria-hidden />
          {t('warp.hist.badge.error')}
        </Badge>
      ) : null}
    </>
  )
}

/**
 * v7.4 — one label/value cell of the detail-dialog meta grid (mono ltr by
 * default; `mono={false}` renders plain RTL text for fa-only values like
 * «ثبت‌شده»).
 */
function WarpMetaCell({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="shrink-0 text-[10px] text-muted-foreground">{label}</span>
      <span
        className={cn(
          'min-w-0 truncate text-[10px] leading-5 tabular-nums',
          mono ? 'font-mono text-foreground' : 'text-foreground',
        )}
        dir={mono ? 'ltr' : undefined}
      >
        {value}
      </span>
    </div>
  )
}

/**
 * v7.4 — body of the per-run detail dialog. Duration/copy helpers arrive
 * as props so the panel keeps ONE implementation of each; everything else
 * (meta grid, ranges chips, endpoint rows) derives from the run itself.
 * (The run date renders once in the parent's DialogDescription.)
 */
function WarpDetailBody({
  run,
  fmtDur,
  onCopyAll,
}: {
  run: WarpHistoryRun
  fmtDur: (ms: number) => string
  onCopyAll: () => void
}) {
  const { t, num } = useI18n()
  return (
    <div className="space-y-3">
      {/* badges row — custom / registered / stopped / exhausted / error + target marker */}
      <div className="flex flex-wrap items-center gap-1.5">
        <WarpRunBadges run={run} />
        <span className="ms-auto font-mono text-[10px] text-muted-foreground" dir="ltr">
          {run.stopped ? '■' : '🎯'} ×{num(run.target)}
        </span>
      </div>

      {/* error line (engine-side failure, honest red) */}
      {run.error ? (
        <p className="text-[10px] font-semibold text-red-600 dark:text-red-400" role="alert">
          {run.error}
        </p>
      ) : null}

      {/* meta grid — duration / target / universe / speed / ports / identity */}
      <div className="grid grid-cols-1 gap-x-3 gap-y-1 rounded-lg border bg-background/40 p-2 sm:grid-cols-2">
        <WarpMetaCell label={t('warp.hist.detail.duration')} value={fmtDur(run.finishedAt - run.startedAt)} />
        <WarpMetaCell label={t('warp.hist.detail.target')} value={num(run.target)} />
        <WarpMetaCell label={t('warp.hist.detail.planned')} value={num(run.planned)} />
        {typeof run.eps === 'number' ? (
          <WarpMetaCell label={t('warp.hist.detail.eps')} value={`${num(run.eps)}/s`} />
        ) : null}
        <WarpMetaCell
          label={t('warp.hist.detail.ports')}
          value={run.ports.length > 0 ? run.ports.map((p) => num(p)).join('/') : '—'}
        />
        <WarpMetaCell
          label={t('warp.hist.detail.identity')}
          value={run.registered ? t('warp.hist.badge.registered') : t('warp.hist.detail.reg.none')}
          mono={false}
        />
      </div>

      {/* ranges — count + the actual cidrs as small mono chips */}
      {run.ranges.length > 0 ? (
        <div>
          <p className="text-[10px] font-semibold text-muted-foreground">
            {t('warp.hist.detail.ranges')}
            <span className="ms-1.5 font-mono" dir="ltr">
              ({num(run.ranges.length)})
            </span>
          </p>
          <div className="mt-1 flex flex-wrap gap-1">
            {run.ranges.map((r) => (
              <span
                key={r}
                className="rounded border border-zinc-500/30 bg-zinc-500/5 px-1.5 py-0.5 font-mono text-[10px] text-zinc-600 dark:text-zinc-300"
                dir="ltr"
              >
                {r}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {/* live endpoints — count chip + copy-all, then a scrollable list mirroring the live results rows */}
      <div>
        <div className="flex items-center justify-between gap-2">
          <p className="text-[10px] font-semibold text-muted-foreground">{t('warp.hist.detail.found')}</p>
          {run.found.length > 0 ? (
            <div className="flex items-center gap-1.5">
              <Badge variant="outline" className="shrink-0 px-1 font-mono text-[9px]" dir="ltr">
                {num(run.found.length)}
              </Badge>
              <button
                type="button"
                onClick={onCopyAll}
                aria-label={t('warp.hist.detail.copyall')}
                className="inline-flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-emerald-500/10 hover:text-emerald-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/60 dark:hover:text-emerald-400"
              >
                <Copy className="size-3" aria-hidden />
              </button>
            </div>
          ) : null}
        </div>
        {run.found.length === 0 ? (
          <div className="mt-1 flex h-10 items-center justify-center rounded-md border border-dashed bg-background/40 px-2 text-center text-[10px] text-muted-foreground">
            {t('warp.hist.detail.found.empty')}
          </div>
        ) : (
          <ul className="scrollbar-thin mt-1 max-h-64 space-y-1 overflow-y-auto pe-1">
            {run.found.map((e) => (
              <li
                key={e.endpoint}
                className="flex items-center justify-between gap-2 rounded-md border bg-background/50 px-2 py-1"
              >
                <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-foreground" dir="ltr">
                  {e.endpoint}
                </span>
                <span className="flex shrink-0 items-center gap-1.5">
                  {typeof e.rttMs === 'number' ? (
                    <span className="whitespace-nowrap font-mono text-[10px] tabular-nums text-muted-foreground">
                      {t('warp.hist.detail.rtt', { n: num(e.rttMs) })}
                    </span>
                  ) : null}
                  {e.response ? (
                    <Badge
                      variant="outline"
                      className={cn(
                        'shrink-0 px-1 text-[8px]',
                        e.response === 'handshake'
                          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                          : 'border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400',
                      )}
                    >
                      {t(e.response === 'handshake' ? 'warp.resp.handshake' : 'warp.resp.cookie')}
                    </Badge>
                  ) : null}
                  {typeof e.attempts === 'number' && e.attempts > 1 ? (
                    <Badge
                      variant="outline"
                      className="shrink-0 border-zinc-500/40 bg-zinc-500/10 px-1 text-[8px] text-zinc-600 dark:text-zinc-300"
                    >
                      {t('warp.hist.detail.attempts', { n: num(e.attempts) })}
                    </Badge>
                  ) : null}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
