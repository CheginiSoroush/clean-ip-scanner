'use client'

/**
 * GoogleHunterPanel — fully standalone "Google IP hunter" section.
 *
 * Independent of the scan pipeline on purpose (engine-side `google-hunt:*`):
 * it does NOT read scan results, probe grades or any other panel state.
 *
 * Funnel-v3 core (engine-side):
 *   stage A  cheap raw TCP connect → kills dead candidates for free
 *   stage B  TLS (Google SNI) + GET /generate_204 → alive-only verdicts
 *   stage C  `verify` extra confirmation passes → flaky IPs never listed
 * plus RECON — the sampler reverse-engineers Google's own published
 * infrastructure live (DNS SPF netblocks via DoH + gstatic goog.json/cloud.json)
 * and rDNS-fingerprints /24 blocks (PTR *.1e100.net = Google user-facing edge),
 * an adaptive ε-greedy sampler that learns productive blocks (persisted across
 * engine restarts) and a /api/hunt history.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import { formatDistanceToNow } from 'date-fns'
import { faIR, enUS } from 'date-fns/locale'
import { buildSchedulerJournalCsvRows, csvBool, csvFileStamp, csvNum, downloadCsv } from '@/lib/csv'
import {
  Activity,
  AlertCircle,
  Antenna,
  BadgeCheck,
  Building2,
  CalendarClock,
  ChevronLeft,
  ChevronRight,
  Chrome,
  Copy,
  Cpu,
  Crosshair,
  ChevronDown,
  Check,
  CheckCircle2,
  Download,
  Droplets,
  Filter,
  Gauge,
  GitCompareArrows,
  Globe,
  History,
  Layers,
  ListChecks,
  Loader2,
  MapPin,
  Play,
  Radar,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  ShieldCheck,
  ShieldX,
  Signal,
  Square,
  Target,
  Timer,
  TimerOff,
  Trash2,
  Wand2,
  Waves,
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
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Progress } from '@/components/ui/progress'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'
import type {
  GoogleHuntCandidate,
  GoogleHuntHistoryRun,
  GoogleHuntRecon,
  GoogleHuntSettings,
  GoogleHuntState,
  HuntProviderId,
  HuntProviderSelection,
  HuntProviderStats,
  HuntScheduleFireSettings,
  HuntScheduleJournalEntry,
  HuntScheduleState,
  HuntTargetOverride,
} from '@/lib/scan-protocol'
import {
  HUNT_FRAGMENT_PRESETS,
  HUNT_RECON_RANGES_CAP,
  HUNT_SCHEDULE_JOURNAL_CAP,
  HUNT_SELECTED_MAX_CIDRS,
  HUNT_SNI_PRESETS,
} from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import { DICT, type DictKey } from '@/lib/i18n'

interface GoogleHunterPanelProps {
  connected: boolean
  huntState: GoogleHuntState | null
  /** live recon intelligence from the engine (Google SPF + goog.json + cloud.json + PTR fingerprints) */
  recon: GoogleHuntRecon | null
  /** v7.0 — live engine-side hunt scheduler state (honest disabled default before the first sync) */
  schedState: HuntScheduleState
  onStart: (settings?: Partial<GoogleHuntSettings>) => Promise<GoogleHuntState | null>
  onStop: () => Promise<GoogleHuntState | null>
  onReset: () => Promise<GoogleHuntState | null>
  onRefreshRecon: () => Promise<GoogleHuntRecon | null>
  /** v7.0 — enable/disable the engine-side hunt scheduler; resolves with the fresh state (null = failed/offline) */
  onSetSchedule: (
    enabled: boolean,
    intervalMinutes: number,
    settings: Partial<GoogleHuntSettings> | null,
  ) => Promise<HuntScheduleState | null>
}

const TARGETS = [10, 25, 50] as const
const VERIFY_LEVELS = [0, 1, 2] as const
const RECENT_SHOW = 10
const HISTORY_SHOW = 5

/** v7.0 — hunt scheduler interval presets in minutes (all within the engine's 5..1440 clamp) */
const HUNT_SCHED_INTERVALS = [15, 30, 60, 120, 360, 1440] as const

/** v7.0 — one aggregated row of the per-ISP latency profile (latency = tlsMs, fallback tcpMs) */
interface IspLatencyRow {
  /** raw engine label, e.g. 'AS197207' */
  label: string
  /** healthy candidates carrying this label */
  count: number
  /** avg/min/max latency ms — null when NO labelled entry carried a latency sample */
  avg: number | null
  min: number | null
  max: number | null
}

/** v7.0 — countdown breakdown for the scheduler card (always ≤ 24h) */
function fmtCountdownParts(ms: number): { h: number; m: number; s: number } {
  const total = Math.max(0, Math.floor(ms / 1000))
  return {
    h: Math.floor(total / 3600),
    m: Math.floor((total % 3600) / 60),
    s: total % 60,
  }
}

const HUNT_PROVIDER_IDS_UI: HuntProviderId[] = ['google', 'cloudflare', 'arvan', 'custom']

/**
 * v7.1 — the two run-comparison columns. A = newer run (emerald chip + emerald
 * column border), B = older run (zinc). Ordering happens in the `cmp` memo by
 * startedAt desc; these constants only carry presentation.
 */
const CMP_SIDES: { side: 'a' | 'b'; chipKey: DictKey; chipCls: string; colCls: string }[] = [
  {
    side: 'a',
    chipKey: 'hunt.cmp.col.newer',
    chipCls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
    colCls: 'border-emerald-500/30',
  },
  {
    side: 'b',
    chipKey: 'hunt.cmp.col.older',
    chipCls: 'border-zinc-500/40 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300',
    colCls: 'border-zinc-500/30',
  },
]

/** providers whose ranges the v6.1 checklist dialog can list (custom keeps its own textarea, 'all' is not a real pool) */
type HuntRangeProvider = Exclude<HuntProviderId, 'custom'>
const HUNT_RANGE_TABS: HuntRangeProvider[] = ['google', 'cloudflare', 'arvan']

// ---------- hunt v6.5: ISP tab inside the ranges dialog ----------

/**
 * Whitelisted Iranian consumer ISPs (the /api/isp route resolves exactly these
 * ASNs — RIPEstat announced prefixes, 30-min server cache). Names are dict keys
 * so the FA/EN toggle relabels the chips without another fetch.
 */
const ISP_ASN_LIST: { asn: string; nameKey: DictKey }[] = [
  { asn: 'AS197207', nameKey: 'isp.name.197207' },
  { asn: 'AS44244', nameKey: 'isp.name.44244' },
  { asn: 'AS58224', nameKey: 'isp.name.58224' },
  { asn: 'AS31549', nameKey: 'isp.name.31549' },
  { asn: 'AS57218', nameKey: 'isp.name.57218' },
  { asn: 'AS44288', nameKey: 'isp.name.44288' },
  { asn: 'AS16322', nameKey: 'isp.name.16322' },
]

/** ISP prefix fetch lifecycle — one active request at a time (last click wins) */
type IspFetchState =
  | { st: 'idle' }
  | { st: 'loading'; asn: string }
  | { st: 'ok'; asn: string; name: string; prefixes: string[]; count4: number; count6: number; cached: boolean }
  | { st: 'err'; asn: string; code: string }

/** provider selection chips — active styling per provider (custom = zinc/slate tone, intentionally NOT indigo/blue) */
const PROVIDER_CHIPS: { id: HuntProviderSelection; labelKey: DictKey; activeCls: string }[] = [
  { id: 'all', labelKey: 'hunt.provider.all', activeCls: 'border-teal-500/50 bg-teal-500/10 text-teal-700 dark:text-teal-300' },
  { id: 'google', labelKey: 'hunt.provider.google', activeCls: 'border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' },
  { id: 'cloudflare', labelKey: 'hunt.provider.cloudflare', activeCls: 'border-orange-500/50 bg-orange-500/10 text-orange-700 dark:text-orange-300' },
  { id: 'arvan', labelKey: 'hunt.provider.arvan', activeCls: 'border-violet-500/50 bg-violet-500/10 text-violet-700 dark:text-violet-300' },
  { id: 'custom', labelKey: 'hunt.custom.label', activeCls: 'border-zinc-500/50 bg-zinc-500/10 text-zinc-700 dark:text-zinc-300' },
]

/**
 * hunt v5 parallel engine speed presets — TCP/TLS pool ceilings mirror the
 * engine-side registry; the chosen preset rides along in the start settings.
 */
type HuntSpeedPreset = 'calm' | 'normal' | 'fast' | 'insane'
const SPEED_PRESETS: { id: HuntSpeedPreset; labelKey: DictKey; tcp: number; tls: number }[] = [
  { id: 'calm', labelKey: 'hunt.speed.calm', tcp: 128, tls: 32 },
  { id: 'normal', labelKey: 'hunt.speed.normal', tcp: 320, tls: 96 },
  { id: 'fast', labelKey: 'hunt.speed.fast', tcp: 640, tls: 192 },
  { id: 'insane', labelKey: 'hunt.speed.insane', tcp: 1024, tls: 384 },
]
const SPEED_ACTIVE_CLS = 'border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'

/** compact provider badge shown on candidate rows + history rows */
const PROVIDER_BADGE: Record<string, { label: string; cls: string }> = {
  google: { label: 'G', cls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' },
  cloudflare: { label: 'CF', cls: 'border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400' },
  arvan: { label: 'A', cls: 'border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-400' },
  custom: { label: 'CU', cls: 'border-zinc-500/40 bg-zinc-500/10 text-zinc-600 dark:text-zinc-400' },
  all: { label: 'G+CF+A', cls: 'border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400' },
}

/** tooltip description per recon source key */
const SOURCE_TIP: Record<string, DictKey> = {
  goog: 'hunt.recon.src.goog',
  spf: 'hunt.recon.src.spf',
  cloud: 'hunt.recon.src.cloud',
  ipsv4: 'hunt.recon.src.ipsv4',
  api: 'hunt.recon.src.api',
  ripe: 'hunt.recon.src.ripe',
}

/** verdict chip colors */
const VERDICT_STYLES: Record<GoogleHuntCandidate['verdict'], string> = {
  healthy: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  blocked: 'border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400',
  dead: 'border-zinc-500/30 bg-zinc-500/10 text-zinc-500',
}

/** hunt v6.4 — censorship forensics verdict badge colors (dead-candidate rows + tally chips) */
const RST_BADGE_STYLES: Record<NonNullable<GoogleHuntCandidate['rst']>, string> = {
  rst: 'border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400',
  drop: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  refused: 'border-zinc-500/40 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300',
  live: 'border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400',
}

function fmtElapsed(ms: number): string {
  const s = Math.floor(ms / 1000)
  const m = Math.floor(s / 60)
  return m > 0 ? `${m}:${String(s % 60).padStart(2, '0')}` : `${s}s`
}

/** sort modes of the healthy-result filter chain (hunt v5.9) */
type HuntSortMode = 'default' | 'tcp' | 'tls'

/** Persian keyboard digits → ASCII so the filter inputs accept both */
function toEnDigits(v: string): string {
  return v.replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 1776))
}

// ---------- hunt v6.3: per-provider probe-target overrides ----------

/** raw per-provider override inputs — empty string = provider default */
interface HuntOvInput {
  host: string
  port: string
  path: string
}

/** raw override inputs → engine payload entry (only non-empty fields ride along) */
function buildHuntOverride(ov: HuntOvInput): HuntTargetOverride | null {
  const host = ov.host.trim()
  const portRaw = toEnDigits(ov.port.trim())
  const port = portRaw !== '' ? Math.floor(Number(portRaw)) : NaN
  const path = ov.path.trim()
  const out: HuntTargetOverride = {}
  if (host !== '') out.host = host.slice(0, 253)
  if (portRaw !== '' && Number.isFinite(port) && port >= 1 && port <= 65535) out.port = port
  if (path !== '') out.path = path.slice(0, 256)
  return Object.keys(out).length > 0 ? out : null
}

/**
 * The exact address a candidate displays as — and copies as.
 * hunt v5.9 multi-port: when a non-default port was probed the row shows (and the
 * clipboard receives) `ip:port`; legacy candidates without `port` render/copy the
 * bare IP exactly as before.
 * hunt v6.1 IPv6: candidates sampled from v6 prefixes (or any `ip` containing `:`)
 * render/copy bracketed `[v6]:port` — one change covers rows, copy and the generator.
 */
function candidateAddr(c: GoogleHuntCandidate): string {
  if (c.v6 || c.ip.includes(':')) return `[${c.ip}]:${c.port ?? 443}`
  return c.port != null ? `${c.ip}:${c.port}` : c.ip
}

/** true when a candidate row is an IPv6 sample (v6 flag OR a v6 literal) */
function isV6Candidate(c: GoogleHuntCandidate): boolean {
  return !!c.v6 || c.ip.includes(':')
}

/**
 * v7.1/v7.3 — TLS latency stats over a candidate list, per-ISP convention:
 * latency = tlsMs ?? tcpMs; entries missing BOTH are excluded from the stats.
 * ONE shared implementation — the v7.1 comparison card and the v7.3 per-run
 * detail dialog both render avg/min/max from it.
 */
function huntLatencyStats(ips: GoogleHuntCandidate[]): { avg: number; min: number; max: number } | null {
  let sum = 0
  let n = 0
  let min = Infinity
  let max = 0
  for (const c of ips) {
    const v = typeof c.tlsMs === 'number' ? c.tlsMs : typeof c.tcpMs === 'number' ? c.tcpMs : null
    if (v !== null && v >= 0) {
      sum += v
      n += 1
      if (v < min) min = v
      if (v > max) max = v
    }
  }
  return n > 0 ? { avg: Math.round(sum / n), min, max } : null
}

/**
 * v7.6 — compact LTR echo of the settings a scheduled fire used (journal rows).
 * All-latin/technical string — deliberately NOT i18n'd; absent fields (and
 * their separators) are skipped. host renders only paired with port (else the
 * bare port alone), mirroring the CSV echo columns.
 */
function journalFireEcho(s: HuntScheduleFireSettings): string {
  const parts: string[] = []
  if (typeof s.provider === 'string' && s.provider) parts.push(s.provider)
  if (s.host && s.port != null) parts.push(`${s.host}:${s.port}`)
  else if (s.port != null) parts.push(String(s.port))
  if (s.target != null) parts.push(`target ${s.target}`)
  if (s.batchSize != null) parts.push(`batch ${s.batchSize}`)
  if (s.concurrency != null) parts.push(`conc ${s.concurrency}`)
  if (s.verify != null) parts.push(`verify ${s.verify}`)
  if (typeof s.speed === 'string' && s.speed) parts.push(s.speed)
  return parts.join(' · ')
}

/** `/NN` size hint derived from a CIDR string (checklist rows, v4 and v6 alike) */
function cidrSizeHint(cidr: string): string {
  const m = /\/(\d{1,3})\s*$/.exec(cidr)
  return m ? `/${m[1]}` : ''
}

// ---------- hunt v6.0: config generator (VLESS/VMess over WS+TLS) ----------

type CfgProtocol = 'vless' | 'vmess'

/** hard cap of generated URIs per dialog render (current view order) */
const CFG_MAX_CONFIGS = 50
/** hard cap of user CIDR lines accepted client-side (engine clamps the same way) */
const CFG_CUSTOM_CIDR_CAP = 64

/** random UUIDv4 — crypto.randomUUID with a manual RFC4122 fallback for non-secure/old contexts */
function randomUuid(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (ch) => {
    const r = (Math.random() * 16) | 0
    const v = ch === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}

export function GoogleHunterPanel({ connected, huntState, recon, schedState, onStart, onStop, onReset, onRefreshRecon, onSetSchedule }: GoogleHunterPanelProps) {
  const { t, num, dir, dateLocale, lang } = useI18n()
  const [target, setTarget] = useState<number>(10)
  const [verify, setVerify] = useState<number>(1)
  const [provider, setProvider] = useState<HuntProviderSelection>('all')
  const [speed, setSpeed] = useState<HuntSpeedPreset>('normal')
  // result filter chain (hunt v5.9) — pure client-side view state, the engine stream is untouched
  const [maxTcp, setMaxTcp] = useState<string>('')
  const [maxTls, setMaxTls] = useState<string>('')
  const [sortMode, setSortMode] = useState<HuntSortMode>('default')
  // hunt v6.0 — custom provider: raw textarea content, parsed client-side (deduped, capped at 64 CIDRs)
  const [customRangesText, setCustomRangesText] = useState('')
  // hunt v6.0 — config generator dialog (VLESS/VMess over WS+TLS)
  const [cfgOpen, setCfgOpen] = useState(false)
  const [cfgProtocol, setCfgProtocol] = useState<CfgProtocol>('vless')
  const [cfgUuid, setCfgUuid] = useState(() => randomUuid())
  const [cfgPath, setCfgPath] = useState('/ws')
  const [cfgSni, setCfgSni] = useState('')
  const [cfgPrefix, setCfgPrefix] = useState('hunt')
  // hunt v6.1 — config generator SNI preset select ('' = free-text / auto-derived)
  const [cfgSniPreset, setCfgSniPreset] = useState('')
  // hunt v6.1 — config generator xray fragment preset (VLESS URIs only)
  const [cfgFragment, setCfgFragment] = useState('none')
  // hunt v6.1 — IPv6 sampling toggle (rides along in the start payload ONLY when on)
  const [enableV6, setEnableV6] = useState(false)
  // hunt v6.4 — censorship forensics on dead candidates (default on; always sent in the payload)
  const [forensicsOn, setForensicsOn] = useState(true)
  // hunt v6.3 — per-provider probe-target overrides (raw inputs; '' = provider default)
  const [ovOpen, setOvOpen] = useState(false)
  const [ovGoogle, setOvGoogle] = useState<HuntOvInput>({ host: '', port: '', path: '' })
  const [ovCloud, setOvCloud] = useState<HuntOvInput>({ host: '', port: '', path: '' })
  // hunt v6.2 — «ذخیره در ساب» POST of the generated URIs to /api/configs
  const [savingConfigs, setSavingConfigs] = useState(false)
  // hunt v6.1 — range checklist: committed single-provider allow-list (null = hunt the whole pool)
  const [selectedRanges, setSelectedRanges] = useState<{ provider: HuntRangeProvider; cidrs: string[] } | null>(null)
  // v7.0 — ISP source labels for the committed selection (cidr → 'AS<digits>'; ranges from other tabs stay unlabelled)
  const [selectedLabels, setSelectedLabels] = useState<Record<string, string>>({})
  // hunt v6.1 — ranges dialog working state (tab / search / checked set, committed on confirm)
  const [rangesOpen, setRangesOpen] = useState(false)
  const [rangesTab, setRangesTab] = useState<HuntRangeProvider>('google')
  const [rangesQuery, setRangesQuery] = useState('')
  const [rangesChecked, setRangesChecked] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  // hunt history from /api/hunt (persisted engine-side, survives restarts)
  const [runs, setRuns] = useState<GoogleHuntHistoryRun[]>([])
  const runsStampRef = useRef<string>('')
  // finish toasts fire exactly once per hunt run
  const lastFinishRef = useRef<number>(0)

  const running = !!huntState?.running
  // realtime payloads are never trusted structurally — a malformed/partial
  // state (e.g. an ack serialising wrong) degrades to the empty view
  const s = useMemo(() => {
    if (!huntState) return null
    if (!Array.isArray(huntState.healthyIps) || !Array.isArray(huntState.recent)) return null
    return huntState
  }, [huntState])

  // ----- result filter chain (hunt v5.9) — client-side only, over the healthy list -----
  const healthyIps = s?.healthyIps ?? []
  const hasHealthy = healthyIps.length > 0
  /** empty input = no limit; digit-stripped on input so Number() is NaN-safe */
  const maxTcpNum = maxTcp.trim() === '' ? null : Number(maxTcp)
  const maxTlsNum = maxTls.trim() === '' ? null : Number(maxTls)
  const filtersActive = maxTcpNum !== null || maxTlsNum !== null || sortMode !== 'default'
  /**
   * filtered + sorted view of the healthy list — the default mode returns the
   * ORIGINAL array untouched so legacy (no filters) rendering is byte-identical.
   */
  const visibleHealthy = useMemo(() => {
    let list = healthyIps
    if (maxTcpNum !== null) list = list.filter((c) => (c.tcpMs ?? Infinity) <= maxTcpNum)
    if (maxTlsNum !== null) list = list.filter((c) => (c.tlsMs ?? Infinity) <= maxTlsNum)
    if (sortMode === 'tcp') list = [...list].sort((a, b) => (a.tcpMs ?? Infinity) - (b.tcpMs ?? Infinity))
    else if (sortMode === 'tls') list = [...list].sort((a, b) => (a.tlsMs ?? Infinity) - (b.tlsMs ?? Infinity))
    return list
  }, [healthyIps, maxTcpNum, maxTlsNum, sortMode])
  /** datacenter spread — aggregated over the FULL healthy list (stable overview, independent of view filters) */
  const coloCounts = useMemo(() => {
    const m = new Map<string, number>()
    for (const c of healthyIps) {
      if (c.colo) m.set(c.colo, (m.get(c.colo) ?? 0) + 1)
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
  }, [healthyIps])
  const coloChips = coloCounts.slice(0, 5)

  // ----- hunt v6.0: custom provider — client-side CIDR parsing (one per line, trimmed, deduped, cap 64) -----
  const customCidrs = useMemo(() => {
    const seen = new Set<string>()
    const out: string[] = []
    for (const raw of customRangesText.split(/\r?\n/)) {
      const line = raw.trim()
      if (line === '' || seen.has(line)) continue
      seen.add(line)
      out.push(line)
      if (out.length >= CFG_CUSTOM_CIDR_CAP) break
    }
    return out
  }, [customRangesText])

  // ----- hunt v6.1: range checklist over the recon snapshot (hidden on legacy engines without ranges) -----
  const reconHasRanges = useMemo(
    () => HUNT_RANGE_TABS.some((pid) => (recon?.providers[pid]?.ranges?.length ?? 0) > 0),
    [recon],
  )
  /** ranges of the active dialog tab (defensively re-capped to the protocol limit) */
  const tabRanges = useMemo(
    () => (recon?.providers[rangesTab]?.ranges ?? []).slice(0, HUNT_RECON_RANGES_CAP),
    [recon, rangesTab],
  )
  /** search-filtered view — case-insensitive substring on the CIDR string */
  const visibleTabRanges = useMemo(() => {
    const q = rangesQuery.trim().toLowerCase()
    if (q === '') return tabRanges
    return tabRanges.filter((r) => r.toLowerCase().includes(q))
  }, [tabRanges, rangesQuery])
  /** IPv6 prefixes available for the current provider scope (0 ⇒ the v6 toggle is inert) */
  const v6SourceCount = useMemo(() => {
    if (!recon || provider === 'custom') return 0
    const pids: HuntProviderId[] = selectedRanges
      ? [selectedRanges.provider]
      : provider === 'all'
        ? ['google', 'cloudflare', 'arvan']
        : [provider]
    return pids.reduce((acc, pid) => acc + (recon.providers[pid]?.cidrsV6 ?? 0), 0)
  }, [recon, provider, selectedRanges])

  // ----- hunt v6.0: config generator — URIs for every VISIBLE (filtered) healthy candidate -----
  const cfgUuidValid = cfgUuid.trim() !== ''
  /**
   * Generated in the CURRENT view order (filters/sort respected), capped at CFG_MAX_CONFIGS.
   * VLESS addr = candidateAddr(c) with :443 appended to bare-IP candidates so the URI always
   * carries host:port per the vless:// standard (v6 candidates arrive bracketed [v6]:port);
   * VMess keeps add=ip + port field per the vmess:// base64 JSON shape. Path auto-fixes to a
   * leading '/'; remark = prefix-index. hunt v6.1: a non-`none` fragment preset appends the
   * `fragment` URI param on VLESS ONLY (the VMess JSON schema is rigid — no fragment field).
   */
  const cfgList = useMemo<string[]>(() => {
    const uuid = cfgUuid.trim()
    if (uuid === '') return []
    const sni = cfgSni.trim() || 'www.cloudflare.com'
    const rawPath = cfgPath.trim() || '/ws'
    const path = rawPath.startsWith('/') ? rawPath : `/${rawPath}`
    const prefix = cfgPrefix.trim() || 'hunt'
    const fragment =
      cfgProtocol === 'vless' ? (HUNT_FRAGMENT_PRESETS.find((f) => f.id === cfgFragment && f.id !== 'none')?.value ?? '') : ''
    const view = visibleHealthy.slice(0, CFG_MAX_CONFIGS)
    const out: string[] = []
    for (let i = 0; i < view.length; i++) {
      const c = view[i]!
      const remark = `${prefix}-${i + 1}`
      if (cfgProtocol === 'vless') {
        const addr = candidateAddr(c)
        const hostPort = addr.includes(':') ? addr : `${addr}:443`
        const encSni = encodeURIComponent(sni)
        out.push(
          `vless://${uuid}@${hostPort}?encryption=none&security=tls&sni=${encSni}&fp=chrome&host=${encSni}&path=${encodeURIComponent(path)}&type=ws${fragment ? `&fragment=${encodeURIComponent(fragment)}` : ''}#${encodeURIComponent(remark)}`,
        )
      } else {
        const json = JSON.stringify({
          v: '2',
          ps: remark,
          add: c.ip,
          port: String(c.port ?? 443),
          id: uuid,
          aid: '0',
          scy: 'auto',
          net: 'ws',
          type: 'none',
          host: sni,
          path,
          tls: 'tls',
          sni,
        })
        // UTF-8 safe base64 (btoa alone mangles non-ASCII remarks)
        out.push(`vmess://${btoa(unescape(encodeURIComponent(json)))}`)
      }
    }
    return out
  }, [visibleHealthy, cfgProtocol, cfgUuid, cfgSni, cfgPath, cfgPrefix, cfgFragment])
  const cfgText = cfgList.join('\n')

  const fetchRuns = useCallback(async () => {
    try {
      const res = await fetch('/api/hunt', { cache: 'no-store' })
      if (!res.ok) return
      const data = (await res.json()) as { runs?: GoogleHuntHistoryRun[] }
      setRuns(Array.isArray(data.runs) ? data.runs : [])
    } catch {
      // history is best-effort — never block the panel on it
    }
  }, [])

  // initial load + refetch once per finished run
  useEffect(() => {
    void fetchRuns()
  }, [fetchRuns])

  useEffect(() => {
    if (!s?.finished || s.running) return
    const stamp = `${s.startedAt ?? 0}-${s.tested}`
    if (runsStampRef.current === stamp) return
    runsStampRef.current = stamp
    void fetchRuns()
  }, [s?.finished, s?.startedAt, s?.tested, s?.running, s, fetchRuns])

  // toast on finish (target reached / stopped / cap / error)
  useEffect(() => {
    if (!s || !s.finished || s.running) return
    const stamp = s.startedAt ?? 0
    if (lastFinishRef.current === stamp) return
    lastFinishRef.current = stamp
    if (s.error) {
      toast.error(t('hunt.done.fail', { e: s.error }))
      return
    }
    if (s.stopped) toast.info(t('hunt.done.stopped', { n: num(s.healthy) }))
    else if (s.healthy >= s.target) toast.success(t('hunt.done.ok', { n: num(s.healthy) }))
    else toast.warning(t('hunt.done.cap', { n: num(s.healthy) }))
  }, [s, t, num])

  /**
   * v7.0 — THE single settings builder: the Start button AND the hunt scheduler
   * both send exactly this object, so scheduled runs always match what the user
   * configured on the form (the engine normalizes missing fields). Key order is
   * deterministic → the scheduler drift check can JSON.stringify() it.
   */
  const buildHuntSettings = useCallback((): Partial<GoogleHuntSettings> => {
    // hunt v6.3 — per-provider probe-target overrides (google + cloudflare only;
    // arvan/custom stay SNI-less on the IP itself by engine rule)
    const providerOverrides: Partial<Record<HuntProviderId, HuntTargetOverride>> = {}
    const gOv = buildHuntOverride(ovGoogle)
    if (gOv) providerOverrides.google = gOv
    const cOv = buildHuntOverride(ovCloud)
    if (cOv) providerOverrides.cloudflare = cOv
    // v7.0 — parallel ISP labels aligned 1:1 with the sliced selectedCidrs array
    // (the engine aligns labels to its canonicalized cidrs via a parallel cursor,
    // so same order + same length is mandatory). All-empty ⇒ omit entirely —
    // a hunt with no ISP ranges keeps the exact legacy payload shape.
    let selectedLabelsArr: string[] | null = null
    if (selectedRanges && selectedRanges.cidrs.length > 0) {
      const sliced = selectedRanges.cidrs.slice(0, HUNT_SELECTED_MAX_CIDRS)
      const labels = sliced.map((cidr) => selectedLabels[cidr] ?? '')
      if (labels.some((l) => l !== '')) selectedLabelsArr = labels
    }
    return {
      target,
      verify,
      // hunt v6.1 — an active range selection FORCES the provider of the checklist
      provider: selectedRanges ? selectedRanges.provider : provider,
      speed,
      // custom CIDRs ride along ONLY for the custom provider (hunt v6.0; never combined with a selection)
      ...(provider === 'custom' && !selectedRanges ? { customCidrs: customCidrs.slice(0, CFG_CUSTOM_CIDR_CAP) } : {}),
      // hunt v6.1 — IPv6 sampling rides along ONLY when enabled (omitted keeps the legacy payload shape)
      ...(enableV6 ? { enableV6: true } : {}),
      // hunt v6.4 — censorship forensics on dead candidates (always sent, default true)
      forensics: forensicsOn,
      // hunt v6.1 — explicit range allow-list over the recon pool (engine hunts ONLY these ranges)
      ...(selectedRanges && selectedRanges.cidrs.length > 0
        ? { selectedCidrs: selectedRanges.cidrs.slice(0, HUNT_SELECTED_MAX_CIDRS) }
        : {}),
      // v7.0 — parallel ISP source labels (omitted keeps the payload byte-identical)
      ...(selectedLabelsArr ? { selectedLabels: selectedLabelsArr } : {}),
      // hunt v6.3 — per-provider custom host/port/path (omitted keeps the payload byte-identical)
      ...(Object.keys(providerOverrides).length > 0 ? { providerOverrides } : {}),
    }
  }, [target, verify, provider, speed, customCidrs, selectedRanges, selectedLabels, enableV6, forensicsOn, ovGoogle, ovCloud])

  const handleStart = useCallback(async () => {
    if (!connected) {
      toast.error(t('hunt.offline'))
      return
    }
    setBusy(true)
    try {
      const state = await onStart(buildHuntSettings())
      if (!state) toast.error(t('hunt.offline'))
      else if (state.running) lastFinishRef.current = 0
    } finally {
      setBusy(false)
    }
  }, [connected, onStart, buildHuntSettings, t])

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

  /** resets the client-side result filter chain (hunt v5.9) */
  const clearFilters = useCallback(() => {
    setMaxTcp('')
    setMaxTls('')
    setSortMode('default')
  }, [])

  // ----- hunt v6.1: range checklist handlers (dialog state is working memory; confirm commits) -----
  /** opens the dialog pre-checked with the committed selection (if any) and lands on its provider tab */
  const openRanges = useCallback(() => {
    setRangesTab(selectedRanges ? selectedRanges.provider : 'google')
    setRangesChecked(selectedRanges ? new Set(selectedRanges.cidrs) : new Set())
    setRangesQuery('')
    setIspActive(false)
    setRangesOpen(true)
  }, [selectedRanges])
  /** selection is single-provider by design — switching tabs resets the checked set to that provider's committed checks */
  const switchRangesTab = useCallback(
    (tab: HuntRangeProvider) => {
      setRangesTab(tab)
      setRangesChecked(selectedRanges && selectedRanges.provider === tab ? new Set(selectedRanges.cidrs) : new Set())
    },
    [selectedRanges],
  )
  const toggleRange = useCallback((cidr: string) => {
    setRangesChecked((prev) => {
      const next = new Set(prev)
      if (next.has(cidr)) next.delete(cidr)
      else next.add(cidr)
      return next
    })
  }, [])
  /** select-all / unselect-all over the VISIBLE (search-filtered) set only */
  const toggleAllVisibleRanges = useCallback(() => {
    setRangesChecked((prev) => {
      const next = new Set(prev)
      const allChecked = visibleTabRanges.length > 0 && visibleTabRanges.every((r) => next.has(r))
      if (allChecked) visibleTabRanges.forEach((r) => next.delete(r))
      else visibleTabRanges.forEach((r) => next.add(r))
      return next
    })
  }, [visibleTabRanges])
  /** commits the working set as THE single-provider allow-list (capped to the protocol limit) */
  const confirmRanges = useCallback(() => {
    if (rangesChecked.size === 0) return
    const cidrs = [...rangesChecked].slice(0, HUNT_SELECTED_MAX_CIDRS)
    setSelectedRanges({ provider: rangesTab, cidrs })
    // v7.0 — keep labels aligned with the committed selection: only cidrs that
    // survived this commit stay labelled (everything else is dropped with it)
    setSelectedLabels((prev) => {
      const next: Record<string, string> = {}
      for (const c of cidrs) {
        if (prev[c]) next[c] = prev[c]
      }
      return next
    })
    setRangesOpen(false)
  }, [rangesChecked, rangesTab])
  const clearSelectedRanges = useCallback(() => {
    setSelectedRanges(null)
    setSelectedLabels({})
  }, [])

  // ----- hunt v6.5: ISP tab — fetch-on-click prefixes, added straight into the committed selection -----
  const [ispActive, setIspActive] = useState(false)
  const [ispState, setIspState] = useState<IspFetchState>({ st: 'idle' })
  const [ispShow, setIspShow] = useState(false)
  /** request seq guard — a slow response must never overwrite a newer pick */
  const ispReqRef = useRef(0)

  /** GET /api/isp?asn=… — whitelisted Iranian operators only (server-side RIPEstat proxy with a 30-min cache) */
  const fetchIsp = useCallback(
    async (asn: string) => {
      const req = ++ispReqRef.current
      setIspState({ st: 'loading', asn })
      setIspShow(false)
      try {
        const res = await fetch(`/api/isp?asn=${encodeURIComponent(asn)}`)
        const data = (await res.json().catch(() => null)) as
          | {
              ok?: boolean
              asn?: unknown
              name?: unknown
              prefixes?: unknown
              count4?: unknown
              count6?: unknown
              cached?: unknown
              error?: unknown
              detail?: unknown
            }
          | null
        if (ispReqRef.current !== req) return
        if (!res.ok || !data || data.ok !== true) {
          // 400/502 map to a named server error; anything else degrades to HTTP status
          const code =
            typeof data?.error === 'string' && data.error !== ''
              ? data.error
              : `HTTP ${res.status}`
          setIspState({ st: 'err', asn, code })
          toast.error(t('isp.err'))
          return
        }
        // defensive shape pass — only real CIDR-ish strings survive
        const prefixes = Array.isArray(data.prefixes)
          ? data.prefixes.filter((p): p is string => typeof p === 'string' && p.includes('/'))
          : []
        setIspState({
          st: 'ok',
          asn: typeof data.asn === 'string' ? data.asn : asn,
          name: typeof data.name === 'string' ? data.name : asn,
          prefixes,
          count4: Number(data.count4) || 0,
          count6: Number(data.count6) || 0,
          cached: data.cached === true,
        })
      } catch {
        if (ispReqRef.current !== req) return
        setIspState({ st: 'err', asn, code: 'network' })
        toast.error(t('isp.fail'))
      }
    },
    [t],
  )

  /**
   * Appends the fetched ISP prefixes to the SAME committed selection the other
   * three tabs feed — dedupe against the existing cidrs, respect the protocol
   * cap, dialog stays open (the amber tile outside updates instantly).
   * v7.0 — every fresh prefix is remembered as labelled with its ASN
   * ('AS<digits>') so the start payload can carry parallel selectedLabels.
   */
  const addIspRanges = useCallback(
    (name: string, prefixes: string[], asnLabel: string) => {
      const incoming = prefixes.filter((p) => typeof p === 'string' && p.trim() !== '')
      if (incoming.length === 0) {
        toast.warning(t('isp.err'))
        return
      }
      const existing = selectedRanges?.cidrs ?? []
      const seen = new Set(existing)
      let fresh: string[] = []
      for (const c of incoming) {
        if (!seen.has(c)) {
          seen.add(c)
          fresh.push(c)
        }
      }
      let dupes = incoming.length - fresh.length
      // respect the protocol cap — room left in the committed selection
      const capLeft = HUNT_SELECTED_MAX_CIDRS - existing.length
      if (capLeft <= 0) {
        toast.warning(t('isp.add.dup', { n: num(incoming.length) }))
        return
      }
      if (fresh.length > capLeft) {
        dupes += fresh.length - capLeft
        fresh = fresh.slice(0, capLeft)
      }
      if (fresh.length === 0) {
        toast.info(t('isp.add.dup', { n: num(dupes) }))
        return
      }
      // the selection stays single-provider: an ISP addition rides the existing
      // selection's probe provider, else the active chip when it is a concrete pool
      const nextProvider: HuntRangeProvider =
        selectedRanges?.provider ??
        (provider === 'google' || provider === 'cloudflare' || provider === 'arvan' ? provider : 'google')
      setSelectedRanges({ provider: nextProvider, cidrs: [...existing, ...fresh] })
      // v7.0 — label ONLY the fresh additions (dupes keep their original label/absence)
      const label = typeof asnLabel === 'string' ? asnLabel.trim() : ''
      if (label !== '') {
        setSelectedLabels((prev) => {
          const next = { ...prev }
          for (const c of fresh) next[c] = label
          return next
        })
      }
      toast.success(t('isp.add.ok', { n: num(fresh.length), name }))
      if (dupes > 0) toast.info(t('isp.add.dup', { n: num(dupes) }))
    },
    [selectedRanges, provider, t, num],
  )

  // live recon refresh — ack resolves fast, the real update arrives via broadcast
  const [reconBusy, setReconBusy] = useState(false)
  const handleRefreshRecon = useCallback(async () => {
    if (!connected) {
      toast.error(t('hunt.offline'))
      return
    }
    setReconBusy(true)
    try {
      await onRefreshRecon()
    } finally {
      window.setTimeout(() => setReconBusy(false), 1200)
    }
  }, [connected, onRefreshRecon, t])

  // ----- v7.0: engine-side hunt scheduler card (auto hunt) -----
  /** local interval picker state — engine truth re-syncs it via broadcast/ack */
  const [hsInterval, setHsInterval] = useState<number>(schedState.intervalMinutes)
  const [schedBusy, setSchedBusy] = useState(false)
  /** v7.1 — journal collapsible visibility (header always shows the live count) */
  const [jrnOpen, setJrnOpen] = useState(false)
  /** v7.7 — journal entry behind the open detail dialog (null = closed) */
  const [jrnDetail, setJrnDetail] = useState<HuntScheduleJournalEntry | null>(null)
  /** 1s wall clock for the live countdown (ticking only while a schedule is armed) */
  const [schedNow, setSchedNow] = useState(() => Date.now())
  /**
   * Settings snapshot captured at enable/update time (JSON of buildHuntSettings()
   * output). Empty string = no in-session baseline → the drift hint stays quiet
   * (honest: we never pretend to know what the engine captured before this page loaded).
   */
  const schedSnapRef = useRef<string>('')
  // engine truth wins whenever the broadcast reports a different interval
  useEffect(() => {
    setHsInterval(schedState.intervalMinutes)
  }, [schedState.intervalMinutes])
  useEffect(() => {
    if (!schedState.enabled || schedState.running) return
    setSchedNow(Date.now())
    const id = window.setInterval(() => setSchedNow(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [schedState.enabled, schedState.running])

  /** current form snapshot string — recomputed only when the builder inputs change */
  const schedCurrentSnap = useMemo(() => JSON.stringify(buildHuntSettings()), [buildHuntSettings])
  /** settings-drift: enabled AND we captured a baseline AND the form moved since then */
  const schedDrift = schedState.enabled && schedSnapRef.current !== '' && schedCurrentSnap !== schedSnapRef.current
  /** ms until the next scheduled fire — null when disarmed or the engine has not stamped nextRunAt yet */
  const schedNextIn = schedState.enabled && schedState.nextRunAt != null ? schedState.nextRunAt - schedNow : null
  /** padded hh:mm:ss / mm:ss countdown in locale digits (≤ 24h by engine contract) */
  const schedCountdownText = useMemo(() => {
    if (schedNextIn == null) return null
    const p = fmtCountdownParts(schedNextIn)
    const pad = (n: number) => num(n, { minimumIntegerDigits: 2 })
    return p.h > 0 ? `${pad(p.h)}:${pad(p.m)}:${pad(p.s)}` : `${pad(p.m)}:${pad(p.s)}`
  }, [schedNextIn, num])
  /** v7.1 — scheduler journal (newest-first, capped engine-side) — OPTIONAL on the state type, safe-rendered */
  const schedJournal = schedState.journal ?? []

  /**
   * v7.2 — journal CSV export (client-built, Excel-safe BOM, honest count toast).
   * v7.6 — 15-column shape via the shared buildSchedulerJournalCsvRows helper
   * (ONE row-builder for the manual exporter AND the Telegram auto-attach):
   * at_iso,at_ms,kind,tested,healthy,stopped,duration_ms + the 8 per-fire
   * settings-echo columns provider,target,batch,concurrency,host,port,speed,
   * verify — settings cells stay EMPTY for done/postponed events and legacy
   * fire rows recorded before the echo existed. The blob/stamp plumbing
   * (v7.5) stays in lib/csv.
   */
  const exportJournalCsv = useCallback(() => {
    if (schedJournal.length === 0) return
    downloadCsv(`hunt-scheduler-journal-${csvFileStamp()}.csv`, buildSchedulerJournalCsvRows(schedJournal))
    toast.success(t('hunt.jrn.export.ok', { n: num(schedJournal.length) }))
  }, [schedJournal, num, t])

  /**
   * v7.5 — history CSV export (same conventions as the journal exporter: BOM +
   * blob plumbing via lib/csv, honest empty cells, no quoting — hosts are
   * hostnames/CIDRs and never contain commas). Column order:
   * at_iso,at_ms,kind,host,port,target,tested,healthy,blocked,dead,tcpAlive,
   * verify,healthy_rate_pct,healthy_ips_count,provider. at_* is the run's
   * startedAt (the SAME timestamp the time-range chips filter on); kind follows
   * the v7.2 auto/manual convention; healthy_rate_pct is one decimal, no % sign.
   */
  const exportHistoryCsv = useCallback(() => {
    if (runs.length === 0) return
    const rows: string[] = [
      'at_iso,at_ms,kind,host,port,target,tested,healthy,blocked,dead,tcpAlive,verify,healthy_rate_pct,healthy_ips_count,provider',
    ]
    for (const r of runs) {
      const rate = r.tested > 0 ? Math.round((r.healthy / r.tested) * 1000) / 10 : null
      rows.push(
        [
          new Date(r.startedAt).toISOString(),
          String(r.startedAt),
          r.auto === true ? 'auto' : 'manual',
          r.host,
          String(r.port),
          String(r.target),
          String(r.tested),
          String(r.healthy),
          String(r.blocked),
          String(r.dead),
          String(r.tcpAlive),
          String(r.verify),
          rate === null ? '' : String(rate),
          String((r.healthyIps ?? []).length),
          r.provider ?? '',
        ].join(','),
      )
    }
    downloadCsv(`hunt-history-${csvFileStamp()}.csv`, rows)
    toast.success(t('hunt.hist.export.ok', { n: num(runs.length) }))
  }, [runs, num, t])

  /** OFF→ON captures the EXACT start-button settings; ON→OFF clears the baseline */
  const handleSchedToggle = useCallback(
    async (on: boolean) => {
      if (!connected) {
        toast.error(t('hunt.offline'))
        return
      }
      setSchedBusy(true)
      try {
        if (on) {
          const settings = buildHuntSettings()
          const snap = await onSetSchedule(true, hsInterval, settings)
          if (!snap) {
            toast.error(t('hs.fail'))
            return
          }
          schedSnapRef.current = JSON.stringify(settings)
          toast.success(t('hs.ok.on'))
        } else {
          const snap = await onSetSchedule(false, hsInterval, null)
          if (!snap) {
            toast.error(t('hs.fail'))
            return
          }
          schedSnapRef.current = ''
          toast.info(t('hs.ok.off'))
        }
      } finally {
        setSchedBusy(false)
      }
    },
    [connected, onSetSchedule, hsInterval, buildHuntSettings, t],
  )

  /** while armed, an interval change re-sends with settings=null (stored settings untouched) */
  const handleSchedInterval = useCallback(
    async (m: number) => {
      setHsInterval(m)
      if (!schedState.enabled) return // disabled ⇒ local only, applied on next enable
      if (!connected) {
        toast.error(t('hunt.offline'))
        return
      }
      setSchedBusy(true)
      try {
        const snap = await onSetSchedule(true, m, null)
        if (!snap) toast.error(t('hs.fail'))
        else toast.success(t('hs.ok.interval', { n: num(m) }))
      } finally {
        setSchedBusy(false)
      }
    },
    [schedState.enabled, connected, onSetSchedule, t, num],
  )

  /** drift-resolution button — re-captures the CURRENT form settings into the schedule */
  const handleSchedUpdate = useCallback(async () => {
    if (!connected) {
      toast.error(t('hunt.offline'))
      return
    }
    setSchedBusy(true)
    try {
      const settings = buildHuntSettings()
      const snap = await onSetSchedule(true, hsInterval, settings)
      if (!snap) {
        toast.error(t('hs.fail'))
        return
      }
      schedSnapRef.current = JSON.stringify(settings)
      toast.success(t('hs.ok.update'))
    } finally {
      setSchedBusy(false)
    }
  }, [connected, onSetSchedule, hsInterval, buildHuntSettings, t])

  // ----- v7.0: per-ISP latency profile over the healthy list -----
  /** latency of one healthy entry: tlsMs, fallback tcpMs; missing both = counted but excluded from latency stats */
  const ispLatencyRows = useMemo<IspLatencyRow[]>(() => {
    const m = new Map<string, { count: number; sum: number; n: number; min: number; max: number }>()
    for (const c of healthyIps) {
      const label = typeof c.isp === 'string' ? c.isp.trim() : ''
      if (label === '') continue
      let e = m.get(label)
      if (!e) {
        e = { count: 0, sum: 0, n: 0, min: Infinity, max: 0 }
        m.set(label, e)
      }
      e.count += 1
      const lat = typeof c.tlsMs === 'number' ? c.tlsMs : typeof c.tcpMs === 'number' ? c.tcpMs : null
      if (lat !== null && lat >= 0) {
        e.sum += lat
        e.n += 1
        e.min = Math.min(e.min, lat)
        e.max = Math.max(e.max, lat)
      }
    }
    const rows: IspLatencyRow[] = [...m.entries()].map(([label, e]) => ({
      label,
      count: e.count,
      avg: e.n > 0 ? Math.round(e.sum / e.n) : null,
      min: e.n > 0 ? e.min : null,
      max: e.n > 0 ? e.max : null,
    }))
    rows.sort((a, b) => b.count - a.count || (a.avg ?? Infinity) - (b.avg ?? Infinity))
    return rows
  }, [healthyIps])
  const maxIspCount = ispLatencyRows.length > 0 ? ispLatencyRows[0]!.count : 0

  /** 'AS197207' → t('isp.name.197207') when the dict knows it; anything else falls back to the raw label */
  const ispDisplayName = useCallback(
    (label: string): string => {
      const m = /^AS(\d{1,10})$/.exec(label)
      if (m) {
        const key = `isp.name.${m[1]}` as DictKey
        if (Object.prototype.hasOwnProperty.call(DICT.fa, key)) return t(key)
      }
      return label
    },
    [t],
  )

  const copyText = useCallback(
    async (text: string, okKey: DictKey, vars?: Record<string, string | number>) => {
      try {
        await navigator.clipboard.writeText(text)
        toast.success(t(okKey, vars))
      } catch {
        toast.error(t('xray.toast.copyfail'))
      }
    },
    [t],
  )

  const copyAll = useCallback(() => {
    // copies the FILTERED view (ip:port when a non-default port was probed) — hunt v5.9
    const ips = visibleHealthy.map((c) => candidateAddr(c))
    if (ips.length === 0) return
    void copyText(ips.join('\n'), 'hunt.list.copyall.ok', { n: num(ips.length) })
  }, [visibleHealthy, copyText, num])

  /** opens the config generator and re-derives the SNI default from the first visible candidate (hunt v6.0) */
  const openConfig = useCallback(() => {
    if (visibleHealthy.length === 0) return
    const derived = (visibleHealthy[0]?.host ?? '').trim() || 'www.cloudflare.com'
    setCfgSni(derived)
    // highlight the preset select when the derived SNI happens to be one of the presets (hunt v6.1)
    setCfgSniPreset(HUNT_SNI_PRESETS.includes(derived) ? derived : '')
    setCfgOpen(true)
  }, [visibleHealthy])

  /** label of a fragment preset — tlshello/http are protocol terms and stay language-neutral */
  const fragmentLabel = (id: string): string => {
    if (id === 'none') return t('hunt.fragment.none')
    if (id === 'tls-long') return t('hunt.fragment.tlslong')
    return id
  }

  const copyConfigs = useCallback(() => {
    if (cfgList.length === 0) return
    void copyText(cfgText, 'hunt.config.copyok', { n: num(cfgList.length) })
  }, [cfgList.length, cfgText, copyText, num])

  /** .txt export of the generated URIs (Blob + anchor download) — hunt v6.0 */
  const downloadConfigs = useCallback(() => {
    if (cfgList.length === 0) return
    const prefix = cfgPrefix.trim() || 'hunt'
    const blob = new Blob([`${cfgText}\n`], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${prefix}-configs.txt`
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }, [cfgList.length, cfgText, cfgPrefix])

  /** hunt v6.2 — saves the currently generated URIs (already capped at CFG_MAX_CONFIGS) to the subscription store; dupes are skipped server-side via the unique uri key */
  const saveConfigsToSub = useCallback(async () => {
    if (cfgList.length === 0 || savingConfigs) return
    setSavingConfigs(true)
    try {
      const res = await fetch('/api/configs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          uris: cfgList,
          label: cfgPrefix.trim() || 'hunt',
          sni: cfgSni.trim() || 'www.cloudflare.com',
        }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = (await res.json()) as { saved?: number; duplicates?: number }
      toast.success(
        t('hunt.config.save.ok', { n: num(data.saved ?? 0), m: num(data.duplicates ?? 0) }),
      )
    } catch {
      toast.error(t('hunt.config.save.fail'))
    } finally {
      setSavingConfigs(false)
    }
  }, [cfgList, savingConfigs, cfgPrefix, cfgSni, t, num])

  const copyRun = useCallback(
    (run: GoogleHuntHistoryRun) => {
      const ips = (run.healthyIps ?? []).map((c) => candidateAddr(c)).filter(Boolean)
      if (ips.length === 0) return
      void copyText(ips.join('\n'), 'hunt.history.copy.ok', { n: num(ips.length) })
    },
    [copyText, num],
  )

  const fmtRunDate = useCallback(
    (ts: number) =>
      new Intl.DateTimeFormat(dateLocale, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(
        new Date(ts),
      ),
    [dateLocale],
  )

  /**
   * v7.1 — humanized duration for journal done-rows + run comparison
   * (< 60s → seconds, < 1h → minutes(+seconds), else hours(+minutes); zero
   * parts dropped, all digits via num(), fa joins parts with «و»).
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

  // ----- v7.1: past-hunt run comparison (side-by-side, max 2 runs) -----
  const [compareIds, setCompareIds] = useState<string[]>([])
  /** toggle one run in the compare selection — a third pick fires an honest info toast and changes nothing */
  const toggleCompare = useCallback(
    (id: string) => {
      if (compareIds.includes(id)) {
        setCompareIds(compareIds.filter((x) => x !== id))
        return
      }
      if (compareIds.length >= 2) {
        toast.info(t('hunt.cmp.max'))
        return
      }
      setCompareIds([...compareIds, id])
    },
    [compareIds, t],
  )
  // keep the selection honest when the history refetches (a run may age out of the cap-30 window)
  useEffect(() => {
    setCompareIds((prev) => {
      if (prev.length === 0) return prev
      const ids = new Set(runs.map((r) => r.id))
      const next = prev.filter((id) => ids.has(id))
      return next.length === prev.length ? prev : next
    })
  }, [runs])

  // ----- v7.2: history management (per-run delete + clear-all + filter) -----
  /** id of the run whose delete-confirmation dialog is open (null = closed) — ONE shared dialog */
  const [pendingDelId, setPendingDelId] = useState<string | null>(null)
  const [delBusy, setDelBusy] = useState(false)
  const [confirmClear, setConfirmClear] = useState(false)
  const [clearBusy, setClearBusy] = useState(false)
  /** 'auto' = scheduler-fired runs only · 'manual' = everything else (auto !== true) */
  const [histFilter, setHistFilter] = useState<'all' | 'auto' | 'manual'>('all')
  /**
   * v7.5 — time-range filter (shared hist.range.* keys with the WARP history):
   * '24h'/'7d' keep runs whose startedAt is inside the window, 'all' = everything.
   * Date.now() inside the memo is fine — recomputing on state change is enough.
   */
  const [histRange, setHistRange] = useState<'all' | '24h' | '7d'>('all')
  /** v7.2 integration polish — visible rows grow via «نمایش بیشتر» (v7.3: resets when the filter, search query or sort changes) */
  const [histShow, setHistShow] = useState<number>(HISTORY_SHOW)
  /** the run behind the open delete dialog — feeds the date line in the description */
  const pendingDelRun = useMemo(
    () => (pendingDelId ? runs.find((r) => r.id === pendingDelId) ?? null : null),
    [pendingDelId, runs],
  )
  /**
   * history rows after the auto/manual filter AND the v7.5 time-range filter —
   * comparison keeps working on the UNFILTERED selection.
   * v7.5 pipeline: kind filter → time range → search → sort (in visibleRuns).
   * A range-only empty list falls into the existing honest «هیچ اجرایی با این
   * فیلتر نیست» state — no new key needed.
   */
  const filteredRuns = useMemo(() => {
    const cutoff = histRange === '24h' ? Date.now() - 86_400_000 : histRange === '7d' ? Date.now() - 7 * 86_400_000 : 0
    return runs
      .filter((r) => (histFilter === 'all' ? true : histFilter === 'auto' ? r.auto === true : r.auto !== true))
      .filter((r) => r.startedAt >= cutoff)
  }, [runs, histFilter, histRange])
  /** per-chip honest counts (all / scheduled / manual) */
  const autoCount = useMemo(() => runs.filter((r) => r.auto === true).length, [runs])

  // ----- v7.3: history search + sort + per-run detail dialog -----
  /** client-side search over healthyIps[].ip / host / provider (case-insensitive substring; ≤30 runs ⇒ no debounce) */
  const [histQuery, setHistQuery] = useState('')
  /** 'date' = store order (already startedAt-desc) · 'healthy'/'tested' = metric desc, tie → startedAt desc */
  const [histSort, setHistSort] = useState<'date' | 'healthy' | 'tested'>('date')
  /** the run behind the open detail dialog (null = closed) */
  const [detailRun, setDetailRun] = useState<GoogleHuntHistoryRun | null>(null)

  /** copies the FULL healthy list of the run shown in the detail dialog (same ip:port join as the row copy) */
  const copyDetailIps = useCallback(() => {
    if (!detailRun) return
    const ips = (detailRun.healthyIps ?? []).map((c) => candidateAddr(c)).filter(Boolean)
    if (ips.length === 0) return
    void copyText(ips.join('\n'), 'hunt.hist.detail.copyall.ok', { n: num(ips.length) })
  }, [detailRun, copyText, num])

  /**
   * v7.3 — full composition pipeline: v7.2 auto/manual filter → search → sort.
   * Pagination (histShow + «نمایش بیشتر») slices THIS downstream; both the list
   * and the show-more button key off visibleRuns, never off filteredRuns.
   */
  const visibleRuns = useMemo(() => {
    const q = histQuery.trim().toLowerCase()
    const searched =
      q === ''
        ? filteredRuns
        : filteredRuns.filter(
            (r) =>
              r.host.toLowerCase().includes(q) ||
              (r.provider ?? '').toLowerCase().includes(q) ||
              (r.healthyIps ?? []).some((c) => c.ip.toLowerCase().includes(q)),
          )
    if (histSort === 'date') return searched // store order is already newest-first (current behavior)
    return [...searched].sort((a, b) => {
      const d = histSort === 'healthy' ? b.healthy - a.healthy : b.tested - a.tested
      return d !== 0 ? d : b.startedAt - a.startedAt
    })
  }, [filteredRuns, histQuery, histSort])

  /**
   * DELETE /api/hunt?id=… → optimistic local removal (no refetch needed). The
   * compareIds prune effect above (runs watcher) drops a deleted id from the
   * selection, so a comparison never references a run that no longer exists.
   */
  const deleteRun = useCallback(async () => {
    const id = pendingDelId
    if (!id || delBusy) return
    setDelBusy(true)
    try {
      const res = await fetch(`/api/hunt?id=${encodeURIComponent(id)}`, { method: 'DELETE' })
      const data = (res.ok ? await res.json().catch(() => null) : null) as { ok?: boolean } | null
      if (res.ok && data?.ok) {
        setRuns((prev) => prev.filter((r) => r.id !== id))
        setPendingDelId(null)
        toast.success(t('hunt.hist.del.ok'))
      } else {
        toast.error(t('hunt.hist.del.fail'))
      }
    } catch {
      toast.error(t('hunt.hist.del.fail'))
    } finally {
      setDelBusy(false)
    }
  }, [pendingDelId, delBusy, t])

  /** DELETE /api/hunt (no id) → clears the whole history AND the compare selection */
  const clearAllRuns = useCallback(async () => {
    if (clearBusy) return
    setClearBusy(true)
    try {
      const res = await fetch('/api/hunt', { method: 'DELETE' })
      const data = (res.ok ? await res.json().catch(() => null) : null) as { ok?: boolean } | null
      if (res.ok && data?.ok) {
        setRuns([])
        setCompareIds([]) // empty history cannot be compared (the prune effect would do the same)
        setConfirmClear(false)
        toast.success(t('hunt.hist.clear.ok'))
      } else {
        toast.error(t('hunt.hist.clear.fail'))
      }
    } catch {
      toast.error(t('hunt.hist.clear.fail'))
    } finally {
      setClearBusy(false)
    }
  }, [clearBusy, t])

  /** one metric row of a comparison column — winner cells get the subtle emerald tint + sr-only «بهتر» */
  const cmpRow = (label: string, value: string, winner = false) => (
    <div className="flex items-center justify-between gap-2">
      <dt className="shrink-0 text-[10px] text-muted-foreground">{label}</dt>
      <dd
        className={cn(
          'min-w-0 truncate rounded px-1 text-end font-mono text-[10px] leading-5 tabular-nums',
          winner ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'text-foreground',
        )}
        dir="ltr"
      >
        {winner ? <span className="sr-only">{t('hunt.cmp.better')}</span> : null}
        {value}
      </dd>
    </div>
  )

  /** everything the comparison card renders — null until EXACTLY two valid runs are picked */
  const cmp = useMemo(() => {
    const byId = new Map(runs.map((r) => [r.id, r]))
    const picked = compareIds.map((id) => byId.get(id)).filter((r): r is GoogleHuntHistoryRun => r !== undefined)
    if (picked.length !== 2) return null
    picked.sort((a, b) => b.startedAt - a.startedAt) // newest-first ⇒ A = newer, B = older
    const a = picked[0]!
    const b = picked[1]!
    // per-ISP convention reused: latency = tlsMs ?? tcpMs; entries missing both are excluded from the stats
    const lat = huntLatencyStats
    const aLat = lat(a.healthyIps ?? [])
    const bLat = lat(b.healthyIps ?? [])
    const aIps = (a.healthyIps ?? []).map((c) => c.ip)
    const bSet = new Set((b.healthyIps ?? []).map((c) => c.ip))
    const overlap = aIps.filter((ip) => bSet.has(ip))
    const rateOf = (r: GoogleHuntHistoryRun) => (r.tested > 0 ? r.healthy / r.tested : null)
    /** higher-is-better unless `lower`; ties and no-data (null) ⇒ no winner (honest) */
    const better = (va: number | null, vb: number | null, lower = false): 'a' | 'b' | null => {
      if (va == null || vb == null || va === vb) return null
      return (lower ? va < vb : va > vb) ? 'a' : 'b'
    }
    return {
      a,
      b,
      aLat,
      bLat,
      overlap,
      win: {
        healthy: better(a.healthy, b.healthy),
        rate: better(rateOf(a), rateOf(b)),
        avgTls: better(aLat?.avg ?? null, bLat?.avg ?? null, true),
      },
    }
  }, [runs, compareIds])

  const healthyTargetPct = s ? Math.min(100, Math.round((s.healthy / Math.max(1, s.target)) * 100)) : 0
  // funnel conversion rates (defensive: engine fields may be missing mid-upgrade)
  const tcpAlive = s?.tcpAlive ?? 0
  const verified = s?.verified ?? 0
  const verifyLevel = s?.verify ?? verify
  const hotBlocks = s && Array.isArray(s.hotBlocks) ? s.hotBlocks : []
  const tcpPct = s && s.tested > 0 ? Math.round((tcpAlive / s.tested) * 100) : 0
  const okPct = tcpAlive > 0 ? Math.round(((s?.healthy ?? 0) / tcpAlive) * 100) : 0
  // recon strip inputs (per-provider, hunt v4)
  const reconStatus = recon?.status ?? 'idle'
  const reconLoading = reconStatus === 'loading'
  const reconReady = reconStatus === 'ready' || (reconStatus === 'loading' && (recon?.total ?? 0) > 0)
  const fmtReconTime = useCallback(
    (ts: number) =>
      new Intl.DateTimeFormat(dateLocale, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(
        new Date(ts),
      ),
    [dateLocale],
  )

  // ----- parallel pipeline telemetry (hunt v5) — gated so legacy engine states render untouched -----
  const showParallel = !!s && (
    s.engine === 'pipeline-v5' ||
    s.inFlight !== undefined ||
    s.tlsInFlight !== undefined ||
    s.concurrency !== undefined ||
    s.tlsConcurrency !== undefined ||
    s.tcpPoolMax !== undefined ||
    s.tlsPoolMax !== undefined ||
    s.sampled !== undefined
  )
  const inFlight = s?.inFlight ?? 0
  const tlsInFlight = s?.tlsInFlight ?? 0
  const sampledCount = s?.sampled ?? 0
  /** pool utilisation 0..100, clamped — meters never overflow their track */
  const poolPct = (c: number | undefined, max: number | undefined) =>
    !max ? 0 : Math.min(100, Math.max(0, Math.round(((c ?? 0) / max) * 100)))
  const tcpPoolPct = poolPct(s?.concurrency, s?.tcpPoolMax)
  const tlsPoolPct = poolPct(s?.tlsConcurrency, s?.tlsPoolMax)

  return (
    <div
      className="rounded-xl border border-teal-500/20 bg-card/60 p-4 backdrop-blur sm:p-6"
      id="google-hunter"
    >
      {/* ---------- header ---------- */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="flex size-8 items-center justify-center rounded-lg bg-teal-500/10 text-teal-600 dark:text-teal-400">
            <Chrome className="size-4" aria-hidden />
          </span>
          <h2 className="text-base font-bold">{t('hunt.title')}</h2>
          <Badge
            variant="outline"
            className="border-teal-500/30 bg-teal-500/10 text-teal-600 dark:text-teal-400"
          >
            {t('hunt.badge')}
          </Badge>
          {running ? (
            <Badge className="border-teal-500/40 bg-teal-500/15 text-teal-700 dark:text-teal-300">
              <Loader2 className="size-3 animate-spin" aria-hidden />
              {t('hunt.stat.wave')} {num(s?.wave ?? 0)}
            </Badge>
          ) : null}
          {/* v7.0 — honest marker while a scheduler-triggered hunt is executing */}
          {running && s?.auto ? (
            <Badge
              variant="outline"
              className="gap-0.5 border-zinc-500/40 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
            >
              <CalendarClock className="size-2.5" aria-hidden />
              {t('hs.hist.badge')}
            </Badge>
          ) : null}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* verify-level selector */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="h-9 gap-1 px-2 text-teal-700 dark:text-teal-400"
                disabled={running}
                aria-label={t('hunt.verify.label')}
              >
                <BadgeCheck className="size-3.5" aria-hidden />
                <span className="font-mono text-[10px]" dir="ltr">
                  ×{num(verify)}
                </span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel dir={dir}>{t('hunt.verify.tip')}</DropdownMenuLabel>
              {VERIFY_LEVELS.map((v) => (
                <DropdownMenuItem
                  key={v}
                  onClick={() => setVerify(v)}
                  className="cursor-pointer justify-between gap-3"
                >
                  <span>{t(`hunt.verify.${v}` as DictKey)}</span>
                  {verify === v ? <Check className="size-3.5 text-emerald-500" aria-hidden /> : null}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>

          {/* target selector */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="h-9 gap-1 px-2 text-teal-700 dark:text-teal-400"
                disabled={running}
                aria-label={t('hunt.target.label')}
              >
                <Target className="size-3.5" aria-hidden />
                <span className="font-mono text-[10px]" dir="ltr">
                  ×{num(target)}
                </span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel dir={dir}>{t('hunt.target.tip')}</DropdownMenuLabel>
              {TARGETS.map((n) => (
                <DropdownMenuItem
                  key={n}
                  onClick={() => setTarget(n)}
                  className="cursor-pointer justify-between gap-3"
                >
                  <span className="font-mono" dir="ltr">
                    ×{num(n)}
                  </span>
                  {target === n ? <Check className="size-3.5 text-emerald-500" aria-hidden /> : null}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>

          {/* start / stop */}
          {running ? (
            <Button
              variant="outline"
              size="sm"
              className="h-9 gap-1.5 border-red-500/30 text-red-600 hover:bg-red-500/10 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
              onClick={() => void handleStop()}
              disabled={busy}
            >
              <Square className="size-3.5" aria-hidden />
              <span className="hidden sm:inline">{t('hunt.stop')}</span>
            </Button>
          ) : (
            <div className="flex items-center gap-2">
              {s && (s.healthyIps.length > 0 || s.tested > 0) ? (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-9 gap-1.5 text-muted-foreground hover:text-foreground"
                  onClick={() => void handleReset()}
                  disabled={busy}
                >
                  <RotateCcw className="size-3.5" aria-hidden />
                  <span className="hidden sm:inline">{t('hunt.reset')}</span>
                </Button>
              ) : null}
              <Button
                size="sm"
                className="h-9 gap-1.5 bg-teal-600 text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-600"
                onClick={() => void handleStart()}
                disabled={
                  busy ||
                  !connected ||
                  (provider === 'custom' && customCidrs.length === 0) ||
                  // hunt v6.1 — a selection that somehow holds zero ranges must never start
                  (!!selectedRanges && selectedRanges.cidrs.length === 0)
                }
              >
                {busy ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <Play className="size-3.5" aria-hidden />}
                <span className="hidden sm:inline">{t('hunt.start')}</span>
                <span className="font-mono text-[10px] sm:hidden" dir="ltr">
                  ×{num(target)}
                </span>
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* ---------- description ---------- */}
      <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
        {t('hunt.desc', { n: num(target) })}
        {s && s.provider && s.provider !== 'all' ? (
          <span className="ms-1 font-mono text-[10px]" dir="ltr">
            {t('hunt.sni', { host: s.host, port: num(s.port) })}
          </span>
        ) : null}
      </p>

      {/* ---------- provider selector (hunt v4 multi-provider) ---------- */}
      <div className="mt-3 flex flex-wrap items-center gap-1.5" role="group" aria-label={t('hunt.provider.label')}>
        <span className="flex items-center gap-1 text-[11px] font-semibold text-muted-foreground">
          <Layers className="size-3.5 text-teal-500" aria-hidden />
          {t('hunt.provider.label')}
        </span>
        {PROVIDER_CHIPS.map((p) => (
          <TooltipProvider key={p.id} delayDuration={120}>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  aria-pressed={provider === p.id}
                  disabled={running}
                  onClick={() => setProvider(p.id)}
                  className={cn(
                    'rounded-md border px-2 py-1 text-[11px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50',
                    provider === p.id ? p.activeCls : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                  )}
                >
                  {t(p.labelKey)}
                </button>
              </TooltipTrigger>
              <TooltipContent dir={dir} className="text-[10px]">
                {p.id === 'custom' ? t('hunt.custom.tip') : t('hunt.provider.tip')}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ))}

        {/* hunt v6.1 — range checklist button (visible only when recon carries ranges; hidden on legacy engines) */}
        {reconReady && reconHasRanges ? (
          <TooltipProvider delayDuration={120}>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  aria-pressed={!!selectedRanges}
                  disabled={running}
                  onClick={openRanges}
                  className={cn(
                    'flex min-h-11 items-center gap-1 rounded-md border px-2 py-1 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 disabled:cursor-not-allowed disabled:opacity-50',
                    selectedRanges
                      ? 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                      : 'border-zinc-500/50 bg-zinc-500/10 text-zinc-700 dark:text-zinc-300',
                  )}
                >
                  <ListChecks className="size-3" aria-hidden />
                  {t('hunt.ranges.btn')}
                  {selectedRanges ? (
                    <span className="font-mono text-[10px]" dir="ltr">
                      ({num(selectedRanges.cidrs.length)})
                    </span>
                  ) : null}
                </button>
              </TooltipTrigger>
              <TooltipContent dir={dir} className="text-[10px]">
                {t('hunt.ranges.desc')}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ) : null}
      </div>

      {/* ---------- hunt v6.1 — active range selection tile (amber) ---------- */}
      {selectedRanges ? (
        <div
          className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2"
          role="status"
          aria-label={t('hunt.selected.tile', { n: num(selectedRanges.cidrs.length) })}
        >
          <p className="flex min-w-0 flex-wrap items-center gap-1.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300">
            <ListChecks className="size-3.5 shrink-0" aria-hidden />
            {t('hunt.selected.tile', { n: num(selectedRanges.cidrs.length) })}
            <Badge
              variant="outline"
              className="border-amber-500/40 bg-background/60 px-1 py-0 text-[9px] font-normal text-amber-700 dark:text-amber-300"
            >
              {t(`hunt.provider.${selectedRanges.provider}` as DictKey)}
            </Badge>
          </p>
          <button
            type="button"
            onClick={clearSelectedRanges}
            disabled={running}
            aria-label={t('hunt.selected.clear')}
            className="inline-flex size-7 shrink-0 items-center justify-center rounded-md text-amber-700 transition-colors hover:bg-amber-500/20 hover:text-amber-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60 disabled:cursor-not-allowed disabled:opacity-50 dark:text-amber-300 dark:hover:text-amber-100"
          >
            <X className="size-3.5" aria-hidden />
          </button>
        </div>
      ) : null}

      {/* ---------- custom provider — user CIDR ranges (hunt v6.0) ---------- */}
      {provider === 'custom' ? (
        <div
          className="mt-3 rounded-lg border border-zinc-500/30 bg-zinc-500/5 p-3"
          role="group"
          aria-label={t('hunt.custom.ranges')}
        >
          <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
            <TooltipProvider delayDuration={120}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="flex cursor-default items-center gap-1 text-[11px] font-semibold text-muted-foreground">
                    <Layers className="size-3.5 text-zinc-500" aria-hidden />
                    {t('hunt.custom.ranges')}
                  </span>
                </TooltipTrigger>
                <TooltipContent dir={dir} className="text-[10px]">
                  {t('hunt.custom.tip')}
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            <span
              className="rounded-md border border-zinc-500/30 bg-background/60 px-1.5 py-0.5 text-[10px] font-medium text-zinc-600 dark:text-zinc-300"
              aria-live="polite"
            >
              {t('hunt.custom.count', { n: num(customCidrs.length) })}
            </span>
          </div>
          <Textarea
            value={customRangesText}
            onChange={(e) => setCustomRangesText(e.target.value)}
            dir="ltr"
            placeholder={t('hunt.custom.placeholder')}
            aria-label={t('hunt.custom.ranges')}
            spellCheck={false}
            className="max-h-40 min-h-20 w-full overflow-y-auto font-mono text-xs"
          />
          <p className="mt-1.5 text-[10px] text-muted-foreground">{t('hunt.custom.tip')}</p>
        </div>
      ) : null}

      {/* ---------- engine speed preset (hunt v5 parallel pools) ---------- */}
      <div className="mt-3 flex flex-wrap items-center gap-1.5" role="group" aria-label={t('hunt.speed.label')}>
        <span className="flex items-center gap-1 text-[11px] font-semibold text-muted-foreground">
          <Gauge className="size-3.5 text-teal-500" aria-hidden />
          {t('hunt.speed.label')}
        </span>
        {SPEED_PRESETS.map((sp) => (
          <TooltipProvider key={sp.id} delayDuration={120}>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  aria-pressed={speed === sp.id}
                  disabled={running}
                  onClick={() => setSpeed(sp.id)}
                  className={cn(
                    'flex min-h-11 items-center rounded-md border px-3 py-1 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 disabled:cursor-not-allowed disabled:opacity-50',
                    speed === sp.id ? SPEED_ACTIVE_CLS : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                  )}
                >
                  {t(sp.labelKey)}
                </button>
              </TooltipTrigger>
              <TooltipContent dir={dir} className="text-[10px]">
                <p>{t('hunt.speed.tip')}</p>
                <p className="mt-0.5 font-mono" dir="ltr">
                  TCP {num(sp.tcp)} · TLS {num(sp.tls)}
                </p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ))}

        {/* hunt v6.1 — IPv6 sampling toggle chip (hidden for the custom provider; inert when the scope has no v6 source) */}
        {provider !== 'custom' ? (
          <TooltipProvider delayDuration={120}>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  role="switch"
                  aria-checked={enableV6}
                  disabled={running}
                  onClick={() => setEnableV6((v) => !v)}
                  className={cn(
                    'flex min-h-11 items-center gap-1 rounded-md border px-3 py-1 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 disabled:cursor-not-allowed disabled:opacity-50',
                    enableV6
                      ? 'border-teal-500/50 bg-teal-500/10 text-teal-700 dark:text-teal-300'
                      : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                  )}
                >
                  <Globe className="size-3" aria-hidden />
                  {t('hunt.v6.label')}
                </button>
              </TooltipTrigger>
              <TooltipContent dir={dir} className="text-[10px]">
                <p>{t('hunt.v6.note')}</p>
                {v6SourceCount === 0 ? (
                  <p className="mt-0.5 text-amber-600 dark:text-amber-400">{t('hunt.v6.none')}</p>
                ) : null}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ) : null}

        {/* hunt v6.4 — censorship forensics toggle chip (same pattern as the IPv6 chip; default on) */}
        <TooltipProvider delayDuration={120}>
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                type="button"
                role="switch"
                aria-checked={forensicsOn}
                disabled={running}
                onClick={() => setForensicsOn((v) => !v)}
                className={cn(
                  'flex min-h-11 items-center gap-1 rounded-md border px-3 py-1 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60 disabled:cursor-not-allowed disabled:opacity-50',
                  forensicsOn
                    ? 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                    : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                )}
              >
                <ShieldX className="size-3" aria-hidden />
                {t('hunt.forensics.label')}
              </button>
            </TooltipTrigger>
            <TooltipContent dir={dir} className="text-[10px]">
              <p>{t('hunt.forensics.note')}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>

      {/* hunt v6.1 — one-line v6 note under the settings row (warns when the scope has no IPv6 source) */}
      {provider !== 'custom' ? (
        <p
          className={cn(
            'mt-1.5 text-[10px]',
            v6SourceCount === 0 ? 'text-amber-600 dark:text-amber-400' : 'text-muted-foreground',
          )}
        >
          {v6SourceCount === 0 ? t('hunt.v6.none') : t('hunt.v6.note')}
        </p>
      ) : null}

      {/* ---------- hunt v6.3 — per-provider custom probe targets (collapsible, default closed) ---------- */}
      <div className="mt-3 rounded-lg border border-zinc-500/30 bg-zinc-500/5">
        <button
          type="button"
          aria-expanded={ovOpen}
          onClick={() => setOvOpen((v) => !v)}
          className="flex min-h-11 w-full items-center justify-between gap-2 px-3 py-2 text-start transition-colors hover:bg-zinc-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-500/60"
        >
          <span className="flex items-center gap-1.5 text-[11px] font-semibold text-zinc-700 dark:text-zinc-300">
            <Crosshair className="size-3.5 text-zinc-500" aria-hidden />
            {t('hunt.ov.title')}
          </span>
          <ChevronDown
            className={cn('size-3.5 shrink-0 text-zinc-500 transition-transform', ovOpen && 'rotate-180')}
            aria-hidden
          />
        </button>
        {ovOpen ? (
          <div className="space-y-2.5 border-t border-zinc-500/20 px-3 py-3">
            <HuntOvRow
              labelKey="hunt.provider.google"
              badgeCls="border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
              value={ovGoogle}
              onChange={setOvGoogle}
              hostPlaceholder="www.google.com"
              pathPlaceholder="/generate_204"
              disabled={running}
            />
            <HuntOvRow
              labelKey="hunt.provider.cloudflare"
              badgeCls="border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400"
              value={ovCloud}
              onChange={setOvCloud}
              hostPlaceholder="www.cloudflare.com"
              pathPlaceholder="/"
              disabled={running}
            />
            <p className="text-[10px] leading-relaxed text-muted-foreground">{t('hunt.ov.note')}</p>
          </div>
        ) : null}
      </div>

      {/* ---------- v7.0 — engine-side hunt scheduler (auto hunt) ---------- */}
      <div
        className="mt-3 rounded-lg border border-teal-500/25 bg-teal-500/5 p-3"
        role="group"
        aria-label={t('hs.title')}
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <CalendarClock className="size-3.5 text-teal-500" aria-hidden />
            {t('hs.title')}
            {schedState.enabled ? (
              <Badge
                variant="outline"
                className="border-emerald-500/40 bg-emerald-500/10 px-1 py-0 text-[9px] text-emerald-600 dark:text-emerald-400"
              >
                {t('hs.badge.on')}
              </Badge>
            ) : null}
          </p>
          <label htmlFor="hs-switch" className="flex cursor-pointer items-center gap-2 text-[11px] text-muted-foreground">
            {t('hs.switch')}
            <Switch
              id="hs-switch"
              checked={schedState.enabled}
              onCheckedChange={(v) => void handleSchedToggle(v === true)}
              disabled={!connected || schedBusy}
              aria-label={t('hs.switch')}
            />
          </label>
        </div>

        <p className="mt-1.5 text-[10px] leading-relaxed text-muted-foreground">
          {!connected ? t('hunt.offline') : t('hs.desc')}
        </p>

        {/* interval presets — while disabled they are local-only (applied on next enable) */}
        <div className="mt-2 flex flex-wrap items-center gap-1.5" role="group" aria-label={t('hs.interval.aria')}>
          <span className="flex items-center gap-1 text-[11px] font-semibold text-muted-foreground">
            <Timer className="size-3.5 text-teal-500" aria-hidden />
            {t('hs.interval')}
          </span>
          {HUNT_SCHED_INTERVALS.map((m) => (
            <button
              key={m}
              type="button"
              aria-pressed={hsInterval === m}
              disabled={schedBusy}
              onClick={() => void handleSchedInterval(m)}
              className={cn(
                'flex min-h-11 items-center rounded-md border px-2.5 py-1 font-mono text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 disabled:cursor-not-allowed disabled:opacity-50',
                hsInterval === m
                  ? 'border-teal-500/50 bg-teal-500/10 text-teal-700 dark:text-teal-300'
                  : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
              )}
            >
              {t('hs.interval.chip', { n: num(m) })}
            </button>
          ))}
        </div>

        {/* live status — only when the engine actually reports an armed schedule (no fake countdown) */}
        {schedState.enabled ? (
          <div
            className="mt-2 grid grid-cols-1 gap-1.5 rounded-md border border-teal-500/20 bg-background/50 p-2 sm:grid-cols-3"
            role="status"
            aria-label={t('hs.state.aria')}
          >
            <div>
              <p className="text-[10px] text-muted-foreground">{t('hs.next')}</p>
              {schedState.running ? (
                <p className="mt-0.5 flex items-center gap-1 text-xs font-bold text-teal-700 dark:text-teal-300">
                  <Loader2 className="size-3 animate-spin" aria-hidden />
                  {t('hs.running')}
                </p>
              ) : schedNextIn == null ? (
                <p className="mt-0.5 font-mono text-xs font-bold text-muted-foreground">—</p>
              ) : schedCountdownText != null && schedNextIn > 0 ? (
                <p
                  className="mt-0.5 font-mono text-sm font-bold tabular-nums text-teal-700 dark:text-teal-300"
                  dir="ltr"
                  aria-label={t('hs.next.aria')}
                >
                  {schedCountdownText}
                </p>
              ) : (
                <p className="mt-0.5 text-xs font-bold text-teal-700 dark:text-teal-300">{t('hs.next.soon')}</p>
              )}
            </div>
            <div>
              <p className="text-[10px] text-muted-foreground">{t('hs.runs')}</p>
              <p className="mt-0.5 font-mono text-sm font-bold tabular-nums" dir="ltr">
                {num(schedState.runsCount)}
              </p>
            </div>
            <div>
              <p className="text-[10px] text-muted-foreground">{t('hs.last')}</p>
              <p className="mt-0.5 text-xs font-bold">
                {schedState.lastRunAt == null ? (
                  <span className="font-mono text-muted-foreground">—</span>
                ) : (
                  formatDistanceToNow(new Date(schedState.lastRunAt), {
                    addSuffix: true,
                    locale: lang === 'fa' ? faIR : enUS,
                  })
                )}
              </p>
            </div>
          </div>
        ) : null}

        {/* engine-captured settings echo (engine truth, not the form) */}
        {schedState.enabled && schedState.settings ? (
          <p className="mt-1.5 text-[10px] text-muted-foreground">
            {t('hs.captured', { n: num(schedState.settings.target ?? 0), host: schedState.settings.host ?? '—' })}
          </p>
        ) : null}

        {/* settings-drift hint — amber, with a one-tap re-capture */}
        {schedDrift ? (
          <div
            className="mt-2 flex flex-wrap items-center justify-between gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-2.5 py-2"
            role="alert"
          >
            <p className="flex min-w-0 items-center gap-1.5 text-[11px] font-medium text-amber-700 dark:text-amber-300">
              <AlertCircle className="size-3.5 shrink-0" aria-hidden />
              {t('hs.drift')}
            </p>
            <Button
              type="button"
              size="sm"
              className="h-8 gap-1 bg-amber-600 text-white hover:bg-amber-700 dark:bg-amber-500 dark:hover:bg-amber-600"
              onClick={() => void handleSchedUpdate()}
              disabled={schedBusy || !connected}
            >
              <RefreshCw className={cn('size-3', schedBusy && 'animate-spin')} aria-hidden />
              {t('hs.drift.update')}
            </Button>
          </div>
        ) : null}

        {/* ---------- v7.1 — scheduler journal (fires / dones / postponements, newest-first) ---------- */}
        <div className="mt-2 rounded-lg border border-zinc-500/30 bg-zinc-500/5">
          {/* v7.2 — flex row wrapper: the collapse toggle stays its own <button> and the
             CSV export button sits BESIDE it (never nested inside the toggle) */}
          <div className="flex items-center gap-1 pe-2">
            <button
              type="button"
              aria-expanded={jrnOpen}
              onClick={() => setJrnOpen((v) => !v)}
              className="flex min-h-11 min-w-0 flex-1 items-center justify-between gap-2 px-3 py-2 text-start transition-colors hover:bg-zinc-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-500/60"
            >
              <span className="flex items-center gap-1.5 text-[11px] font-semibold text-zinc-700 dark:text-zinc-300">
                <ListChecks className="size-3.5 text-zinc-500" aria-hidden />
                {t('hunt.jrn.title')}
              </span>
              <span className="flex items-center gap-1.5">
                <span
                  className="rounded border border-zinc-500/40 bg-background/60 px-1.5 py-0.5 font-mono text-[10px] tabular-nums text-zinc-600 dark:text-zinc-300"
                  dir="ltr"
                >
                  {num(schedJournal.length)}
                </span>
                <ChevronDown
                  className={cn('size-3.5 shrink-0 text-zinc-500 transition-transform', jrnOpen && 'rotate-180')}
                  aria-hidden
                />
              </span>
            </button>
            {/* v7.2 — journal CSV export (honest: disabled while the journal is empty) */}
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation() // defensive: never toggle the collapsible from this button
                exportJournalCsv()
              }}
              disabled={schedJournal.length === 0}
              aria-label={t('hunt.jrn.export')}
              className="inline-flex size-8 shrink-0 items-center justify-center self-center rounded-md text-muted-foreground transition-colors hover:bg-emerald-500/10 hover:text-emerald-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/60 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent dark:hover:text-emerald-400 sm:size-7"
            >
              <Download className="size-3.5" aria-hidden />
            </button>
          </div>
          {/* honest empty: no entries ⇒ only the header with count ۰, no empty-state box */}
          {jrnOpen && schedJournal.length > 0 ? (
            <ul className="space-y-1 border-t border-zinc-500/20 px-3 py-2" aria-label={t('hunt.jrn.title')}>
              {schedJournal.slice(0, HUNT_SCHEDULE_JOURNAL_CAP).map((e, i) => {
                const text =
                  e.kind === 'done'
                    ? t('hunt.jrn.done.stats', {
                        h: num(e.healthy ?? 0),
                        t: num(e.tested ?? 0),
                        d: fmtDur(e.durationMs ?? 0),
                      })
                    : e.kind === 'postponed'
                      ? t('hunt.jrn.postponed')
                      : t('hunt.jrn.fire')
                // v7.6 — per-fire settings echo (kind=fire only; '' when absent/empty)
                const echo = e.kind === 'fire' && e.settings ? journalFireEcho(e.settings) : ''
                return (
                  <li
                    key={`${e.at}-${i}`}
                    role="button"
                    tabIndex={0}
                    aria-label={t('hunt.jrn.detail.open')}
                    onClick={() => setJrnDetail(e)}
                    onKeyDown={(ev) => {
                      if (ev.key === 'Enter' || ev.key === ' ') {
                        ev.preventDefault()
                        setJrnDetail(e)
                      }
                    }}
                    className="flex cursor-pointer items-center gap-2 rounded-md border border-zinc-500/20 bg-background/50 px-2 py-1.5 transition-colors hover:border-zinc-500/40 hover:bg-background/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-500/60"
                  >
                    {e.kind === 'done' ? (
                      <CheckCircle2 className="size-3.5 shrink-0 text-emerald-500" aria-hidden />
                    ) : e.kind === 'postponed' ? (
                      <TimerOff className="size-3.5 shrink-0 text-amber-500" aria-hidden />
                    ) : (
                      <Zap className="size-3.5 shrink-0 text-zinc-500" aria-hidden />
                    )}
                    <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                      <span
                        className={cn(
                          'text-[11px]',
                          e.kind === 'postponed'
                            ? 'font-medium text-amber-700 dark:text-amber-300'
                            : 'text-foreground',
                        )}
                      >
                        {text}
                        {e.kind === 'done' && e.stopped ? (
                          <span className="ms-1 font-mono text-[10px] text-zinc-500" aria-hidden>
                            ■
                          </span>
                        ) : null}
                      </span>
                      {echo !== '' ? (
                        <span
                          dir="ltr"
                          title={t('hunt.jrn.fire.settings')}
                          aria-label={t('hunt.jrn.fire.settings')}
                          className="truncate font-mono text-[10px] tabular-nums text-zinc-500 dark:text-zinc-400"
                        >
                          {echo}
                        </span>
                      ) : null}
                    </span>
                    <span className="ms-auto shrink-0 text-[10px] text-muted-foreground">
                      {formatDistanceToNow(new Date(e.at), {
                        addSuffix: true,
                        locale: lang === 'fa' ? faIR : enUS,
                      })}
                    </span>
                  </li>
                )
              })}
            </ul>
          ) : null}
        </div>

        {/* ---------- v7.7 — per-event journal detail dialog ---------- */}
        <Dialog
          open={!!jrnDetail}
          onOpenChange={(open) => {
            if (!open) setJrnDetail(null)
          }}
        >
          <DialogContent dir={dir} className="max-h-[85dvh] max-w-md overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <span className="flex size-7 items-center justify-center rounded-lg bg-zinc-500/10 text-zinc-600 dark:text-zinc-300">
                  {jrnDetail?.kind === 'done' ? (
                    <CheckCircle2 className="size-4" aria-hidden />
                  ) : jrnDetail?.kind === 'postponed' ? (
                    <TimerOff className="size-4" aria-hidden />
                  ) : (
                    <Zap className="size-4" aria-hidden />
                  )}
                </span>
                {t('hunt.jrn.detail.title')}
              </DialogTitle>
              <DialogDescription>
                {jrnDetail?.kind === 'done'
                  ? t('hunt.jrn.kind.done')
                  : jrnDetail?.kind === 'postponed'
                    ? t('hunt.jrn.kind.postponed')
                    : t('hunt.jrn.kind.fire')}
              </DialogDescription>
            </DialogHeader>
            {jrnDetail ? (
              <div className="space-y-2.5">
                {/* event time */}
                <div className="rounded-lg border bg-background/40 px-3 py-2">
                  <div className="text-[10px] text-muted-foreground">{t('hunt.jrn.detail.at')}</div>
                  <div className="mt-0.5 font-mono text-xs font-semibold" dir="ltr">
                    {new Date(jrnDetail.at).toLocaleString(dateLocale)}
                  </div>
                  <div className="mt-0.5 text-[10px] text-muted-foreground">
                    {formatDistanceToNow(new Date(jrnDetail.at), {
                      addSuffix: true,
                      locale: lang === 'fa' ? faIR : enUS,
                    })}
                  </div>
                </div>

                {/* v7.7 — full settings echo for fire events (the journal row only shows a compact LTR summary) */}
                {jrnDetail.kind === 'fire' ? (
                  jrnDetail.settings ? (
                    <div>
                      <div className="mb-1 text-[11px] font-semibold text-muted-foreground">
                        {t('hunt.jrn.detail.settings')}
                      </div>
                      <div className="grid grid-cols-2 gap-1.5">
                        {([
                          [t('hunt.jrn.detail.provider'), jrnDetail.settings.provider],
                          [t('hunt.jrn.detail.host'), jrnDetail.settings.host],
                          [t('hunt.jrn.detail.port'), jrnDetail.settings.port != null ? num(jrnDetail.settings.port) : null],
                          [t('hunt.jrn.detail.target'), jrnDetail.settings.target != null ? num(jrnDetail.settings.target) : null],
                          [t('hunt.jrn.detail.batch'), jrnDetail.settings.batchSize != null ? num(jrnDetail.settings.batchSize) : null],
                          [t('hunt.jrn.detail.conc'), jrnDetail.settings.concurrency != null ? num(jrnDetail.settings.concurrency) : null],
                          [t('hunt.jrn.detail.verify'), jrnDetail.settings.verify != null ? num(jrnDetail.settings.verify) : null],
                          [t('hunt.jrn.detail.speed'), jrnDetail.settings.speed],
                        ] as Array<[string, string | number | null | undefined]>)
                          .filter(([, v]) => v != null && v !== '')
                          .map(([k, v]) => (
                            <div key={k} className="rounded-lg border bg-background/40 px-2.5 py-1.5">
                              <div className="truncate text-[9.5px] text-muted-foreground">{k}</div>
                              <div className="mt-0.5 truncate font-mono text-[11px] font-semibold" dir="ltr">
                                {v}
                              </div>
                            </div>
                          ))}
                      </div>
                    </div>
                  ) : (
                    <p className="rounded-lg border border-dashed bg-background/40 px-3 py-2 text-[11px] text-muted-foreground">
                      {t('hunt.jrn.detail.nothing')}
                    </p>
                  )
                ) : null}

                {/* done events — full run stats */}
                {jrnDetail.kind === 'done' ? (
                  <div>
                    <div className="mb-1 text-[11px] font-semibold text-muted-foreground">{t('hunt.jrn.detail.result')}</div>
                    <div className="grid grid-cols-2 gap-1.5">
                      {([
                        [t('hunt.jrn.detail.tested'), num(jrnDetail.tested ?? 0)],
                        [t('hunt.jrn.detail.healthy'), num(jrnDetail.healthy ?? 0)],
                        [
                          t('hunt.jrn.detail.rate'),
                          jrnDetail.tested
                            ? `${num(Math.round(((jrnDetail.healthy ?? 0) / jrnDetail.tested) * 1000) / 10)}%`
                            : '—',
                        ],
                        [t('hunt.jrn.detail.duration'), fmtDur(jrnDetail.durationMs ?? 0)],
                        [t('hunt.jrn.detail.stopped'), jrnDetail.stopped ? '■' : null],
                      ] as Array<[string, string | null]>)
                        .filter(([, v]) => v !== null)
                        .map(([k, v]) => (
                          <div key={k} className="rounded-lg border bg-background/40 px-2.5 py-1.5">
                            <div className="truncate text-[9.5px] text-muted-foreground">{k}</div>
                            <div className="mt-0.5 truncate font-mono text-[11px] font-semibold" dir="ltr">
                              {v}
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>
                ) : null}

                {/* postponed events — honest explanation */}
                {jrnDetail.kind === 'postponed' ? (
                  <p className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-700 dark:text-amber-300">
                    {t('hunt.jrn.postponed')}
                  </p>
                ) : null}
              </div>
            ) : null}
          </DialogContent>
        </Dialog>
      </div>

      {/* ---------- recon strip (reverse-engineered Google intelligence) ---------- */}
      <div className="mt-3 rounded-lg border border-teal-500/20 bg-teal-500/5 p-3" aria-live="polite">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <Radar className={cn('size-3.5 text-teal-500', reconLoading && 'animate-pulse')} aria-hidden />
            {t('hunt.recon.title')}
            {reconStatus === 'ready' ? (
              <Badge
                variant="outline"
                className="border-emerald-500/30 bg-emerald-500/10 px-1 py-0 text-[9px] text-emerald-600 dark:text-emerald-400"
              >
                <ShieldCheck className="size-2.5" aria-hidden />
                {t('hunt.recon.status.ready')}
              </Badge>
            ) : reconLoading ? (
              <Badge
                variant="outline"
                className="border-amber-500/30 bg-amber-500/10 px-1 py-0 text-[9px] text-amber-600 dark:text-amber-400"
              >
                <Loader2 className="size-2.5 animate-spin" aria-hidden />
                {t('hunt.recon.status.loading')}
              </Badge>
            ) : reconStatus === 'failed' ? (
              <Badge
                variant="outline"
                className="border-red-500/30 bg-red-500/10 px-1 py-0 text-[9px] text-red-600 dark:text-red-400"
              >
                <ShieldX className="size-2.5" aria-hidden />
                {t('hunt.recon.status.failed')}
              </Badge>
            ) : (
              <Badge
                variant="outline"
                className="border-zinc-500/30 bg-zinc-500/10 px-1 py-0 text-[9px] text-zinc-500"
              >
                {t('hunt.recon.status.idle')}
              </Badge>
            )}
          </p>
          <TooltipProvider delayDuration={120}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 gap-1 px-2 text-[11px] text-teal-700 hover:bg-teal-500/10 hover:text-teal-800 dark:text-teal-400"
                  onClick={() => void handleRefreshRecon()}
                  disabled={reconBusy || reconLoading || !connected}
                  aria-label={t('hunt.recon.refresh')}
                >
                  <RefreshCw className={cn('size-3', (reconBusy || reconLoading) && 'animate-spin')} aria-hidden />
                  <span className="hidden sm:inline">{t('hunt.recon.refresh')}</span>
                </Button>
              </TooltipTrigger>
              <TooltipContent dir={dir} className="text-[10px]">
                {t('hunt.recon.refresh.tip')}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>

        {recon && reconReady ? (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <TooltipProvider delayDuration={120}>
              {/* per-provider recon chips (hunt v4) */}
              {HUNT_PROVIDER_IDS_UI.map((pid) => {
                const p = recon.providers[pid]
                if (!p) return null // legacy engines carry no 'custom' entry
                const dotCls =
                  p.status === 'ready'
                    ? 'bg-emerald-500'
                    : p.status === 'loading'
                      ? 'bg-amber-500 animate-pulse'
                      : p.status === 'failed'
                        ? 'bg-red-500'
                        : 'bg-zinc-400'
                const srcs = Object.entries(p.sources).filter(([, n]) => n > 0)
                return (
                  <Tooltip key={pid}>
                    <TooltipTrigger asChild>
                      <span
                        className="inline-flex cursor-default items-center gap-1 rounded-md border border-teal-500/30 bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-teal-700 dark:text-teal-300"
                        dir="ltr"
                      >
                        <span className={cn('size-1.5 rounded-full', dotCls)} aria-hidden />
                        {t(`hunt.provider.${pid}` as DictKey)} {num(p.cidrs)}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent dir={dir} className="text-[10px]">
                      {srcs.map(([k, n]) => (
                        <p key={k} className="font-mono" dir="ltr">
                          {k}: {num(n)} — {SOURCE_TIP[k] ? t(SOURCE_TIP[k]) : ''}
                        </p>
                      ))}
                      {p.updatedAt > 0 ? (
                        <p className="mt-0.5 opacity-80">{fmtReconTime(p.updatedAt)}</p>
                      ) : null}
                    </TooltipContent>
                  </Tooltip>
                )
              })}
              {/* merged live pool */}
              <span
                className="inline-flex cursor-default items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[10px] text-emerald-600 dark:text-emerald-400"
                dir="ltr"
              >
                <Target className="size-2.5" aria-hidden />
                {t('hunt.recon.cidrs', { n: num(recon.total) })}
              </span>
              {/* PTR fingerprint chip (Google user-facing edge) */}
              <Tooltip>
                <TooltipTrigger asChild>
                  <span
                    className="inline-flex cursor-default items-center gap-1 rounded-md border border-violet-500/30 bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-violet-700 dark:text-violet-300"
                    dir="ltr"
                  >
                    <Radar className="size-2.5" aria-hidden />
                    1e100 {num(recon.ptr.edge)}/{num(recon.ptr.scanned)}
                  </span>
                </TooltipTrigger>
                <TooltipContent dir={dir} className="text-[10px]">
                  <p>{t('hunt.recon.ptr.tip')}</p>
                  {recon.ptr.top.length > 0 ? (
                    <p className="mt-1 font-mono text-[9px]" dir="ltr">
                      {recon.ptr.top.join(' · ')}
                    </p>
                  ) : null}
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            {recon.updatedAt > 0 ? (
              <span className="text-[9px] text-muted-foreground/70" dir="ltr">
                {fmtReconTime(recon.updatedAt)}
              </span>
            ) : null}
          </div>
        ) : reconStatus === 'failed' ? (
          <p className="mt-2 text-[10px] text-amber-600 dark:text-amber-400">{t('hunt.recon.failed')}</p>
        ) : (
          <p className="mt-2 text-[10px] text-muted-foreground">{t('hunt.recon.status.idle.tip')}</p>
        )}

        {/* hunt v6.4 — last recon pull health per named source (rate-limit resilience observability) */}
        {recon?.health && Object.keys(recon.health).length > 0 ? (
          <div className="mt-1.5 flex flex-wrap items-center gap-1">
            <span className="text-[10px] text-muted-foreground">{t('hunt.health.title')}</span>
            {Object.entries(recon.health)
              .sort(([a], [b]) => a.localeCompare(b))
              .slice(0, 12)
              .map(([key, h]) =>
                h && typeof h.ok === 'boolean' ? (
                  <span
                    key={key}
                    className={cn(
                      'inline-flex cursor-default items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[9px]',
                      h.ok
                        ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                        : 'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400',
                    )}
                    dir="ltr"
                  >
                    {key}
                    {h.ok ? (
                      <CheckCircle2 className="size-2.5 shrink-0" aria-hidden />
                    ) : (
                      <ShieldX className="size-2.5 shrink-0" aria-hidden />
                    )}
                    {h.ok ? num(h.ms) : (h.err ?? 'err').slice(0, 20)}
                  </span>
                ) : null,
              )}
          </div>
        ) : null}
      </div>

      {/* ---------- target progress ---------- */}
      {s ? (
        <div className="mt-4">
          <div className="mb-1.5 flex items-center justify-between text-xs">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <Crosshair className="size-3.5 text-teal-500" aria-hidden />
              {t('hunt.progress.tip', { h: num(s.healthy), t: num(s.target) })}
            </span>
            <span className="flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground" dir="ltr">
              <Timer className="size-3.5" aria-hidden />
              {fmtElapsed(s.elapsedMs)}
              <span aria-hidden>·</span>
              <Signal className="size-3.5" aria-hidden />
              {num(s.ipsPerSecond)}/s
            </span>
          </div>
          <Progress value={healthyTargetPct} className="h-2" aria-label={t('hunt.progress.tip', { h: num(s.healthy), t: num(s.target) })} />
        </div>
      ) : null}

      {/* ---------- detection funnel (v2) ---------- */}
      {s && s.tested > 0 ? (
        <div className="mt-4 rounded-lg border bg-background/40 p-3">
          <p className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <Filter className="size-3" aria-hidden />
            {t('hunt.funnel.title')}
            {verifyLevel > 0 ? (
              <Badge
                variant="outline"
                className="border-emerald-500/30 bg-emerald-500/10 px-1 py-0 text-[9px] text-emerald-600 dark:text-emerald-400"
              >
                {t('hunt.funnel.verify.badge', { n: num(verifyLevel) })}
              </Badge>
            ) : (
              <Badge
                variant="outline"
                className="border-zinc-500/30 bg-zinc-500/10 px-1 py-0 text-[9px] text-zinc-500"
              >
                {t('hunt.funnel.verify.off')}
              </Badge>
            )}
          </p>
          <div className="flex items-stretch gap-1.5 sm:gap-2">
            <FunnelStage
              label={t('hunt.stat.tested')}
              value={num(s.tested)}
              sub={null}
              icon={Crosshair}
              tone="zinc"
            />
            {dir === 'rtl' ? (
              <ChevronLeft className="mt-4 size-3.5 shrink-0 text-muted-foreground/50" aria-hidden />
            ) : (
              <ChevronRight className="mt-4 size-3.5 shrink-0 text-muted-foreground/50" aria-hidden />
            )}
            <FunnelStage
              label={t('hunt.funnel.tcp')}
              value={num(tcpAlive)}
              sub={t('hunt.funnel.rate', { n: num(tcpPct) })}
              icon={Signal}
              tone="teal"
            />
            {dir === 'rtl' ? (
              <ChevronLeft className="mt-4 size-3.5 shrink-0 text-muted-foreground/50" aria-hidden />
            ) : (
              <ChevronRight className="mt-4 size-3.5 shrink-0 text-muted-foreground/50" aria-hidden />
            )}
            <FunnelStage
              label={t('hunt.funnel.ok')}
              value={num(s.healthy)}
              sub={t('hunt.funnel.rate', { n: num(okPct) })}
              icon={ShieldCheck}
              tone="emerald"
            />
          </div>
          {verified > 0 ? (
            <p className="mt-2 flex items-center gap-1 text-[10px] text-emerald-600 dark:text-emerald-400">
              <BadgeCheck className="size-3" aria-hidden />
              {t('hunt.funnel.verified', { n: num(verified) })}
            </p>
          ) : null}
          {/* hunt v6.1 — sampling-source chips (hidden on legacy engines without the fields) */}
          {(s.v6Sampled ?? 0) > 0 || (s.fromSelected ?? 0) > 0 ? (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              {(s.v6Sampled ?? 0) > 0 ? (
                <TooltipProvider delayDuration={120}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span
                        className="inline-flex cursor-default items-center gap-1 rounded-md border border-teal-500/30 bg-teal-500/10 px-1.5 py-0.5 font-mono text-[10px] text-teal-600 dark:text-teal-400"
                        dir="ltr"
                      >
                        <Globe className="size-2.5" aria-hidden />
                        {t('hunt.v6.chip', { n: num(s.v6Sampled ?? 0) })}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent dir={dir} className="text-[10px]">
                      {t('hunt.v6.note')}
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              ) : null}
              {(s.fromSelected ?? 0) > 0 ? (
                <TooltipProvider delayDuration={120}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span
                        className="inline-flex cursor-default items-center gap-1 rounded-md border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-amber-700 dark:text-amber-300"
                        dir="ltr"
                      >
                        <ListChecks className="size-2.5" aria-hidden />
                        {t('hunt.selected.chip', { n: num(s.fromSelected ?? 0) })}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent dir={dir} className="text-[10px]">
                      {t('hunt.ranges.desc')}
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              ) : null}
            </div>
          ) : null}
          {/* hunt v6.4 — censorship forensics tallies over dead candidates (hidden on legacy engines without the field) */}
          {s.forensics ? (
            <>
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <span
                  className="inline-flex cursor-default items-center gap-1 rounded-md border border-border bg-background/60 px-1.5 py-0.5 font-mono text-[10px] font-medium text-foreground"
                  dir="ltr"
                >
                  <span className={cn('rounded border px-1 py-0 text-[8px] font-sans', RST_BADGE_STYLES.rst)}>
                    {t('hunt.forensics.chip.rst')}
                  </span>
                  {num(s.forensics.rst ?? 0)}
                </span>
                <span
                  className="inline-flex cursor-default items-center gap-1 rounded-md border border-border bg-background/60 px-1.5 py-0.5 font-mono text-[10px] font-medium text-foreground"
                  dir="ltr"
                >
                  <span className={cn('rounded border px-1 py-0 text-[8px] font-sans', RST_BADGE_STYLES.drop)}>
                    {t('hunt.forensics.chip.drop')}
                  </span>
                  {num(s.forensics.drop ?? 0)}
                </span>
                <span
                  className="inline-flex cursor-default items-center gap-1 rounded-md border border-border bg-background/60 px-1.5 py-0.5 font-mono text-[10px] font-medium text-foreground"
                  dir="ltr"
                >
                  <span className={cn('rounded border px-1 py-0 text-[8px] font-sans', RST_BADGE_STYLES.refused)}>
                    {t('hunt.forensics.chip.refused')}
                  </span>
                  {num(s.forensics.refused ?? 0)}
                </span>
                <span
                  className="inline-flex cursor-default items-center gap-1 rounded-md border border-border bg-background/60 px-1.5 py-0.5 font-mono text-[10px] font-medium text-foreground"
                  dir="ltr"
                >
                  <span className={cn('rounded border px-1 py-0 text-[8px] font-sans', RST_BADGE_STYLES.live)}>
                    {t('hunt.forensics.chip.live')}
                  </span>
                  {num(s.forensics.live ?? 0)}
                </span>
              </div>
              <p className="mt-1 text-[10px] leading-relaxed text-muted-foreground">{t('hunt.forensics.explain')}</p>
            </>
          ) : null}
        </div>
      ) : null}

      {/* ---------- parallel engine telestrip (hunt v5 — hidden on legacy engine states) ---------- */}
      {s && showParallel ? (
        <div
          className="mt-3 rounded-lg border border-teal-500/20 bg-teal-500/5 p-3"
          role="status"
          aria-label={t('hunt.parallel.title')}
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
              <Zap className="size-3.5 text-teal-500" aria-hidden />
              {t('hunt.parallel.title')}
            </p>
            {s.engine ? (
              <span
                className="inline-flex cursor-default items-center gap-1 rounded-md border border-teal-500/30 bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-teal-700 dark:text-teal-300"
                dir="ltr"
              >
                <Cpu className="size-2.5" aria-hidden />
                {s.engine}
              </span>
            ) : null}
          </div>

          {/* live pipeline counters */}
          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5">
            <span className="inline-flex min-w-0 items-center gap-1.5 rounded-md border border-teal-500/30 bg-background/60 px-1.5 py-0.5 text-[10px]">
              <Activity className="size-2.5 shrink-0 text-teal-500" aria-hidden />
              <span className="text-muted-foreground">{t('hunt.parallel.inflight')}</span>
              <span
                className={cn(
                  'font-mono text-[11px] font-bold tabular-nums text-teal-600 dark:text-teal-400',
                  s.running && 'animate-pulse',
                )}
                dir="ltr"
              >
                {num(inFlight)}
              </span>
              {s.tlsInFlight !== undefined ? (
                <span className="inline-flex min-w-0 items-center gap-1 rounded bg-teal-500/10 px-1 py-px text-[9px] text-muted-foreground">
                  {t('hunt.parallel.tlsinflight')}
                  <span className="font-mono tabular-nums" dir="ltr">
                    {num(tlsInFlight)}
                  </span>
                </span>
              ) : null}
            </span>
            <span className="inline-flex min-w-0 items-center gap-1.5 rounded-md border border-emerald-500/30 bg-background/60 px-1.5 py-0.5 text-[10px]">
              <Droplets className="size-2.5 shrink-0 text-emerald-500" aria-hidden />
              <span className="text-muted-foreground">{t('hunt.parallel.sampled')}</span>
              <span className="font-mono text-[11px] font-bold tabular-nums text-emerald-600 dark:text-emerald-400" dir="ltr">
                {num(sampledCount)}
              </span>
            </span>
          </div>

          {/* pool utilisation meters */}
          <div className="mt-2.5 grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-2">
            <PoolMeter
              label={t('hunt.parallel.tcppool')}
              value={num(s.concurrency ?? 0)}
              max={num(s.tcpPoolMax ?? 0)}
              pct={tcpPoolPct}
              barCls="bg-teal-500"
            />
            <PoolMeter
              label={t('hunt.parallel.tlspool')}
              value={num(s.tlsConcurrency ?? 0)}
              max={num(s.tlsPoolMax ?? 0)}
              pct={tlsPoolPct}
              barCls="bg-emerald-500"
            />
          </div>
        </div>
      ) : null}

      {/* ---------- counters ---------- */}
      {s ? (
        <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-5">
          <Counter label={t('hunt.stat.tested')} value={num(s.tested)} icon={Crosshair} tone="neutral" />
          <Counter label={t('hunt.stat.healthy')} value={num(s.healthy)} icon={ShieldCheck} tone="emerald" highlight />
          <Counter label={t('hunt.stat.blocked')} value={num(s.blocked)} icon={ShieldX} tone="red" />
          <Counter label={t('hunt.stat.dead')} value={num(s.dead)} icon={Signal} tone="zinc" />
          <Counter label={t('hunt.stat.wave')} value={num(s.wave)} icon={Waves} tone="teal" />
        </div>
      ) : null}

      {/* ---------- per-provider yield (hunt v4) ---------- */}
      {s && s.provider === 'all' && s.perProvider ? (
        <div className="mt-3">
          <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <Layers className="size-3 text-teal-500" aria-hidden />
            {t('hunt.perprovider.title')}
          </p>
          <div className={cn('grid gap-2', s.perProvider?.custom ? 'grid-cols-2 sm:grid-cols-4' : 'grid-cols-3')}>
            {HUNT_PROVIDER_IDS_UI.map((pid) => {
              const pp = s.perProvider?.[pid]
              if (pid === 'custom' && !pp) return null // only render the custom tile when the run actually hunted custom ranges
              const badge = PROVIDER_BADGE[pid]!
              return (
                <div key={pid} className="rounded-lg border bg-background/50 px-2.5 py-2">
                  <p className="flex items-center gap-1 text-[10px] text-muted-foreground">
                    <Badge variant="outline" className={cn('px-1 py-0 text-[8px]', badge.cls)}>
                      {badge.label}
                    </Badge>
                    {t(`hunt.provider.${pid}` as DictKey)}
                  </p>
                  <p className="mt-0.5 font-mono text-xs font-bold tabular-nums text-emerald-600 dark:text-emerald-400" dir="ltr">
                    {num(pp?.healthy ?? 0)}
                    <span className="text-[10px] font-normal text-muted-foreground"> / {num(pp?.tested ?? 0)}</span>
                  </p>
                </div>
              )
            })}
          </div>
        </div>
      ) : null}

      {/* ---------- learned hot blocks ---------- */}
      {s && hotBlocks.length > 0 ? (
        <div className="mt-4">
          <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <Crosshair className="size-3 text-teal-500" aria-hidden />
            {t('hunt.blocks.title')}
          </p>
          <div className="flex flex-wrap gap-1.5">
            {hotBlocks.map((b) => (
              <TooltipProvider key={b.block} delayDuration={120}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="min-w-28 cursor-default rounded-lg border bg-background/50 px-2 py-1.5">
                      <p className="flex items-center gap-1 font-mono text-[10px] text-foreground/80" dir="ltr">
                        {b.block}
                        {b.ptr === 'edge' ? (
                          <Badge
                            variant="outline"
                            className="border-violet-500/40 bg-violet-500/10 px-1 py-0 text-[8px] text-violet-600 dark:text-violet-400"
                          >
                            1e100
                          </Badge>
                        ) : null}
                      </p>
                      <p className="mt-0.5 text-[10px] text-emerald-600 dark:text-emerald-400" dir="ltr">
                        {num(b.healthy)} / {num(b.probed)}
                      </p>
                      <div className="mt-1 h-0.5 w-full overflow-hidden rounded-full bg-muted">
                        <div
                          className="h-full rounded-full bg-emerald-500"
                          style={{ width: `${Math.max(4, Math.min(100, Math.round(b.score * 100)))}%` }}
                        />
                      </div>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent dir={dir} className="text-[10px]">
                    <p dir="ltr" className="font-mono">
                      {t('hunt.blocks.stat', { h: num(b.healthy), p: num(b.probed) })}
                    </p>
                    <p dir="ltr" className="font-mono">
                      score {b.score.toFixed(3)}
                    </p>
                    {b.ptr === 'edge' ? <p dir="ltr" className="mt-1">{t('hunt.blocks.ptr.edge')}</p> : null}
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            ))}
          </div>
        </div>
      ) : null}

      {/* ---------- recent probe ticker ---------- */}
      {s && s.recent.length > 0 ? (
        <div className="mt-4">
          <p className="mb-1.5 text-[11px] font-semibold text-muted-foreground">{t('hunt.recent.title')}</p>
          <div className="flex flex-wrap items-center gap-1.5" aria-live="off">
            {s.recent.slice(-RECENT_SHOW).map((c, i) => (
              <TooltipProvider key={`${c.ip}-${i}`} delayDuration={120}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span
                      className={cn(
                        'inline-flex cursor-default items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[10px]',
                        VERDICT_STYLES[c.verdict],
                      )}
                      dir="ltr"
                    >
                      {c.verdict === 'dead' ? '×' : c.httpStatus ?? '—'}
                      {c.rst ? (
                        <span
                          className={cn(
                            'inline-flex items-center rounded border px-1 py-0 text-[8px] font-sans font-medium',
                            RST_BADGE_STYLES[c.rst],
                          )}
                        >
                          {t(`hunt.forensics.chip.${c.rst}` as DictKey)}
                        </span>
                      ) : null}
                      {c.colo ? (
                        <span className="inline-flex items-center gap-0.5 text-[9px] opacity-90">
                          <MapPin className="size-2" aria-hidden />
                          {c.colo}
                        </span>
                      ) : null}
                    </span>
                  </TooltipTrigger>
                  <TooltipContent dir={dir} className="text-[10px]">
                    <p className="font-mono" dir="ltr">
                      {candidateAddr(c)}
                      {c.provider ? ` [${PROVIDER_BADGE[c.provider]?.label ?? c.provider}]` : ''} — {t(`hunt.verdict.${c.verdict}` as DictKey)}
                      {c.tlsMs != null ? ` · TLS ${c.tlsMs}ms` : ''}
                    </p>
                    {c.colo ? (
                      <p className="mt-0.5 flex items-center gap-1 font-mono text-[9px] opacity-80" dir="ltr">
                        <MapPin className="size-2" aria-hidden />
                        {c.colo} — {t('hunt.colo.tip')}
                      </p>
                    ) : null}
                    {c.server ? (
                      <p className="mt-0.5 font-mono text-[9px] opacity-80" dir="ltr">
                        server: {c.server}
                      </p>
                    ) : null}
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            ))}
          </div>
        </div>
      ) : null}

      {/* ---------- datacenter spread (hunt v5.9 — colo from cdn-cgi/trace) ---------- */}
      {coloChips.length > 0 ? (
        <div className="mt-4">
          <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <MapPin className="size-3 text-teal-500" aria-hidden />
            {t('hunt.colo.title')}
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            {coloChips.map(([code, count]) => (
              <TooltipProvider key={code} delayDuration={120}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span
                      className="inline-flex cursor-default items-center gap-1 rounded-md border border-teal-500/30 bg-teal-500/10 px-1.5 py-0.5 font-mono text-[10px] text-teal-700 dark:text-teal-300"
                      dir="ltr"
                    >
                      <MapPin className="size-2.5" aria-hidden />
                      {code} {num(count)}
                    </span>
                  </TooltipTrigger>
                  <TooltipContent dir={dir} className="text-[10px]">
                    <p>{t('hunt.colo.tip')}</p>
                    <p className="mt-0.5 font-mono" dir="ltr">
                      {code}: {num(count)}
                    </p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            ))}
          </div>
        </div>
      ) : null}

      {/* ---------- healthy IP list ---------- */}
      <div className="mt-4">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <p className="text-[11px] font-semibold text-muted-foreground">
            {t('hunt.list.title')}
            {s && s.healthyIps.length > 0 ? (
              <span className="ms-1.5 font-mono" dir="ltr">
                ({num(s.healthyIps.length)})
              </span>
            ) : null}
          </p>
          {s && s.healthyIps.length > 0 ? (
            <div className="flex items-center gap-1.5">
              {/* config generator (hunt v6.0) — disabled while the visible/filtered list is empty */}
              <Button
                variant="outline"
                size="sm"
                className="h-7 gap-1 border-teal-500/30 px-2 text-[11px] text-teal-700 hover:bg-teal-500/10 dark:text-teal-400"
                onClick={openConfig}
                disabled={visibleHealthy.length === 0}
              >
                <Wand2 className="size-3" aria-hidden />
                {t('hunt.config.title')}
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7 gap-1 border-emerald-500/30 px-2 text-[11px] text-emerald-700 hover:bg-emerald-500/10 dark:text-emerald-400"
                onClick={copyAll}
              >
                <Copy className="size-3" aria-hidden />
                {t('hunt.list.copyall')}
              </Button>
            </div>
          ) : null}
        </div>

        {/* ---------- result filter chain (hunt v5.9 — client-side view over the healthy list) ---------- */}
        <div role="group" aria-label={t('hunt.filter.title')} className="mb-2 rounded-lg border bg-background/40 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="flex items-center gap-1 text-[11px] font-semibold text-muted-foreground">
              <Filter className="size-3.5 text-teal-500" aria-hidden />
              {t('hunt.filter.title')}
            </span>
            <label className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <span className="shrink-0">{t('hunt.filter.tcp')}</span>
              <Input
                value={maxTcp}
                onChange={(e) => setMaxTcp(toEnDigits(e.target.value).replace(/[^\d]/g, ''))}
                inputMode="numeric"
                dir="ltr"
                placeholder="—"
                disabled={!hasHealthy}
                aria-label={t('hunt.filter.tcp')}
                className="h-11 w-20 shrink-0 px-2 text-center font-mono text-xs tabular-nums sm:h-8"
              />
            </label>
            <label className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <span className="shrink-0">{t('hunt.filter.tls')}</span>
              <Input
                value={maxTls}
                onChange={(e) => setMaxTls(toEnDigits(e.target.value).replace(/[^\d]/g, ''))}
                inputMode="numeric"
                dir="ltr"
                placeholder="—"
                disabled={!hasHealthy}
                aria-label={t('hunt.filter.tls')}
                className="h-11 w-20 shrink-0 px-2 text-center font-mono text-xs tabular-nums sm:h-8"
              />
            </label>
            <Select
              value={sortMode}
              onValueChange={(v) => setSortMode(v as HuntSortMode)}
              disabled={!hasHealthy}
              dir={dir}
            >
              <SelectTrigger className="w-32 shrink-0 text-[11px] sm:w-36" aria-label={t('hunt.filter.sort')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent dir={dir}>
                <SelectItem value="default" className="text-xs">
                  {t('hunt.sort.default')}
                </SelectItem>
                <SelectItem value="tcp" className="text-xs">
                  {t('hunt.sort.tcp')}
                </SelectItem>
                <SelectItem value="tls" className="text-xs">
                  {t('hunt.sort.tls')}
                </SelectItem>
              </SelectContent>
            </Select>
            {filtersActive ? (
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <span className="text-[10px] font-medium text-teal-700 dark:text-teal-300" aria-live="polite">
                  {t('hunt.filter.showing', { x: num(visibleHealthy.length), y: num(healthyIps.length) })}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={clearFilters}
                  className="h-11 gap-1 border border-red-500/30 px-2 text-[11px] text-red-600 hover:bg-red-500/10 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 sm:h-7"
                >
                  <X className="size-3" aria-hidden />
                  {t('hunt.filter.clear')}
                </Button>
              </div>
            ) : null}
          </div>
        </div>

        {!s || s.healthyIps.length === 0 ? (
          <div className="flex h-20 items-center justify-center rounded-lg border border-dashed bg-background/40 text-xs text-muted-foreground">
            {t('hunt.list.empty')}
          </div>
        ) : visibleHealthy.length === 0 ? (
          // every candidate excluded by the active filters — the counter above states «نمایش ۰ از Y»
          <div className="flex h-20 items-center justify-center rounded-lg border border-dashed bg-background/40 text-xs text-muted-foreground">
            {t('hunt.filter.showing', { x: num(0), y: num(s.healthyIps.length) })}
          </div>
        ) : (
          <ul className="scrollbar-thin max-h-96 space-y-1.5 overflow-y-auto pe-1" aria-label={t('hunt.list.title')}>
            {visibleHealthy.map((c, i) => (
              <li
                key={c.ip}
                className="flex items-center justify-between gap-2 rounded-lg border bg-background/50 px-2.5 py-1.5"
              >
                <div className="flex min-w-0 items-center gap-2">
                  <span className="flex size-5 shrink-0 items-center justify-center rounded bg-emerald-500/10 font-mono text-[10px] text-emerald-600 dark:text-emerald-400" dir="ltr">
                    {num(i + 1)}
                  </span>
                  {c.port != null || isV6Candidate(c) ? (
                    <TooltipProvider delayDuration={120}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="truncate font-mono text-xs" dir="ltr">
                            {candidateAddr(c)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent dir={dir} className="text-[10px]">
                          <p className="font-mono" dir="ltr">
                            {t('hunt.port.tip')}: {c.port ?? 443}
                          </p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ) : (
                    <span className="truncate font-mono text-xs" dir="ltr">
                      {c.ip}
                    </span>
                  )}
                  {c.v6 ? (
                    <Badge
                      variant="outline"
                      className="shrink-0 border-zinc-500/40 bg-zinc-500/10 px-1 text-[8px] text-zinc-600 dark:text-zinc-400"
                      dir="ltr"
                    >
                      {t('hunt.v6.tag')}
                    </Badge>
                  ) : null}
                  {c.selected ? (
                    <TooltipProvider delayDuration={120}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge
                            variant="outline"
                            className="shrink-0 border-amber-500/40 bg-amber-500/10 px-1 text-[8px] text-amber-700 dark:text-amber-300"
                          >
                            {t('hunt.selected.row')}
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent dir={dir} className="text-[10px]">
                          {t('hunt.ranges.desc')}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ) : null}
                  {c.provider ? (
                    <TooltipProvider delayDuration={120}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge variant="outline" className={cn('shrink-0 px-1 text-[8px]', PROVIDER_BADGE[c.provider]?.cls ?? 'border-border')}>
                            {PROVIDER_BADGE[c.provider]?.label ?? '?'}
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent dir={dir} className="text-[10px]">
                          {t(`hunt.provider.${c.provider === 'all' ? 'multi' : c.provider}` as DictKey)}
                          {c.server ? (
                            <p className="mt-0.5 font-mono text-[9px] opacity-80" dir="ltr">
                              server: {c.server}
                            </p>
                          ) : null}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ) : null}
                  {c.colo ? (
                    <TooltipProvider delayDuration={120}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge
                            variant="outline"
                            className="shrink-0 gap-0.5 border-teal-500/40 bg-teal-500/10 px-1 text-[8px] text-teal-600 dark:text-teal-400"
                            dir="ltr"
                          >
                            <MapPin className="size-2" aria-hidden />
                            {c.colo}
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent dir={dir} className="text-[10px]">
                          {t('hunt.colo.tip')}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ) : null}
                  {c.jitterMs != null && c.jitterMs <= 20 ? (
                    <TooltipProvider delayDuration={120}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge
                            variant="outline"
                            className="shrink-0 gap-0.5 border-emerald-500/40 bg-emerald-500/10 px-1 text-[8px] text-emerald-600 dark:text-emerald-400"
                            dir="ltr"
                          >
                            <Activity className="size-2" aria-hidden />
                            {num(c.jitterMs)}ms
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent dir={dir} className="text-[10px]">
                          <p>
                            {t('hunt.jitter.stable')} — {t('hunt.jitter.tip')}
                          </p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ) : null}
                  <span
                    className="hidden shrink-0 items-center gap-1 font-mono text-[10px] text-muted-foreground sm:inline-flex"
                    dir="ltr"
                  >
                    HTTP {c.httpStatus ?? '—'} · {t('hunt.tls')} {c.tlsMs ?? '—'}ms
                  </span>
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  {(c.attempts ?? 1) > 1 ? (
                    <TooltipProvider delayDuration={120}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge
                            variant="outline"
                            className="border-teal-500/30 bg-teal-500/10 px-1 text-[9px] text-teal-600 dark:text-teal-400"
                          >
                            <BadgeCheck className="size-2.5" aria-hidden />
                            ×{num(c.attempts ?? 1)}
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent dir={dir} className="text-[10px]">
                          {t('hunt.verified.tip', { n: num(c.attempts ?? 1) })}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ) : null}
                  <Badge
                    variant="outline"
                    className="border-emerald-500/30 bg-emerald-500/10 text-[10px] text-emerald-600 dark:text-emerald-400"
                  >
                    {t('hunt.verdict.healthy')}
                  </Badge>
                  <TooltipProvider delayDuration={120}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <button
                          type="button"
                          onClick={() => void copyText(candidateAddr(c), 'hunt.list.copy.ok', { ip: candidateAddr(c) })}
                          aria-label={t('hunt.list.copy.aria', { ip: candidateAddr(c) })}
                          className="inline-flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-emerald-500/10 hover:text-emerald-600 dark:hover:text-emerald-400"
                        >
                          <Copy className="size-3" aria-hidden />
                        </button>
                      </TooltipTrigger>
                      <TooltipContent dir={dir} className="text-[10px]">
                        <p className="font-mono" dir="ltr">
                          HTTP {c.httpStatus ?? '—'} · {t('hunt.tls')} {c.tlsMs ?? '—'}ms
                          {c.jitterMs != null ? ` · ${t('hunt.jitter.ms', { n: num(c.jitterMs) })}` : ''}
                        </p>
                        {c.jitterMs != null ? (
                          <p className={cn('mt-0.5', c.jitterMs <= 20 && 'text-emerald-600 dark:text-emerald-400')}>
                            {t('hunt.jitter.tip')}
                            {c.jitterMs <= 20 ? ` — ${t('hunt.jitter.stable')}` : ''}
                          </p>
                        ) : null}
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* ---------- v7.0 — per-ISP latency profile (honest empty: hidden entirely without labelled healthy IPs) ---------- */}
      {ispLatencyRows.length > 0 ? (
        <div
          className="mt-4 rounded-lg border border-emerald-500/25 bg-emerald-500/5 p-3"
          role="region"
          aria-label={t('hunt.ispprofile.title')}
        >
          <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <Building2 className="size-3.5 text-emerald-500" aria-hidden />
            {t('hunt.ispprofile.title')}
          </p>
          <p className="mt-1 text-[10px] leading-relaxed text-muted-foreground">{t('hunt.ispprofile.hint')}</p>
          <ul className="mt-2 space-y-2.5">
            {ispLatencyRows.map((row) => {
              const pct = maxIspCount > 0 ? Math.max(6, Math.round((row.count / maxIspCount) * 100)) : 0
              return (
                <li key={row.label}>
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                    <span className="text-xs font-bold">{ispDisplayName(row.label)}</span>
                    <span
                      className="rounded-md border border-emerald-500/30 bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-emerald-700 dark:text-emerald-300"
                      aria-live="polite"
                    >
                      {num(row.count)} {t('hunt.ispprofile.count')}
                    </span>
                    <span className="ms-auto text-[10px] text-muted-foreground">
                      {row.avg != null ? (
                        <span>
                          {t('hunt.ispprofile.avg')} {num(row.avg)} · {t('hunt.ispprofile.min')} {num(row.min ?? 0)} ·{' '}
                          {t('hunt.ispprofile.max')} {num(row.max ?? 0)} ms
                        </span>
                      ) : (
                        <span className="text-amber-600 dark:text-amber-400">{t('hunt.ispprofile.nolatency')}</span>
                      )}
                    </span>
                  </div>
                  <div
                    className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-muted"
                    role="img"
                    aria-label={`${ispDisplayName(row.label)} — ${t('hunt.ispprofile.bar')}`}
                  >
                    <div
                      className="h-full rounded-full bg-emerald-500/60 transition-[width] duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </li>
              )
            })}
          </ul>
          <p className="mt-2 text-[10px] text-muted-foreground">{t('hunt.ispprofile.sample')}</p>
        </div>
      ) : null}

      {/* ---------- past hunts (persisted history) ---------- */}
      <div className="mt-4">
        <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
          <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
            <History className="size-3" aria-hidden />
            {t('hunt.history.title')}
          </p>
          {/* v7.5 — history CSV export + v7.2 clear-all, one right-side cluster (honest: both disabled on empty history) */}
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={exportHistoryCsv}
              disabled={runs.length === 0}
              aria-label={t('hunt.hist.export')}
              title={t('hunt.hist.export')}
              className="inline-flex size-8 shrink-0 items-center justify-center self-center rounded-md text-muted-foreground transition-colors hover:bg-emerald-500/10 hover:text-emerald-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/60 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent dark:hover:text-emerald-400 sm:size-7"
            >
              <Download className="size-3.5" aria-hidden />
            </button>
            <button
              type="button"
              onClick={() => setConfirmClear(true)}
              disabled={runs.length === 0}
              aria-label={t('hunt.hist.clear')}
              className="inline-flex h-11 items-center gap-1 rounded-md border border-red-500/40 px-2.5 text-[11px] font-medium text-red-600 transition-colors hover:bg-red-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500/60 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent dark:text-red-400 dark:hover:bg-red-500/10 sm:h-9"
            >
              <Trash2 className="size-3" aria-hidden />
              {t('hunt.hist.clear')}
            </button>
          </div>
        </div>

        {/* v7.2 — auto/manual filter chips (same segmented-chip recipe as the scheduler intervals) */}
        {runs.length > 0 ? (
          <div className="mb-1.5 flex flex-wrap items-center gap-1.5" role="group" aria-label={t('hunt.hist.filter')}>
            {(['all', 'auto', 'manual'] as const).map((fid) => (
              <button
                key={fid}
                type="button"
                aria-pressed={histFilter === fid}
                onClick={() => {
                  setHistFilter(fid)
                  setHistShow(HISTORY_SHOW)
                }}
                className={cn(
                  'flex h-11 items-center rounded-md border px-2.5 py-1 text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 sm:h-9',
                  histFilter === fid
                    ? 'border-teal-500/50 bg-teal-500/10 text-teal-700 dark:text-teal-300'
                    : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                )}
              >
                {t(`hunt.hist.filter.${fid}`)}
                <span className="font-mono text-[10px] leading-none opacity-70" dir="ltr">
                  {num(fid === 'all' ? runs.length : fid === 'auto' ? autoCount : runs.length - autoCount)}
                </span>
              </button>
            ))}
            {/* v7.5 — time-range chips (same row + group as the auto/manual chips; divider is decorative) */}
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
                  'flex h-11 items-center rounded-md border px-2.5 py-1 text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 sm:h-9',
                  histRange === rid
                    ? 'border-teal-500/50 bg-teal-500/10 text-teal-700 dark:text-teal-300'
                    : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                )}
              >
                {t(`hist.range.${rid}`)}
              </button>
            ))}
          </div>
        ) : null}

        {/* v7.3 — client-side search over IP / host / provider (mono ltr island; ≤30 runs ⇒ no debounce) */}
        {runs.length > 0 ? (
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
              placeholder={t('hunt.hist.search.ph')}
              aria-label={t('hunt.hist.search')}
              spellCheck={false}
              dir="ltr"
              className="h-11 w-full rounded-md border border-border bg-background/40 px-8 font-mono text-[12px] text-left text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 [&::-webkit-search-cancel-button]:hidden sm:h-9"
            />
            {histQuery !== '' ? (
              <button
                type="button"
                onClick={() => setHistQuery('')}
                aria-label={t('hunt.hist.search.clear')}
                className="absolute right-1.5 top-1/2 inline-flex size-6 -translate-y-1/2 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-red-500/10 hover:text-red-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 dark:hover:text-red-400"
              >
                <X className="size-3.5" aria-hidden />
              </button>
            ) : null}
          </div>
        ) : null}

        {/* v7.3 — sort chips (same segmented-chip recipe as the filter chips; counts live on the filter chips only) */}
        {runs.length > 0 ? (
          <div className="mb-1.5 flex flex-wrap items-center gap-1.5" role="group" aria-label={t('hunt.hist.sort')}>
            {(['date', 'healthy', 'tested'] as const).map((sid) => (
              <button
                key={sid}
                type="button"
                aria-pressed={histSort === sid}
                onClick={() => {
                  setHistSort(sid)
                  setHistShow(HISTORY_SHOW)
                }}
                className={cn(
                  'flex h-11 items-center rounded-md border px-2.5 py-1 text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 sm:h-9',
                  histSort === sid
                    ? 'border-teal-500/50 bg-teal-500/10 text-teal-700 dark:text-teal-300'
                    : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                )}
              >
                {t(`hunt.hist.sort.${sid}`)}
              </button>
            ))}
          </div>
        ) : null}

        {/* ---------- v7.1 — run comparison (side-by-side over the compare selection, A = newer) ---------- */}
        {cmp ? (
          <div
            className="mt-1.5 rounded-lg border border-emerald-500/25 bg-emerald-500/5 p-3"
            role="region"
            aria-label={t('hunt.cmp.title')}
          >
            <div className="flex items-center justify-between gap-2">
              <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
                <GitCompareArrows className="size-3.5 text-emerald-500" aria-hidden />
                {t('hunt.cmp.title')}
              </p>
              <button
                type="button"
                onClick={() => setCompareIds([])}
                aria-label={t('hunt.cmp.clear')}
                className="inline-flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-red-500/10 hover:text-red-600 dark:hover:text-red-400"
              >
                <X className="size-3.5" aria-hidden />
              </button>
            </div>

            <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
              {CMP_SIDES.map(({ side, chipKey, chipCls, colCls }) => {
                const run = side === 'a' ? cmp.a : cmp.b
                const lat = side === 'a' ? cmp.aLat : cmp.bLat
                const rate = run.tested > 0 ? (run.healthy / run.tested) * 100 : null
                return (
                  <div key={side} className={cn('rounded-md border bg-background/50 p-2', colCls)}>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge variant="outline" className={cn('shrink-0 px-1 py-0 text-[9px]', chipCls)}>
                        {t(chipKey)}
                      </Badge>
                      <Badge
                        variant="outline"
                        className={cn(
                          'shrink-0 px-1 text-[8px]',
                          PROVIDER_BADGE[run.provider ?? 'all']?.cls ?? 'border-border',
                        )}
                      >
                        {PROVIDER_BADGE[run.provider ?? 'all']?.label ?? '?'}
                      </Badge>
                      {run.auto ? (
                        <Badge
                          variant="outline"
                          className="shrink-0 gap-0.5 border-zinc-500/40 bg-zinc-500/10 px-1 text-[8px] text-zinc-600 dark:text-zinc-300"
                        >
                          <CalendarClock className="size-2" aria-hidden />
                          {t('hs.hist.badge')}
                        </Badge>
                      ) : null}
                      <span className="ms-auto font-mono text-[10px] text-muted-foreground" dir="ltr">
                        {run.stopped ? '■' : '🎯'} ×{num(run.target)}
                      </span>
                    </div>
                    <p className="mt-1 text-[10px] text-muted-foreground">{fmtRunDate(run.finishedAt)}</p>
                    <dl className="mt-1.5 space-y-0.5">
                      {cmpRow(t('hunt.cmp.duration'), fmtDur(run.finishedAt - run.startedAt))}
                      {cmpRow(t('hunt.cmp.tested'), num(run.tested))}
                      {cmpRow(t('hunt.cmp.healthy'), num(run.healthy), cmp.win.healthy === side)}
                      {cmpRow(t('hunt.cmp.blocked'), num(run.blocked))}
                      {cmpRow(t('hunt.cmp.dead'), num(run.dead))}
                      {cmpRow(
                        t('hunt.cmp.rate'),
                        rate === null ? '—' : `${num(rate, { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%`,
                        cmp.win.rate === side,
                      )}
                      {cmpRow(t('hunt.cmp.avgTls'), lat ? `${num(lat.avg)} ms` : '—', cmp.win.avgTls === side)}
                      {cmpRow(t('hunt.cmp.minTls'), lat ? `${num(lat.min)} ms` : '—')}
                      {cmpRow(t('hunt.cmp.maxTls'), lat ? `${num(lat.max)} ms` : '—')}
                    </dl>
                  </div>
                )
              })}
            </div>

            {/* shared-IP overlap between the two runs (Set intersection over healthyIps) */}
            <div className="mt-2 border-t border-emerald-500/20 pt-2">
              <p className="text-[11px] font-semibold text-muted-foreground">
                {t('hunt.cmp.overlap', { n: num(cmp.overlap.length) })}
              </p>
              {cmp.overlap.length > 0 ? (
                <div className="mt-1.5 flex flex-wrap gap-1" dir="ltr">
                  {cmp.overlap.slice(0, 8).map((ip) => (
                    <span
                      key={ip}
                      className="rounded border border-zinc-500/30 bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-zinc-600 dark:text-zinc-300"
                    >
                      {ip}
                    </span>
                  ))}
                  {cmp.overlap.length > 8 ? (
                    <span className="rounded border border-zinc-500/30 bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-zinc-600 dark:text-zinc-300">
                      +{num(cmp.overlap.length - 8)}
                    </span>
                  ) : null}
                </div>
              ) : (
                <p className="mt-1 text-[10px] text-muted-foreground">{t('hunt.cmp.overlap.none')}</p>
              )}
            </div>
          </div>
        ) : null}

        {runs.length === 0 ? (
          <div className="flex h-12 items-center justify-center rounded-lg border border-dashed bg-background/40 text-[11px] text-muted-foreground">
            {t('hunt.history.empty')}
          </div>
        ) : filteredRuns.length === 0 ? (
          <div className="flex h-12 items-center justify-center rounded-lg border border-dashed bg-background/40 text-[11px] text-muted-foreground">
            {t('hunt.hist.empty.filter')}
          </div>
        ) : visibleRuns.length === 0 ? (
          <div className="flex h-12 items-center justify-center rounded-lg border border-dashed bg-background/40 px-3 text-center text-[11px] text-muted-foreground">
            {t('hunt.hist.empty.search', { q: histQuery.trim() })}
          </div>
        ) : (
          <ul className="space-y-1.5" aria-label={t('hunt.history.title')}>
            {visibleRuns.slice(0, histShow).map((run) => (
              <li
                key={run.id}
                className={cn(
                  'flex items-center justify-between gap-2 rounded-lg border bg-background/50 px-2.5 py-1.5',
                  compareIds.includes(run.id) && 'border-emerald-500/50 ring-1 ring-emerald-500/40',
                )}
              >
                {/* v7.3 — the info area is a real button opening the per-run detail dialog (action buttons stay siblings) */}
                <button
                  type="button"
                  onClick={() => setDetailRun(run)}
                  aria-label={t('hunt.hist.detail')}
                  className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 rounded-md text-right transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60"
                >
                  <span className="flex size-5 shrink-0 items-center justify-center rounded bg-teal-500/10 text-teal-600 dark:text-teal-400">
                    <History className="size-3" aria-hidden />
                  </span>
                  <span className="whitespace-nowrap text-[11px] text-muted-foreground">
                    {fmtRunDate(run.finishedAt)}
                  </span>
                  <Badge
                    variant="outline"
                    className={cn('shrink-0 px-1 text-[8px]', PROVIDER_BADGE[run.provider ?? 'all']?.cls ?? 'border-border')}
                  >
                    {PROVIDER_BADGE[run.provider ?? 'all']?.label ?? '?'}
                  </Badge>
                  {/* v7.0 — neutral badge for scheduler-triggered runs */}
                  {run.auto ? (
                    <Badge
                      variant="outline"
                      className="shrink-0 gap-0.5 border-zinc-500/40 bg-zinc-500/10 px-1 text-[8px] text-zinc-600 dark:text-zinc-300"
                    >
                      <CalendarClock className="size-2" aria-hidden />
                      {t('hs.hist.badge')}
                    </Badge>
                  ) : null}
                  <span className="truncate font-mono text-[10px] text-muted-foreground" dir="ltr">
                    {run.stopped ? '■' : '🎯'} ×{num(run.target)} · {t('hunt.history.stat', { h: num(run.healthy), p: num(run.tested) })}
                  </span>
                </button>
                <div className="flex shrink-0 items-center gap-1.5">
                  <TooltipProvider delayDuration={120}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <button
                          type="button"
                          onClick={() => toggleCompare(run.id)}
                          aria-label={t('hunt.cmp.select')}
                          aria-pressed={compareIds.includes(run.id)}
                          className={cn(
                            'inline-flex size-6 items-center justify-center rounded-md transition-colors',
                            compareIds.includes(run.id)
                              ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                              : 'text-muted-foreground hover:bg-emerald-500/10 hover:text-emerald-600 dark:hover:text-emerald-400',
                          )}
                        >
                          <GitCompareArrows className="size-3" aria-hidden />
                        </button>
                      </TooltipTrigger>
                      <TooltipContent dir={dir} className="text-[10px]">
                        {t('hunt.cmp.select')}
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                  {(run.healthyIps ?? []).length > 0 ? (
                    <TooltipProvider delayDuration={120}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => copyRun(run)}
                            aria-label={t('hunt.history.copy')}
                            className="inline-flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-emerald-500/10 hover:text-emerald-600 dark:hover:text-emerald-400"
                          >
                            <Copy className="size-3" aria-hidden />
                          </button>
                        </TooltipTrigger>
                        <TooltipContent dir={dir} className="text-[10px]">
                          {t('hunt.history.copy')}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ) : null}
                  {/* v7.2 — per-row delete (opens the shared confirm dialog) */}
                  <TooltipProvider delayDuration={120}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <button
                          type="button"
                          onClick={() => setPendingDelId(run.id)}
                          aria-label={t('hunt.hist.del')}
                          className="inline-flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-red-500/10 hover:text-red-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500/60 dark:hover:text-red-400"
                        >
                          <Trash2 className="size-3" aria-hidden />
                        </button>
                      </TooltipTrigger>
                      <TooltipContent dir={dir} className="text-[10px]">
                        {t('hunt.hist.del')}
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </div>
              </li>
            ))}
          </ul>
        )}
        {/* v7.2 integration polish — honest «show more» (the store keeps up to 30 runs; HISTORY_SHOW caps the rows; v7.3: counts the search+sorted pipeline) */}
        {visibleRuns.length > histShow ? (
          <button
            type="button"
            onClick={() => setHistShow((n) => n + 10)}
            aria-label={t('hunt.hist.more', { n: num(visibleRuns.length - histShow) })}
            className="mt-1.5 flex h-11 w-full items-center justify-center gap-1.5 rounded-md border border-dashed text-[11px] text-muted-foreground transition-colors hover:bg-background/70 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 sm:h-9"
          >
            <ChevronDown className="size-3" aria-hidden />
            {t('hunt.hist.more', { n: num(visibleRuns.length - histShow) })}
          </button>
        ) : null}
      </div>

      {/* ---------- config generator dialog (hunt v6.0 — VLESS/VMess over WS+TLS) ---------- */}
      <Dialog open={cfgOpen} onOpenChange={setCfgOpen}>
        <DialogContent dir={dir} className="max-h-[85dvh] max-w-lg overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <Wand2 className="size-4 text-teal-500" aria-hidden />
              {t('hunt.config.title')}
            </DialogTitle>
            <DialogDescription className="text-xs" aria-live="polite">
              {t('hunt.config.output', { n: num(cfgList.length) })}
            </DialogDescription>
          </DialogHeader>

          {/* fields — single column below sm so inputs stay full-width on mobile */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="flex flex-col gap-1.5 text-[11px] font-medium text-muted-foreground">
              <span>{t('hunt.config.protocol')}</span>
              <Select value={cfgProtocol} onValueChange={(v) => setCfgProtocol(v as CfgProtocol)} dir={dir}>
                <SelectTrigger className="h-11 w-full text-xs sm:h-9" aria-label={t('hunt.config.protocol')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent dir={dir}>
                  <SelectItem value="vless" className="text-xs">
                    VLESS
                  </SelectItem>
                  <SelectItem value="vmess" className="text-xs">
                    VMess
                  </SelectItem>
                </SelectContent>
              </Select>
            </label>

            <label className="flex flex-col gap-1.5 text-[11px] font-medium text-muted-foreground">
              <span>{t('hunt.config.prefix')}</span>
              <Input
                value={cfgPrefix}
                onChange={(e) => setCfgPrefix(e.target.value)}
                dir="ltr"
                aria-label={t('hunt.config.prefix')}
                className="h-11 font-mono text-xs sm:h-9"
              />
            </label>

            <div className="flex flex-col gap-1.5 text-[11px] font-medium text-muted-foreground sm:col-span-2">
              <span>{t('hunt.config.uuid')}</span>
              <div className="flex items-center gap-1.5">
                <Input
                  value={cfgUuid}
                  onChange={(e) => setCfgUuid(e.target.value)}
                  dir="ltr"
                  aria-label={t('hunt.config.uuid')}
                  aria-invalid={!cfgUuidValid}
                  className={cn('h-11 flex-1 font-mono text-xs sm:h-9', !cfgUuidValid && 'border-red-500/50 focus-visible:ring-red-500/30')}
                />
                <TooltipProvider delayDuration={120}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        className="size-11 shrink-0 sm:size-9"
                        onClick={() => setCfgUuid(randomUuid())}
                        aria-label={t('hunt.config.regenerate')}
                      >
                        <RefreshCw className="size-3.5" aria-hidden />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent dir={dir} className="text-[10px]">
                      {t('hunt.config.regenerate')}
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </div>
              {!cfgUuidValid ? (
                <p className="text-[10px] font-semibold text-red-500" role="alert">
                  {t('hunt.config.erruuid')}
                </p>
              ) : null}
            </div>

            <label className="flex flex-col gap-1.5 text-[11px] font-medium text-muted-foreground">
              <span>{t('hunt.config.path')}</span>
              <Input
                value={cfgPath}
                onChange={(e) => setCfgPath(e.target.value)}
                dir="ltr"
                placeholder="/ws"
                aria-label={t('hunt.config.path')}
                className="h-11 font-mono text-xs sm:h-9"
              />
            </label>

            <div className="flex flex-col gap-1.5 text-[11px] font-medium text-muted-foreground">
              <span>{t('hunt.config.sni')}</span>
              <Input
                value={cfgSni}
                onChange={(e) => {
                  const v = e.target.value
                  setCfgSni(v)
                  // free-text wins — the preset select re-highlights only on an exact match (hunt v6.1)
                  setCfgSniPreset(HUNT_SNI_PRESETS.includes(v.trim()) ? v.trim() : '')
                }}
                dir="ltr"
                placeholder="www.cloudflare.com"
                aria-label={t('hunt.config.sni')}
                className="h-11 font-mono text-xs sm:h-9"
              />
              {/* hunt v6.1 — SNI preset picker: fills the free-text input above, never blocks it */}
              <Select
                value={cfgSniPreset === '' ? undefined : cfgSniPreset}
                onValueChange={(v) => {
                  setCfgSniPreset(v)
                  setCfgSni(v)
                }}
                dir={dir}
              >
                <SelectTrigger className="h-11 w-full text-xs sm:h-9" aria-label={t('hunt.sni.preset')}>
                  <SelectValue placeholder={t('hunt.sni.preset')} />
                </SelectTrigger>
                <SelectContent dir={dir}>
                  {HUNT_SNI_PRESETS.map((preset) => (
                    <SelectItem key={preset} value={preset} className="font-mono text-xs">
                      {preset}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* hunt v6.1 — xray fragment presets (appended to VLESS URIs only) */}
            <label className="flex flex-col gap-1.5 text-[11px] font-medium text-muted-foreground sm:col-span-2">
              <span>{t('hunt.fragment.label')}</span>
              <Select value={cfgFragment} onValueChange={(v) => setCfgFragment(v)} dir={dir}>
                <SelectTrigger className="h-11 w-full text-xs sm:h-9" aria-label={t('hunt.fragment.label')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent dir={dir}>
                  {HUNT_FRAGMENT_PRESETS.map((f) => (
                    <SelectItem key={f.id} value={f.id} className="text-xs">
                      {fragmentLabel(f.id)}
                      {f.value ? (
                        <span className="ms-2 font-mono text-[10px] opacity-60" dir="ltr">
                          {f.value}
                        </span>
                      ) : null}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {cfgProtocol === 'vmess' && cfgFragment !== 'none' ? (
                <p className="text-[10px] font-normal text-amber-600 dark:text-amber-400">{t('hunt.fragment.note')}</p>
              ) : null}
            </label>
          </div>

          {/* output — readonly box + copy/download */}
          <div className="flex flex-col gap-1.5">
            <p className="flex items-center justify-between gap-2 text-[11px] font-semibold text-muted-foreground">
              <span>{t('hunt.config.output', { n: num(cfgList.length) })}</span>
              <span className="font-mono text-[10px] opacity-70" dir="ltr">
                {cfgProtocol === 'vless' ? 'vless://…' : 'vmess://…'}
              </span>
            </p>
            <Textarea
              readOnly
              value={cfgText}
              placeholder="—"
              dir="ltr"
              aria-label={t('hunt.config.output', { n: num(cfgList.length) })}
              spellCheck={false}
              className="max-h-48 min-h-20 w-full overflow-y-auto font-mono text-xs"
            />
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="outline"
                className="h-11 flex-1 gap-1 border-emerald-500/30 px-3 text-[11px] text-emerald-700 hover:bg-emerald-500/10 dark:text-emerald-400 sm:h-9 sm:flex-none"
                onClick={copyConfigs}
                disabled={cfgList.length === 0}
              >
                <Copy className="size-3" aria-hidden />
                {t('hunt.config.copy')}
              </Button>
              <Button
                type="button"
                variant="outline"
                className="h-11 flex-1 gap-1 border-teal-500/30 px-3 text-[11px] text-teal-700 hover:bg-teal-500/10 dark:text-teal-400 sm:h-9 sm:flex-none"
                onClick={downloadConfigs}
                disabled={cfgList.length === 0}
              >
                <Download className="size-3" aria-hidden />
                {t('hunt.config.download')}
              </Button>
              {/* hunt v6.2 — save the generated URIs into the subscription store (/api/configs) */}
              <Button
                type="button"
                variant="outline"
                className="h-11 flex-1 gap-1 border-zinc-500/30 px-3 text-[11px] text-zinc-700 hover:bg-zinc-500/10 dark:text-zinc-300 sm:h-9 sm:flex-none"
                onClick={() => void saveConfigsToSub()}
                disabled={cfgList.length === 0 || savingConfigs}
              >
                {savingConfigs ? (
                  <Loader2 className="size-3 animate-spin" aria-hidden />
                ) : (
                  <Save className="size-3" aria-hidden />
                )}
                {t('hunt.config.save')}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* ---------- range checklist dialog (hunt v6.1 — explicit allow-list over the recon ranges) ---------- */}
      <Dialog open={rangesOpen} onOpenChange={setRangesOpen}>
        <DialogContent dir={dir} className="max-h-[85dvh] max-w-lg overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <ListChecks className="size-4 text-amber-500" aria-hidden />
              {t('hunt.ranges.title')}
            </DialogTitle>
            <DialogDescription className="text-xs">
              {t('hunt.ranges.desc')}
            </DialogDescription>
          </DialogHeader>

          {/* provider tabs — google/cloudflare/arvan + ISPها (custom keeps its own textarea, 'all' is not a real pool) */}
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={t('hunt.provider.label')}>
            {HUNT_RANGE_TABS.map((pid) => {
              const p = recon?.providers[pid]
              const active = !ispActive && rangesTab === pid
              return (
                <button
                  key={pid}
                  type="button"
                  aria-pressed={active}
                  onClick={() => {
                    setIspActive(false)
                    switchRangesTab(pid)
                  }}
                  className={cn(
                    'flex min-h-11 items-center gap-1 rounded-md border px-2 py-1 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60',
                    active
                      ? 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                      : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                  )}
                >
                  {t(`hunt.provider.${pid}` as DictKey)}
                  <span className="font-mono text-[9px] opacity-70" dir="ltr">
                    {num(p?.ranges?.length ?? 0)}
                  </span>
                </button>
              )
            })}
            {/* hunt v6.5 — ISP tab: one-tap official prefixes of the whitelisted Iranian operators */}
            <button
              type="button"
              aria-pressed={ispActive}
              onClick={() => setIspActive(true)}
              className={cn(
                'flex min-h-11 items-center gap-1 rounded-md border px-2 py-1 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60',
                ispActive
                  ? 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                  : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
              )}
            >
              <Building2 className="size-3" aria-hidden />
              {t('isp.tab')}
            </button>
          </div>

          {ispActive ? (
            <IspRangePanel
              state={ispState}
              show={ispShow}
              running={running}
              selectedCount={selectedRanges?.cidrs.length ?? 0}
              onToggleShow={() => setIspShow((v) => !v)}
              onPick={(asn) => void fetchIsp(asn)}
              onAdd={addIspRanges}
            />
          ) : (
            <>
          {/* search + bulk actions + live count */}
          <div className="flex flex-wrap items-center gap-2">
            <Input
              value={rangesQuery}
              onChange={(e) => setRangesQuery(e.target.value)}
              dir="ltr"
              placeholder={t('hunt.ranges.search')}
              aria-label={t('hunt.ranges.search')}
              spellCheck={false}
              className="h-11 min-w-0 flex-1 font-mono text-xs sm:h-9"
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-11 gap-1 border-teal-500/30 px-2 text-[11px] text-teal-700 hover:bg-teal-500/10 dark:text-teal-400 sm:h-9"
              onClick={toggleAllVisibleRanges}
              disabled={visibleTabRanges.length === 0}
            >
              <Check className="size-3" aria-hidden />
              {t('hunt.ranges.all')}
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-11 gap-1 border-red-500/30 px-2 text-[11px] text-red-600 hover:bg-red-500/10 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 sm:h-9"
              onClick={() => setRangesChecked(new Set())}
              disabled={rangesChecked.size === 0}
            >
              <X className="size-3" aria-hidden />
              {t('hunt.ranges.clear')}
            </Button>
            <span
              className="rounded-md border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-300"
              aria-live="polite"
            >
              {t('hunt.ranges.count', { n: num(rangesChecked.size) })}
            </span>
          </div>

          {/* checklist rows — search-filtered, scrollable, size hint + v6 tag per row */}
          {visibleTabRanges.length === 0 ? (
            <div className="flex h-20 items-center justify-center rounded-lg border border-dashed bg-background/40 text-xs text-muted-foreground">
              {t('hunt.ranges.empty')}
            </div>
          ) : (
            <div
              className="scrollbar-thin max-h-96 overflow-y-auto rounded-lg border bg-background/40 p-1.5"
              role="group"
              aria-label={t('hunt.ranges.title')}
            >
              <ul className="space-y-1">
                {visibleTabRanges.map((cidr) => {
                  const checked = rangesChecked.has(cidr)
                  const v6 = cidr.includes(':')
                  const sizeHint = cidrSizeHint(cidr)
                  return (
                    <li key={cidr}>
                      <label className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 transition-colors hover:bg-background/80">
                        <Checkbox
                          checked={checked}
                          onCheckedChange={() => toggleRange(cidr)}
                          aria-label={cidr}
                          className="shrink-0"
                        />
                        <span className="min-w-0 flex-1 truncate font-mono text-xs" dir="ltr">
                          {cidr}
                        </span>
                        {sizeHint ? (
                          <span className="shrink-0 font-mono text-[10px] text-muted-foreground" dir="ltr">
                            {sizeHint}
                          </span>
                        ) : null}
                        {v6 ? (
                          <Badge
                            variant="outline"
                            className="shrink-0 border-zinc-500/40 bg-zinc-500/10 px-1 text-[8px] text-zinc-600 dark:text-zinc-400"
                            dir="ltr"
                          >
                            {t('hunt.v6.tag')}
                          </Badge>
                        ) : null}
                      </label>
                    </li>
                  )
                })}
              </ul>
            </div>
          )}

          {/* confirm — commits ONE single-provider selection; disabled at 0 checked */}
          <div className="flex justify-end">
            <Button
              type="button"
              size="sm"
              className="h-11 gap-1.5 bg-teal-600 text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-600 sm:h-9"
              onClick={confirmRanges}
              disabled={rangesChecked.size === 0}
            >
              <Check className="size-3.5" aria-hidden />
              {t('hunt.ranges.confirm')}
              <span className="font-mono text-[10px]" dir="ltr">
                ({num(rangesChecked.size)})
              </span>
            </Button>
          </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* ---------- v7.2 — per-run delete confirmation (ONE shared dialog driven by pendingDelId) ---------- */}
      <AlertDialog
        open={pendingDelId !== null}
        onOpenChange={(o) => {
          if (!o && !delBusy) setPendingDelId(null)
        }}
      >
        <AlertDialogContent dir={dir}>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('hunt.hist.del.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('hunt.hist.del.desc')}
              {pendingDelRun ? (
                <span className="mt-1 block text-[10px] text-muted-foreground">
                  {fmtRunDate(pendingDelRun.finishedAt)}
                </span>
              ) : null}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={delBusy}>{t('hunt.hist.del.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault() // stay open while the DELETE is in flight — closed on success
                void deleteRun()
              }}
              disabled={delBusy}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              {delBusy ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : null}
              {t('hunt.hist.del.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ---------- v7.2 — clear-all history confirmation ---------- */}
      <AlertDialog
        open={confirmClear}
        onOpenChange={(o) => {
          if (!o && !clearBusy) setConfirmClear(false)
        }}
      >
        <AlertDialogContent dir={dir}>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('hunt.hist.clear.title')}</AlertDialogTitle>
            <AlertDialogDescription>{t('hunt.hist.clear.desc', { n: num(runs.length) })}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={clearBusy}>{t('hunt.hist.clear.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault() // stay open while the DELETE is in flight — closed on success
                void clearAllRuns()
              }}
              disabled={clearBusy}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              {clearBusy ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : null}
              {t('hunt.hist.clear.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ---------- v7.3 — per-run detail dialog (badges + meta + funnel + per-provider + latency + healthy IPs) ---------- */}
      <Dialog
        open={detailRun !== null}
        onOpenChange={(o) => {
          if (!o) setDetailRun(null)
        }}
      >
        <DialogContent dir={dir} className="max-h-[85dvh] max-w-lg overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <History className="size-4 text-teal-500" aria-hidden />
              {t('hunt.hist.detail')}
            </DialogTitle>
            <DialogDescription>
              {detailRun
                ? `${fmtRunDate(detailRun.finishedAt)}${detailRun.auto ? ` · ${t('hs.hist.badge')}` : ''}`
                : null}
            </DialogDescription>
          </DialogHeader>
          {detailRun ? (
            <HuntDetailBody run={detailRun} fmtDate={fmtRunDate} fmtDur={fmtDur} onCopyAll={copyDetailIps} />
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  )
}

/** v7.3 — one label/value cell of the detail-dialog meta grid (muted label + mono ltr value) */
function DetailMetaCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="shrink-0 text-[10px] text-muted-foreground">{label}</span>
      <span className="min-w-0 truncate font-mono text-[10px] leading-5 tabular-nums text-foreground" dir="ltr">
        {value}
      </span>
    </div>
  )
}

/** v7.3 — one stat cell of the detail-dialog funnel / latency grids */
function DetailFunnelCell({ label, value, cls }: { label: string; value: string; cls?: string }) {
  return (
    <div className="rounded-md border bg-background/50 px-1.5 py-1 text-center">
      <p className="truncate text-[9px] text-muted-foreground">{label}</p>
      <p className={cn('font-mono text-[11px] leading-5 tabular-nums', cls ?? 'text-foreground')} dir="ltr">
        {value}
      </p>
    </div>
  )
}

/**
 * v7.3 — body of the per-run detail dialog. Date/duration/copy helpers arrive
 * as props so the panel keeps ONE implementation of each; everything else
 * (funnel math, per-provider rows, latency stats) derives from the run itself.
 */
function HuntDetailBody({
  run,
  fmtDate,
  fmtDur,
  onCopyAll,
}: {
  run: GoogleHuntHistoryRun
  fmtDate: (ts: number) => string
  fmtDur: (ms: number) => string
  onCopyAll: () => void
}) {
  const { t, num } = useI18n()
  const ips = run.healthyIps ?? []
  const dLat = huntLatencyStats(ips)
  const rate = run.tested > 0 ? (run.healthy / run.tested) * 100 : null
  /** funnel-bar segments — healthy/blocked ⊆ tcpAlive, so widths are normalized at render (flexGrow) instead of raw tested shares */
  const segs: { n: number; cls: string }[] = [
    { n: run.tcpAlive, cls: 'bg-teal-500/60' },
    { n: run.healthy, cls: 'bg-emerald-500/60' },
    { n: run.blocked, cls: 'bg-amber-500/60' },
    { n: run.dead, cls: 'bg-zinc-500/60' },
  ]
  // red-ish zinc sliver for anything the named stages do not account for (honest guard for odd engine data)
  const unaccounted = run.tested - segs.reduce((acc, x) => acc + x.n, 0)
  if (unaccounted > 0) segs.push({ n: unaccounted, cls: 'bg-red-500/25' })
  const shown = segs.filter((x) => x.n > 0)
  const ppEntries = Object.entries(run.perProvider ?? {}).filter(
    (e): e is [string, HuntProviderStats] => e[1] != null,
  )

  return (
    <div className="space-y-3">
      {/* badges row — provider / scheduled / verify passes / stopped marker */}
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge
          variant="outline"
          className={cn('shrink-0 px-1 text-[8px]', PROVIDER_BADGE[run.provider ?? 'all']?.cls ?? 'border-border')}
        >
          {PROVIDER_BADGE[run.provider ?? 'all']?.label ?? '?'}
        </Badge>
        {run.auto ? (
          <Badge
            variant="outline"
            className="shrink-0 gap-0.5 border-zinc-500/40 bg-zinc-500/10 px-1 text-[8px] text-zinc-600 dark:text-zinc-300"
          >
            <CalendarClock className="size-2" aria-hidden />
            {t('hs.hist.badge')}
          </Badge>
        ) : null}
        <Badge
          variant="outline"
          className="shrink-0 gap-0.5 border-emerald-500/40 bg-emerald-500/10 px-1 text-[8px] text-emerald-600 dark:text-emerald-400"
          dir="ltr"
        >
          <BadgeCheck className="size-2" aria-hidden />
          <span className="sr-only">{t('hunt.verify.label')}: </span>
          ×{num(run.verify)}
        </Badge>
        <span className="ms-auto font-mono text-[10px] text-muted-foreground" dir="ltr">
          {run.stopped ? '■' : '🎯'} ×{num(run.target)}
        </span>
      </div>

      {/* meta grid — duration / host:port / started / finished */}
      <div className="grid grid-cols-1 gap-x-3 gap-y-1 rounded-lg border bg-background/40 p-2 sm:grid-cols-2">
        <DetailMetaCell label={t('hunt.hist.detail.duration')} value={fmtDur(run.finishedAt - run.startedAt)} />
        <DetailMetaCell label={t('hunt.hist.detail.host')} value={`${run.host}:${run.port}`} />
        <DetailMetaCell label={t('hunt.hist.detail.started')} value={fmtDate(run.startedAt)} />
        <DetailMetaCell label={t('hunt.hist.detail.finished')} value={fmtDate(run.finishedAt)} />
      </div>

      {/* funnel stats + thin proportional bar */}
      <div>
        <p className="text-[10px] font-semibold text-muted-foreground">{t('hunt.hist.detail.funnel')}</p>
        <div className="mt-1 grid grid-cols-2 gap-1.5 sm:grid-cols-3">
          <DetailFunnelCell label={t('hunt.cmp.tested')} value={num(run.tested)} />
          <DetailFunnelCell label={t('hunt.hist.detail.tcpalive')} value={num(run.tcpAlive)} />
          <DetailFunnelCell
            label={t('hunt.cmp.healthy')}
            value={num(run.healthy)}
            cls="text-emerald-600 dark:text-emerald-400"
          />
          <DetailFunnelCell
            label={t('hunt.cmp.blocked')}
            value={num(run.blocked)}
            cls="text-amber-700 dark:text-amber-300"
          />
          <DetailFunnelCell label={t('hunt.cmp.dead')} value={num(run.dead)} cls="text-zinc-500" />
          <DetailFunnelCell
            label={t('hunt.hist.detail.rate')}
            value={rate === null ? '—' : `${num(rate, { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%`}
          />
        </div>
        {run.tested > 0 && shown.length > 0 ? (
          <div className="mt-1.5 flex h-1.5 overflow-hidden rounded-full bg-background/70" role="presentation">
            {shown.map((x) => (
              <div key={x.cls} className={cn('h-full min-w-[3px]', x.cls)} style={{ flexGrow: x.n, flexBasis: 0 }} />
            ))}
          </div>
        ) : null}
      </div>

      {/* per-provider breakdown (only when the run carries per-provider counters) */}
      {ppEntries.length > 0 ? (
        <div>
          <p className="text-[10px] font-semibold text-muted-foreground">{t('hunt.hist.detail.providers')}</p>
          <ul className="mt-1 space-y-0.5">
            {ppEntries.map(([pid, st]) => (
              <li
                key={pid}
                className="flex items-center justify-between gap-2 rounded-md border bg-background/40 px-1.5 py-1"
              >
                <span className="flex shrink-0 items-center gap-1">
                  <Badge variant="outline" className={cn('px-1 text-[8px]', PROVIDER_BADGE[pid]?.cls ?? 'border-border')}>
                    {PROVIDER_BADGE[pid]?.label ?? '?'}
                  </Badge>
                  <span className="font-mono text-[9px] text-muted-foreground" dir="ltr">
                    {pid}
                  </span>
                </span>
                <span className="min-w-0 truncate font-mono text-[9px] text-muted-foreground" dir="ltr">
                  {num(st.tested)} → {num(st.healthy)} {t('hunt.cmp.healthy')} · {num(st.blocked)} {t('hunt.cmp.blocked')} ·{' '}
                  {num(st.dead)} {t('hunt.cmp.dead')}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* TLS latency summary (only when at least one healthy IP carries tlsMs??tcpMs) */}
      {dLat ? (
        <div>
          <p className="text-[10px] font-semibold text-muted-foreground">{t('hunt.hist.detail.latency')}</p>
          <div className="mt-1 grid grid-cols-3 gap-1.5">
            <DetailFunnelCell label={t('hunt.hist.detail.latency.avg')} value={`${num(dLat.avg)} ms`} />
            <DetailFunnelCell label={t('hunt.hist.detail.latency.min')} value={`${num(dLat.min)} ms`} />
            <DetailFunnelCell label={t('hunt.hist.detail.latency.max')} value={`${num(dLat.max)} ms`} />
          </div>
        </div>
      ) : null}

      {/* healthy IPs — count chip + copy-all, then a scrollable list mirroring the live results rows */}
      <div>
        <div className="flex items-center justify-between gap-2">
          <p className="text-[10px] font-semibold text-muted-foreground">{t('hunt.hist.detail.ips')}</p>
          {ips.length > 0 ? (
            <div className="flex items-center gap-1.5">
              <Badge variant="outline" className="shrink-0 px-1 font-mono text-[9px]" dir="ltr">
                {num(ips.length)}
              </Badge>
              <button
                type="button"
                onClick={onCopyAll}
                aria-label={t('hunt.hist.detail.copyall')}
                className="inline-flex size-6 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-emerald-500/10 hover:text-emerald-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/60 dark:hover:text-emerald-400"
              >
                <Copy className="size-3" aria-hidden />
              </button>
            </div>
          ) : null}
        </div>
        {ips.length === 0 ? (
          <p className="mt-1 text-[10px] text-muted-foreground">—</p>
        ) : (
          <ul className="scrollbar-thin mt-1 max-h-56 space-y-1 overflow-y-auto pe-1">
            {ips.map((c) => {
              const lat = typeof c.tlsMs === 'number' ? c.tlsMs : typeof c.tcpMs === 'number' ? c.tcpMs : null
              return (
                <li
                  key={candidateAddr(c)}
                  className="flex items-center justify-between gap-2 rounded-md border bg-background/50 px-2 py-1"
                >
                  <span className="flex min-w-0 items-center gap-1.5">
                    <span className="truncate font-mono text-[11px] text-foreground" dir="ltr">
                      {candidateAddr(c)}
                    </span>
                    {c.colo ? (
                      <Badge
                        variant="outline"
                        className="shrink-0 gap-0.5 border-teal-500/40 bg-teal-500/10 px-1 text-[8px] text-teal-600 dark:text-teal-400"
                        dir="ltr"
                      >
                        <MapPin className="size-2" aria-hidden />
                        {c.colo}
                      </Badge>
                    ) : null}
                  </span>
                  <span className="flex shrink-0 items-center gap-1.5">
                    {lat !== null ? (
                      <span className="font-mono text-[10px] text-muted-foreground" dir="ltr">
                        {num(lat)} ms
                      </span>
                    ) : null}
                    {c.server ? (
                      <span className="max-w-24 truncate font-mono text-[9px] text-muted-foreground" dir="ltr">
                        {c.server}
                      </span>
                    ) : null}
                  </span>
                </li>
              )
            })}
          </ul>
        )}
      </div>
    </div>
  )
}

/** hunt v6.5 — the «ISPها» tab of the ranges dialog: whitelisted Iranian operators, click-to-fetch prefixes, one-tap add to the committed selection */
function IspRangePanel({
  state,
  show,
  running,
  selectedCount,
  onToggleShow,
  onPick,
  onAdd,
}: {
  state: IspFetchState
  /** prefix list visibility of the active (fetched) chip */
  show: boolean
  running?: boolean
  /** size of the committed selection — mirrored as the familiar count chip */
  selectedCount: number
  onToggleShow: () => void
  onPick: (asn: string) => void
  /** v7.0 — third arg: the ASN label ('AS<digits>') so fresh prefixes are remembered as labelled */
  onAdd: (name: string, prefixes: string[], asnLabel: string) => void
}) {
  const { t, num } = useI18n()
  return (
    <div className="space-y-2" role="group" aria-label={t('isp.aria')}>
      <p className="flex items-start gap-1.5 text-[11px] leading-relaxed text-muted-foreground">
        <Antenna className="mt-0.5 size-3.5 shrink-0 text-amber-500" aria-hidden />
        <span>
          <span className="font-semibold text-foreground">{t('isp.title')}</span> — {t('isp.hint')}
        </span>
      </p>

      {/* 7 whitelisted operators — 2 cols mobile / 3-4 desktop; the fetched chip expands over the full row */}
      <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3 md:grid-cols-4" aria-label={t('isp.title')}>
        {ISP_ASN_LIST.map((isp) => {
          const isActive = state.st !== 'idle' && state.asn === isp.asn
          const loading = state.st === 'loading' && state.asn === isp.asn
          const ok = state.st === 'ok' && state.asn === isp.asn ? state : null
          const err = state.st === 'err' && state.asn === isp.asn ? state : null
          return (
            <div
              key={isp.asn}
              className={cn(
                'rounded-lg border p-1.5 transition-colors',
                ok
                  ? 'col-span-2 border-amber-500/40 bg-amber-500/5 sm:col-span-3 md:col-span-4'
                  : 'border-border bg-background/40',
              )}
            >
              <button
                type="button"
                onClick={() => onPick(isp.asn)}
                aria-pressed={isActive}
                aria-label={`${t(isp.nameKey)} — ${isp.asn}`}
                className="flex min-h-11 w-full items-center justify-between gap-1.5 rounded-md px-1 text-start transition-colors hover:bg-background/70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60"
              >
                <span className="min-w-0">
                  <span className="block truncate text-xs font-bold">{t(isp.nameKey)}</span>
                  <span className="block font-mono text-[9px] text-muted-foreground" dir="ltr">
                    {isp.asn}
                  </span>
                </span>
                <span className="shrink-0 ps-1">
                  {loading ? (
                    <Loader2 className="size-3.5 animate-spin text-amber-500" aria-hidden />
                  ) : ok ? (
                    <CheckCircle2 className="size-3.5 text-emerald-500" aria-hidden />
                  ) : null}
                </span>
              </button>

              {ok ? (
                <div className="mt-1.5 space-y-2 border-t border-border pt-2">
                  <p className="flex flex-wrap items-center gap-1.5">
                    <span
                      className="rounded-md border border-teal-500/30 bg-teal-500/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-teal-700 dark:text-teal-300"
                      dir="ltr"
                      aria-live="polite"
                    >
                      {t('isp.count', { v4: num(ok.count4), v6: num(ok.count6) })}
                    </span>
                    {ok.cached ? <span className="text-[9px] text-muted-foreground">{t('isp.cache')}</span> : null}
                    {ok.prefixes.length === 0 ? (
                      <span className="text-[9px] text-muted-foreground">{t('hunt.ranges.empty')}</span>
                    ) : null}
                  </p>
                  <div className="flex flex-wrap items-center gap-2">
                    <Button
                      type="button"
                      size="sm"
                      className="h-11 gap-1.5 bg-amber-600 text-white hover:bg-amber-700 dark:bg-amber-500 dark:hover:bg-amber-600 sm:h-9"
                      onClick={() => onAdd(t(isp.nameKey), ok.prefixes, ok.asn)}
                      disabled={running || ok.prefixes.length === 0}
                    >
                      <ListChecks className="size-3.5" aria-hidden />
                      {t('isp.add')}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-11 gap-1 border-zinc-500/40 px-2.5 text-[11px] text-zinc-700 hover:bg-zinc-500/10 hover:text-zinc-800 dark:text-zinc-300 dark:hover:text-zinc-100 sm:h-9"
                      onClick={onToggleShow}
                      aria-expanded={show}
                      disabled={ok.prefixes.length === 0}
                    >
                      <ChevronDown className={cn('size-3 transition-transform', show && 'rotate-180')} aria-hidden />
                      {show ? t('isp.hide') : t('isp.show')}
                    </Button>
                  </div>
                  {show ? (
                    <div
                      className="scrollbar-thin max-h-40 overflow-y-auto rounded-md border border-border bg-background/60 p-1.5"
                      role="region"
                      aria-label={`${t(isp.nameKey)} — ${t('isp.show')}`}
                    >
                      <ul className="space-y-0.5">
                        {ok.prefixes.map((p) => (
                          <li key={p} className="font-mono text-[10px] leading-5 text-muted-foreground" dir="ltr">
                            {p}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              ) : null}

              {err ? (
                <p role="alert" className="mt-1 flex flex-wrap items-center gap-1 px-1 pb-0.5 text-[10px] text-red-600 dark:text-red-400">
                  <AlertCircle className="size-3 shrink-0" aria-hidden />
                  {t('isp.err')}
                  <span className="font-mono text-[9px] text-muted-foreground" dir="ltr">
                    {err.code}
                  </span>
                </p>
              ) : null}
            </div>
          )
        })}
      </div>

      {/* committed selection size — the same single-provider pool the other three tabs feed */}
      <div className="flex justify-end">
        <span
          className="rounded-md border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-300"
          aria-live="polite"
        >
          {t('hunt.ranges.count', { n: num(selectedCount) })}
        </span>
      </div>
    </div>
  )
}

/** hunt v6.3 — one per-provider override row (provider badge + host/port/path inputs; '' = default) */
function HuntOvRow({
  labelKey,
  badgeCls,
  value,
  onChange,
  hostPlaceholder,
  pathPlaceholder,
  disabled,
}: {
  labelKey: DictKey
  badgeCls: string
  value: HuntOvInput
  onChange: (next: HuntOvInput) => void
  hostPlaceholder: string
  pathPlaceholder: string
  disabled?: boolean
}) {
  const { t } = useI18n()
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={t(labelKey)}>
      <Badge
        variant="outline"
        className={cn('shrink-0 px-1.5 py-0 text-[9px]', badgeCls)}
        dir="ltr"
      >
        {t(labelKey)}
      </Badge>
      <Input
        value={value.host}
        onChange={(e) => onChange({ ...value, host: e.target.value })}
        dir="ltr"
        spellCheck={false}
        placeholder={hostPlaceholder}
        aria-label={`${t(labelKey)} — ${t('hunt.ov.host.aria')}`}
        disabled={disabled}
        className="h-11 min-w-36 flex-1 font-mono text-xs disabled:opacity-60 sm:h-9"
      />
      <Input
        value={value.port}
        onChange={(e) => onChange({ ...value, port: e.target.value })}
        dir="ltr"
        inputMode="numeric"
        placeholder="443"
        aria-label={`${t(labelKey)} — ${t('hunt.ov.port.aria')}`}
        disabled={disabled}
        className="h-11 w-20 shrink-0 font-mono text-xs disabled:opacity-60 sm:h-9"
      />
      <Input
        value={value.path}
        onChange={(e) => onChange({ ...value, path: e.target.value })}
        dir="ltr"
        spellCheck={false}
        placeholder={pathPlaceholder}
        aria-label={`${t(labelKey)} — ${t('hunt.ov.path.aria')}`}
        disabled={disabled}
        className="h-11 min-w-28 flex-1 font-mono text-xs disabled:opacity-60 sm:h-9"
      />
    </div>
  )
}

/** one stage of the detection funnel (tested → tcp-alive → healthy) */
function FunnelStage({
  label,
  value,
  sub,
  icon: Icon,
  tone,
}: {
  label: string
  value: string
  sub: string | null
  icon: React.ComponentType<{ className?: string; 'aria-hidden'?: boolean }>
  tone: 'zinc' | 'teal' | 'emerald'
}) {
  const toneCls =
    tone === 'emerald'
      ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-600 dark:text-emerald-400'
      : tone === 'teal'
        ? 'border-teal-500/30 bg-teal-500/5 text-teal-600 dark:text-teal-400'
        : 'border-border bg-background/60 text-muted-foreground'
  return (
    <div className={cn('min-w-0 flex-1 rounded-lg border px-2 py-1.5', toneCls)}>
      <p className="flex items-start gap-1 text-[10px] leading-tight">
        <Icon className="mt-px size-3 shrink-0" aria-hidden />
        <span className="min-w-0">{label}</span>
      </p>
      <p className="mt-0.5 font-mono text-sm font-bold tabular-nums" dir="ltr">
        {value}
      </p>
      {sub ? <p className="font-mono text-[9px] opacity-70" dir="ltr">{sub}</p> : null}
    </div>
  )
}

/** small stat tile used in the counters grid */
function Counter({
  label,
  value,
  icon: Icon,
  tone,
  highlight,
}: {
  label: string
  value: string
  icon: React.ComponentType<{ className?: string; 'aria-hidden'?: boolean }>
  tone: 'neutral' | 'emerald' | 'red' | 'zinc' | 'teal'
  highlight?: boolean
}) {
  const toneCls =
    tone === 'emerald'
      ? 'text-emerald-600 dark:text-emerald-400'
      : tone === 'red'
        ? 'text-red-500'
        : tone === 'teal'
          ? 'text-teal-600 dark:text-teal-400'
          : 'text-muted-foreground'
  return (
    <div
      className={cn(
        'rounded-lg border bg-background/50 px-2.5 py-2',
        highlight && 'border-emerald-500/30 bg-emerald-500/5',
      )}
    >
      <p className={cn('flex items-center gap-1 text-[10px] text-muted-foreground', toneCls)}>
        <Icon className="size-3" aria-hidden />
        {label}
      </p>
      <p className={cn('mt-0.5 font-mono text-sm font-bold tabular-nums', toneCls)} dir="ltr">
        {value}
      </p>
    </div>
  )
}

/** one pool utilisation meter of the parallel pipeline telestrip (hunt v5) */
function PoolMeter({
  label,
  value,
  max,
  pct,
  barCls,
}: {
  label: string
  value: string
  max: string
  pct: number
  barCls: string
}) {
  return (
    <div className="min-w-0">
      <p className="flex items-center justify-between gap-2 text-[10px] text-muted-foreground">
        <span className="min-w-0 truncate">{label}</span>
        <span className="shrink-0 font-mono tabular-nums" dir="ltr">
          {value}/{max}
        </span>
      </p>
      <div
        className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-muted"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct}
        aria-label={label}
      >
        <div
          className={cn('h-full rounded-full transition-[width] duration-500', barCls)}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}
