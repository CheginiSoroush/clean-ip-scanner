'use client'

/**
 * IntegrationsPanel — hunt v6.3 integrations tab (Persian-first RTL).
 *
 * Three cards in a responsive grid (the third wraps to a new row):
 *   1. Cloudflare DDNS — settings (token/zone/record/TTL/proxy), connection
 *      test, sync-push of healthy hunt IPs (create/keep/remove semantics),
 *      the scheduled auto-push controls (v6.5 — server-side scheduler reads
 *      the latest healthy hunt on an interval) and the push history journal.
 *   2. Telegram — bot settings, send test, manual + automatic hunt and WARP
 *      digests (each fires once per finished run when «ارسال خودکار» is on);
 *      v7.6 — scheduled-run digests auto-attach the scheduler-journal CSV.
 *   3. Settings backup (v6.7) — download the DNS/Telegram settings as one
 *      JSON file (tokens opt-in) and restore them from a file, with a
 *      client-side envelope validation + preview before anything is sent.
 *
 * Visual language mirrors SavedConfigsPanel/WarpPanel: TanStack Query +
 * sonner toasts + lucide icons, amber/zinc accents (NO indigo/blue).
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import type { Locale } from 'date-fns'
import { faIR, enUS } from 'date-fns/locale'
import { toast } from 'sonner'
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  CloudCog,
  DatabaseBackup,
  Download,
  Eye,
  EyeOff,
  FileUp,
  Globe,
  Loader2,
  Paperclip,
  RotateCcw,
  Send,
  Wifi,
  WifiOff,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { fetchJson } from '@/lib/api-types'
import { buildSchedulerJournalCsvRows, csvFileStamp } from '@/lib/csv'
import { useI18n } from '@/components/i18n-provider'
import { cn } from '@/lib/utils'
import type {
  GoogleHuntCandidate,
  GoogleHuntState,
  HuntScheduleJournalEntry,
  WarpScanState,
} from '@/lib/scan-protocol'
import type { SettingsExport } from '@/lib/scan-protocol'

export interface IntegrationsPanelProps {
  /** live engine socket status (shown as a micro badge on the Telegram card) */
  connected?: boolean
  /** healthy IPv4 addresses of the current hunt view (v6 filtered out upstream) */
  healthyIps: string[]
  /** healthy IPv6 addresses of the current hunt view (hunt v6.4 — fills the AAAA push) */
  healthyIpsV6: string[]
  /** full live hunt state — feeds the digest composer + auto-send */
  huntState: GoogleHuntState | null
  /** v6.6 — full live WARP scan state — feeds the WARP digest composer + auto-send */
  warpState?: WarpScanState | null
  /** v7.6 — hunt-scheduler journal (newest-first) — feeds the journal-CSV auto-attach for scheduled-run digests */
  schedJournal?: HuntScheduleJournalEntry[]
}

// ---------- API response shapes (mirrors /api/dns + /api/telegram) ----------

interface DnsPushLogRow {
  id: number
  recordName: string
  ips: string
  created: number
  kept: number
  removed: number
  ok: boolean
  detail: string
  createdAt: string
}

interface DnsSettingsInfo {
  configured: boolean
  recordName?: string
  recordType?: string
  zoneId?: string
  ttl?: number
  proxied?: boolean
  tokenHint?: string
  /** hunt v6.5 — scheduled auto-push (server-side scheduler, never client timers) */
  autoPush?: boolean
  /** interval in MINUTES (server clamps 10..1440) */
  autoPushMin?: number
  /** per-push IP cap (server clamps 1..10) */
  autoPushMaxIps?: number
  /** ISO timestamp of the last auto-push run (null = never) */
  autoPushAt?: string | null
  updatedAt?: string
}

interface DnsResponse {
  settings: DnsSettingsInfo
  pushes: DnsPushLogRow[]
}

interface TgSettingsInfo {
  configured: boolean
  chatId?: string
  autoOnFinish?: boolean
  tokenHint?: string
  updatedAt?: string
}

// ---------- validation + small helpers ----------

const TTL_OPTIONS = [1, 300, 600, 1800, 3600, 7200] as const
const TTL_SET = new Set<number>(TTL_OPTIONS)
/** lenient zone id (CF issues 32-hex; accept 16..40 hex chars) */
const ZONE_ID_RE = /^[a-f0-9]{16,40}$/i
/** hostname-ish record name */
const RECORD_NAME_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i
/** strict dotted-quad IPv4 */
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
/**
 * full IPv6 (groups + :: compression) — client-side mirror of the server's
 * authoritative `net.isIP(ip) === 6` check (no IPv4-mapped tails, rare edge)
 */
const IPV6_RE =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/
const PUSH_MAX_IPS = 10
/** hunt v6.5 — auto-push interval presets in minutes (the Select offers these; the server clamps 10..1440) */
const AUTO_PUSH_INTERVAL_OPTIONS = [10, 15, 30, 60, 120, 360] as const
const AUTO_PUSH_IPS_MAX = 10

/** defensive clamp of the stored auto-push interval (minutes) — default 30 */
function clampAutoPushMin(v: unknown): number {
  const n = Math.floor(Number(v))
  if (!Number.isFinite(n)) return 30
  return Math.min(1440, Math.max(10, n))
}
/** defensive clamp of the stored per-push IP cap — default 10 */
function clampAutoPushMaxIps(v: unknown): number {
  const n = Math.floor(Number(v))
  if (!Number.isFinite(n)) return AUTO_PUSH_IPS_MAX
  return Math.min(AUTO_PUSH_IPS_MAX, Math.max(1, n))
}

/** DNS record type (hunt v6.4 — A for IPv4, AAAA for IPv6) */
type DnsRecordType = 'A' | 'AAAA'

/** the stored type exactly as the server normalises it */
function asRecordType(v: string | undefined | null): DnsRecordType {
  return v === 'AAAA' ? 'AAAA' : 'A'
}
/** per-type validity check (client mirror of the server rule) */
function isValidIpFor(ip: string, recordType: DnsRecordType): boolean {
  return recordType === 'AAAA' ? IPV6_RE.test(ip) : IPV4_RE.test(ip)
}
const DIGEST_MAX = 4000

/** Persian keyboard digits → ASCII so numeric inputs accept both */
function toEnDigits(v: string): string {
  return v.replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 1776))
}

/** compact m:ss elapsed label (digest text) */
function fmtElapsedShort(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000))
  const m = Math.floor(s / 60)
  return m > 0 ? `${m}:${String(s % 60).padStart(2, '0')}` : `${s}s`
}

/** display/copy address of a healthy candidate (v6 gets brackets) */
function candidateAddr(c: GoogleHuntCandidate): string {
  if (c.v6 || c.ip.includes(':')) return `[${c.ip}]:${c.port ?? 443}`
  return c.port != null ? `${c.ip}:${c.port}` : c.ip
}

/**
 * Hunt digest text (≤4000 chars) — client-composed summary of a finished run:
 * tested/healthy/blocked/dead + verified/IPv6 counts, rate and the top 5
 * healthy IPs (mono-friendly plain text, no parse_mode on the Telegram side).
 */
function buildDigest(s: GoogleHuntState, fa: boolean, num: (n: number) => string): string {
  const providerLabel = s.provider && s.provider !== 'all' ? s.provider : fa ? 'همه' : 'all'
  const v6 = s.healthyIps.filter((c) => c.v6 || c.ip.includes(':')).length
  const lines: string[] = []
  lines.push(fa ? '🎯 خلاصه شکار — Clean IP Scanner' : '🎯 Hunt digest — Clean IP Scanner')
  lines.push(`${fa ? 'ارائه‌دهنده' : 'Provider'}: ${providerLabel} · ${fa ? 'هدف' : 'Target'}: ${num(s.target)}`)
  lines.push(
    `${fa ? 'بررسی‌شده' : 'Tested'}: ${num(s.tested)} · ${fa ? 'سالم' : 'Healthy'}: ${num(s.healthy)} · ${fa ? 'مسدود' : 'Blocked'}: ${num(s.blocked)} · ${fa ? 'مرده' : 'Dead'}: ${num(s.dead)}`,
  )
  lines.push(`${fa ? 'تأییدشده' : 'Verified'}: ${num(s.verified)} · IPv6: ${num(v6)}`)
  if (s.startedAt) {
    const elapsed = fmtElapsedShort(s.elapsedMs || Date.now() - s.startedAt)
    lines.push(
      `${fa ? 'زمان' : 'Time'}: ${elapsed} · ${fa ? 'سرعت' : 'Rate'}: ${num(Math.round(s.ipsPerSecond || 0))}/s`,
    )
  }
  const top = s.healthyIps.slice(0, 5)
  if (top.length > 0) {
    lines.push('')
    lines.push(fa ? 'IPهای سالم برتر:' : 'Top healthy IPs:')
    top.forEach((c, i) => {
      const tls = c.tlsMs != null ? ` (TLS ${num(c.tlsMs)}ms)` : ''
      lines.push(`${num(i + 1)}. ${candidateAddr(c)}${tls}`)
    })
  }
  return lines.join('\n').slice(0, DIGEST_MAX)
}

/**
 * v6.6 — WARP digest text (≤4000 chars), mirrors buildDigest structure:
 * status, tested/alive, elapsed + eps, registered identity flag, ports +
 * ranges count, then the top ≤10 live endpoints sorted by rtt (missing last).
 * Returns null when there is nothing to send (caller disables + toasts).
 */
function composeWarpDigest(w: WarpScanState | null, fa: boolean, num: (n: number) => string): string | null {
  if (!w || !Array.isArray(w.found) || w.found.length === 0) return null
  const ports = Array.isArray(w.ports) ? w.ports : []
  const ranges = Array.isArray(w.ranges) ? w.ranges : []
  const lines: string[] = []
  lines.push(fa ? '📡 خلاصه اسکن WARP — Clean IP Scanner' : '📡 WARP scan digest — Clean IP Scanner')
  lines.push(`${fa ? 'وضعیت' : 'Status'}: ${w.stopped ? (fa ? 'متوقف شد' : 'Stopped') : fa ? 'تکمیل شد' : 'Finished'}`)
  lines.push(`${fa ? 'بررسی‌شده' : 'Tested'}: ${num(w.tested)} · ${fa ? 'زنده' : 'Alive'}: ${num(w.alive)}`)
  if (w.startedAt) {
    const elapsed = fmtElapsedShort(w.elapsedMs || Date.now() - w.startedAt)
    lines.push(
      `${fa ? 'زمان' : 'Time'}: ${elapsed} · ${fa ? 'سرعت' : 'Rate'}: ${num(Math.round(w.epsPerSecond || 0))}/s`,
    )
  }
  if (w.registered != null) {
    lines.push(
      fa
        ? `هویت ثبت‌شده: ${w.registered ? 'بله — هندشیک واقعی' : 'خیر — کلید عمومی موجود نیست'}`
        : `Registered identity: ${w.registered ? 'yes — real handshakes' : 'no — no public key'}`,
    )
  }
  lines.push(`${fa ? 'پورت‌ها' : 'Ports'}: ${ports.map((p) => num(p)).join(', ')}`)
  lines.push(`${fa ? 'بازه‌ها' : 'Ranges'}: ${num(ranges.length)}`)
  const top = [...w.found]
    .sort((a, b) => {
      const ra = a.rttMs ?? Number.POSITIVE_INFINITY
      const rb = b.rttMs ?? Number.POSITIVE_INFINITY
      return ra - rb
    })
    .slice(0, 10)
  if (top.length > 0) {
    lines.push('')
    lines.push(fa ? 'نقاط زنده:' : 'Live endpoints:')
    top.forEach((e, i) => {
      const rtt = e.rttMs != null ? `${num(e.rttMs)} ms` : '—'
      const kind =
        e.response === 'handshake'
          ? fa ? 'هندشیک' : 'handshake'
          : e.response === 'cookie'
            ? fa ? 'کوکی' : 'cookie'
            : fa ? 'پاسخ' : 'response'
      lines.push(`${num(i + 1)}. ${e.endpoint} — ${rtt} — ${kind}`)
    })
  }
  lines.push('')
  lines.push(`⏱ ${new Date().toLocaleString(fa ? 'fa-IR' : 'en-US')}`)
  return lines.join('\n').slice(0, DIGEST_MAX)
}

/**
 * Auto-send guard — module-level (NOT a useRef) so re-mounting the panel
 * (tab switching) never re-fires the digest for the same finished run.
 * Mirrors sessionStorage so a reload does not double-send either.
 */
const DIGEST_STAMP_KEY = 'cis-tg-digest-stamp'
let lastDigestStamp = 0
try {
  lastDigestStamp = Number(window.sessionStorage.getItem(DIGEST_STAMP_KEY) ?? 0) || 0
} catch {
  /* private mode etc. */
}
function markDigestSent(stamp: number) {
  lastDigestStamp = stamp
  try {
    window.sessionStorage.setItem(DIGEST_STAMP_KEY, String(stamp))
  } catch {
    /* ignore */
  }
}

/**
 * v6.6 — WARP auto-send guard — own stamp key + own module-level counter so the
 * hunt and WARP auto-digests never shadow each other (same sessionStorage
 * mirror: tab switches and reloads cannot double-send).
 */
const WARP_DIGEST_STAMP_KEY = 'cis-tg-digest-stamp-warp'
let lastWarpDigestStamp = 0
try {
  lastWarpDigestStamp = Number(window.sessionStorage.getItem(WARP_DIGEST_STAMP_KEY) ?? 0) || 0
} catch {
  /* private mode etc. */
}
function markWarpDigestSent(stamp: number) {
  lastWarpDigestStamp = stamp
  try {
    window.sessionStorage.setItem(WARP_DIGEST_STAMP_KEY, String(stamp))
  } catch {
    /* ignore */
  }
}

// ---------- root ----------

export function IntegrationsPanel({
  connected,
  healthyIps,
  healthyIpsV6,
  huntState,
  warpState,
  schedJournal = [],
}: IntegrationsPanelProps) {
  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
      <DnsCard healthyIps={healthyIps} healthyIpsV6={healthyIpsV6} />
      <TelegramCard
        connected={connected}
        huntState={huntState}
        warpState={warpState ?? null}
        schedJournal={schedJournal}
      />
      {/* v6.7 — third card: wraps to a new row on lg naturally */}
      <SettingsBackupCard />
    </div>
  )
}

// ---------- card 1: Cloudflare DDNS ----------

function DnsCard({ healthyIps, healthyIpsV6 }: { healthyIps: string[]; healthyIpsV6: string[] }) {
  const { t } = useI18n()
  const dns = useQuery<DnsResponse>({
    queryKey: ['dns-settings'],
    queryFn: () => fetchJson<DnsResponse>('/api/dns'),
    retry: false,
  })
  const settings = dns.data?.settings
  const pushes = useMemo(() => dns.data?.pushes ?? [], [dns.data])
  const configured = !!settings?.configured

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur sm:p-6">
      {/* ---------- header ---------- */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex size-8 items-center justify-center rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-400">
          <Globe className="size-4" aria-hidden />
        </span>
        <h2 className="text-base font-bold">{t('dns.title')}</h2>
        <Badge
          variant="outline"
          className={cn(
            'px-1.5 py-0 text-[10px]',
            configured
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
              : 'border-zinc-500/40 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300',
          )}
        >
          {t(configured ? 'dns.configured' : 'dns.not.configured')}
        </Badge>
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{t('dns.desc')}</p>

      {/* ---------- loading ---------- */}
      {dns.isLoading ? (
        <div className="mt-4 space-y-2">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-11 w-full rounded-lg" />
          ))}
        </div>
      ) : null}

      {/* ---------- settings + push + auto-push + history (one keyed body — the canonical row drives every field) ---------- */}
      {settings && !dns.isLoading ? (
        <DnsPanel
          key={settings.updatedAt ?? 'new'}
          settings={settings}
          pushes={pushes}
          healthyIps={healthyIps}
          healthyIpsV6={healthyIpsV6}
        />
      ) : null}

      {dns.isError ? (
        <p role="alert" className="mt-3 flex items-center gap-1.5 text-xs text-red-600 dark:text-red-400">
          <AlertCircle className="size-3.5" aria-hidden />
          {t('dns.load.fail')}
        </p>
      ) : null}
    </div>
  )
}

/**
 * One key-remounted body for the whole DDNS card (v6.5): the settings form, the
 * sync-push sub-card, the scheduled auto-push section and the history journal
 * all live here so the single save mutation carries every field at once.
 * Remounts whenever the canonical server row changes (updatedAt) — state
 * initializers always read fresh server values, never stale local edits.
 */
function DnsPanel({
  settings,
  pushes,
  healthyIps,
  healthyIpsV6,
}: {
  settings: DnsSettingsInfo
  pushes: DnsPushLogRow[]
  healthyIps: string[]
  healthyIpsV6: string[]
}) {
  const { t, num, lang, dir } = useI18n()
  const qc = useQueryClient()
  const configured = !!settings.configured
  // v6.4.1 — the type the user is EDITING in the form drives the push card too
  // (falls back to the stored server type before the first touch), so the
  // visible Select, the textarea validation and the actual push never disagree
  const [activeType, setActiveType] = useState<DnsRecordType | null>(null)
  const invalidate = useCallback(() => {
    void qc.invalidateQueries({ queryKey: ['dns-settings'] })
  }, [qc])

  // ---- settings form fields (token stays empty = keep saved) ----
  const [token, setToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [zoneId, setZoneId] = useState(settings.zoneId ?? '')
  const [recordName, setRecordName] = useState(settings.recordName ?? '')
  const [recordType, setRecordType] = useState<DnsRecordType>(asRecordType(settings.recordType))
  const [ttl, setTtl] = useState(String(settings.ttl ?? 300))
  const [proxied, setProxied] = useState(settings.proxied ?? false)
  // ---- hunt v6.5 — scheduled auto-push fields (same save, same PUT body) ----
  const [autoPush, setAutoPush] = useState(settings.autoPush ?? false)
  const [autoPushMin, setAutoPushMin] = useState(String(clampAutoPushMin(settings.autoPushMin)))
  const [autoPushMaxIps, setAutoPushMaxIps] = useState(String(clampAutoPushMaxIps(settings.autoPushMaxIps)))
  const autoPushMinNum = clampAutoPushMin(autoPushMin)
  const autoPushMaxIpsNum = clampAutoPushMaxIps(autoPushMaxIps)
  /** interval presets + the stored value when the server clamped it outside the offered set */
  const autoPushMinOptions = useMemo<number[]>(() => {
    const opts: number[] = [...AUTO_PUSH_INTERVAL_OPTIONS]
    if (!opts.includes(autoPushMinNum)) {
      opts.push(autoPushMinNum)
      opts.sort((a, b) => a - b)
    }
    return opts
  }, [autoPushMinNum])
  const [testState, setTestState] = useState<{ ok: boolean; zoneName?: string; error?: string } | null>(null)

  const save = useMutation({
    mutationFn: async () => {
      const res = await fetch('/api/dns', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cfToken: token.trim() || undefined,
          zoneId: zoneId.trim(),
          recordName: recordName.trim(),
          recordType,
          ttl: Number(ttl),
          proxied,
          autoPush,
          autoPushMin: autoPushMinNum,
          autoPushMaxIps: autoPushMaxIpsNum,
        }),
      })
      const data = (await res.json().catch(() => null)) as { ok?: boolean; error?: string } | null
      if (!res.ok || !data?.ok) throw new Error(data?.error ?? 'http_error')
      return true
    },
    onSuccess: () => {
      toast.success(t('dns.saved'))
      setTestState(null)
      invalidate()
    },
    onError: () => toast.error(t('dns.save.fail')),
  })

  const testConn = useMutation({
    mutationFn: async () => {
      const res = await fetch('/api/dns/test', { method: 'POST' })
      const data = (await res.json().catch(() => null)) as
        | { ok?: boolean; zoneName?: string; errors?: string[]; error?: string }
        | null
      if (res.status === 400) throw new Error(data?.error ?? 'not_configured')
      if (res.status === 502) throw new Error(data?.error ?? 'cloudflare_unreachable')
      return data ?? { ok: false }
    },
    onSuccess: (data) => {
      const ok = !!data.ok
      setTestState({
        ok,
        zoneName: data.zoneName,
        error: ok ? undefined : (data.errors ?? [data.error ?? 'cloudflare_error']).join(' | '),
      })
    },
    onError: (e) => setTestState({ ok: false, error: e.message }),
  })

  // client validation mirrors the server (never trust, also fail fast)
  const saveDisabled =
    save.isPending ||
    !ZONE_ID_RE.test(zoneId.trim()) ||
    !RECORD_NAME_RE.test(recordName.trim()) ||
    !(recordType === 'A' || recordType === 'AAAA') ||
    !TTL_SET.has(Number(ttl)) ||
    (token.trim() !== '' && (token.trim().length < 20 || token.trim().length > 60)) ||
    autoPushMinNum < 10 ||
    autoPushMinNum > 1440 ||
    autoPushMaxIpsNum < 1 ||
    autoPushMaxIpsNum > 10

  const dateFnsLocale = lang === 'fa' ? faIR : enUS

  return (
    <div className="mt-4 space-y-3" role="group" aria-label={t('dns.title')}>
      {/* token (password + eye toggle, empty = keep saved) */}
      <div className="space-y-1">
        <Label htmlFor="dns-token" className="text-[11px] font-semibold text-muted-foreground">
          {t('dns.token')}
        </Label>
        <div className="relative">
          <Input
            id="dns-token"
            type={showToken ? 'text' : 'password'}
            value={token}
            onChange={(e) => setToken(e.target.value)}
            dir="ltr"
            autoComplete="off"
            spellCheck={false}
            placeholder={settings.configured ? settings.tokenHint : ''}
            aria-label={t('dns.token')}
            className="h-11 pe-10 font-mono text-xs sm:h-9"
          />
          <button
            type="button"
            onClick={() => setShowToken((v) => !v)}
            aria-label={t('dns.token.eye')}
            aria-pressed={showToken}
            className="absolute end-1.5 top-1/2 inline-flex size-8 -translate-y-1/2 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-amber-500/10 hover:text-amber-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500/60 dark:hover:text-amber-400"
          >
            {showToken ? <EyeOff className="size-3.5" aria-hidden /> : <Eye className="size-3.5" aria-hidden />}
          </button>
        </div>
        <p className="text-[10px] text-muted-foreground">{t('dns.token.hint')}</p>
      </div>

      {/* zone + record */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="dns-zone" className="text-[11px] font-semibold text-muted-foreground">
            {t('dns.zone')}
          </Label>
          <Input
            id="dns-zone"
            value={zoneId}
            onChange={(e) => setZoneId(e.target.value)}
            dir="ltr"
            spellCheck={false}
            aria-label={t('dns.zone')}
            className="h-11 font-mono text-xs sm:h-9"
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="dns-record" className="text-[11px] font-semibold text-muted-foreground">
            {t('dns.record')}
          </Label>
          <Input
            id="dns-record"
            value={recordName}
            onChange={(e) => setRecordName(e.target.value)}
            dir="ltr"
            spellCheck={false}
            placeholder="clean.example.com"
            aria-label={t('dns.record')}
            className="h-11 font-mono text-xs sm:h-9"
          />
        </div>
      </div>

      {/* record type + TTL + proxied */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="w-36 space-y-1">
          <Label htmlFor="dns-type" className="text-[11px] font-semibold text-muted-foreground">
            {t('dns.type')}
          </Label>
          <Select
            value={recordType}
            onValueChange={(v) => {
              const nt = asRecordType(v)
              setRecordType(nt)
              setActiveType(nt)
            }}
          >
            <SelectTrigger id="dns-type" aria-label={t('dns.type')} className="h-11 w-full text-xs sm:h-9">
              <SelectValue />
            </SelectTrigger>
            <SelectContent dir={dir}>
              <SelectItem value="A">{t('dns.type.a')}</SelectItem>
              <SelectItem value="AAAA">{t('dns.type.aaaa')}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="w-36 space-y-1">
          <Label htmlFor="dns-ttl" className="text-[11px] font-semibold text-muted-foreground">
            {t('dns.ttl')}
          </Label>
          <Select value={ttl} onValueChange={setTtl}>
            <SelectTrigger id="dns-ttl" aria-label={t('dns.ttl')} className="h-11 w-full text-xs sm:h-9">
              <SelectValue />
            </SelectTrigger>
            <SelectContent dir={dir}>
              {TTL_OPTIONS.map((v) => (
                <SelectItem key={v} value={String(v)}>
                  {v === 1 ? t('dns.ttl.auto') : num(v)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex h-11 items-center gap-2 sm:h-9">
          <Switch id="dns-proxied" checked={proxied} onCheckedChange={setProxied} aria-label={t('dns.proxied')} />
          <Label htmlFor="dns-proxied" className="cursor-pointer text-xs text-muted-foreground">
            {t('dns.proxied')}
          </Label>
        </div>
      </div>

      {/* actions */}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          className="h-11 gap-1.5 bg-amber-600 text-white hover:bg-amber-700 dark:bg-amber-500 dark:hover:bg-amber-600 sm:h-9"
          onClick={() => save.mutate()}
          disabled={saveDisabled}
        >
          {save.isPending ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <CheckCircle2 className="size-3.5" aria-hidden />}
          {save.isPending ? t('dns.saving') : t('dns.save')}
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-11 gap-1.5 border-amber-500/30 px-3 text-amber-700 hover:bg-amber-500/10 hover:text-amber-800 dark:text-amber-400 sm:h-9"
          onClick={() => testConn.mutate()}
          disabled={testConn.isPending}
        >
          {testConn.isPending ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <Globe className="size-3.5" aria-hidden />}
          {testConn.isPending ? t('dns.testing') : t('dns.test')}
        </Button>
      </div>

      {/* inline test result (live region) */}
      {testState ? (
        <p
          role={testState.ok ? 'status' : 'alert'}
          aria-live="polite"
          className={cn(
            'flex flex-wrap items-center gap-1.5 text-xs',
            testState.ok ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400',
          )}
        >
          {testState.ok ? (
            <CheckCircle2 className="size-3.5 shrink-0" aria-hidden />
          ) : (
            <AlertCircle className="size-3.5 shrink-0" aria-hidden />
          )}
          <span>
            {testState.ok ? t('dns.test.ok', { zone: testState.zoneName ?? '—' }) : t('dns.test.fail')}
          </span>
          {testState.error ? (
            <span className="font-mono text-[10px] text-muted-foreground" dir="ltr">
              {testState.error}
            </span>
          ) : null}
        </p>
      ) : null}

      {/* ---------- push sub-card (sync semantics; type = the type being edited, else stored) ---------- */}
      {configured ? (
        <DnsPushCard
          recordType={activeType ?? asRecordType(settings.recordType)}
          healthyIps={healthyIps}
          healthyIpsV6={healthyIpsV6}
          onPushed={invalidate}
        />
      ) : null}

      {/* ---------- hunt v6.5 — scheduled auto-push (server-side scheduler; the save button carries these fields) ---------- */}
      <DnsAutoPushSection
        autoPush={autoPush}
        onAutoPush={setAutoPush}
        min={autoPushMin}
        minOptions={autoPushMinOptions}
        max={autoPushMaxIps}
        onMin={setAutoPushMin}
        onMax={setAutoPushMaxIps}
        autoPushAt={settings.autoPushAt ?? null}
        dateFnsLocale={dateFnsLocale}
      />

      {/* ---------- push history ---------- */}
      <div className="pt-1">
        <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
          <CloudCog className="size-3.5 text-amber-500" aria-hidden />
          {t('dns.log.title')}
        </p>
        {pushes.length === 0 ? (
          <p className="rounded-lg border border-dashed border-border bg-background/40 px-3 py-4 text-center text-[11px] text-muted-foreground">
            {t('dns.log.empty')}
          </p>
        ) : (
          <ul
            className="scrollbar-thin max-h-64 space-y-1.5 overflow-y-auto"
            aria-label={t('dns.log.title')}
          >
            {pushes.map((p) => (
              <li
                key={p.id}
                title={!p.ok && p.detail ? p.detail : undefined}
                className="flex items-center justify-between gap-2 rounded-lg border bg-background/50 px-2.5 py-1.5"
              >
                <div className="min-w-0">
                  <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                    <span className="shrink-0 font-mono text-[10px] text-muted-foreground" dir="ltr">
                      {p.recordName}
                    </span>
                    <Badge
                      variant="outline"
                      className="border-emerald-500/40 bg-emerald-500/10 px-1 py-0 text-[9px] text-emerald-600 dark:text-emerald-400"
                      dir="ltr"
                    >
                      {t('dns.badge.created', { n: num(p.created) })}
                    </Badge>
                    <Badge
                      variant="outline"
                      className="border-zinc-500/40 bg-zinc-500/10 px-1 py-0 text-[9px] text-zinc-600 dark:text-zinc-300"
                      dir="ltr"
                    >
                      {t('dns.badge.kept', { n: num(p.kept) })}
                    </Badge>
                    <Badge
                      variant="outline"
                      className="border-red-500/40 bg-red-500/10 px-1 py-0 text-[9px] text-red-600 dark:text-red-400"
                      dir="ltr"
                    >
                      {t('dns.badge.removed', { n: num(p.removed) })}
                    </Badge>
                  </div>
                  <p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground/80" dir="ltr" title={p.ips}>
                    {p.ips}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  <span className="hidden whitespace-nowrap text-[10px] text-muted-foreground/70 sm:inline">
                    {formatDistanceToNow(new Date(p.createdAt), { addSuffix: true, locale: dateFnsLocale })}
                  </span>
                  {p.ok ? (
                    <CheckCircle2 className="size-3.5 shrink-0 text-emerald-500" aria-hidden />
                  ) : (
                    <AlertCircle className="size-3.5 shrink-0 text-red-500" aria-hidden />
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

/** hunt v6.5 — scheduled auto-push controls (Switch + interval/IP-cap selects + last-run status; saved with the form) */
function DnsAutoPushSection({
  autoPush,
  onAutoPush,
  min,
  minOptions,
  max,
  onMin,
  onMax,
  autoPushAt,
  dateFnsLocale,
}: {
  autoPush: boolean
  onAutoPush: (v: boolean) => void
  /** interval as a string — Select values are ASCII, labels render through num() */
  min: string
  minOptions: number[]
  max: string
  onMin: (v: string) => void
  onMax: (v: string) => void
  /** ISO timestamp of the last server-side auto-push run (null = never) */
  autoPushAt: string | null
  dateFnsLocale: Locale
}) {
  const { t, num, dir } = useI18n()
  const minNum = clampAutoPushMin(min)
  return (
    <div className="rounded-lg border bg-background/40 p-3" role="group" aria-label={t('dns.auto.title')}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
          <Clock className="size-3.5 text-amber-500" aria-hidden />
          {t('dns.auto.title')}
        </p>
        <div className="flex min-h-9 items-center gap-2">
          <Switch
            id="dns-auto-push"
            checked={autoPush}
            onCheckedChange={onAutoPush}
            aria-label={t('dns.auto.switch')}
          />
          <Label htmlFor="dns-auto-push" className="cursor-pointer text-[11px] text-muted-foreground">
            {t('dns.auto.switch')}
          </Label>
        </div>
      </div>

      <div className="mt-2 flex flex-wrap items-start gap-3">
        <div className="w-40 space-y-1">
          <Label htmlFor="dns-auto-interval" className="text-[11px] font-semibold text-muted-foreground">
            {t('dns.auto.interval')}
          </Label>
          <Select value={min} onValueChange={onMin}>
            <SelectTrigger id="dns-auto-interval" aria-label={t('dns.auto.interval')} className="h-11 w-full text-xs sm:h-9">
              <SelectValue />
            </SelectTrigger>
            <SelectContent dir={dir}>
              {minOptions.map((v) => (
                <SelectItem key={v} value={String(v)}>
                  {num(v)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-[10px] text-muted-foreground">{t('dns.auto.min')}</p>
        </div>
        <div className="w-28 space-y-1">
          <Label htmlFor="dns-auto-max" className="text-[11px] font-semibold text-muted-foreground">
            {t('dns.auto.max')}
          </Label>
          <Select value={max} onValueChange={onMax}>
            <SelectTrigger id="dns-auto-max" aria-label={t('dns.auto.max')} className="h-11 w-full text-xs sm:h-9">
              <SelectValue />
            </SelectTrigger>
            <SelectContent dir={dir}>
              {Array.from({ length: AUTO_PUSH_IPS_MAX }, (_, i) => i + 1).map((v) => (
                <SelectItem key={v} value={String(v)}>
                  {num(v)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* status line — last auto-push run (relative time; never-run fallback) + the honest source explainer */}
      <p className="mt-2 text-[10px] text-muted-foreground" aria-live="polite">
        {t('dns.auto.last')}{' '}
        {autoPushAt ? (
          <span>{formatDistanceToNow(new Date(autoPushAt), { addSuffix: true, locale: dateFnsLocale })}</span>
        ) : (
          <span className="text-muted-foreground/80">{t('dns.auto.never')}</span>
        )}
      </p>
      <p className="text-[10px] text-muted-foreground/80">{t('dns.auto.source', { min: num(minNum) })}</p>
      <p className="mt-1 text-[10px] text-muted-foreground/70">{t('dns.auto.save.hint')}</p>
      <p className="text-[10px] text-muted-foreground/70">{t('dns.auto.note')}</p>
    </div>
  )
}

/** push sub-card — 1..10 IP lines of the STORED record type, sync-applied to the record name (hunt v6.4) */
function DnsPushCard({
  recordType,
  healthyIps,
  healthyIpsV6,
  onPushed,
}: {
  recordType: DnsRecordType
  healthyIps: string[]
  healthyIpsV6: string[]
  onPushed: () => void
}) {
  const { t, num, dir } = useI18n()
  const [ipsText, setIpsText] = useState('')

  const parsedIps = useMemo(
    () =>
      [...new Set(ipsText.split(/\r?\n/).map((l) => toEnDigits(l.trim())).filter((l) => isValidIpFor(l, recordType)))].slice(
        0,
        PUSH_MAX_IPS,
      ),
    [ipsText, recordType],
  )
  /** fill-from-hunt pool: v4 list for A, v6 list for AAAA (defensively re-filtered with the same rule) */
  const huntIps = useMemo(
    () =>
      (recordType === 'AAAA' ? healthyIpsV6 : healthyIps)
        .filter((ip) => isValidIpFor(ip, recordType))
        .slice(0, PUSH_MAX_IPS),
    [healthyIps, healthyIpsV6, recordType],
  )

  const push = useMutation({
    mutationFn: async (ips: string[]) => {
      const res = await fetch('/api/dns/push', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips, recordType }),
      })
      const data = (await res.json().catch(() => null)) as
        | { ok?: boolean; created?: number; kept?: number; removed?: number; error?: string }
        | null
      if (res.status === 400) throw new Error(data?.error ?? 'invalid_ips')
      return data ?? { ok: false }
    },
    onSuccess: (data) => {
      if (data.ok) {
        toast.success(
          t('dns.push.ok', {
            created: num(data.created ?? 0),
            kept: num(data.kept ?? 0),
            removed: num(data.removed ?? 0),
          }),
        )
        setIpsText('')
        onPushed()
      } else {
        toast.error(t('dns.push.fail'))
      }
    },
    onError: (e) => {
      // the server names the record type on invalid ip payloads — surface the exact reason
      if (e.message === 'invalid_ipv6') toast.error(t('dns.invalid.v6'))
      else toast.error(t('dns.push.fail'))
    },
  })

  return (
    <div className="mt-4 rounded-lg border bg-background/40 p-3" role="group" aria-label={t('dns.push.title')}>
      <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
        <p className="text-[11px] font-semibold text-muted-foreground">{t('dns.push.title')}</p>
        <span className="rounded-md border border-border bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground" dir="ltr" aria-live="polite">
          {parsedIps.length}/{PUSH_MAX_IPS}
        </span>
      </div>
      <p className="mb-2 text-[10px] leading-relaxed text-muted-foreground">
        {t('dns.push.desc', { type: recordType, ip: recordType === 'AAAA' ? 'IPv6' : 'IPv4' })}
      </p>
      <Textarea
        value={ipsText}
        onChange={(e) => setIpsText(e.target.value)}
        dir="ltr"
        spellCheck={false}
        placeholder={recordType === 'AAAA' ? '2606:4700:4700::1111' : '104.21.0.1'}
        aria-label={t('dns.push.ips.aria')}
        className="max-h-40 min-h-20 w-full overflow-y-auto font-mono text-xs"
      />
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <TooltipProvider delayDuration={120}>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className="h-11 gap-1.5 border-zinc-500/40 px-3 text-[11px] text-zinc-700 hover:bg-zinc-500/10 hover:text-zinc-800 dark:text-zinc-300 dark:hover:text-zinc-100 sm:h-9"
                onClick={() => setIpsText(huntIps.join('\n'))}
                disabled={huntIps.length === 0}
                aria-label={t('dns.fill.fromHunt')}
              >
                <Globe className="size-3.5" aria-hidden />
                {t('dns.fill.fromHunt')}
              </Button>
            </TooltipTrigger>
            <TooltipContent dir={dir} className="text-[10px]">
              {t('dns.push.ips')}
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
        <Button
          size="sm"
          className="h-11 gap-1.5 bg-teal-600 text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-600 sm:h-9"
          onClick={() => push.mutate(parsedIps)}
          disabled={push.isPending || parsedIps.length === 0}
        >
          {push.isPending ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <CloudCog className="size-3.5" aria-hidden />}
          {push.isPending ? t('dns.pushing') : t('dns.push.apply')}
        </Button>
      </div>
      {ipsText.trim() !== '' && parsedIps.length === 0 ? (
        <p role="alert" className="mt-2 text-[10px] text-amber-600 dark:text-amber-400">
          {recordType === 'AAAA' ? t('dns.invalid.v6') : t('dns.push.empty')}
        </p>
      ) : null}
    </div>
  )
}

// ---------- card 2: Telegram ----------

function TelegramCard({
  connected,
  huntState,
  warpState,
  schedJournal,
}: {
  connected?: boolean
  huntState: GoogleHuntState | null
  warpState: WarpScanState | null
  /** v7.6 — scheduler journal — journal-CSV auto-attach on scheduled-run digests */
  schedJournal: HuntScheduleJournalEntry[]
}) {
  const { t, num, lang } = useI18n()
  const qc = useQueryClient()

  const tg = useQuery<TgSettingsInfo>({
    queryKey: ['telegram-settings'],
    queryFn: () => fetchJson<TgSettingsInfo>('/api/telegram'),
    retry: false,
  })
  const settings = tg.data
  const configured = !!settings?.configured
  const autoOnFinish = !!settings?.autoOnFinish
  const invalidate = useCallback(() => {
    void qc.invalidateQueries({ queryKey: ['telegram-settings'] })
  }, [qc])

  const sendDigestText = useCallback(
    async (s: GoogleHuntState) => {
      const text = buildDigest(s, lang === 'fa', num)
      // v7.6 — scheduled runs (auto=true) also attach the scheduler-journal CSV.
      // ONE request: the API sends the text via sendMessage then the document via
      // sendDocument — identical body for the manual button and the auto-on-finish
      // effect (the stamp dedupe upstream is unchanged; no second request/stamp).
      const attach =
        s.auto === true && schedJournal.length > 0
          ? {
              filename: `hunt-scheduler-journal-${csvFileStamp()}.csv`,
              content: buildSchedulerJournalCsvRows(schedJournal).join('\n'),
              caption: `🧾 ${t('hunt.jrn.title')} · ${num(schedJournal.length)}`,
            }
          : undefined
      try {
        const res = await fetch('/api/telegram/digest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text, attach }),
        })
        const data = (await res.json().catch(() => null)) as { ok?: boolean; sent?: string[] } | null
        if (res.ok && data?.ok)
          toast.success(data.sent?.includes('document') ? t('tg.digest.attach.ok') : t('tg.digest.ok'))
        else toast.error(t('tg.digest.fail'))
      } catch {
        toast.error(t('tg.digest.fail'))
      }
    },
    [t, lang, num, schedJournal],
  )

  // auto-send once per finished hunt (stamp guard survives tab switches + reloads)
  useEffect(() => {
    const s = huntState
    if (!s || s.running || !s.finished || !s.startedAt) return
    if (s.healthy <= 0) return
    if (!autoOnFinish || !configured) return
    if (lastDigestStamp === s.startedAt) return
    markDigestSent(s.startedAt)
    void sendDigestText(s)
  }, [huntState, autoOnFinish, configured, sendDigestText])

  // v6.6 — WARP digest sender: composes from the live warpState, same POST + toast mapping as the hunt digest
  const sendWarpDigestText = useCallback(async () => {
    const text = composeWarpDigest(warpState, lang === 'fa', num)
    if (text == null) {
      toast.info(t('tg.warp.empty'))
      return
    }
    try {
      const res = await fetch('/api/telegram/digest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      })
      const data = (await res.json().catch(() => null)) as { ok?: boolean } | null
      if (res.ok && data?.ok) toast.success(t('tg.digest.ok'))
      else toast.error(t('tg.digest.fail'))
    } catch {
      toast.error(t('tg.digest.fail'))
    }
  }, [warpState, lang, num, t])

  // v6.6 — auto-send once per finished WARP scan (own stamp key + own useRef-style module guard)
  useEffect(() => {
    const w = warpState
    if (!w || w.running || !w.finished || !w.startedAt) return
    if (!Array.isArray(w.found) || w.found.length === 0) return
    if (!autoOnFinish || !configured) return
    if (lastWarpDigestStamp === w.startedAt) return
    markWarpDigestSent(w.startedAt)
    void sendWarpDigestText()
  }, [warpState, autoOnFinish, configured, sendWarpDigestText])

  const digestDisabled = !huntState || huntState.healthy === 0
  // v6.6 — WARP button mirrors the hunt disabled rule against the warp state
  const warpDigestDisabled = !warpState || !Array.isArray(warpState.found) || warpState.found.length === 0

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur sm:p-6">
      {/* ---------- header ---------- */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex size-8 items-center justify-center rounded-lg bg-teal-500/10 text-teal-600 dark:text-teal-400">
          <Send className="size-4" aria-hidden />
        </span>
        <h2 className="text-base font-bold">{t('tg.title')}</h2>
        <Badge
          variant="outline"
          className={cn(
            'px-1.5 py-0 text-[10px]',
            configured
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
              : 'border-zinc-500/40 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300',
          )}
        >
          {t(configured ? 'tg.configured' : 'tg.not.configured')}
        </Badge>
        {connected != null ? (
          <Badge
            variant="outline"
            className={cn(
              'gap-1 px-1.5 py-0 text-[10px]',
              connected
                ? 'border-emerald-500/40 text-emerald-600 dark:text-emerald-400'
                : 'border-amber-500/40 text-amber-600 dark:text-amber-400',
            )}
          >
            {connected ? <Wifi className="size-3" aria-hidden /> : <WifiOff className="size-3" aria-hidden />}
            {t(connected ? 'header.conn.ok' : 'header.conn.off')}
          </Badge>
        ) : null}
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{t('tg.desc')}</p>

      {/* ---------- loading ---------- */}
      {tg.isLoading ? (
        <div className="mt-4 space-y-2">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-11 w-full rounded-lg" />
          ))}
        </div>
      ) : null}

      {/* ---------- settings form ---------- */}
      {settings && !tg.isLoading ? (
        <TgSettingsForm key={settings.updatedAt ?? 'new'} settings={settings} onSaved={invalidate} />
      ) : null}

      {/* ---------- manual digest ---------- */}
      <div className="mt-4 rounded-lg border bg-background/40 p-3" role="group" aria-label={t('tg.digest')}>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="h-11 gap-1.5 border-teal-500/30 px-3 text-[11px] text-teal-700 hover:bg-teal-500/10 hover:text-teal-800 dark:text-teal-400 sm:h-9"
            onClick={() => {
              if (!huntState || huntState.healthy === 0) {
                toast.info(t('tg.digest.empty'))
                return
              }
              void sendDigestText(huntState)
            }}
            disabled={digestDisabled}
            aria-label={t('tg.digest')}
          >
            <Send className="size-3.5" aria-hidden />
            {t('tg.digest')}
          </Button>
          {/* v6.6 — WARP digest: second button in the same wrapping row, amber accent to match the WARP tab */}
          <Button
            variant="outline"
            size="sm"
            className="h-11 gap-1.5 border-amber-500/30 px-3 text-[11px] text-amber-700 hover:bg-amber-500/10 hover:text-amber-800 dark:text-amber-400 sm:h-9"
            onClick={() => {
              if (composeWarpDigest(warpState, lang === 'fa', num) == null) {
                toast.info(t('tg.warp.empty'))
                return
              }
              void sendWarpDigestText()
            }}
            disabled={warpDigestDisabled}
            aria-label={t('tg.warp.button')}
          >
            <Send className="size-3.5" aria-hidden />
            {t('tg.warp.button')}
          </Button>
          {digestDisabled ? (
            <p className="text-[10px] text-muted-foreground" aria-live="polite">
              {t('tg.digest.empty')}
            </p>
          ) : (
            <span className="font-mono text-[10px] text-muted-foreground" dir="ltr" aria-live="polite">
              {num(huntState?.healthy ?? 0)} IP
            </span>
          )}
          {warpDigestDisabled ? (
            <p className="text-[10px] text-muted-foreground" aria-live="polite">
              {t('tg.warp.empty')}
            </p>
          ) : (
            <span className="font-mono text-[10px] text-muted-foreground" dir="ltr" aria-live="polite">
              {num(warpState?.found.length ?? 0)} EP
            </span>
          )}
        </div>
        {/* v7.6 — honest hint: scheduled runs ride the scheduler-journal CSV onto the auto digest */}
        {autoOnFinish && schedJournal.length > 0 ? (
          <p className="mt-2 flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <Paperclip className="size-3 shrink-0" aria-hidden />
            {t('tg.digest.attach.hint')}
          </p>
        ) : null}
      </div>

      {tg.isError ? (
        <p role="alert" className="mt-3 flex items-center gap-1.5 text-xs text-red-600 dark:text-red-400">
          <AlertCircle className="size-3.5" aria-hidden />
          {t('tg.load.fail')}
        </p>
      ) : null}
    </div>
  )
}

/** telegram settings form — key-remounted from the canonical row (token stays empty = keep) */
function TgSettingsForm({
  settings,
  onSaved,
}: {
  settings: TgSettingsInfo
  onSaved: () => void
}) {
  const { t } = useI18n()
  const [token, setToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [chatId, setChatId] = useState(settings.chatId ?? '')
  const [autoOnFinish, setAutoOnFinish] = useState(settings.autoOnFinish ?? false)

  const save = useMutation({
    mutationFn: async () => {
      const res = await fetch('/api/telegram', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          botToken: token.trim() || undefined,
          chatId: chatId.trim(),
          autoOnFinish,
        }),
      })
      const data = (await res.json().catch(() => null)) as { ok?: boolean; error?: string } | null
      if (!res.ok || !data?.ok) throw new Error(data?.error ?? 'http_error')
      return true
    },
    onSuccess: () => {
      toast.success(t('tg.saved'))
      onSaved()
    },
    onError: () => toast.error(t('tg.save.fail')),
  })

  const testSend = useMutation({
    mutationFn: async () => {
      const res = await fetch('/api/telegram/test', { method: 'POST' })
      const data = (await res.json().catch(() => null)) as { ok?: boolean; error?: string } | null
      if (res.status === 400) throw new Error('not_configured')
      return data ?? { ok: false }
    },
    onSuccess: (data) => {
      if (data.ok) toast.success(t('tg.test.ok'))
      else toast.error(`${t('tg.test.fail')} — ${data.error ?? ''}`)
    },
    onError: () => toast.error(t('tg.test.fail')),
  })

  const saveDisabled =
    save.isPending ||
    chatId.trim() === '' ||
    chatId.trim().length > 64 ||
    (token.trim() !== '' && (token.trim().length < 20 || token.trim().length > 60))

  return (
    <div className="mt-4 space-y-3" role="group" aria-label={t('tg.title')}>
      {/* bot token (password + eye toggle, empty = keep saved) */}
      <div className="space-y-1">
        <Label htmlFor="tg-token" className="text-[11px] font-semibold text-muted-foreground">
          {t('tg.token')}
        </Label>
        <div className="relative">
          <Input
            id="tg-token"
            type={showToken ? 'text' : 'password'}
            value={token}
            onChange={(e) => setToken(e.target.value)}
            dir="ltr"
            autoComplete="off"
            spellCheck={false}
            placeholder={settings.configured ? settings.tokenHint : ''}
            aria-label={t('tg.token')}
            className="h-11 pe-10 font-mono text-xs sm:h-9"
          />
          <button
            type="button"
            onClick={() => setShowToken((v) => !v)}
            aria-label={t('tg.token.eye')}
            aria-pressed={showToken}
            className="absolute end-1.5 top-1/2 inline-flex size-8 -translate-y-1/2 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-teal-500/10 hover:text-teal-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-500/60 dark:hover:text-teal-400"
          >
            {showToken ? <EyeOff className="size-3.5" aria-hidden /> : <Eye className="size-3.5" aria-hidden />}
          </button>
        </div>
        <p className="text-[10px] text-muted-foreground">{t('tg.token.hint')}</p>
      </div>

      {/* chat id */}
      <div className="space-y-1">
        <Label htmlFor="tg-chat" className="text-[11px] font-semibold text-muted-foreground">
          {t('tg.chat')}
        </Label>
        <Input
          id="tg-chat"
          value={chatId}
          onChange={(e) => setChatId(e.target.value)}
          dir="ltr"
          spellCheck={false}
          placeholder="123456789"
          aria-label={t('tg.chat')}
          className="h-11 font-mono text-xs sm:h-9"
        />
      </div>

      {/* auto-send switch */}
      <div className="flex h-11 items-center gap-2 sm:h-9">
        <Switch
          id="tg-auto"
          checked={autoOnFinish}
          onCheckedChange={setAutoOnFinish}
          aria-label={t('tg.auto')}
        />
        <Label htmlFor="tg-auto" className="cursor-pointer text-xs text-muted-foreground">
          {t('tg.auto')}
        </Label>
      </div>
      {/* v6.6 — honest hint: the same auto-send now also covers finished WARP scans */}
      <p className="text-[10px] leading-relaxed text-muted-foreground">{t('tg.warp.auto')}</p>

      {/* actions */}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          className="h-11 gap-1.5 bg-teal-600 text-white hover:bg-teal-700 dark:bg-teal-500 dark:hover:bg-teal-600 sm:h-9"
          onClick={() => save.mutate()}
          disabled={saveDisabled}
        >
          {save.isPending ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <CheckCircle2 className="size-3.5" aria-hidden />}
          {save.isPending ? t('tg.saving') : t('tg.save')}
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-11 gap-1.5 border-teal-500/30 px-3 text-teal-700 hover:bg-teal-500/10 hover:text-teal-800 dark:text-teal-400 sm:h-9"
          onClick={() => testSend.mutate()}
          disabled={testSend.isPending}
        >
          {testSend.isPending ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <Send className="size-3.5" aria-hidden />}
          {testSend.isPending ? t('tg.testing') : t('tg.test')}
        </Button>
      </div>
    </div>
  )
}

// ---------- card 3: settings backup (v6.7) ----------

/** local timestamp for the backup file name — clean-ip-scanner-settings-YYYYMMDD-HHmm.json */
function backupFileStamp(): string {
  const d = new Date()
  const p2 = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}-${p2(d.getHours())}${p2(d.getMinutes())}`
}

/** chat id shown masked in the preview — only the last 4 chars are readable */
function maskId(v: string | undefined): string {
  if (!v) return '—'
  return `••••${v.slice(-4)}`
}

/**
 * v6.7 — settings backup card.
 *
 * EXPORT: GET /api/settings/export (+?tokens=1 when the opt-in switch is on)
 * → blob download. The switch honestly resets to OFF after every export.
 * IMPORT: the file is parsed + validated client-side (kind/schemaVersion);
 * only a valid envelope reaches POST /api/settings/import — and only after
 * the user sees the per-section preview and presses «بازیابی تنظیمات».
 */
function SettingsBackupCard() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const dateFnsLocale = lang === 'fa' ? faIR : enUS

  // ---- export state ----
  const [includeTokens, setIncludeTokens] = useState(false)
  const [exporting, setExporting] = useState(false)

  // ---- import state ----
  const [importError, setImportError] = useState<string | null>(null)
  const [env, setEnv] = useState<SettingsExport | null>(null)
  const [envFileName, setEnvFileName] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  /** after a successful import the other two cards must re-read their settings (masked-token hints) */
  const invalidateSettings = useCallback(() => {
    void qc.invalidateQueries({ queryKey: ['dns-settings'] })
    void qc.invalidateQueries({ queryKey: ['telegram-settings'] })
  }, [qc])

  const exportBackup = async () => {
    if (exporting) return
    setExporting(true)
    try {
      const res = await fetch(`/api/settings/export${includeTokens ? '?tokens=1' : ''}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `clean-ip-scanner-settings-${backupFileStamp()}.json`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      toast.success(t('bak.export.ok'))
      // honest default — tokens are opt-in per export, never sticky
      setIncludeTokens(false)
    } catch {
      toast.error(t('bak.export.fail'))
    } finally {
      setExporting(false)
    }
  }

  /** client-side gate: empty file → invalid JSON → wrong envelope; only valid envelopes are previewed */
  const onFilePicked = async (file: File | undefined) => {
    setImportError(null)
    setEnv(null)
    setEnvFileName('')
    if (!file) return
    try {
      const text = await file.text()
      if (text.trim() === '') {
        setImportError(t('bak.empty.file'))
        return
      }
      let parsed: unknown
      try {
        parsed = JSON.parse(text)
      } catch {
        setImportError(t('bak.invalid.file'))
        return
      }
      const e = parsed as SettingsExport | null
      if (
        !e ||
        typeof e !== 'object' ||
        (e as { kind?: unknown }).kind !== 'clean-ip-scanner-settings' ||
        (e as { schemaVersion?: unknown }).schemaVersion !== 1
      ) {
        setImportError(t('bak.invalid.env'))
        return
      }
      setEnv(e)
      setEnvFileName(file.name)
    } catch {
      setImportError(t('bak.invalid.file'))
    }
  }

  const doImport = useMutation({
    mutationFn: async () => {
      if (!env) throw new Error('no_env')
      const res = await fetch('/api/settings/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(env), // envelope sent as-is — the server is authoritative
      })
      const data = (await res.json().catch(() => null)) as
        | { ok?: boolean; applied?: { dns?: boolean; telegram?: boolean }; error?: string }
        | null
      if (res.status === 400) {
        const err = new Error(data?.error ?? 'invalid_envelope') as Error & { code?: string }
        err.code = data?.error ?? 'invalid_envelope'
        throw err
      }
      if (!res.ok || !data?.ok) throw new Error('http_error')
      return data.applied ?? {}
    },
    onSuccess: (applied) => {
      toast.success(
        t('bak.import.ok', { dns: applied.dns ? '✓' : '—', tg: applied.telegram ? '✓' : '—' }),
      )
      setEnv(null)
      setEnvFileName('')
      setImportError(null)
      if (fileRef.current) fileRef.current.value = ''
      invalidateSettings()
    },
    onError: (e) => {
      const code = (e as Error & { code?: string }).code
      if (code === 'invalid_envelope') toast.error(t('bak.invalid.env'))
      else if (code === 'nothing_to_import') toast.info(t('bak.nothing'))
      else if (code) toast.error(`${t('bak.import.fail')} — ${code}`)
      else toast.error(t('bak.import.fail'))
    },
  })

  const hasDns = !!env && typeof env.dns === 'object' && env.dns != null
  const hasTg = !!env && typeof env.telegram === 'object' && env.telegram != null

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur sm:p-6">
      {/* ---------- header ---------- */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex size-8 items-center justify-center rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-400">
          <DatabaseBackup className="size-4" aria-hidden />
        </span>
        <h2 className="text-base font-bold">{t('bak.title')}</h2>
      </div>
      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{t('bak.desc')}</p>

      {/* ---------- export ---------- */}
      <div className="mt-4 rounded-lg border bg-background/40 p-3" role="group" aria-label={t('bak.title')}>
        <div className="flex min-h-11 items-center gap-2 sm:min-h-9">
          <Switch
            id="bak-tokens"
            checked={includeTokens}
            onCheckedChange={setIncludeTokens}
            aria-label={t('bak.tokens')}
          />
          <Label htmlFor="bak-tokens" className="cursor-pointer text-xs text-muted-foreground">
            {t('bak.tokens')}
          </Label>
        </div>
        {includeTokens ? (
          <p className="mt-1 flex items-start gap-1.5 text-[10px] leading-relaxed text-amber-600 dark:text-amber-400">
            <AlertCircle className="mt-0.5 size-3 shrink-0" aria-hidden />
            {t('bak.tokens.warn')}
          </p>
        ) : null}
        <div className="mt-2">
          <Button
            size="sm"
            className="h-11 gap-1.5 bg-amber-600 text-white hover:bg-amber-700 dark:bg-amber-500 dark:hover:bg-amber-600 sm:h-9"
            onClick={() => void exportBackup()}
            disabled={exporting}
          >
            {exporting ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <Download className="size-3.5" aria-hidden />}
            {exporting ? t('bak.exporting') : t('bak.export')}
          </Button>
        </div>
      </div>

      {/* ---------- import ---------- */}
      <div className="mt-3 rounded-lg border bg-background/40 p-3" role="group" aria-label={t('bak.import')}>
        {/* sr-only input — the visible outline button opens the picker (44px touch target) */}
        <input
          ref={fileRef}
          id="bak-file"
          type="file"
          accept=".json,application/json"
          className="sr-only"
          aria-label={t('bak.pick')}
          onChange={(e) => {
            void onFilePicked(e.target.files?.[0])
          }}
        />
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-11 gap-1.5 border-zinc-500/40 px-3 text-[11px] text-zinc-700 hover:bg-zinc-500/10 hover:text-zinc-800 dark:text-zinc-300 dark:hover:text-zinc-100 sm:h-9"
          onClick={() => fileRef.current?.click()}
          aria-label={t('bak.pick')}
        >
          <FileUp className="size-3.5" aria-hidden />
          {t('bak.pick')}
        </Button>

        {/* client-side validation failures never reach the API */}
        {importError ? (
          <p role="alert" className="mt-2 flex items-start gap-1.5 text-[10.5px] leading-relaxed text-red-600 dark:text-red-400">
            <AlertCircle className="mt-0.5 size-3 shrink-0" aria-hidden />
            {importError}
          </p>
        ) : null}

        {/* preview panel — shown only for a valid envelope, before anything is sent */}
        {env ? (
          <div className="mt-2 rounded-lg border bg-background/50 p-3" role="region" aria-label={t('bak.preview')}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-[11px] font-semibold text-muted-foreground">{t('bak.preview')}</p>
              {envFileName ? (
                <span dir="ltr" className="max-w-44 truncate font-mono text-[10px] text-muted-foreground/70" title={envFileName}>
                  {envFileName}
                </span>
              ) : null}
            </div>
            <p className="mt-1 text-[10px] text-muted-foreground">
              {t(
                'bak.at',
                {
                  at:
                    env.exportedAt && !Number.isNaN(new Date(env.exportedAt).getTime())
                      ? formatDistanceToNow(new Date(env.exportedAt), { addSuffix: true, locale: dateFnsLocale })
                      : '—',
                },
              )}
            </p>

            <p className="mt-2 text-[10px] font-semibold text-muted-foreground">{t('bak.sections')}</p>
            {hasDns || hasTg ? (
              <ul className="mt-1 space-y-1.5">
                {hasDns ? (
                  <li className="flex flex-wrap items-center gap-1.5 rounded-md border bg-background/60 px-2 py-1.5 text-[10.5px]">
                    <Globe className="size-3.5 shrink-0 text-amber-500" aria-hidden />
                    <span className="font-semibold">{t('bak.dns')}</span>
                    {env.dns?.recordName ? (
                      <span dir="ltr" className="font-mono text-muted-foreground">
                        {env.dns.recordName}
                      </span>
                    ) : null}
                    {env.dns?.recordType ? (
                      <Badge variant="outline" className="px-1 py-0 font-mono text-[9px]" dir="ltr">
                        {env.dns.recordType}
                      </Badge>
                    ) : null}
                    <span className="ms-auto flex items-center gap-1 text-[10px] text-muted-foreground">
                      {env.dns?.cfToken ? (
                        <CheckCircle2 className="size-3 shrink-0 text-emerald-500" aria-hidden />
                      ) : (
                        <AlertCircle className="size-3 shrink-0 text-zinc-400" aria-hidden />
                      )}
                      {env.dns?.cfToken ? t('bak.tokens.on') : t('bak.tokens.off')}
                    </span>
                  </li>
                ) : null}
                {hasTg ? (
                  <li className="flex flex-wrap items-center gap-1.5 rounded-md border bg-background/60 px-2 py-1.5 text-[10.5px]">
                    <Send className="size-3.5 shrink-0 text-teal-600 dark:text-teal-400" aria-hidden />
                    <span className="font-semibold">{t('bak.telegram')}</span>
                    <span dir="ltr" className="font-mono text-muted-foreground">
                      {maskId(env.telegram?.chatId)}
                    </span>
                    <span className="ms-auto flex items-center gap-1 text-[10px] text-muted-foreground">
                      {env.telegram?.botToken ? (
                        <CheckCircle2 className="size-3 shrink-0 text-emerald-500" aria-hidden />
                      ) : (
                        <AlertCircle className="size-3 shrink-0 text-zinc-400" aria-hidden />
                      )}
                      {env.telegram?.botToken ? t('bak.tokens.on') : t('bak.tokens.off')}
                    </span>
                  </li>
                ) : null}
              </ul>
            ) : (
              <p className="mt-1 rounded-md border border-dashed border-border px-2 py-2 text-center text-[10.5px] text-muted-foreground">
                {t('bak.nothing')}
              </p>
            )}

            <div className="mt-2.5 flex flex-wrap items-center gap-2">
              <Button
                size="sm"
                className="h-11 gap-1.5 bg-red-600 text-white hover:bg-red-700 dark:bg-red-500 dark:hover:bg-red-600 sm:h-9"
                onClick={() => doImport.mutate()}
                disabled={doImport.isPending || (!hasDns && !hasTg)}
              >
                {doImport.isPending ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <RotateCcw className="size-3.5" aria-hidden />}
                {doImport.isPending ? t('bak.importing') : t('bak.import')}
              </Button>
            </div>
            <p className="mt-1.5 text-[10px] leading-relaxed text-muted-foreground/80">{t('bak.restored.hint')}</p>
          </div>
        ) : null}
      </div>
    </div>
  )
}
