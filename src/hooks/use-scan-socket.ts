'use client'

/**
 * use-scan-socket — client hook managing the realtime socket.io connection
 * to the scan-engine mini service (through the gateway: /?XTransformPort=3003).
 *
 * - Restores a running scan after page refresh via 'scan:state'
 * - Buffers results (max 500), logs (max 300) and latency sparkline (max 60)
 * - Measures RTT every 5s via 'ping:rtt'
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { io, type Socket } from 'socket.io-client'
import {
  HUNT_SCHEDULE_JOURNAL_CAP,
  SCAN_SOCKET_PORT,
  type AutoScanState,
  type GoogleHuntRecon,
  type GoogleHuntReconStatus,
  type GoogleHuntSettings,
  type GoogleHuntState,
  type HuntScheduleFireSettings,
  type HuntScheduleJournalEntry,
  type HuntScheduleSetPayload,
  type HuntScheduleState,
  type LiveResult,
  type ScanConfig,
  type ScanLogLine,
  type ScanProgress,
  type ScanQueueState,
  type ScanSummary,
  type WarpScanSettings,
  type WarpScanState,
  type XrayProbeRequest,
  type XrayProbeResult,
} from '@/lib/scan-protocol'

const MAX_RESULTS = 500
const MAX_LOGS = 300
const MAX_SPARK_POINTS = 60
const RTT_INTERVAL_MS = 5000

/** realtime recon payloads are never trusted structurally — degrade to null */
function sanitizeRecon(r: unknown): GoogleHuntRecon | null {
  if (!r || typeof r !== 'object') return null
  const s = r as Partial<GoogleHuntRecon>
  if (typeof s.status !== 'string') return null
  const sanitizeProvider = (p: unknown): GoogleHuntRecon['providers']['google'] => {
    const raw = (p ?? {}) as Partial<GoogleHuntRecon['providers']['google']>
    const sources: Record<string, number> = {}
    if (raw.sources && typeof raw.sources === 'object') {
      for (const [k, v] of Object.entries(raw.sources).slice(0, 12)) {
        if (typeof v === 'number' && Number.isFinite(v) && v >= 0) sources[k] = Math.min(v, 100_000)
      }
    }
    return {
      status: (['idle', 'loading', 'ready', 'failed'].includes(String(raw.status)) ? raw.status : 'idle') as GoogleHuntReconStatus,
      updatedAt: typeof raw.updatedAt === 'number' ? raw.updatedAt : 0,
      sources,
      cidrs: typeof raw.cidrs === 'number' && Number.isFinite(raw.cidrs) ? Math.min(raw.cidrs, 100_000) : 0,
      // hunt v6.1 — IPv6 count + checklist ranges (degrade silently for legacy engines)
      cidrsV6: typeof raw.cidrsV6 === 'number' && Number.isFinite(raw.cidrsV6) ? Math.min(raw.cidrsV6, 100_000) : 0,
      ranges: Array.isArray(raw.ranges)
        ? raw.ranges.filter((x): x is string => typeof x === 'string' && x.length > 0).slice(0, 256)
        : undefined,
    }
  }
  return {
    status: (['idle', 'loading', 'ready', 'failed'].includes(s.status) ? s.status : 'idle') as GoogleHuntReconStatus,
    updatedAt: typeof s.updatedAt === 'number' ? s.updatedAt : 0,
    total: typeof s.total === 'number' && Number.isFinite(s.total) ? Math.min(s.total, 100_000) : 0,
    providers: {
      google: sanitizeProvider(s.providers?.google),
      cloudflare: sanitizeProvider(s.providers?.cloudflare),
      arvan: sanitizeProvider(s.providers?.arvan),
      custom: sanitizeProvider(s.providers?.custom),
    },
    ptr: {
      scanned: typeof s.ptr?.scanned === 'number' ? s.ptr.scanned : 0,
      edge: typeof s.ptr?.edge === 'number' ? s.ptr.edge : 0,
      top: Array.isArray(s.ptr?.top) ? s.ptr.top.filter((x): x is string => typeof x === 'string').slice(0, 4) : [],
    },
    fallback: !!s.fallback,
    // hunt v6.4 — per-source recon pull health (rate-limit resilience observability)
    health: (() => {
      if (!s.health || typeof s.health !== 'object') return undefined
      const out: NonNullable<GoogleHuntRecon['health']> = {}
      for (const [k, v] of Object.entries(s.health as Record<string, unknown>).slice(0, 24)) {
        if (!v || typeof v !== 'object') continue
        const h = v as Partial<NonNullable<GoogleHuntRecon['health']>[string]>
        out[k.slice(0, 24)] = {
          ok: !!h.ok,
          ms: typeof h.ms === 'number' && Number.isFinite(h.ms) ? Math.min(h.ms, 60_000) : 0,
          err: typeof h.err === 'string' ? h.err.slice(0, 80) : undefined,
          at: typeof h.at === 'number' && Number.isFinite(h.at) ? h.at : 0,
        }
      }
      return Object.keys(out).length > 0 ? out : undefined
    })(),
  }
}

/** realtime hunt-state payloads are never trusted structurally (array fields must exist) */
function sanitizeHuntState(s: unknown): GoogleHuntState | null {
  if (!s || typeof s !== 'object') return null
  const raw = s as Partial<GoogleHuntState>
  if (!Array.isArray(raw.healthyIps) || !Array.isArray(raw.recent)) return null
  const perProvider: GoogleHuntState['perProvider'] = {}
  if (raw.perProvider && typeof raw.perProvider === 'object') {
    for (const key of ['google', 'cloudflare', 'arvan', 'custom'] as const) {
      const v = raw.perProvider[key]
      if (v && typeof v === 'object') {
        perProvider[key] = {
          tested: typeof v.tested === 'number' ? v.tested : 0,
          healthy: typeof v.healthy === 'number' ? v.healthy : 0,
          blocked: typeof v.blocked === 'number' ? v.blocked : 0,
          dead: typeof v.dead === 'number' ? v.dead : 0,
        }
      }
    }
  }
  const num = (v: unknown, min: number, max: number): number | undefined =>
    typeof v === 'number' && Number.isFinite(v) ? Math.min(max, Math.max(min, Math.round(v))) : undefined
  return {
    ...(raw as GoogleHuntState),
    perProvider,
    // parallel pipeline telemetry (v5) — defensive coercion, undefined-safe for legacy engines
    inFlight: num(raw.inFlight, 0, 1e6),
    tlsInFlight: num(raw.tlsInFlight, 0, 1e6),
    concurrency: num(raw.concurrency, 0, 1024),
    tlsConcurrency: num(raw.tlsConcurrency, 0, 1024),
    tcpPoolMax: num(raw.tcpPoolMax, 0, 1024),
    tlsPoolMax: num(raw.tlsPoolMax, 0, 1024),
    sampled: num(raw.sampled, 0, 1e7),
    v6Sampled: num(raw.v6Sampled, 0, 1e7),
    fromSelected: num(raw.fromSelected, 0, 1e7),
    engine: typeof raw.engine === 'string' ? raw.engine : undefined,
    // hunt v6.4 — anti-censorship forensics tallies (undefined-safe for legacy engines)
    forensics: (() => {
      const f = raw.forensics
      if (!f || typeof f !== 'object') return undefined
      const t = f as Partial<NonNullable<GoogleHuntState['forensics']>>
      const n = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? Math.min(Math.max(Math.round(v), 0), 1e7) : 0)
      return { rst: n(t.rst), drop: n(t.drop), refused: n(t.refused), live: n(t.live) }
    })(),
  }
}

/**
 * v7.0 — sensible disabled default for the hunt-scheduler snapshot (never null,
 * so the UI can always render an honest «خاموش» state before the first sync).
 */
export const HUNT_SCHEDULE_DISABLED: HuntScheduleState = {
  enabled: false,
  intervalMinutes: 30,
  nextRunAt: null,
  lastRunAt: null,
  runsCount: 0,
  running: false,
  settings: null,
}

/**
 * v7.6 — per-fire settings-echo whitelist (journal entries): rebuilt FIELD-BY-FIELD
 * with the SAME clamps the engine applies, so a hostile socket payload can never
 * smuggle oversized strings or out-of-range numbers into the journal UI/CSV.
 * Numbers must be finite (Math.round + min/max clamps); strings are trimmed then
 * capped. Absent/invalid fields stay absent; the object is attached only when ≥1
 * key survived (undefined otherwise).
 */
function sanitizeHuntFireSettings(raw: unknown): HuntScheduleFireSettings | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined
  const s = raw as Partial<HuntScheduleFireSettings>
  const num = (v: unknown, min: number, max: number): number | undefined =>
    typeof v === 'number' && Number.isFinite(v) ? Math.min(max, Math.max(min, Math.round(v))) : undefined
  const str = (v: unknown, cap: number): string | undefined => {
    if (typeof v !== 'string') return undefined
    const trimmed = v.trim().slice(0, cap)
    return trimmed === '' ? undefined : trimmed
  }
  const out: HuntScheduleFireSettings = {}
  const provider = str(s.provider, 20)
  if (provider !== undefined) out.provider = provider
  const target = num(s.target, 1, 100)
  if (target !== undefined) out.target = target
  const batchSize = num(s.batchSize, 500, 10_000)
  if (batchSize !== undefined) out.batchSize = batchSize
  const concurrency = num(s.concurrency, 32, 1024)
  if (concurrency !== undefined) out.concurrency = concurrency
  const host = str(s.host, 255)
  if (host !== undefined) out.host = host
  const port = num(s.port, 1, 65535)
  if (port !== undefined) out.port = port
  const speed = str(s.speed, 10)
  if (speed !== undefined) out.speed = speed
  const verify = num(s.verify, 0, 3)
  if (verify !== undefined) out.verify = verify
  return Object.keys(out).length > 0 ? out : undefined
}

/** v7.1 — realtime journal payloads are never trusted structurally — keep only valid entries, newest-first, capped */
function sanitizeHuntJournal(raw: unknown): HuntScheduleJournalEntry[] {
  if (!Array.isArray(raw)) return []
  const kinds: HuntScheduleJournalEntry['kind'][] = ['fire', 'done', 'postponed']
  const entries: HuntScheduleJournalEntry[] = []
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue
    const e = item as Partial<HuntScheduleJournalEntry>
    if (typeof e.at !== 'number' || !Number.isFinite(e.at) || !kinds.includes(e.kind as HuntScheduleJournalEntry['kind'])) continue
    const entry: HuntScheduleJournalEntry = {
      at: e.at,
      kind: e.kind as HuntScheduleJournalEntry['kind'],
      tested: typeof e.tested === 'number' && Number.isFinite(e.tested) ? Math.max(0, Math.round(e.tested)) : undefined,
      healthy: typeof e.healthy === 'number' && Number.isFinite(e.healthy) ? Math.max(0, Math.round(e.healthy)) : undefined,
      stopped: typeof e.stopped === 'boolean' ? e.stopped : undefined,
      durationMs: typeof e.durationMs === 'number' && Number.isFinite(e.durationMs) ? Math.max(0, Math.round(e.durationMs)) : undefined,
    }
    // v7.6 — per-fire settings echo: whitelisted rebuild, attached only when ≥1 key survived
    // (absent/invalid ⇒ the field stays truly absent — legacy entries render unchanged)
    const settings = sanitizeHuntFireSettings(e.settings)
    if (settings) entry.settings = settings
    entries.push(entry)
  }
  return entries.sort((a, b) => b.at - a.at).slice(0, HUNT_SCHEDULE_JOURNAL_CAP)
}

/** realtime hunt-scheduler payloads are never trusted structurally — degrade to the disabled default */
function sanitizeHuntSchedule(s: unknown): HuntScheduleState {
  if (!s || typeof s !== 'object') return { ...HUNT_SCHEDULE_DISABLED }
  const raw = s as Partial<HuntScheduleState>
  const interval =
    typeof raw.intervalMinutes === 'number' && Number.isFinite(raw.intervalMinutes)
      ? Math.min(1440, Math.max(5, Math.round(raw.intervalMinutes)))
      : HUNT_SCHEDULE_DISABLED.intervalMinutes
  return {
    enabled: raw.enabled === true,
    intervalMinutes: interval,
    nextRunAt: typeof raw.nextRunAt === 'number' && Number.isFinite(raw.nextRunAt) ? raw.nextRunAt : null,
    lastRunAt: typeof raw.lastRunAt === 'number' && Number.isFinite(raw.lastRunAt) ? raw.lastRunAt : null,
    runsCount: typeof raw.runsCount === 'number' && Number.isFinite(raw.runsCount) ? Math.max(0, Math.round(raw.runsCount)) : 0,
    running: raw.running === true,
    settings: raw.settings && typeof raw.settings === 'object' ? raw.settings : null,
    // v7.1 — journal pass-through (absent on legacy engines ⇒ [])
    journal: sanitizeHuntJournal(raw.journal),
  }
}

/** realtime warp-state payloads are never trusted structurally (array fields must exist) */
function sanitizeWarpState(s: unknown): WarpScanState | null {
  if (!s || typeof s !== 'object') return null
  const raw = s as Partial<WarpScanState>
  if (!Array.isArray(raw.found) || !Array.isArray(raw.recent)) return null
  const ep = (e: unknown): WarpScanState['found'][number] | null => {
    if (!e || typeof e !== 'object') return null
    const r = e as Partial<WarpScanState['found'][number]>
    if (typeof r.endpoint !== 'string' || typeof r.ip !== 'string') return null
    return {
      endpoint: r.endpoint,
      ip: r.ip,
      port: typeof r.port === 'number' ? r.port : 2408,
      rttMs: typeof r.rttMs === 'number' ? r.rttMs : undefined,
      response: r.response === 'cookie' ? 'cookie' : r.response === 'handshake' ? 'handshake' : undefined,
      range: typeof r.range === 'string' ? r.range : undefined,
      attempts: typeof r.attempts === 'number' ? r.attempts : undefined,
    }
  }
  return {
    ...(raw as WarpScanState),
    found: raw.found.map(ep).filter((e): e is WarpScanState['found'][number] => e !== null).slice(0, 200),
    recent: raw.recent.map(ep).filter((e): e is WarpScanState['recent'][number] => e !== null).slice(0, 12),
    ranges: Array.isArray(raw.ranges) ? raw.ranges.filter((x): x is string => typeof x === 'string').slice(0, 16) : [],
    ports: Array.isArray(raw.ports) ? raw.ports.filter((x): x is number => typeof x === 'number').slice(0, 8) : [],
    concurrency: typeof raw.concurrency === 'number' ? raw.concurrency : undefined,
    registered: !!raw.registered,
  }
}

export interface LatencyPoint {
  t: number
  latency: number
}

export interface UseScanSocketReturn {
  connected: boolean
  running: boolean
  progress: ScanProgress | null
  results: LiveResult[]
  logs: ScanLogLine[]
  summary: ScanSummary | null
  rtt: number | null
  latencyHistory: LatencyPoint[]
  /** increments once per live 'scan:done' event (not restored state) — used to trigger auto-save */
  finishedCount: number
  /** live engine-side scheduler state (null until first sync) */
  autoState: AutoScanState | null
  /** live engine-side multi-CDN queue state (null until first sync) */
  queueState: ScanQueueState | null
  start: (cfg: ScanConfig) => void
  stop: () => void
  /** quick TCPing health check for watchlist IPs (never conflicts with scans) */
  checkIps: (ips: string[], port: number) => Promise<LiveResult[]>
  /** enable/disable the engine-side scheduled auto-scan; resolves with fresh state */
  setAutoScan: (enabled: boolean, intervalMinutes: number, config: ScanConfig | null, notifyUrl?: string) => Promise<AutoScanState | null>
  /** POST a test payload to the given webhook URL from the engine; resolves true on success */
  testNotify: (url: string) => Promise<boolean>
  /** store/clear Telegram credentials on the engine ('' clears a field, undefined keeps it) */
  setTelegram: (token?: string, chatId?: string, digest?: boolean) => Promise<AutoScanState | null>
  /** send a Telegram test message using the stored credentials */
  testTelegram: () => Promise<boolean>
  /** add a config to the engine-side multi-CDN scan queue */
  addToQueue: (config: ScanConfig, label?: string) => Promise<ScanQueueState | null>
  /** remove one non-running queue item */
  removeFromQueue: (id: string) => Promise<ScanQueueState | null>
  /** remove every non-running queue item */
  clearQueue: () => Promise<ScanQueueState | null>
  /** swap a waiting queue item with its neighbour (dir -1 = earlier, +1 = later) */
  moveQueueItem: (id: string, dir: -1 | 1) => Promise<ScanQueueState | null>
  /** drag & drop reorder — move a waiting queue item to the given array index */
  reorderQueueItem: (id: string, index: number) => Promise<ScanQueueState | null>
  /** enable/disable a waiting queue item (disabled items are skipped by the processor) */
  toggleQueueItem: (id: string) => Promise<ScanQueueState | null>
  /** edit a waiting queue item in place (label + partial scan config, engine re-clamps) */
  updateQueueItem: (id: string, patch: { label?: string; config?: Partial<ScanConfig> }) => Promise<ScanQueueState | null>
  /** Xray-style TLS probe of a raw IP with the given SNI host */
  probeXray: (payload: XrayProbeRequest) => Promise<XrayProbeResult | null>
  /** live state of the standalone Google-friendly IP hunter (null until first sync) */
  huntState: GoogleHuntState | null
  /** v7.0 — live engine-side hunt scheduler state (honest disabled default before the first sync) */
  huntSchedState: HuntScheduleState
  /** v7.0 — enable/disable the engine-side hunt scheduler; resolves with the fresh state (null on failure/offline) */
  setHuntSchedule: (
    enabled: boolean,
    intervalMinutes: number,
    settings: Partial<GoogleHuntSettings> | null,
  ) => Promise<HuntScheduleState | null>
  /** start the Google IP hunter (independent of scans); resolves with the fresh state */
  startHunt: (settings?: Partial<GoogleHuntSettings>) => Promise<GoogleHuntState | null>
  /** stop the running hunt */
  stopHunt: () => Promise<GoogleHuntState | null>
  /** clear the accumulated hunt results (idle only) */
  resetHunt: () => Promise<GoogleHuntState | null>
  /** live reverse-engineered recon intelligence (Google SPF + goog.json + cloud.json + PTR) */
  reconState: GoogleHuntRecon | null
  /** trigger a live recon refresh on the engine; resolves with the immediate snapshot */
  refreshRecon: () => Promise<GoogleHuntRecon | null>
  /** live state of the WARP UDP endpoint scanner (null until first sync) */
  warpState: WarpScanState | null
  /** start the WARP endpoint scanner; resolves with the fresh state */
  startWarp: (settings?: Partial<WarpScanSettings>) => Promise<WarpScanState | null>
  /** stop the running WARP scan */
  stopWarp: () => Promise<WarpScanState | null>
  /** clear the accumulated WARP endpoints (idle only) */
  resetWarp: () => Promise<WarpScanState | null>
}

type EngineSocket = Socket<
  import('@/lib/scan-protocol').ServerToClientEvents,
  import('@/lib/scan-protocol').ClientToServerEvents
>

export function useScanSocket(): UseScanSocketReturn {
  const socketRef = useRef<EngineSocket | null>(null)
  const resultMapRef = useRef<Map<string, LiveResult>>(new Map())

  const [connected, setConnected] = useState(false)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [results, setResults] = useState<LiveResult[]>([])
  const [logs, setLogs] = useState<ScanLogLine[]>([])
  const [summary, setSummary] = useState<ScanSummary | null>(null)
  const [rtt, setRtt] = useState<number | null>(null)
  const [latencyHistory, setLatencyHistory] = useState<LatencyPoint[]>([])
  const [finishedCount, setFinishedCount] = useState(0)
  const [autoState, setAutoState] = useState<AutoScanState | null>(null)
  const [queueState, setQueueState] = useState<ScanQueueState | null>(null)
  const [huntState, setHuntState] = useState<GoogleHuntState | null>(null)
  const [reconState, setReconState] = useState<GoogleHuntRecon | null>(null)
  // v7.0 — engine-side hunt scheduler (starts from the honest disabled default, synced on connect)
  const [huntSchedState, setHuntSchedState] = useState<HuntScheduleState>(() => ({ ...HUNT_SCHEDULE_DISABLED }))
  const [warpState, setWarpState] = useState<WarpScanState | null>(null)

  const pushLog = useCallback((line: ScanLogLine) => {
    setLogs((prev) => [...prev.slice(-(MAX_LOGS - 1)), line])
  }, [])

  const commitResults = useCallback(() => {
    const arr = Array.from(resultMapRef.current.values())
    setResults(arr.length > MAX_RESULTS ? arr.slice(-MAX_RESULTS) : arr)
  }, [])

  const mergeResults = useCallback(
    (incoming: LiveResult[]) => {
      if (!incoming?.length) return
      const map = resultMapRef.current
      for (const r of incoming) {
        if (!r || !r.ip) continue
        map.set(r.ip, { ...map.get(r.ip), ...r })
      }
      commitResults()
    },
    [commitResults]
  )

  // ----- socket lifecycle -----
  useEffect(() => {
    const socket: EngineSocket = io(`/?XTransformPort=${SCAN_SOCKET_PORT}`, {
      transports: ['websocket', 'polling'],
      forceNew: true,
      reconnection: true,
      reconnectionAttempts: 10,
    })
    socketRef.current = socket

    const onConnect = () => {
      setConnected(true)
      // restore state on first connect AND after reconnects (page refresh / engine restart)
      socket.timeout(8000).emit('scan:state', (err, s) => {
        if (err || !s) return
        setLogs((s.logs ?? []).slice(-MAX_LOGS))
        if (s.running) {
          setRunning(true)
          setProgress(s.progress ?? null)
          resultMapRef.current = new Map(
            (s.results ?? []).map((r) => [r.ip, r])
          )
          commitResults()
        } else if (s.summary) {
          setSummary(s.summary)
          setProgress(null)
          resultMapRef.current = new Map(
            (s.summary.results ?? []).map((r) => [r.ip, r])
          )
          commitResults()
        } else if (s.results?.length) {
          resultMapRef.current = new Map(s.results.map((r) => [r.ip, r]))
          commitResults()
        }
      })
      // sync the scheduler state too
      socket.timeout(8000).emit('auto-scan:state', (err, s) => {
        if (!err && s) setAutoState(s)
      })
      // sync the multi-CDN queue state
      socket.timeout(8000).emit('queue:state', (err, s) => {
        if (!err && s) setQueueState(s)
      })
      // sync the standalone Google IP hunter state
      socket.timeout(8000).emit('google-hunt:state', (err, s) => {
        if (!err) setHuntState(sanitizeHuntState(s))
      })
      // sync the reverse-engineered recon intelligence
      socket.timeout(8000).emit('google-hunt:recon', (err, r) => {
        if (!err) setReconState(sanitizeRecon(r))
      })
      // sync the WARP UDP endpoint scanner state
      socket.timeout(8000).emit('warp:state', (err, s) => {
        if (!err) setWarpState(sanitizeWarpState(s))
      })
      // v7.0 — sync the engine-side hunt scheduler state
      socket.timeout(8000).emit('hunt-schedule:state', (err, s) => {
        if (!err && s) setHuntSchedState(sanitizeHuntSchedule(s))
      })
    }
    const onDisconnect = () => setConnected(false)
    const onConnectError = () => setConnected(false)

    socket.on('connect', onConnect)
    socket.on('disconnect', onDisconnect)
    socket.on('connect_error', onConnectError)

    socket.on('scan:progress', (p) => {
      setProgress(p)
      setRunning(true)
      if (typeof p?.recentLatency === 'number' && p.recentLatency > 0) {
        setLatencyHistory((prev) => {
          const next = [
            ...prev,
            { t: Date.now(), latency: p.recentLatency },
          ]
          return next.length > MAX_SPARK_POINTS
            ? next.slice(-MAX_SPARK_POINTS)
            : next
        })
      }
    })

    socket.on('scan:alive', (batch) => mergeResults(batch))
    socket.on('scan:result', (r) => mergeResults([r]))

    socket.on('scan:done', (s) => {
      setSummary(s)
      setRunning(false)
      resultMapRef.current = new Map((s?.results ?? []).map((r) => [r.ip, r]))
      commitResults()
      setFinishedCount((c) => c + 1)
    })

    socket.on('scan:log', (l) => pushLog(l))
    socket.on('auto-scan:state', (s) => setAutoState(s))
    socket.on('queue:state', (s) => setQueueState(s))
    socket.on('google-hunt:state', (s) => setHuntState(sanitizeHuntState(s)))
    socket.on('google-hunt:recon', (r) => setReconState(sanitizeRecon(r)))
    socket.on('warp:state', (s) => setWarpState(sanitizeWarpState(s)))
    // v7.0 — hunt scheduler broadcasts whenever its state changes
    socket.on('hunt-schedule:state', (s) => setHuntSchedState(sanitizeHuntSchedule(s)))
    socket.on('scan:error', (e) => {
      pushLog({
        ts: Date.now(),
        level: 'error',
        message: e?.message ?? 'خطای ناشناخته',
      })
    })
    socket.on('pong:rtt', (t) => setRtt(Math.max(0, Date.now() - t)))

    return () => {
      socket.removeAllListeners()
      socket.disconnect()
      socketRef.current = null
    }
  }, [commitResults, mergeResults, pushLog])

  // ----- RTT probe every 5s -----
  useEffect(() => {
    if (!connected) return
    const probe = () => {
      try {
        socketRef.current?.timeout(3000).emit('ping:rtt', (err, t) => {
          if (!err && typeof t === 'number') setRtt(Math.max(0, Date.now() - t))
        })
      } catch {
        /* ignore */
      }
    }
    probe()
    const id = window.setInterval(probe, RTT_INTERVAL_MS)
    return () => window.clearInterval(id)
  }, [connected])

  // ----- actions -----
  const start = useCallback(
    (cfg: ScanConfig) => {
      const socket = socketRef.current
      if (!socket || !socket.connected) return
      resultMapRef.current = new Map()
      setResults([])
      setLogs([])
      setSummary(null)
      setProgress(null)
      setLatencyHistory([])
      setRtt(null)
      setRunning(true)
      socket.emit('scan:start', cfg)
      pushLog({
        ts: Date.now(),
        level: 'info',
        message: 'درخواست شروع اسکن ارسال شد…',
        messageEn: 'Scan start requested…',
      })
    },
    [pushLog]
  )

  const stop = useCallback(() => {
    const socket = socketRef.current
    if (!socket || !socket.connected) return
    socket.emit('scan:stop')
    pushLog({
      ts: Date.now(),
      level: 'warn',
      message: 'درخواست توقف اسکن ارسال شد…',
      messageEn: 'Scan stop requested…',
    })
  }, [pushLog])

  const checkIps = useCallback(
    (ips: string[], port: number) =>
      new Promise<LiveResult[]>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected || ips.length === 0) {
          resolve([])
          return
        }
        const timer = window.setTimeout(() => resolve([]), 15_000)
        socket.timeout(15_000).emit(
          'check:ips',
          { ips: ips.slice(0, 50), port, pingCount: 3, timeoutMs: 1500 },
          (err, results) => {
            window.clearTimeout(timer)
            resolve(err || !Array.isArray(results) ? [] : results)
          },
        )
      }),
    [],
  )

  const setAutoScan = useCallback(
    (enabled: boolean, intervalMinutes: number, config: ScanConfig | null, notifyUrl?: string) =>
      new Promise<AutoScanState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit(
          'auto-scan:set',
          { enabled, intervalMinutes, config, notifyUrl: notifyUrl ?? undefined },
          (err, s) => {
            if (!err && s) {
              setAutoState(s)
              resolve(s)
            } else {
              resolve(null)
            }
          },
        )
      }),
    [],
  )

  const testNotify = useCallback(
    (url: string) =>
      new Promise<boolean>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected || !url.trim()) {
          resolve(false)
          return
        }
        socket.timeout(12_000).emit('auto-scan:notify-test', url.trim(), (err, res) => {
          resolve(!err && !!res?.ok)
        })
      }),
    [],
  )

  const setTelegram = useCallback(
    (token?: string, chatId?: string, digest?: boolean) =>
      new Promise<AutoScanState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('telegram:set', { token, chatId, digest }, (err, s) => {
          if (!err && s) {
            setAutoState(s)
            resolve(s)
          } else {
            resolve(null)
          }
        })
      }),
    [],
  )

  const testTelegram = useCallback(
    () =>
      new Promise<boolean>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(false)
          return
        }
        socket.timeout(12_000).emit('telegram:test', (err, res) => {
          resolve(!err && !!res?.ok)
        })
      }),
    [],
  )

  const addToQueue = useCallback(
    (config: ScanConfig, label?: string) =>
      new Promise<ScanQueueState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('queue:add', { config, label }, (err, s) => {
          if (!err && s) {
            setQueueState(s)
            resolve(s)
          } else {
            resolve(null)
          }
        })
      }),
    [],
  )

  const removeFromQueue = useCallback(
    (id: string) =>
      new Promise<ScanQueueState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('queue:remove', id, (err, s) => {
          if (!err && s) {
            setQueueState(s)
            resolve(s)
          } else {
            resolve(null)
          }
        })
      }),
    [],
  )

  const clearQueue = useCallback(
    () =>
      new Promise<ScanQueueState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('queue:clear', (err, s) => {
          if (!err && s) {
            setQueueState(s)
            resolve(s)
          } else {
            resolve(null)
          }
        })
      }),
    [],
  )

  const moveQueueItem = useCallback(
    (id: string, dir: -1 | 1) =>
      new Promise<ScanQueueState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('queue:move', { id, dir }, (err, s) => {
          if (!err && s) {
            setQueueState(s)
            resolve(s)
          } else {
            resolve(null)
          }
        })
      }),
    [],
  )

  const toggleQueueItem = useCallback(
    (id: string) =>
      new Promise<ScanQueueState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('queue:toggle', id, (err, s) => {
          if (!err && s) {
            setQueueState(s)
            resolve(s)
          } else {
            resolve(null)
          }
        })
      }),
    [],
  )

  const updateQueueItem = useCallback(
    (id: string, patch: { label?: string; config?: Partial<ScanConfig> }) =>
      new Promise<ScanQueueState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('queue:update', { id, ...patch }, (err, s) => {
          if (!err && s) {
            setQueueState(s)
            resolve(s)
          } else {
            resolve(null)
          }
        })
      }),
    [],
  )

  const reorderQueueItem = useCallback(
    (id: string, index: number) =>
      new Promise<ScanQueueState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('queue:reorder', { id, index }, (err, s) => {
          if (!err && s) {
            setQueueState(s)
            resolve(s)
          } else {
            resolve(null)
          }
        })
      }),
    [],
  )

  const probeXray = useCallback(
    (payload: XrayProbeRequest) =>
      new Promise<XrayProbeResult | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(15_000).emit('xray:probe', payload, (err, r) => {
          resolve(err || !r ? null : r)
        })
      }),
    [],
  )

  // ----- v7.0 — engine-side hunt scheduler (mirrors setAutoScan exactly) -----
  const setHuntSchedule = useCallback(
    (enabled: boolean, intervalMinutes: number, settings: Partial<GoogleHuntSettings> | null) =>
      new Promise<HuntScheduleState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        // the engine normalizes partial settings (contract: null = keep the stored snapshot)
        const payload = {
          enabled,
          intervalMinutes,
          settings: (settings ?? null) as HuntScheduleSetPayload['settings'],
        }
        socket.timeout(8000).emit('hunt-schedule:set', payload, (err, s) => {
          const snap = err ? null : sanitizeHuntSchedule(s)
          if (snap) setHuntSchedState(snap)
          resolve(snap)
        })
      }),
    [],
  )

  // ----- standalone Google-friendly IP hunter (independent of scans) -----
  const startHunt = useCallback(
    (settings?: Partial<GoogleHuntSettings>) =>
      new Promise<GoogleHuntState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('google-hunt:start', settings, (err, s) => {
          if (!err && s) {
            setHuntState(s)
            resolve(s)
          } else {
            resolve(null)
          }
        })
      }),
    [],
  )

  const stopHunt = useCallback(
    () =>
      new Promise<GoogleHuntState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('google-hunt:stop', (err, s) => {
          if (!err && s) setHuntState(s)
          resolve(err || !s ? null : s)
        })
      }),
    [],
  )

  const resetHunt = useCallback(
    () =>
      new Promise<GoogleHuntState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('google-hunt:reset', (err, s) => {
          setHuntState(err ? null : (s ?? null))
          resolve(err ? null : (s ?? null))
        })
      }),
    [],
  )

  /** trigger a live recon refresh — ack resolves immediately, updates arrive via broadcast */
  const refreshRecon = useCallback(
    () =>
      new Promise<GoogleHuntRecon | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('google-hunt:recon:refresh', (err, r) => {
          const snap = sanitizeRecon(r)
          if (!err && snap) setReconState(snap)
          resolve(err ? null : snap)
        })
      }),
    [],
  )

  /** start the WARP UDP endpoint scanner (independent of scans/hunt) */
  const startWarp = useCallback(
    (settings?: Partial<WarpScanSettings>) =>
      new Promise<WarpScanState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('warp:start', settings, (err, s) => {
          if (!err && s) {
            setWarpState(sanitizeWarpState(s))
            resolve(sanitizeWarpState(s))
          } else {
            resolve(null)
          }
        })
      }),
    [],
  )

  const stopWarp = useCallback(
    () =>
      new Promise<WarpScanState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('warp:stop', (err, s) => {
          const snap = err ? null : sanitizeWarpState(s)
          if (snap) setWarpState(snap)
          resolve(snap)
        })
      }),
    [],
  )

  const resetWarp = useCallback(
    () =>
      new Promise<WarpScanState | null>((resolve) => {
        const socket = socketRef.current
        if (!socket || !socket.connected) {
          resolve(null)
          return
        }
        socket.timeout(8000).emit('warp:reset', (err, s) => {
          const snap = err ? null : sanitizeWarpState(s)
          setWarpState(snap)
          resolve(snap)
        })
      }),
    [],
  )

  return {
    connected,
    running,
    progress,
    results,
    logs,
    summary,
    rtt,
    latencyHistory,
    finishedCount,
    autoState,
    queueState,
    start,
    stop,
    checkIps,
    setAutoScan,
    testNotify,
    setTelegram,
    testTelegram,
    addToQueue,
    removeFromQueue,
    clearQueue,
    moveQueueItem,
    reorderQueueItem,
    toggleQueueItem,
    updateQueueItem,
    probeXray,
    huntState,
    huntSchedState,
    setHuntSchedule,
    startHunt,
    stopHunt,
    resetHunt,
    reconState,
    refreshRecon,
    warpState,
    startWarp,
    stopWarp,
    resetWarp,
  }
}
