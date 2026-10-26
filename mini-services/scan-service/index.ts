/**
 * Clean IP Scanner — Web Edition :: Scan Engine
 * A faithful, optimized re-implementation of the original Go CLI
 * (github.com/4n0nymou3/Clean-IP-Scanner) as a realtime socket.io service.
 *
 * Phases:
 *  1. generating — sample N random IPs from CDN CIDR ranges (proportional, deduped, shuffled)
 *  2. ping       — TCPing with a worker pool: N pings per IP, avg latency + loss rate
 *  3. speed      — real download/upload test against best candidates via forced-IP TLS (SNI bypass)
 *  4. done       — summary emitted; frontend persists it via /api/scans
 */

import { createServer } from 'node:http'
import { Server } from 'socket.io'
import net from 'node:net'
import tls from 'node:tls'
import fs from 'node:fs'
import path from 'node:path'
import dgram from 'node:dgram'
import crypto from 'node:crypto'
import type {
  AutoScanSetPayload,
  AutoScanState,
  ClientToServerEvents,
  GoogleHuntBlockStat,
  GoogleHuntCandidate,
  GoogleHuntHistoryRun,
  GoogleHuntRecon,
  GoogleHuntState,
  GoogleHuntSettings,
  GoogleHuntReconStatus,
  HuntProviderId,
  HuntProviderSelection,
  HuntForensicsTally,
  HuntSourceHealth,
  HuntTargetOverride,
  HuntProviderStats,
  HuntScheduleFireSettings,
  HuntScheduleJournalEntry,
  HuntScheduleSetPayload,
  HuntScheduleState,
  IpCheckPayload,
  LiveResult,
  QueueItem,
  ScanConfig,
  ScanLogLine,
  ScanPhase,
  ScanProgress,
  ScanQueueState,
  ScanSummary,
  ServerToClientEvents,
  WarpEndpoint,
  WarpHistoryRun,
  WarpScanSettings,
  WarpScanState,
  XrayProbeRequest,
  XrayProbeResult,
} from '../../src/lib/scan-protocol'
import { HUNT_RECON_RANGES_CAP, HUNT_SCHEDULE_JOURNAL_CAP, HUNT_SELECTED_MAX_CIDRS, WARP_CUSTOM_RANGES_CAP, WARP_HISTORY_FOUND_CAP, WARP_HISTORY_MAX_RUNS, WARP_RANGE_RE, WARP_RANGES, WARP_UDP_PORTS } from '../../src/lib/scan-protocol'
import { getPresetRanges, CDN_PRESETS } from '../../src/lib/cdn-presets'

const PORT = 3003
const UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36'
const MAX_IPS_PER_CIDR = 5_000_000n
const DL_WINDOW_MS = 8000
const UL_WINDOW_MS = 8000
const UL_TOTAL_BYTES = 25 * 1024 * 1024
const CHUNK = 64 * 1024

// ---------------------------------------------------------------- clamp utils
const clampInt = (v: unknown, min: number, max: number, dflt: number) => {
  const n = Math.floor(Number(v))
  if (!Number.isFinite(n)) return dflt
  return Math.min(max, Math.max(min, n))
}

function normalizeConfig(raw: Partial<ScanConfig>): ScanConfig {
  return {
    preset: typeof raw.preset === 'string' && raw.preset ? raw.preset : 'cloudflare',
    customRanges: typeof raw.customRanges === 'string' ? raw.customRanges.slice(0, 64_000) : '',
    port: clampInt(raw.port, 1, 65535, 443),
    pingCount: clampInt(raw.pingCount, 1, 8, 4),
    timeoutMs: clampInt(raw.timeoutMs, 200, 5000, 1500),
    concurrency: clampInt(raw.concurrency, 16, 1024, 256),
    maxIPs: clampInt(raw.maxIPs, 10, 200_000, 2000),
    speedTestCount: clampInt(raw.speedTestCount, 1, 30, 10),
    speedHost:
      typeof raw.speedHost === 'string' && raw.speedHost.trim()
        ? raw.speedHost.trim().slice(0, 120)
        : 'speed.cloudflare.com',
    maxLatencyMs: clampInt(raw.maxLatencyMs, 0, 5000, 0),
  }
}

// ------------------------------------------------------------------ IP math
function ipToBigInt(ip: string): bigint | null {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some((p) => p < 0 || p > 255)) return null
    return (BigInt(parts[0]) << 24n) | (BigInt(parts[1]) << 16n) | (BigInt(parts[2]) << 8n) | BigInt(parts[3])
  }
  if (!net.isIPv6(ip)) return null
  const dc = ip.split('::')
  if (dc.length > 2) return null
  const expand = (side: string): number[] | null => {
    if (!side) return []
    const segs = side.split(':')
    const out: number[] = []
    for (let i = 0; i < segs.length; i++) {
      const s = segs[i]
      if (s.includes('.')) {
        if (i !== segs.length - 1) return null
        const v4 = ipToBigInt(s)
        if (v4 === null) return null
        out.push(Number((v4 >> 16n) & 0xffffn), Number(v4 & 0xffffn))
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(s)) return null
        out.push(parseInt(s, 16))
      }
    }
    return out
  }
  const head = expand(dc[0])
  const tail = dc.length === 2 ? expand(dc[1]) : []
  if (head === null || tail === null) return null
  const missing = 8 - head.length - tail.length
  if (dc.length === 2 ? missing < 0 : missing !== 0) return null
  const groups = [...head, ...(dc.length === 2 ? Array(missing).fill(0) : []), ...tail]
  let v = 0n
  for (const g of groups) v = (v << 16n) | BigInt(g)
  return v
}

function bigIntToIP(v: bigint, isV4: boolean): string {
  if (isV4) {
    return [24n, 16n, 8n, 0n].map((s) => ((v >> s) & 0xffn).toString()).join('.')
  }
  const groups: string[] = []
  for (let s = 112n; s >= 0n; s -= 16n) groups.push(((v >> s) & 0xffffn).toString(16))
  return groups.join(':')
}

interface CidrRange {
  start: bigint
  end: bigint
  isV4: boolean
  size: bigint
  key: string
}

function parseCIDR(line: string): CidrRange | null {
  let cidr = line.trim()
  if (!cidr || cidr.startsWith('#')) return null
  const slash = cidr.indexOf('/')
  let base = cidr
  let prefix = -1
  if (slash >= 0) {
    base = cidr.slice(0, slash)
    prefix = parseInt(cidr.slice(slash + 1), 10)
  }
  const ipBig = ipToBigInt(base)
  if (ipBig === null) return null
  const isV4 = net.isIPv4(base)
  const totalBits = isV4 ? 32 : 128
  if (prefix < 0) prefix = totalBits
  if (prefix < 0 || prefix > totalBits) return null
  const hostBits = BigInt(totalBits - prefix)
  const mask = hostBits === 0n ? ~0n & ((1n << BigInt(totalBits)) - 1n) : ~((1n << hostBits) - 1n) & ((1n << BigInt(totalBits)) - 1n)
  const start = ipBig & mask
  const size = 1n << hostBits
  const end = start + size - 1n
  return { start, end, isV4, size, key: `${bigIntToIP(start, isV4)}/${prefix}` }
}

function randBelow(size: bigint): bigint {
  const bits = size.toString(2).length
  let v = 0n
  for (let i = 0; i < bits + 16; i += 15) {
    v = (v << 15n) | BigInt(Math.floor(Math.random() * 32768))
  }
  return v % size
}

function shuffle<T>(arr: T[]): T[] {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
  return arr
}

function collectRanges(cfg: ScanConfig): string[] {
  const lines = new Set<string>()
  if (cfg.preset !== 'custom') {
    for (const r of getPresetRanges(cfg.preset)) lines.add(r.trim())
  }
  if (cfg.customRanges) {
    for (const r of cfg.customRanges.split(/\r?\n/)) {
      const t = r.trim()
      if (t && !t.startsWith('#')) lines.add(t)
    }
  }
  return [...lines].filter(Boolean)
}

/** Proportional random sampling across CIDRs with dedup + per-CIDR guard. */
function sampleIPs(rangeLines: string[], maxIPs: number): { ips: string[]; totalAvailable: number; skipped: number; cidrs: number } {
  const seen = new Set<string>()
  const ranges: CidrRange[] = []
  let skipped = 0
  for (const line of rangeLines) {
    const c = parseCIDR(line)
    if (!c) {
      skipped++
      continue
    }
    if (seen.has(c.key)) continue
    seen.add(c.key)
    if (c.size > MAX_IPS_PER_CIDR) {
      skipped++
      continue
    }
    ranges.push(c)
  }
  let totalAvailable = 0n
  for (const r of ranges) totalAvailable += r.size

  const ips: string[] = []
  const ipSeen = new Set<string>()
  const addIP = (v: bigint, isV4: boolean) => {
    const s = bigIntToIP(v, isV4)
    if (!ipSeen.has(s)) {
      ipSeen.add(s)
      ips.push(s)
    }
  }

  const totalBig = totalAvailable
  const want = BigInt(maxIPs)
  if (totalBig <= want) {
    for (const r of ranges) {
      let cur = r.start
      while (cur <= r.end) {
        addIP(cur, r.isV4)
        cur += 1n
      }
    }
  } else {
    for (const r of ranges) {
      const quota = Number((want * r.size) / totalBig)
      const quotaBig = BigInt(Math.max(1, quota))
      if (quotaBig >= r.size) {
        for (let cur = r.start; cur <= r.end; cur += 1n) addIP(cur, r.isV4)
      } else {
        const offsets = new Set<bigint>()
        let guard = 0
        while (offsets.size < Number(quotaBig) && guard < Number(quotaBig) * 12 + 64) {
          offsets.add(randBelow(r.size))
          guard++
        }
        for (const off of offsets) addIP(r.start + off, r.isV4)
      }
    }
  }
  shuffle(ips)
  if (ips.length > maxIPs) ips.length = maxIPs
  return { ips, totalAvailable: Number(totalAvailable), skipped, cidrs: ranges.length }
}

// ------------------------------------------------------------------ tcping
function tcping(ip: string, port: number, timeoutMs: number): Promise<number | null> {
  return new Promise((resolve) => {
    const start = Date.now()
    let done = false
    const sock = net.connect({ host: ip, port })
    const finish = (ms: number | null) => {
      if (done) return
      done = true
      sock.removeAllListeners()
      sock.destroy()
      resolve(ms)
    }
    sock.setTimeout(timeoutMs, () => finish(null))
    sock.once('connect', () => finish(Date.now() - start))
    sock.once('error', () => finish(null))
  })
}

// ------------------------------------------------------------------ speed tests
function forcedConnection(ip: string, port: number, host: string, timeoutMs: number) {
  return () =>
    tls.connect({
      host: ip,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    })
}

function downloadTest(ip: string, port: number, host: string): Promise<number> {
  return new Promise((resolve) => {
    let bytes = 0
    let resolved = false
    const start = Date.now()
    const finish = () => {
      if (resolved) return
      resolved = true
      clearTimeout(timer)
      try {
        req.destroy()
      } catch {}
      const elapsed = Math.max(300, Date.now() - start) / 1000
      resolve(bytes / elapsed)
    }
    let req!: import('node:https').ClientRequest
    let timer: NodeJS.Timeout
    try {
      req = https_request(
        {
          host,
          port,
          path: '/__down?bytes=52428800',
          method: 'GET',
          headers: { Host: host, 'User-Agent': UA, Accept: '*/*' },
          timeout: 10_000,
          createConnection: forcedConnection(ip, port, host, 10_000),
        },
        (res) => {
          if (res.statusCode !== 200) {
            finish()
            return
          }
          res.on('data', (c: Buffer) => {
            bytes += c.length
          })
          res.on('end', finish)
          res.on('error', finish)
        },
      )
      req.on('error', finish)
      req.on('timeout', () => finish())
      timer = setTimeout(finish, DL_WINDOW_MS)
      req.end()
    } catch {
      finish()
    }
  })
}

function uploadTest(ip: string, port: number, host: string): Promise<number> {
  return new Promise((resolve) => {
    let acked = 0
    let queued = 0
    let resolved = false
    const start = Date.now()
    const chunk = Buffer.alloc(CHUNK, 0xab)
    const finish = () => {
      if (resolved) return
      resolved = true
      clearTimeout(timer)
      try {
        req.destroy()
      } catch {}
      const elapsed = Math.max(300, Date.now() - start) / 1000
      resolve(acked / elapsed)
    }
    let req!: import('node:https').ClientRequest
    let timer: NodeJS.Timeout
    const pump = () => {
      if (resolved) return
      while (queued < UL_TOTAL_BYTES) {
        const n = Math.min(CHUNK, UL_TOTAL_BYTES - queued)
        queued += n
        const ok = req.write(n === CHUNK ? chunk : chunk.subarray(0, n), () => {
          acked += n
        })
        if (!ok) {
          req.once('drain', pump)
          return
        }
      }
      req.end()
    }
    try {
      req = https_request(
        {
          host,
          port,
          path: '/__up',
          method: 'POST',
          headers: {
            Host: host,
            'User-Agent': UA,
            'Content-Type': 'application/octet-stream',
            'Content-Length': String(UL_TOTAL_BYTES),
          },
          timeout: UL_WINDOW_MS + 3000,
          createConnection: forcedConnection(ip, port, host, 10_000),
        },
        (res) => {
          res.resume()
          res.on('end', finish)
          res.on('error', finish)
        },
      )
      req.on('error', finish)
      req.on('timeout', () => finish())
      timer = setTimeout(finish, UL_WINDOW_MS)
      pump()
    } catch {
      finish()
    }
  })
}

// tiny indirection so we can import https lazily with types kept simple
import https from 'node:https'
function https_request(
  opts: https.RequestOptions & { createConnection?: () => import('node:tls').TLSSocket },
  cb: (res: import('node:http').IncomingMessage) => void,
): import('node:https').ClientRequest {
  return https.request(opts as https.RequestOptions, cb)
}

// ------------------------------------------------------------------ job state
interface Job {
  id: string
  config: ScanConfig
  startedAt: number
  stopped: boolean
  phase: ScanPhase
  results: LiveResult[]
  aliveResults: LiveResult[]
  pendingAlive: LiveResult[]
  logs: ScanLogLine[]
  progress: ScanProgress | null
  summary: ScanSummary | null
  totalIPs: number
  scanned: number
  alive: number
  speedTested: number
  speedTotal: number
  error?: string
  /** triggered by the scheduler instead of a user */
  auto?: boolean
  /** triggered by the multi-CDN queue */
  fromQueue?: boolean
  queueId?: string
  queueLabel?: string
}

// ------------------------------------------------------- scheduled auto-scan
const AUTO_FILE = path.join(import.meta.dir, '..', '..', 'db', 'auto-scan.json')
const AUTO_MIN_INTERVAL_MIN = 5
const AUTO_MAX_INTERVAL_MIN = 1440
const BOOT_GRACE_MS = 15_000

interface AutoState {
  enabled: boolean
  intervalMinutes: number
  config: ScanConfig | null
  nextRunAt: number | null
  lastRunAt: number | null
  runsCount: number
  notifyUrl: string
  telegramToken: string
  telegramChatId: string
  /** collect finished queue runs and send ONE digest telegram message per batch */
  telegramDigest: boolean
}

const auto: AutoState = {
  enabled: false,
  intervalMinutes: 30,
  config: null,
  nextRunAt: null,
  lastRunAt: null,
  runsCount: 0,
  notifyUrl: '',
  telegramToken: '',
  telegramChatId: '',
  telegramDigest: false,
}
let autoTimer: ReturnType<typeof setTimeout> | null = null

// ------------------------------------------------------------- scan queue
const QUEUE_FILE = path.join(import.meta.dir, '..', '..', 'db', 'scan-queue.json')
const QUEUE_MAX_ITEMS = 50
const QUEUE_MAX_FINISHED = 30

const queue: QueueItem[] = []
let currentQueueId: string | null = null

function queueSnapshot(): ScanQueueState {
  return {
    items: queue.map((i) => ({ ...i })),
    running: !!(currentQueueId && job && !job.summary),
    currentId: currentQueueId,
  }
}

function broadcastQueueState() {
  io.emit('queue:state', queueSnapshot())
}

function persistQueue() {
  try {
    // trim old finished items so the file stays small
    const finished = queue.filter((i) => i.status !== 'waiting' && i.status !== 'running')
    if (finished.length > QUEUE_MAX_FINISHED) {
      const excess = new Set(finished.slice(0, finished.length - QUEUE_MAX_FINISHED).map((i) => i.id))
      for (let i = queue.length - 1; i >= 0; i--) {
        if (excess.has(queue[i]!.id)) queue.splice(i, 1)
      }
    }
    fs.mkdirSync(path.dirname(QUEUE_FILE), { recursive: true })
    fs.writeFileSync(QUEUE_FILE, JSON.stringify(queue, null, 2))
  } catch (e) {
    console.error('[scan-service] queue persist failed:', e)
  }
}

function loadQueue() {
  try {
    if (!fs.existsSync(QUEUE_FILE)) return
    const raw = JSON.parse(fs.readFileSync(QUEUE_FILE, 'utf8')) as QueueItem[]
    if (!Array.isArray(raw)) return
    for (const item of raw.slice(-QUEUE_MAX_ITEMS)) {
      if (!item || typeof item.id !== 'string' || !item.config) continue
      // an interrupted run resumes as waiting on boot
      item.status = item.status === 'running' ? 'waiting' : item.status
      queue.push(item)
    }
    const waiting = queue.filter((i) => i.status === 'waiting').length
    if (waiting > 0) {
      console.log(`[scan-service] queue restored — ${waiting} item(s) waiting`)
      // kick processing shortly after boot
      setTimeout(() => processQueue(), 5000)
    }
  } catch (e) {
    console.error('[scan-service] queue load failed:', e)
  }
}

/** start the next enabled waiting queue item when the engine is idle */
function processQueue() {
  if (job && !job.summary && job.phase !== 'error') return // busy
  const next = queue.find((i) => i.status === 'waiting' && i.enabled !== false)
  if (!next) {
    // batch finished — make it explicit when only paused items remain so the
    // queue never LOOKS like it silently stalled halfway through
    const paused = queue.filter((i) => i.status === 'waiting' && i.enabled === false).length
    if (paused > 0) {
      log(
        'info',
        `📋 صف کامل شد — ${paused} آیتم موقتاً غیرفعال باقی ماند (برای اجرا، آن را از پنل صف فعال کنید)`,
        `📋 Queue batch finished — ${paused} paused item(s) remain (re-enable from the queue panel to run them)`,
      )
    }
    return
  }
  next.status = 'running'
  next.startedAt = Date.now()
  currentQueueId = next.id
  persistQueue()
  broadcastQueueState()
  log('info', `🚀 اجرای آیتم صف: ${next.label}`, `🚀 Running queue item: ${next.label}`)
  void startScan(next.config, { fromQueue: true, queueId: next.id, queueLabel: next.label })
}

function autoSnapshot(): AutoScanState {
  return {
    enabled: auto.enabled,
    intervalMinutes: auto.intervalMinutes,
    nextRunAt: auto.nextRunAt,
    lastRunAt: auto.lastRunAt,
    runsCount: auto.runsCount,
    running: !!(job && job.auto && !job.summary),
    config: auto.config,
    notifyUrl: auto.notifyUrl,
    telegramConfigured: !!auto.telegramToken && !!auto.telegramChatId,
    telegramChatId: auto.telegramChatId,
    telegramDigest: auto.telegramDigest,
  }
}

function broadcastAutoState() {
  io.emit('auto-scan:state', autoSnapshot())
}

function persistAuto() {
  try {
    fs.mkdirSync(path.dirname(AUTO_FILE), { recursive: true })
    fs.writeFileSync(AUTO_FILE, JSON.stringify(auto, null, 2))
  } catch (e) {
    console.error('[scan-service] auto-scan persist failed:', e)
  }
}

function loadAuto() {
  try {
    if (!fs.existsSync(AUTO_FILE)) return
    const raw = JSON.parse(fs.readFileSync(AUTO_FILE, 'utf8')) as Partial<AutoState>
    if (typeof raw.intervalMinutes === 'number') {
      auto.intervalMinutes = clampInt(raw.intervalMinutes, AUTO_MIN_INTERVAL_MIN, AUTO_MAX_INTERVAL_MIN, 30)
    }
    if (raw.config && typeof raw.config === 'object') auto.config = normalizeConfig(raw.config)
    auto.runsCount = clampInt(raw.runsCount, 0, Number.MAX_SAFE_INTEGER, 0)
    auto.lastRunAt = typeof raw.lastRunAt === 'number' ? raw.lastRunAt : null
    if (typeof raw.notifyUrl === 'string') auto.notifyUrl = raw.notifyUrl.slice(0, 500)
    if (typeof raw.telegramToken === 'string') auto.telegramToken = raw.telegramToken.slice(0, 200)
    if (typeof raw.telegramChatId === 'string') auto.telegramChatId = raw.telegramChatId.slice(0, 100)
    auto.telegramDigest = raw.telegramDigest === true
    if (raw.enabled && auto.config) {
      auto.enabled = true
      // never fire immediately after (re)boot — always give a grace period
      const base = auto.lastRunAt ?? Date.now() - auto.intervalMinutes * 60_000
      auto.nextRunAt = Math.max(Date.now() + BOOT_GRACE_MS, base + auto.intervalMinutes * 60_000)
      scheduleAuto()
      console.log(`[scan-service] auto-scan restored — next run in ${Math.round((auto.nextRunAt - Date.now()) / 1000)}s`)
    }
  } catch (e) {
    console.error('[scan-service] auto-scan load failed:', e)
  }
}

function scheduleAuto() {
  if (autoTimer) {
    clearTimeout(autoTimer)
    autoTimer = null
  }
  if (!auto.enabled || !auto.config || auto.nextRunAt == null) return
  const delay = Math.max(0, auto.nextRunAt - Date.now())
  autoTimer = setTimeout(() => {
    autoTimer = null
    void runAutoScan()
  }, delay)
}

function unscheduleAuto() {
  if (autoTimer) {
    clearTimeout(autoTimer)
    autoTimer = null
  }
  auto.nextRunAt = null
}

async function runAutoScan() {
  if (!auto.enabled || !auto.config) return
  const busy = !!(job && !job.summary)
  auto.lastRunAt = Date.now()
  if (busy) {
    log('warn', 'اسکن زمان‌بندی‌شده به دلیل اجرای اسکن دستی به تعویق افتاد', 'Scheduled scan postponed — a manual scan is running')
  } else {
    auto.runsCount++
    log('info', `⏰ اسکن زمان‌بندی‌شده شروع می‌شود (اجر ${auto.runsCount})`, `⏰ Scheduled scan starting (run ${auto.runsCount})`)
    broadcastAutoState()
    await startScan(auto.config, { auto: true })
  }
  // schedule the next round regardless of success/deferral
  if (auto.enabled) {
    auto.nextRunAt = Date.now() + auto.intervalMinutes * 60_000
    scheduleAuto()
  }
  persistAuto()
  broadcastAutoState()
}

// ---------------- v7.0 — engine-side hunt scheduler (mirror of auto-scan) ----------------
/**
 * Runs the Google-hunt automatically every N minutes with a stored settings
 * snapshot (HuntScheduleState). Survives engine restarts via db/hunt-schedule
 * .json + the shared boot grace period. A scheduled fire while a manual hunt
 * is running is POSTPONED (warn log), never queued — the next round is
 * scheduled regardless. Everything mirrors the auto-scan scheduler above.
 */
const HUNT_SCHEDULE_FILE = path.join(import.meta.dir, '..', '..', 'db', 'hunt-schedule.json')

interface HuntSchedState {
  enabled: boolean
  intervalMinutes: number
  nextRunAt: number | null
  lastRunAt: number | null
  runsCount: number
  settings: GoogleHuntSettings | null
  /** v7.1 — newest-first journal of scheduler events (fire/done/postponed), capped */
  journal: HuntScheduleJournalEntry[]
}

const huntSched: HuntSchedState = {
  enabled: false,
  intervalMinutes: 30,
  nextRunAt: null,
  lastRunAt: null,
  runsCount: 0,
  settings: null,
  journal: [],
}
let huntSchedTimer: ReturnType<typeof setTimeout> | null = null

function huntScheduleSnapshot(): HuntScheduleState {
  return {
    enabled: huntSched.enabled,
    intervalMinutes: huntSched.intervalMinutes,
    nextRunAt: huntSched.nextRunAt,
    lastRunAt: huntSched.lastRunAt,
    runsCount: huntSched.runsCount,
    // true only while a SCHEDULER-triggered hunt (state.auto === true) executes
    running: !!(hunt && hunt.state.running && hunt.state.auto === true),
    settings: huntSched.settings,
    // v7.1 — newest-first scheduler journal (fire/done/postponed events)
    journal: huntSched.journal.slice(0, HUNT_SCHEDULE_JOURNAL_CAP),
  }
}

function broadcastHuntSchedule() {
  io.emit('hunt-schedule:state', huntScheduleSnapshot())
}

function persistHuntSchedule() {
  try {
    fs.mkdirSync(path.dirname(HUNT_SCHEDULE_FILE), { recursive: true })
    fs.writeFileSync(HUNT_SCHEDULE_FILE, JSON.stringify(huntSched, null, 2))
  } catch (e) {
    console.error('[scan-service] hunt-schedule persist failed:', e)
  }
}

function loadHuntSchedule() {
  try {
    if (!fs.existsSync(HUNT_SCHEDULE_FILE)) return
    const raw = JSON.parse(fs.readFileSync(HUNT_SCHEDULE_FILE, 'utf8')) as Partial<HuntSchedState>
    if (typeof raw.intervalMinutes === 'number') {
      huntSched.intervalMinutes = clampInt(raw.intervalMinutes, 5, 1440, 30)
    }
    // settings are re-normalized on load so schema evolution self-heals
    huntSched.settings =
      raw.settings && typeof raw.settings === 'object'
        ? normalizeHuntSettings(raw.settings as Partial<GoogleHuntSettings>)
        : null
    huntSched.runsCount = clampInt(raw.runsCount, 0, Number.MAX_SAFE_INTEGER, 0)
    huntSched.lastRunAt = typeof raw.lastRunAt === 'number' ? raw.lastRunAt : null
    // v7.1 — journal round-trip: keep only well-formed entries (plain object +
    // numeric `at` + known `kind`), clamp the numeric extras, newest-first, cap
    if (Array.isArray(raw.journal)) {
      const kinds = new Set(['fire', 'done', 'postponed'])
      huntSched.journal = (raw.journal as unknown[])
        .filter((j): j is Record<string, unknown> => !!j && typeof j === 'object' && !Array.isArray(j))
        .filter(
          (j): j is { at: number; kind: HuntScheduleJournalEntry['kind'] } & Record<string, unknown> =>
            typeof j.at === 'number' &&
            Number.isFinite(j.at) &&
            typeof j.kind === 'string' &&
            kinds.has(j.kind),
        )
        .map((j): HuntScheduleJournalEntry => {
          const entry: HuntScheduleJournalEntry = { at: j.at, kind: j.kind }
          if (typeof j.tested === 'number') entry.tested = clampInt(j.tested, 0, Number.MAX_SAFE_INTEGER, 0)
          if (typeof j.healthy === 'number') entry.healthy = clampInt(j.healthy, 0, Number.MAX_SAFE_INTEGER, 0)
          if (typeof j.durationMs === 'number') entry.durationMs = clampInt(j.durationMs, 0, Number.MAX_SAFE_INTEGER, 0)
          if (j.stopped !== undefined) entry.stopped = j.stopped === true
          // v7.6 — rebuild the per-fire settings echo from the persisted JSON
          // with the same clamps the live fire path uses; legacy entries
          // without settings keep working (the field simply stays absent)
          if (j.settings && typeof j.settings === 'object' && !Array.isArray(j.settings)) {
            const raw = j.settings as Record<string, unknown>
            const echo: HuntScheduleFireSettings = {}
            if (typeof raw.provider === 'string' && raw.provider.trim()) echo.provider = raw.provider.trim().slice(0, 20)
            if (typeof raw.target === 'number' && Number.isFinite(raw.target)) echo.target = Math.min(100, Math.max(1, Math.round(raw.target)))
            if (typeof raw.batchSize === 'number' && Number.isFinite(raw.batchSize)) echo.batchSize = Math.min(10000, Math.max(500, Math.round(raw.batchSize)))
            if (typeof raw.concurrency === 'number' && Number.isFinite(raw.concurrency)) echo.concurrency = Math.min(1024, Math.max(32, Math.round(raw.concurrency)))
            if (typeof raw.host === 'string' && raw.host.trim()) echo.host = raw.host.trim().slice(0, 255)
            if (typeof raw.port === 'number' && Number.isFinite(raw.port)) echo.port = Math.min(65535, Math.max(1, Math.round(raw.port)))
            if (typeof raw.speed === 'string' && raw.speed.trim()) echo.speed = raw.speed.trim().slice(0, 10)
            if (typeof raw.verify === 'number' && Number.isFinite(raw.verify)) echo.verify = Math.min(3, Math.max(0, Math.round(raw.verify)))
            if (Object.keys(echo).length > 0) entry.settings = echo
          }
          return entry
        })
        .sort((a, b) => b.at - a.at)
        .slice(0, HUNT_SCHEDULE_JOURNAL_CAP)
      if (huntSched.journal.length > 0) {
        log(
          'info',
          `دفترچه زمان‌بندی شکار بازیابی شد (${huntSched.journal.length} رویداد)`,
          `hunt schedule journal restored (${huntSched.journal.length} events)`,
        )
      }
    }
    if (raw.enabled && huntSched.settings) {
      huntSched.enabled = true
      // never fire immediately after (re)boot — always give a grace period
      const base = huntSched.lastRunAt ?? Date.now() - huntSched.intervalMinutes * 60_000
      huntSched.nextRunAt = Math.max(Date.now() + BOOT_GRACE_MS, base + huntSched.intervalMinutes * 60_000)
      scheduleHuntSched()
      console.log(
        `[scan-service] hunt schedule restored — next run in ${Math.round((huntSched.nextRunAt - Date.now()) / 1000)}s`,
      )
    }
  } catch (e) {
    console.error('[scan-service] hunt-schedule load failed:', e)
  }
}

function scheduleHuntSched() {
  if (huntSchedTimer) {
    clearTimeout(huntSchedTimer)
    huntSchedTimer = null
  }
  if (!huntSched.enabled || !huntSched.settings || huntSched.nextRunAt == null) return
  const delay = Math.max(0, huntSched.nextRunAt - Date.now())
  huntSchedTimer = setTimeout(() => {
    huntSchedTimer = null
    void runScheduledHunt()
  }, delay)
}

function unscheduleHuntSched() {
  if (huntSchedTimer) {
    clearTimeout(huntSchedTimer)
    huntSchedTimer = null
  }
  huntSched.nextRunAt = null
}

/**
 * v7.6 — compact per-fire settings echo (HuntScheduleFireSettings) for kind=fire
 * journal entries. Captured from the scheduler's stored settings snapshot the
 * moment a scheduled hunt FIRES, so later drift updates / re-captures never
 * rewrite what an older journal entry actually used. Key scalars only, each
 * defensively clamped in the engine's normalize style; invalid/absent fields
 * are omitted entirely (optional-field discipline, persistWarpHistory style).
 * Returns undefined when there is nothing valid to echo (settings-less legacy
 * scheduler) or nothing survived — avoids `{}` noise in the persisted JSON.
 */
function huntSchedFireEcho(s: GoogleHuntSettings | null): HuntScheduleFireSettings | undefined {
  if (!s) return undefined
  const echo: HuntScheduleFireSettings = {}
  // provider was normalized at scheduler-enable time — copy as-is when sane
  if (typeof s.provider === 'string' && s.provider) echo.provider = s.provider
  if (typeof s.target === 'number' && Number.isFinite(s.target)) echo.target = Math.min(100, Math.max(1, Math.round(s.target)))
  if (typeof s.batchSize === 'number' && Number.isFinite(s.batchSize)) echo.batchSize = Math.min(10000, Math.max(500, Math.round(s.batchSize)))
  if (typeof s.concurrency === 'number' && Number.isFinite(s.concurrency)) echo.concurrency = Math.min(1024, Math.max(32, Math.round(s.concurrency)))
  if (typeof s.host === 'string' && s.host.trim()) echo.host = s.host.trim().slice(0, 255)
  if (typeof s.port === 'number' && Number.isFinite(s.port)) echo.port = Math.min(65535, Math.max(1, Math.round(s.port)))
  if (typeof s.speed === 'string' && s.speed) echo.speed = s.speed.slice(0, 10)
  if (typeof s.verify === 'number' && Number.isFinite(s.verify)) echo.verify = Math.min(3, Math.max(0, Math.round(s.verify)))
  if (Object.keys(echo).length === 0) return undefined
  return echo
}

/**
 * v7.1 — append one scheduler journal event (newest-first, capped at
 * HUNT_SCHEDULE_JOURNAL_CAP), then persist + broadcast so the UI observes
 * every scheduler action live. A journal failure must never break the
 * scheduler itself — hence the blanket try/catch.
 */
function journalPush(entry: HuntScheduleJournalEntry): void {
  try {
    huntSched.journal.unshift(entry)
    huntSched.journal = huntSched.journal.slice(0, HUNT_SCHEDULE_JOURNAL_CAP)
    persistHuntSchedule()
    broadcastHuntSchedule()
  } catch (e) {
    console.error('[scan-service] hunt-schedule journal push failed:', e)
  }
}

async function runScheduledHunt() {
  if (!huntSched.enabled) return
  const busy = !!(hunt && hunt.state.running)
  huntSched.lastRunAt = Date.now()
  if (busy) {
    log(
      'warn',
      'شکار زمان‌بندی‌شده به دلیل اجرای شکار دستی به تعویق افتاد',
      'Scheduled hunt postponed — a manual hunt is running',
    )
    // v7.1 — journal the deferral so postponements are auditable in the UI
    journalPush({ at: Date.now(), kind: 'postponed' })
  } else {
    huntSched.runsCount++
    log(
      'info',
      `⏰ شکار زمان‌بندی‌شده شروع می‌شود (اجر ${huntSched.runsCount})`,
      `⏰ Scheduled hunt starting (run ${huntSched.runsCount})`,
    )
    broadcastHuntSchedule()
    // v7.1 — journal the trigger before the run takes off (fire→done pairing)
    // v7.6 — fire entries also carry a compact echo of the settings THIS run used
    journalPush({ at: Date.now(), kind: 'fire', settings: huntSchedFireEcho(huntSched.settings) })
    startGoogleHunt(huntSched.settings ?? undefined, { auto: true })
  }
  // schedule the next round regardless of success/deferral
  if (huntSched.enabled) {
    huntSched.nextRunAt = Date.now() + huntSched.intervalMinutes * 60_000
    scheduleHuntSched()
  }
  persistHuntSchedule()
  broadcastHuntSchedule()
}

/**
 * v7.0 — enable/disable the hunt scheduler. MUST stay synchronous (the socket
 * ack serialises whatever is passed — same trap as auto-scan:set / hunt:start).
 * Disabling is reversible: stored settings/runsCount/lastRunAt survive the off
 * toggle and a later enable without a payload reuses them.
 */
function setHuntSchedule(payload: HuntScheduleSetPayload): HuntScheduleState {
  const interval = clampInt(payload?.intervalMinutes, 5, 1440, 30)
  huntSched.intervalMinutes = interval
  if (payload?.enabled !== true) {
    huntSched.enabled = false
    unscheduleHuntSched()
    persistHuntSchedule()
    broadcastHuntSchedule()
    return huntScheduleSnapshot()
  }
  if (payload.settings && typeof payload.settings === 'object') {
    huntSched.settings = normalizeHuntSettings(payload.settings)
  } else if (!huntSched.settings) {
    // first enable without a settings snapshot → honest normalized defaults
    huntSched.settings = normalizeHuntSettings(undefined)
  }
  huntSched.enabled = true
  // fresh enable = the full interval (never an immediate fire)
  huntSched.nextRunAt = Date.now() + huntSched.intervalMinutes * 60_000
  scheduleHuntSched()
  log(
    'info',
    `⏱️ شکار خودکار فعال شد — هر ${huntSched.intervalMinutes} دقیقه`,
    `⏱️ Auto hunt enabled — every ${huntSched.intervalMinutes} minutes`,
  )
  persistHuntSchedule()
  broadcastHuntSchedule()
  return huntScheduleSnapshot()
}

/** engine-side persistence for scheduled runs (works even when no browser is open) */
async function persistScanToNext(
  summary: ScanSummary,
  rangesText: string,
  label: string | null,
): Promise<string | null> {
  try {
    const res = await fetch('http://127.0.0.1:3000/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ summary, rangesText, label }),
      signal: AbortSignal.timeout(15_000),
    })
    if (!res.ok) {
      console.error('[scan-service] auto persist failed: HTTP', res.status)
      return null
    }
    const data = (await res.json()) as { scan?: { id?: string } }
    return data?.scan?.id ?? null
  } catch (e) {
    console.error('[scan-service] auto persist failed:', e)
    return null
  }
}

/** best-effort completion webhook (Telegram/Discord/generic) */
async function sendWebhook(url: string, payload: Record<string, unknown>): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8000),
    })
    return res.ok
  } catch (e) {
    console.error('[scan-service] webhook failed:', e)
    return false
  }
}

const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

function presetLabelFa(preset: string): string {
  const p = CDN_PRESETS.find((x) => x.id === preset)
  if (p) return p.nameFa
  return preset === 'custom' ? 'رنج سفارشی' : preset
}

function fmtDur(ms: number): string {
  const s = Math.round(ms / 1000)
  const m = Math.floor(s / 60)
  return m > 0 ? `${m}:${String(s % 60).padStart(2, '0')}` : `${s}s`
}

/** send an HTML message through the stored Telegram bot (returns ok + error detail) */
async function sendTelegramMessage(text: string): Promise<{ ok: boolean; status?: number; error?: string }> {
  if (!auto.telegramToken || !auto.telegramChatId) return { ok: false, error: 'not configured' }
  try {
    const res = await fetch(`https://api.telegram.org/bot${auto.telegramToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: auto.telegramChatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      }),
      signal: AbortSignal.timeout(8000),
    })
    if (!res.ok) return { ok: false, status: res.status, error: `HTTP ${res.status}` }
    const data = (await res.json().catch(() => null)) as { ok?: boolean; description?: string } | null
    if (data && data.ok === false) return { ok: false, error: data.description ?? 'telegram error' }
    return { ok: true }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) }
  }
}

/** build the Persian HTML report sent to Telegram after a scheduled scan */
function telegramAutoMessage(summary: ScanSummary): string {
  const best = summary.results[0]
  const preset = presetLabelFa(summary.config?.preset ?? '')
  const lines: string[] = [
    summary.status === 'done' ? '🟢 <b>Clean IP Scanner</b>' : '🟠 <b>Clean IP Scanner</b>',
    `📡 ${escapeHtml(preset)} — پورت ${summary.config?.port ?? 443}`,
    `✅ ${summary.results.length} IP پاک از ${summary.totalIPs} (${summary.alive} پاسخ‌گو)`,
  ]
  if (best) {
    const mbps = (best.totalSpeed ?? 0) / 1048576
    lines.push(`🏆 <code>${escapeHtml(best.ip)}</code> — ${Math.round(best.latencyMs)}ms · ${mbps.toFixed(2)} MB/s`)
  }
  lines.push(`⏱ مدت: ${fmtDur(summary.elapsedMs)}`)
  return lines.join('\n')
}

/** fire the completion webhook + Telegram notification for a finished scheduled scan */
async function notifyAutoDone(summary: ScanSummary, savedScanId: string | null): Promise<void> {
  const best = summary.results[0]
  if (auto.notifyUrl) {
    const ok = await sendWebhook(auto.notifyUrl, {
      event: 'auto-scan.completed',
      service: 'clean-ip-scanner-web',
      scanId: savedScanId,
      status: summary.status,
      startedAt: summary.startedAt,
      elapsedMs: summary.elapsedMs,
      totalIPs: summary.totalIPs,
      scanned: summary.scanned,
      alive: summary.alive,
      cleanIPs: summary.results.length,
      best: best
        ? { ip: best.ip, latencyMs: best.latencyMs, totalSpeed: best.totalSpeed ?? 0 }
        : null,
      results: summary.results.slice(0, 50),
    })
    log(
      ok ? 'success' : 'warn',
      ok
        ? `📣 اعلان وب‌هوک ارسال شد (${auto.notifyUrl})`
        : '📣 ارسال اعلان وب‌هوک ناموفق بود',
      ok
        ? `📣 Webhook notification sent (${auto.notifyUrl})`
        : '📣 Webhook notification failed',
    )
  }

  // digest mode: finished queue runs are buffered and flushed as ONE message when the batch ends
  if (summary.viaQueue && auto.telegramDigest && auto.telegramToken && auto.telegramChatId) {
    queueDigestBuffer.push({
      label: job?.queueLabel ?? presetLabelFa(summary.config?.preset ?? ''),
      ok: summary.status === 'done',
      clean: summary.results.length,
      bestIp: best?.ip,
      bestSpeedBps: best?.totalSpeed ?? 0,
      elapsedMs: summary.elapsedMs,
    })
    log('info', `📥 نتیجه صف به خلاصه تلگرام اضافه شد (${queueDigestBuffer.length} مورد)`)
    // flush when nothing is left waiting → the whole queue batch finished
    const moreWaiting = queue.some((i) => i.status === 'waiting' && i.enabled !== false)
    if (!moreWaiting) void flushQueueDigest()
    return
  }

  if (auto.telegramToken && auto.telegramChatId) {
    const tg = await sendTelegramMessage(telegramAutoMessage(summary))
    log(
      tg.ok ? 'success' : 'warn',
      tg.ok
        ? `📣 اعلان تلگرام ارسال شد (chat ${auto.telegramChatId})`
        : `📣 ارسال اعلان تلگرام ناموفق بود${tg.error ? ` — ${tg.error}` : ''}`,
      tg.ok
        ? `📣 Telegram notification sent (chat ${auto.telegramChatId})`
        : `📣 Telegram notification failed${tg.error ? ` — ${tg.error}` : ''}`,
    )
  }
}

// ---------------------------------------------- telegram digest (queue batches)
interface QueueDigestEntry {
  label: string
  ok: boolean
  clean: number
  bestIp?: string
  bestSpeedBps: number
  elapsedMs: number
}
let queueDigestBuffer: QueueDigestEntry[] = []

/** build + send ONE digest message summarising every finished queue item of the batch */
async function flushQueueDigest(): Promise<void> {
  if (!auto.telegramToken || !auto.telegramChatId) {
    queueDigestBuffer = []
    return
  }
  const entries = queueDigestBuffer
  queueDigestBuffer = []
  if (entries.length === 0) return
  const doneCount = entries.filter((e) => e.ok).length
  const totalClean = entries.reduce((a, e) => a + e.clean, 0)
  const lines: string[] = [
    '📋 <b>Clean IP Scanner — خلاصه صف اسکن</b>',
    `🔹 ${doneCount}/${entries.length} اسکن موفق · مجموعاً <b>${totalClean}</b> IP پاک`,
    '',
  ]
  for (const e of entries) {
    const speed = e.bestSpeedBps > 0 ? ` · ${(e.bestSpeedBps / 1048576).toFixed(1)} MB/s` : ''
    lines.push(
      `${e.ok ? '✅' : '⚠️'} <b>${escapeHtml(e.label)}</b> — ${e.clean} IP پاک${speed}` +
        (e.bestIp ? `\n🏆 <code>${escapeHtml(e.bestIp)}</code>` : ''),
    )
  }
  const tg = await sendTelegramMessage(lines.join('\n'))
  log(
    tg.ok ? 'success' : 'warn',
    tg.ok
      ? `📣 خلاصه تلگرام ارسال شد (${entries.length} آیتم صف)`
      : `📣 ارسال خلاصه تلگرام ناموفق بود${tg.error ? ` — ${tg.error}` : ''}`,
    tg.ok
      ? `📣 Telegram digest sent (${entries.length} queue items)`
      : `📣 Telegram digest failed${tg.error ? ` — ${tg.error}` : ''}`,
  )
}

let job: Job | null = null
const io = new Server<ClientToServerEvents, ServerToClientEvents>(createServer(), {
  path: '/',
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 60_000,
  pingInterval: 25_000,
  // bun's engine.io websocket layer hard-crashes (silent segfault) on some
  // compressed frames negotiated with browsers (permessage-deflate) —
  // reject the extension; localhost bandwidth is irrelevant anyway
  perMessageDeflate: false,
})

function log(level: ScanLogLine['level'], message: string, messageEn?: string) {
  const line: ScanLogLine = { ts: Date.now(), level, message, messageEn }
  if (job) {
    job.logs.push(line)
    if (job.logs.length > 300) job.logs.shift()
  }
  io.emit('scan:log', line)
  // mirror to stdout — engine logs were previously socket-only, which made
  // headless debugging (systemd/nohup) blind to scan activity
  console.log(`[scan:${level}] ${messageEn ?? message}`)
}

function emitProgress() {
  if (!job) return
  job.progress = {
    phase: job.phase,
    scanned: job.scanned,
    total: job.totalIPs,
    alive: job.alive,
    elapsedMs: Date.now() - job.startedAt,
    speedTested: job.speedTested,
    speedTotal: job.speedTotal,
    recentLatency: recentLatencyAvg(),
    ipsPerSecond: ipsPerSecond(),
  }
  io.emit('scan:progress', job.progress)
}

// rolling stats
let recentLatencies: number[] = []
let processedStamps: number[] = []
const recentLatencyAvg = () =>
  recentLatencies.length
    ? Math.round(recentLatencies.reduce((a, b) => a + b, 0) / recentLatencies.length)
    : 0
const ipsPerSecond = () => {
  const now = Date.now()
  processedStamps = processedStamps.filter((t) => now - t < 3000)
  return processedStamps.length >= 2
    ? Math.round((processedStamps.length / Math.min(3000, now - processedStamps[0])) * 1000)
    : 0
}

function flushAlive() {
  if (!job || job.pendingAlive.length === 0) return
  io.emit('scan:alive', job.pendingAlive.splice(0, job.pendingAlive.length))
}

async function finish(status: 'done' | 'stopped' | 'error') {
  if (!job) return
  job.phase = status === 'done' ? 'done' : status === 'stopped' ? 'stopped' : 'error'
  emitProgress()
  flushAlive()
  const summary: ScanSummary = {
    status,
    config: job.config,
    startedAt: job.startedAt,
    elapsedMs: Date.now() - job.startedAt,
    totalIPs: job.totalIPs,
    scanned: job.scanned,
    alive: job.alive,
    speedTested: job.speedTested,
    results: job.results,
    error: job.error,
    auto: job.auto ?? false,
    viaQueue: job.fromQueue ?? false,
  }
  // scheduled & queued runs persist themselves so they survive even with no browser open
  if ((job.auto || job.fromQueue) && status === 'done' && job.results.length > 0) {
    const cfg = job.config
    summary.savedScanId = await persistScanToNext(
      summary,
      cfg.customRanges ?? '',
      job.auto ? 'اسکن زمان‌بندی‌شده' : job.queueLabel ?? 'اسکن صف',
    )
    await notifyAutoDone(summary, summary.savedScanId)
  }
  // settle the queue item this run belonged to
  if (job.fromQueue && job.queueId) {
    const item = queue.find((i) => i.id === job.queueId)
    if (item) {
      item.status = status === 'done' ? 'done' : status === 'stopped' ? 'skipped' : 'error'
      item.finishedAt = Date.now()
      if (summary.savedScanId) item.savedScanId = summary.savedScanId
      item.result = {
        total: summary.totalIPs,
        alive: summary.alive,
        clean: summary.results.length,
        bestIp: summary.results[0]?.ip,
        bestSpeedBps: summary.results[0]?.totalSpeed ?? 0,
      }
    }
    currentQueueId = null
    persistQueue()
    broadcastQueueState()
    setTimeout(() => processQueue(), 1500)
  }
  job.summary = summary
  if (job.auto) {
    broadcastAutoState()
  }
  io.emit('scan:done', summary)
  log(status === 'done' ? 'success' : 'warn',
    status === 'done'
      ? `اسکن کامل شد — ${job.results.length} IP پاک پیدا شد${summary.savedScanId ? ' (ذخیره خودکار شد)' : ''}`
      : status === 'stopped'
        ? 'اسکن توسط کاربر متوقف شد'
        : `خطا: ${job.error ?? 'نامشخص'}`,
    status === 'done'
      ? `Scan finished — ${job.results.length} clean IPs found${summary.savedScanId ? ' (auto-saved)' : ''}`
      : status === 'stopped'
        ? 'Scan stopped by user'
        : `Error: ${job.error ?? 'unknown'}`)
}

async function startScan(
  raw: Partial<ScanConfig>,
  opts?: { auto?: boolean; fromQueue?: boolean; queueId?: string; queueLabel?: string },
) {
  if (job && !job.summary && job.phase !== 'error') {
    log('warn', 'یک اسکن در حال اجراست — ابتدا آن را متوقف کنید', 'A scan is already running — stop it first')
    return
  }
  const cfg = normalizeConfig(raw)
  job = {
    id: Math.random().toString(36).slice(2),
    config: cfg,
    startedAt: Date.now(),
    stopped: false,
    phase: 'generating',
    results: [],
    aliveResults: [],
    pendingAlive: [],
    logs: [],
    progress: null,
    summary: null,
    totalIPs: 0,
    scanned: 0,
    alive: 0,
    speedTested: 0,
    speedTotal: 0,
    auto: !!opts?.auto,
    fromQueue: !!opts?.fromQueue,
    queueId: opts?.queueId,
    queueLabel: opts?.queueLabel,
  }
  recentLatencies = []
  processedStamps = []

  log('info', `شروع اسکن — پورت ${cfg.port} | ${cfg.pingCount} پینگ | تایم‌اوت ${cfg.timeoutMs}ms | ${cfg.concurrency} worker`, `Scan start — port ${cfg.port} | ${cfg.pingCount} pings | timeout ${cfg.timeoutMs}ms | ${cfg.concurrency} workers`)

  try {
    // Phase 1: generating
    const rangeLines = collectRanges(cfg)
    if (rangeLines.length === 0) {
      job.error = 'هیچ رنج معتبری وارد نشده است'
      log('error', job.error, 'No valid ranges provided')
      finish('error')
      return
    }
    log('info', `در حال نمونه‌گیری ${cfg.maxIPs} IP از ${rangeLines.length} رنج CIDR...`, `Sampling ${cfg.maxIPs} IPs from ${rangeLines.length} CIDR ranges...`)
    await new Promise((r) => setTimeout(r, 30))
    const { ips, totalAvailable, skipped, cidrs } = sampleIPs(rangeLines, cfg.maxIPs)
    if (ips.length === 0) {
      job.error = 'هیچ IP معتبری از رنج‌ها تولید نشد'
      log('error', job.error, 'No valid IPs could be generated from the ranges')
      finish('error')
      return
    }
    job.totalIPs = ips.length
    log('info', `${ips.length} IP تصادفی از ${cidrs} CIDR تولید شد (فضای کل: ${totalAvailable.toLocaleString('en')} IP${skipped ? ` | ${skipped} رنج نامعتبر/بزرگ رد شد` : ''})`, `${ips.length} random IPs generated from ${cidrs} CIDRs (total space: ${totalAvailable.toLocaleString('en')} IPs${skipped ? ` | ${skipped} invalid/oversized ranges skipped` : ''})`)
    emitProgress()

    // Phase 2: ping
    job.phase = 'ping'
    log('info', `شروع تست تأخیر TCP روی پورت ${cfg.port}...`, `Starting TCP latency test on port ${cfg.port}...`)
    const aliveResults = job.aliveResults
    let idx = 0
    let lastPctEmit = 0

    const worker = async () => {
      while (!job?.stopped) {
        const my = idx
        if (my >= ips.length) return
        idx++
        const ip = ips[my]
        let recv = 0
        let totalDelay = 0
        for (let p = 0; p < cfg.pingCount; p++) {
          if (job?.stopped) return
          const ms = await tcping(ip, cfg.port, cfg.timeoutMs)
          if (ms !== null) {
            recv++
            totalDelay += ms
          }
        }
        const now = Date.now()
        processedStamps.push(now)
        if (processedStamps.length > 4096) processedStamps.splice(0, 2048)
        if (job) {
          job.scanned++
          if (recv > 0) {
            const avg = totalDelay / recv
            recentLatencies.push(avg)
            if (recentLatencies.length > 120) recentLatencies.shift()
            const lr: LiveResult = {
              ip,
              latencyMs: Math.round(avg * 10) / 10,
              sent: cfg.pingCount,
              received: recv,
              lossRate: Math.round(((cfg.pingCount - recv) / cfg.pingCount) * 100) / 100,
            }
            aliveResults.push(lr)
            job.pendingAlive.push(lr)
            job.alive = aliveResults.length
          }
        }
      }
    }

    const progressTimer = setInterval(() => {
      if (!job) return
      if (job.phase === 'ping' || job.phase === 'speed') emitProgress()
      flushAlive()
    }, 450)

    try {
      await Promise.all(Array.from({ length: cfg.concurrency }, () => worker()))
    } finally {
      clearInterval(progressTimer)
      flushAlive()
    }
    if (!job) return

    if (job.stopped && job.alive === 0) {
      finish('stopped')
      return
    }

    // select candidates: best loss first, then latency
    let candidates = [...aliveResults]
    if (cfg.maxLatencyMs > 0) {
      candidates = candidates.filter((r) => r.latencyMs <= cfg.maxLatencyMs!)
      log('info', `فیلتر تأخیر اعمال شد (≤ ${cfg.maxLatencyMs}ms): ${candidates.length} IP باقی ماند`, `Latency filter applied (≤ ${cfg.maxLatencyMs}ms): ${candidates.length} IPs left`)
    }
    candidates.sort((a, b) => a.lossRate - b.lossRate || a.latencyMs - b.latencyMs)
    candidates = candidates.slice(0, cfg.speedTestCount)
    job.speedTotal = candidates.length
    job.speedTested = 0

    if (candidates.length === 0) {
      log('warn', 'هیچ IP پاسخ‌گویی برای تست سرعت پیدا نشد', 'No responsive IPs found for speed testing')
      finish(job.stopped ? 'stopped' : 'done')
      return
    }

    // Phase 3: speed
    job.phase = 'speed'
    log('info', `شروع تست سرعت واقعی (${job.speedTotal} کاندید برتر) روی ${cfg.speedHost}...`, `Starting real speed test (${job.speedTotal} top candidates) against ${cfg.speedHost}...`)
    for (const cand of candidates) {
      if (job.stopped) break
      const dl = await downloadTest(cand.ip, cfg.port, cfg.speedHost)
      let ul = 0
      if (dl > 0 && !job.stopped) {
        ul = await uploadTest(cand.ip, cfg.port, cfg.speedHost)
      }
      const final: LiveResult = {
        ...cand,
        downloadSpeed: dl,
        uploadSpeed: ul,
        totalSpeed: dl + ul,
      }
      job.results.push(final)
      job.speedTested++
      io.emit('scan:result', final)
      log(
        dl > 0 ? 'success' : 'warn',
        dl > 0
          ? `${cand.ip} — تأخیر ${Math.round(cand.latencyMs)}ms | دانلود ${(dl / 1048576).toFixed(2)} | آپلود ${(ul / 1048576).toFixed(2)} MB/s`
          : `${cand.ip} — تأخیر ${Math.round(cand.latencyMs)}ms | تست سرعت ناموفق (احتمالاً غیر Cloudflare)`,
        dl > 0
          ? `${cand.ip} — latency ${Math.round(cand.latencyMs)}ms | DL ${(dl / 1048576).toFixed(2)} | UL ${(ul / 1048576).toFixed(2)} MB/s`
          : `${cand.ip} — latency ${Math.round(cand.latencyMs)}ms | speed test failed (probably non-Cloudflare)`,
      )
      emitProgress()
    }
    job.results.sort((a, b) => (b.totalSpeed ?? 0) - (a.totalSpeed ?? 0) || a.latencyMs - b.latencyMs)
    finish(job.stopped ? 'stopped' : 'done')
  } catch (e) {
    if (job) {
      job.error = e instanceof Error ? e.message : String(e)
      log('error', `خطای غیرمنتظره: ${job.error}`, `Unexpected error: ${job.error}`)
      finish('error')
    }
  }
}

function stopScan() {
  if (!job || job.summary) return
  job.stopped = true
  log('warn', 'درخواست توقف دریافت شد — در حال جمع‌آوری نتایج...', 'Stop requested — collecting results...')
}

// ----------------------------------------------------- xray-style tls probe
/**
 * Emulates what a proxy core (Xray/V2Ray) does when connecting through a CDN:
 *  1. TCP connect to the RAW ip (forced, no DNS)
 *  2. TLS handshake presenting the given SNI/Host
 *  3. HTTP GET / to measure TTFB and see the edge status code
 * Reports timings, TLS version/cipher/ALPN, leaf certificate details
 * (CN, issuer, expiry, whether the SAN actually covers the host) and a grade.
 * Lightweight single connection — never conflicts with a running scan.
 */
async function xrayProbe(req: XrayProbeRequest): Promise<XrayProbeResult> {
  const port = clampInt(req?.port, 1, 65535, 443)
  const host = String(req?.host ?? '').trim().replace(/^https?:\/\//i, '').split('/')[0]!.slice(0, 253) || 'speed.cloudflare.com'
  const timeoutMs = clampInt(req?.timeoutMs, 1000, 10_000, 6000)
  const base = { ip: String(req?.ip ?? ''), host, port }
  const fail = (error: string): XrayProbeResult => ({ ok: false, ...base, error, totalMs: Date.now() - t0 })
  const t0 = Date.now()
  if (net.isIP(base.ip) === 0) return fail('invalid ip')

  // 1) plain TCP timing
  const tcp = await tcping(base.ip, port, Math.min(timeoutMs, 4000))
  if (tcp === null) return fail('tcp connect failed (IP is dead or port is filtered)')
  const tcpMs = tcp

  // 2) TLS handshake with forced SNI
  const tlsStart = Date.now()
  let sock: import('node:tls').TLSSocket
  try {
    sock = await new Promise<import('node:tls').TLSSocket>((resolve, reject) => {
      const s = tls.connect(
        { host: base.ip, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs },
        () => resolve(s),
      )
      s.once('error', (e) => reject(e instanceof Error ? e : new Error(String(e))))
      s.once('timeout', () => reject(new Error('tls handshake timeout')))
    })
  } catch (e) {
    return { ...fail(`tls handshake failed: ${e instanceof Error ? e.message : 'unknown'}`), tcpMs }
  }
  const tlsMs = Date.now() - tlsStart

  // leaf certificate details
  let cert: XrayProbeResult['cert']
  try {
    const c = sock.getPeerCertificate(true)
    const daysLeft = c.valid_to ? Math.round((new Date(c.valid_to).getTime() - Date.now()) / 86_400_000) : undefined
    // subjectaltname is a string like "DNS:host, DNS:*.host" (not an array)
    const sanRaw = c.subjectaltname
    const san: string[] = (typeof sanRaw === 'string' ? sanRaw : '')
      .split(',')
      .map((x) => x.trim().replace(/^DNS:/i, ''))
      .filter(Boolean)
    const matched = san.some((h) => h === host || (h.startsWith('*.') && host.endsWith(h.slice(1))))
    cert = {
      subjectCN: c.subject?.CN,
      issuer: c.issuer?.O ?? c.issuer?.CN,
      validTo: c.valid_to,
      daysLeft,
      matched,
    }
  } catch {
    /* ignore cert parse issues */
  }

  // 3) HTTP GET for TTFB + edge status
  const httpStart = Date.now()
  const httpStatus = await new Promise<number | undefined>((resolve) => {
    let buf = ''
    let done = false
    const settle = (code?: number) => {
      if (done) return
      done = true
      clearTimeout(timer)
      try {
        sock.destroy()
      } catch {}
      resolve(code)
    }
    const timer = setTimeout(() => settle(undefined), Math.min(timeoutMs, 5000))
    sock.on('readable', function onReadable(this: import('node:tls').TLSSocket) {
      const chunk = this.read()
      if (!chunk) return
      buf += chunk.toString('latin1')
      const m = buf.match(/^HTTP\/[\d.]+ (\d{3})/)
      if (m) {
        this.removeListener('readable', onReadable)
        settle(Number(m[1]))
      }
    })
    sock.once('error', () => settle(undefined))
    sock.write(
      `GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
    )
  })
  const httpMs = httpStatus !== undefined ? Date.now() - httpStart : undefined

  // grade: handshake latency + SAN match + sane status decide
  let grade: XrayProbeResult['grade'] = 'fail'
  if (httpStatus !== undefined && httpStatus < 500) {
    grade = tlsMs < 250 ? 'excellent' : tlsMs < 700 ? 'good' : 'weak'
    if (cert?.matched === false && grade === 'excellent') grade = 'good'
  } else if (tlsMs > 0) {
    // TLS ok but no usable HTTP reply within window — still connectable
    grade = 'weak'
  }

  return {
    ok: true,
    ...base,
    tcpMs,
    tlsMs,
    httpMs,
    totalMs: Date.now() - t0,
    tlsVersion: sock.getProtocol() ?? undefined,
    cipher: sock.getCipher()?.name,
    alpn: sock.alpnProtocol || undefined,
    cert,
    httpStatus,
    grade,
  }
}

// ------------------------------------------------------- google-friendly hunter
/**
 * Fully standalone "Google IP hunter" — independent of the scan pipeline.
 *
 * ARCHITECTURE v2 — "smart funnel hunt" (replaces the flat v1 probe loop):
 *
 *   ① FUNNEL PROBE (3 stages instead of 1 expensive probe per candidate)
 *      stage A  cheap raw TCP connect (no TLS) — kills ~90% of candidates at
 *               a fraction of the CPU/time a TLS handshake would cost
 *      stage B  TLS handshake (SNI = Google host) + GET /generate_204 — only
 *               for TCP-alive candidates → healthy (2xx/3xx) / blocked (4xx5xx)
 *      stage C  VERIFICATION — every "healthy" answer must survive `verify`
 *               extra full probes (all must pass) → flaky IPs never reach the
 *               final list; each candidate carries an `attempts` count
 *
 *   ② ADAPTIVE /24 LEARNING (ε-greedy sampler)
 *      every verdict updates a per-/24 block stat (probed/healthy/blocked/dead).
 *      New candidates are sampled 30% exploration (uniform over the CIDR pool)
 *      + 70% exploitation (blocks weighted by a Bayesian-smoothed healthy rate
 *      with exhaustion decay) → the hunt concentrates on proven productive
 *      blocks wave after wave.
 *
 *   ③ PERSISTENCE
 *      - db/hunt-knowledge.json — learned block stats survive engine restarts
 *        (every new hunt starts smarter than the last)
 *      - db/hunt-history.json — last 30 finished hunts incl. their healthy IPs
 *        (served read-only by /api/hunt)
 *
 *   v5 — PARALLEL PIPELINE (barrier-free): waves are gone. A feeder streams
 *      sampled candidates into a bounded TCP channel; a breathing pool of TCP
 *      workers (stage A) forwards alive candidates into a bounded TLS channel;
 *      a second breathing pool (stages B+C) runs the TLS probe, classification
 *      and verification. Each stage owns its own ceiling (HUNT_SPEED_PRESETS:
 *      calm/normal/fast/insane) and a 1s controller grows/shrinks both pools
 *      from channel depth — no wave barrier, no idle tail, no mixed pool.
 */

/** Google frontend/edge ranges — these serve Google's own TLS endpoints */
const GOOGLE_FRONTEND_RANGES = [
  '142.250.0.0/15', '172.217.0.0/16', '216.58.192.0/19', '64.233.160.0/19',
  '108.177.0.0/17', '209.85.128.0/17', '74.125.0.0/16', '173.194.0.0/16',
  '8.8.4.0/24', '8.8.8.0/24', '8.34.208.0/20', '8.35.200.0/20',
  '64.15.112.0/20', '66.102.0.0/20', '72.14.192.0/18', '216.239.32.0/19',
]
/** Google Cloud (GCP) VM ranges — mixed in with a lower weight */
const GOOGLE_GCP_RANGES = [
  '34.0.0.0/15', '34.4.0.0/15', '34.8.0.0/15', '34.16.0.0/15', '34.24.0.0/15',
  '34.32.0.0/15', '34.48.0.0/15', '34.64.0.0/15', '34.80.0.0/15', '34.96.0.0/15',
  '34.112.0.0/15', '34.128.0.0/15', '34.148.0.0/15',
  '35.184.0.0/14', '35.188.0.0/14', '35.192.0.0/14', '35.196.0.0/14', '35.200.0.0/14',
  '35.204.0.0/14', '35.208.0.0/14', '35.216.0.0/14', '35.220.0.0/14', '35.224.0.0/14',
  '35.228.0.0/14', '35.232.0.0/14', '35.236.0.0/14', '35.240.0.0/14', '35.244.0.0/14',
]
const HUNT_HARD_CAP = 30_000
const HUNT_TIMEOUT_MS = 3500
/** stage A timeout — deliberately short, dead IPs must cost almost nothing */
const HUNT_TCP_TIMEOUT_MS = 1500
/**
 * hunt v6.4 — RST-injection forensics: per-run probe budget (every other stage-B
 * dead gets classified until the budget drains) + per-step timeout of the
 * forensics probe itself (TCP connect step and TLS handshake step each).
 */
const HUNT_FORENSICS_BUDGET = 400
const RST_FORENSICS_TIMEOUT_MS = 2000

// ---------------- hunt v5 — parallel pipeline speed presets ----------------
/**
 * Pool ceilings per stage. TCP probes are cheap (raw connect, 1.5s timeout)
 * while TLS probes are expensive (handshake + HTTP + verification) — v5 gives
 * each stage its OWN ceiling instead of one mixed worker pool.
 */
const HUNT_SPEED_PRESETS = {
  calm: { tcpMax: 128, tlsMax: 32 },
  normal: { tcpMax: 320, tlsMax: 96 },
  fast: { tcpMax: 640, tlsMax: 192 },
  insane: { tcpMax: 1024, tlsMax: 384 },
} as const
type HuntSpeedKey = keyof typeof HUNT_SPEED_PRESETS

// ---------------- hunt v5.9 — Cloudflare TLS multi-port matrix ----------------
/**
 * Cloudflare fronts HTTPS on 443 plus 2053/2083/2087/2096/8443 — when 443 is
 * throttled or interfered with, the alternates often still work. Every sampled
 * cloudflare candidate gets ONE matrix port, weighted so 443 stays dominant
 * (weight 3 vs weight 1 for each alternate).
 */
const HUNT_CF_PORTS: readonly number[] = [443, 2053, 2083, 2087, 2096, 8443]
/** weighted roulette derived from HUNT_CF_PORTS — 8 slots, 443 occupies three */
const HUNT_CF_PORT_ROULETTE: readonly number[] = [443, 443, 443, ...HUNT_CF_PORTS.slice(1)]
function pickCfPort(): number {
  return HUNT_CF_PORT_ROULETTE[Number(randBelow(8n))]!
}

// ---------------- hunt v6.1 — IPv6 anycast sampling + range checklist ----------------
/**
 * IPv6 support for the hunter: recon pulls each provider's own published v6
 * prefixes (goog.json/cloud.json ipv6Prefix, CF ips-v6, the RIPEstat v6 half)
 * and — when the run enables it — ~15% of sampled candidates are generated
 * INSIDE a random v6 prefix (anycast edge hunting: every address of the prefix
 * terminates at the same edge). v6 candidates ride the exact same TCP→TLS
 * pipeline as v4 — no special-casing beyond the flag.
 */
/** share of candidates sampled from live v6 prefixes when settings.enableV6 is on */
const HUNT_V6_SAMPLE_RATE = 0.15

// ---------------- hunt v6.0 — 'custom' provider (user-supplied CIDR ranges) ----------------
/**
 * The 4th provider has NO remote recon sources: its exploration pool is exactly
 * what the user typed into settings.customCidrs — validated + canonicalized in
 * normalizeHuntSettings, parsed ONCE per hunt into customPool (see explorePool).
 */
/** max number of user CIDR ranges per hunt (protocol contract) */
const HUNT_CUSTOM_MAX_CIDRS = 64
/** a user range may hold at most 65 536 IPs (≤ /16) */
const HUNT_CUSTOM_MAX_SIZE = 65_536n

// ---------------- adaptive knowledge: learned per-/24 stats (persisted) ----------------
interface HuntBlockStat {
  probed: number
  healthy: number
  blocked: number
  dead: number
  updatedAt: number
  /** which provider's pool this block belongs to (hunt v4; legacy = google) */
  provider?: HuntProviderId
}
const KNOWLEDGE_FILE = path.join(import.meta.dir, '..', '..', 'db', 'hunt-knowledge.json')
const HISTORY_FILE = path.join(import.meta.dir, '..', '..', 'db', 'hunt-history.json')
const KNOWLEDGE_MAX_BLOCKS = 4000
const KNOWLEDGE_SAVE_MS = 10_000
const HISTORY_MAX_RUNS = 30
/** usable IPs inside one /24 (256 minus network + broadcast) */
const BLOCK_CAPACITY = 251
/** ε — share of candidates that ignore the knowledge and explore uniformly */
const HUNT_EXPLORE_RATE = 0.3

// ============ hunt v4 — multi-provider alignment (Google · Cloudflare · ArvanCloud) ============
/**
 * The hunter is no longer locked to one vendor. Each provider declares:
 *   • its OWN authoritative range sources, pulled live at runtime
 *     (reverse-engineered intel — never a stale hardcoded list)
 *   • the exact probe that identifies a genuine, usable edge of THAT provider:
 *       google     → GET /generate_204 must answer 2xx/3xx via SNI www.google.com
 *       cloudflare → any HTTP response carrying the `server: cloudflare` header
 *                    (even a 403 from __down proves a live, routable CF front-end)
 *       arvan      → any HTTP response over TLS with SNI = the IP itself
 *                    (Arvan edges serve customer certs and do no SNI routing)
 *       custom     → the user's own ranges (settings.customCidrs); probed
 *                    SNI-less on the candidate IP like Arvan's — any HTTP
 *                    answer proves a live, routable edge inside the range
 */

interface HuntSourceDef {
  key: string
  /** sampling weight for ranges discovered through this source */
  w: number
  pull: () => Promise<string[]>
}

interface HuntProviderDef {
  id: HuntProviderId
  /** SNI host for stage B ('arvan' uses the candidate IP itself) */
  host: string
  port: number
  /** request path used for the HTTP probe */
  path: string
  /** classify a stage-B result (HTTP status + Server header) into a verdict */
  classify: (httpStatus: number, server: string) => 'healthy' | 'blocked'
  sources: HuntSourceDef[]
  /** hunt v6.1 — the same provider's published IPv6 prefixes (keys like 'goog-v6'); failing v6 sources never break the v4 pool */
  v6Sources?: HuntSourceDef[]
  /** static fallback ranges until the first successful live pull */
  fallback: string[]
}

const HUNT_PROVIDER_IDS: HuntProviderId[] = ['google', 'cloudflare', 'arvan', 'custom']

const HUNT_PROVIDERS: Record<HuntProviderId, HuntProviderDef> = {
  google: {
    id: 'google',
    host: 'www.google.com',
    port: 443,
    path: '/generate_204',
    classify: (status) => (status >= 200 && status < 400 ? 'healthy' : 'blocked'),
    sources: [
      {
        key: 'goog',
        w: 3,
        pull: async () => {
          const j = await fetchJSON<{ prefixes?: { ipv4Prefix?: unknown }[] }>('https://www.gstatic.com/ipranges/goog.json')
          return (j.prefixes ?? []).map((p) => p.ipv4Prefix).filter(isV4Cidr)
        },
      },
      {
        key: 'spf',
        w: 2,
        pull: async () => {
          const [t1, t3] = await Promise.all([dohQuery('_netblocks.google.com', 'TXT'), dohQuery('_netblocks3.google.com', 'TXT')])
          return [...t1, ...t3].flatMap((txt) => spfV4Ranges(txt))
        },
      },
      {
        key: 'cloud',
        w: 1,
        pull: async () => {
          const j = await fetchJSON<{ prefixes?: { ipv4Prefix?: unknown }[] }>('https://www.gstatic.com/ipranges/cloud.json')
          return (j.prefixes ?? []).map((p) => p.ipv4Prefix).filter(isV4Cidr)
        },
      },
    ],
    v6Sources: [
      {
        key: 'goog-v6',
        w: 3,
        // goog.json entries carry BOTH ipv4Prefix and ipv6Prefix — grab the v6 half
        pull: async () => {
          const j = await fetchJSON<{ prefixes?: { ipv6Prefix?: unknown }[] }>('https://www.gstatic.com/ipranges/goog.json')
          return (j.prefixes ?? []).map((p) => p.ipv6Prefix).filter(isV6Cidr)
        },
      },
      {
        key: 'cloud-v6',
        w: 1,
        pull: async () => {
          const j = await fetchJSON<{ prefixes?: { ipv6Prefix?: unknown }[] }>('https://www.gstatic.com/ipranges/cloud.json')
          return (j.prefixes ?? []).map((p) => p.ipv6Prefix).filter(isV6Cidr)
        },
      },
    ],
    fallback: [...GOOGLE_FRONTEND_RANGES, ...GOOGLE_GCP_RANGES],
  },
  cloudflare: {
    id: 'cloudflare',
    host: 'speed.cloudflare.com',
    port: 443,
    path: '/__down?bytes=1',
    classify: (_status, server) => (/cloudflare/i.test(server) ? 'healthy' : 'blocked'),
    sources: [
      {
        key: 'ipsv4',
        w: 3,
        pull: async () => {
          const txt = await fetchText('https://www.cloudflare.com/ips-v4')
          return txt.split(/\s+/).filter(isV4Cidr)
        },
      },
      {
        key: 'api',
        w: 2,
        pull: async () => {
          const j = await fetchJSON<{ result?: { ipv4_cidrs?: unknown[] } }>('https://api.cloudflare.com/client/v4/ips')
          return (j.result?.ipv4_cidrs ?? []).filter(isV4Cidr)
        },
      },
    ],
    v6Sources: [
      {
        key: 'cf-ips-v6',
        w: 3,
        pull: async () => {
          const txt = await fetchText('https://www.cloudflare.com/ips-v6')
          return txt.split(/\s+/).filter(isV6Cidr)
        },
      },
    ],
    fallback: [
      '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
      '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
      '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
      '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    ],
  },
  arvan: {
    id: 'arvan',
    host: '', // SNI = the candidate IP itself
    port: 443,
    path: '/',
    classify: () => 'healthy', // any HTTP answer over TLS proves a live Arvan edge
    sources: [
      {
        key: 'ripe',
        w: 3,
        // ArvanCloud publishes no official range JSON — the authoritative source is
        // what AS61173 announces on the global BGP table (RIPEstat live view)
        pull: async () => {
          const j = await fetchJSON<{ data?: { prefixes?: { prefix?: unknown }[] } }>(
            'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS61173',
          )
          return (j.data?.prefixes ?? []).map((p) => p.prefix).filter(isV4Cidr)
        },
      },
    ],
    v6Sources: [
      {
        key: 'ripe-v6',
        w: 3,
        // the SAME RIPEstat response announces v4 + v6 — the v6 halves carry '::'
        pull: async () => {
          const j = await fetchJSON<{ data?: { prefixes?: { prefix?: unknown }[] } }>(
            'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS61173',
          )
          return (j.data?.prefixes ?? []).map((p) => p.prefix).filter(isV6Cidr)
        },
      },
    ],
    fallback: [
      '5.182.44.0/24', '5.182.45.0/24', '5.182.46.0/24', '45.159.112.0/24', '45.159.113.0/24',
      '45.159.114.0/24', '45.159.115.0/24', '62.3.42.0/24', '85.208.253.0/24', '85.208.254.0/24',
      '85.208.255.0/24', '185.4.29.0/24', '185.4.30.0/24', '185.4.31.0/24', '185.50.37.0/24',
      '185.50.38.0/24', '185.50.39.0/24', '185.116.160.0/24', '185.116.161.0/24', '185.116.162.0/24',
      '185.116.163.0/24', '185.213.164.0/24', '185.213.165.0/24', '185.213.167.0/24', '185.255.88.0/24',
      '185.255.89.0/24', '185.255.90.0/24', '185.255.91.0/24', '193.141.64.0/24', '193.141.65.0/24',
      '193.141.127.0/24',
    ],
  },
  // hunt v6.0 — the 4th provider: the user's OWN ranges. No remote sources and
  // no fallback — the pool comes ONLY from settings.customCidrs (customPool).
  // `host` is the fixed v1 label shown in the UI; the actual probe runs
  // SNI-less on the candidate IP (probeHost = ip, like Arvan's).
  custom: {
    id: 'custom',
    host: 'www.cloudflare.com',
    port: 443,
    path: '/',
    // generic verdict — ANY HTTP response at all proves the edge answered
    classify: (status?: number) => (status !== undefined ? 'healthy' : 'blocked'),
    sources: [],
    fallback: [],
  },
}

function normalizeProviderSelection(raw?: string): HuntProviderSelection {
  return raw === 'google' || raw === 'cloudflare' || raw === 'arvan' || raw === 'custom' || raw === 'all'
    ? raw
    : 'all'
}

function freshPerProvider(): Record<HuntProviderId, HuntProviderStats> {
  return {
    google: { tested: 0, healthy: 0, blocked: 0, dead: 0 },
    cloudflare: { tested: 0, healthy: 0, blocked: 0, dead: 0 },
    arvan: { tested: 0, healthy: 0, blocked: 0, dead: 0 },
    custom: { tested: 0, healthy: 0, blocked: 0, dead: 0 },
  }
}

// ================= hunt recon v4 — reverse-engineering every provider's real infrastructure =================
// The hunter reads the SAME authoritative sources each provider publishes, live at
// runtime, and merges them into the sampler. Google additionally gets rDNS (PTR)
// fingerprinting — /24 blocks whose IPs resolve to *.1e100.net are Google's
// user-facing edge (exactly what the hunt wants) → those blocks get a sampling boost.

const RECON_FILE = path.join(import.meta.dir, '..', '..', 'db', 'hunt-recon.json')
const RECON_TTL_MS = 6 * 60 * 60 * 1000 // re-pull the providers' published sources every 6h
const RECON_FETCH_TIMEOUT_MS = 8000
const RECON_DOH_TIMEOUT_MS = 6000
const RECON_PTR_SAMPLE = 6 // PTR lookups per fingerprinted /24
const RECON_PTR_BUDGET = 600 // max DoH PTR queries per engine process
const RECON_PTR_TOP = 4
const RECON_PTR_CACHE_MAX = 2000
/** sampling weight per source key — user-facing edge sources rank highest */
const RECON_SOURCE_WEIGHT: Record<string, number> = { goog: 3, spf: 2, cloud: 1, ipsv4: 3, api: 2, ripe: 3 }

type ReconPtrKind = 'edge' | 'google' | 'unknown'
interface ReconPtrEntry {
  kind: ReconPtrKind
  checkedAt: number
}

interface ReconProviderState {
  status: GoogleHuntRecon['providers'][HuntProviderId]['status']
  updatedAt: number
  sources: Record<string, number>
  cidrs: number
  /** hunt v6.1 — live IPv6 prefixes merged into this provider's pool (0 = none yet / sources failed) */
  cidrsV6?: number
  /** hunt v6.1 — actual ranges for the UI checklist (v4 biggest-first, then v6; cap HUNT_RECON_RANGES_CAP) */
  ranges?: string[]
}

function freshProviderState(): ReconProviderState {
  return { status: 'idle' as const, updatedAt: 0, sources: {}, cidrs: 0 }
}

let recon: {
  status: GoogleHuntReconStatus
  updatedAt: number
  fallback: boolean
  ptr: { scanned: number; edge: number; top: string[] }
  providers: Record<HuntProviderId, ReconProviderState>
} = {
  status: 'idle',
  updatedAt: 0,
  fallback: true,
  ptr: { scanned: 0, edge: 0, top: [] },
  providers: {
    google: freshProviderState(),
    cloudflare: freshProviderState(),
    arvan: freshProviderState(),
    custom: freshProviderState(),
  },
}
let reconRefreshing = false
/** live recon ranges across all providers — replaces the static fallbacks for exploration */
let reconPool: { cidr: string; provider: HuntProviderId; source: string; r: CidrRange }[] = []
let reconPtr = new Map<string, ReconPtrEntry>()
let reconPtrBudget = RECON_PTR_BUDGET
let reconDirty = false
/** rebuilt whenever the recon pool or the provider selection changes */
let exploreCache: { pool: { r: CidrRange; w: number; provider: HuntProviderId }[]; total: bigint; stamp: string } | null = null
/** v6.0 — 'custom' provider pool: settings.customCidrs parsed ONCE per hunt (startGoogleHunt) */
let customPool: CidrRange[] = []
/**
 * hunt v6.1 — range-checklist pool: settings.selectedCidrs parsed ONCE per hunt
 * (v4 entries via parseCIDR, v6 via parseCidr6). While non-empty it REPLACES the
 * provider pool entirely (explorePool → selectedExplore); every start rebuilds it
 * from scratch, so a later hunt without selectedCidrs reverts to the normal pools.
 */
let selectedPool: { r: CidrRange; isV6: boolean; isp?: string }[] = []
/** v6.1 — prebuilt exploration pool over selectedPool (uniform w=3 like custom) so per-candidate picks stay cheap */
let selectedExplore: { pool: { r: CidrRange; w: number; provider: HuntProviderId; isp?: string }[]; total: bigint } | null = null
/**
 * hunt v6.3 — per-provider probe-target overrides for google + cloudflare
 * (host/port/path), validated + clamped in normalizeHuntSettings and set ONCE
 * per hunt (startGoogleHunt) — the same one-pool-per-run pattern as customPool
 * /selectedPool. arvan/custom never appear here (SNI-less by design).
 */
let huntOverrides: Partial<Record<HuntProviderId, HuntTargetOverride>> = {}
/** v6.1 — one live IPv6 prefix of a provider (net already masked; canonical cidr key) */
interface ReconV6Prefix {
  cidr: string
  network: bigint
  bits: number
  provider: HuntProviderId
}
let reconV6: Partial<Record<HuntProviderId, ReconV6Prefix[]>> = {}
/** v6.1 — all providers' v6 prefixes flattened for the 'all' selection (first provider wins duplicates) */
let reconV6All: ReconV6Prefix[] = []

/**
 * hunt v6.4 — rate-limit resilience observability: last-pull health per named
 * recon source. Keys are the HUNT_PROVIDERS source keys ('goog', 'spf',
 * 'cloud', 'goog-v6', 'cf-ips-v6', 'ripe', …) plus 'doh:<resolver host>' for
 * every DoH attempt and 'ptr' for the rDNS fingerprint queries. Mirrors the
 * huntKnowledge pattern — module-level Map, merged into every recon snapshot.
 */
const reconHealth = new Map<string, HuntSourceHealth>()

/** record one source-pull outcome (success clears any stale err, failure keeps ms at 0) */
function recordSourceHealth(key: string, ok: boolean, ms: number, err?: unknown): void {
  if (ok) {
    reconHealth.set(key, { ok: true, ms, at: Date.now() })
    return
  }
  let reason = err instanceof Error ? err.message : typeof err === 'string' ? err : 'failed'
  if (/abort/i.test(reason)) reason = 'abort'
  reason = reason.replace(/\s+/g, ' ').trim().slice(0, 80) || 'failed'
  reconHealth.set(key, { ok: false, ms: 0, err: reason, at: Date.now() })
}

function reconSnapshot(): GoogleHuntRecon {
  return {
    status: recon.status,
    updatedAt: recon.updatedAt,
    total: reconPool.length,
    ptr: { ...recon.ptr, top: [...recon.ptr.top] },
    fallback: recon.fallback,
    providers: {
      google: { ...recon.providers.google, sources: { ...recon.providers.google.sources } },
      cloudflare: { ...recon.providers.cloudflare, sources: { ...recon.providers.cloudflare.sources } },
      arvan: { ...recon.providers.arvan, sources: { ...recon.providers.arvan.sources } },
      custom: { ...recon.providers.custom, sources: { ...recon.providers.custom.sources } },
    },
    // hunt v6.4 — last-pull health per named source key (rate-limit resilience)
    health: Object.fromEntries(reconHealth),
  }
}

function broadcastRecon() {
  io.emit('google-hunt:recon', reconSnapshot())
}

/** top fingerprinted edge blocks (most recent first) + progress counters */
function ptrSnapshot(): GoogleHuntRecon['ptr'] {
  const top = [...reconPtr.entries()]
    .filter(([, e]) => e.kind === 'edge')
    .sort((a, b) => b[1].checkedAt - a[1].checkedAt)
    .slice(0, RECON_PTR_TOP)
    .map(([block]) => block)
  let edge = 0
  for (const e of reconPtr.values()) if (e.kind === 'edge') edge++
  return { scanned: reconPtr.size, edge, top }
}

function persistRecon(force = false) {
  if (!reconDirty && !force) return
  reconDirty = false
  try {
    fs.mkdirSync(path.dirname(RECON_FILE), { recursive: true })
    const ptr: Record<string, ReconPtrEntry> = {}
    for (const [b, e] of reconPtr) ptr[b] = e
    fs.writeFileSync(
      RECON_FILE,
      JSON.stringify({
        v: 2,
        updatedAt: recon.updatedAt,
        providers: recon.providers,
        pool: reconPool.map((p) => ({ c: p.cidr, p: p.provider, s: p.source })),
        ptr,
      }),
    )
  } catch (e) {
    console.error('[recon] persist failed:', e)
  }
}

/** restore the last recon pool + PTR fingerprints so a restarted engine hunts smart immediately */
function loadReconFile() {
  try {
    if (!fs.existsSync(RECON_FILE)) return
    const raw = JSON.parse(fs.readFileSync(RECON_FILE, 'utf8')) as {
      v?: number
      updatedAt?: number
      providers?: Record<string, Partial<ReconProviderState>>
      pool?: { c?: unknown; p?: unknown; s?: unknown }[]
      ptr?: Record<string, { kind?: unknown; checkedAt?: unknown }>
    }
    if (raw.ptr && typeof raw.ptr === 'object') {
      for (const [block, e] of Object.entries(raw.ptr).slice(0, RECON_PTR_CACHE_MAX)) {
        if (!e) continue
        if (e.kind === 'edge' || e.kind === 'google' || e.kind === 'unknown') {
          reconPtr.set(block, { kind: e.kind, checkedAt: typeof e.checkedAt === 'number' ? e.checkedAt : 0 })
        }
      }
    }
    if (raw.v === 2 && Array.isArray(raw.pool)) {
      const seen = new Set<string>()
      const pool: typeof reconPool = []
      for (const item of raw.pool.slice(0, 5000)) {
        const cidr = String(item?.c ?? '')
        const provider = item?.p
        if (seen.has(cidr)) continue
        if (provider !== 'google' && provider !== 'cloudflare' && provider !== 'arvan') continue
        const r = parseCIDR(cidr)
        if (!r || r.size > MAX_IPS_PER_CIDR) continue
        seen.add(cidr)
        pool.push({ cidr, provider, source: String(item?.s ?? 'fallback'), r })
      }
      if (pool.length > 0) {
        reconPool = pool
        for (const id of HUNT_PROVIDER_IDS) {
          const saved = raw.providers?.[id]
          if (saved && typeof saved === 'object') {
            recon.providers[id] = {
              status: saved.status === 'ready' ? 'ready' : 'idle',
              updatedAt: typeof saved.updatedAt === 'number' ? saved.updatedAt : 0,
              sources: saved.sources && typeof saved.sources === 'object' ? { ...saved.sources } : {},
              cidrs: typeof saved.cidrs === 'number' ? saved.cidrs : 0,
            }
          }
        }
        buildProviderRanges() // hunt v6.1 — rebuild the UI checklist ranges over the restored pool
        const anyReady = HUNT_PROVIDER_IDS.some((id) => recon.providers[id].status === 'ready')
        recon.status = anyReady ? 'ready' : recon.status
        recon.updatedAt = anyReady
          ? Math.max(...HUNT_PROVIDER_IDS.filter((id) => recon.providers[id].status === 'ready').map((id) => recon.providers[id].updatedAt))
          : recon.updatedAt
        recon.fallback = !anyReady
        console.log(
          `[recon] restored — ${pool.length} CIDR(s) (${HUNT_PROVIDER_IDS.map((id) => `${id} ${recon.providers[id].cidrs}`).join(' · ')}) · ${reconPtr.size} fingerprinted block(s)`,
        )
      }
    }
  } catch (e) {
    console.error('[recon] load failed:', e)
  }
}

/**
 * DNS-over-HTTPS (443-only, sandbox friendly) — hunt v6.4 resolver rotation:
 * dns.google first, cloudflare-dns.com as the fallback mirror (rate-limit /
 * outage resilience). The first NON-EMPTY answer set wins; an empty-but-valid
 * answer also rotates (a hijacked/poisoned resolver often answers 200-empty).
 * Every attempt records its health under 'doh:<resolver host>'.
 */
const DOH_RESOLVERS: { host: string; url: (name: string, type: string) => string }[] = [
  { host: 'dns.google', url: (name, type) => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}` },
  {
    host: 'cloudflare-dns.com',
    url: (name, type) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
  },
]

async function dohQuery(name: string, type: string): Promise<string[]> {
  for (const resolver of DOH_RESOLVERS) {
    const t0 = Date.now()
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), RECON_DOH_TIMEOUT_MS)
    try {
      const res = await fetch(resolver.url(name, type), {
        signal: ctrl.signal,
        headers: { accept: 'application/dns-json' },
      })
      if (!res.ok) {
        recordSourceHealth(`doh:${resolver.host}`, false, 0, `HTTP ${res.status}`)
        continue
      }
      const j = (await res.json()) as { Answer?: { data?: unknown }[] }
      const answers = (Array.isArray(j.Answer) ? j.Answer : [])
        .map((a) => (typeof a?.data === 'string' ? a.data : ''))
        .filter(Boolean)
      recordSourceHealth(`doh:${resolver.host}`, true, Date.now() - t0)
      if (answers.length > 0) return answers // first non-empty answer wins
    } catch (e) {
      recordSourceHealth(`doh:${resolver.host}`, false, 0, e instanceof Error ? e.message : e)
    } finally {
      clearTimeout(timer)
    }
  }
  return []
}

/**
 * hunt v6.4 — shared recon fetch core with ONE retry after an 800 ms backoff
 * (2 attempts total, RECON_FETCH_TIMEOUT_MS per attempt). Retries fire on
 * network errors, aborts (timeout) and HTTP ≥ 400 (429/5xx thundering-herd
 * resilience); a malformed body / bad JSON is NOT retried (the source pull
 * treats it like an empty list anyway).
 */
async function fetchResilient(url: string, accept: string): Promise<Response> {
  let lastErr: unknown = new Error('fetch failed')
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt > 0) await new Promise((wake) => setTimeout(wake, 800))
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), RECON_FETCH_TIMEOUT_MS)
    try {
      const res = await fetch(url, { signal: ctrl.signal, headers: { accept } })
      if (!res.ok) {
        lastErr = new Error(`HTTP ${res.status}`)
        try {
          await res.body?.cancel() // free the socket for the next attempt
        } catch {}
        continue
      }
      return res
    } catch (e) {
      lastErr = e
    } finally {
      clearTimeout(timer)
    }
  }
  throw lastErr
}

async function fetchJSON<T>(url: string): Promise<T> {
  const res = await fetchResilient(url, 'application/json')
  return (await res.json()) as T
}

async function fetchText(url: string): Promise<string> {
  const res = await fetchResilient(url, 'text/plain')
  return await res.text()
}

/** extract ip4:… CIDRs from an SPF record string */
function spfV4Ranges(txt: string): string[] {
  return txt
    .split(/\s+/)
    .filter((tok) => tok.startsWith('ip4:'))
    .map((tok) => tok.slice(4).trim())
    .filter((r) => /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(r))
}

function isV4Cidr(x: unknown): x is string {
  return typeof x === 'string' && /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(x) && net.isIPv4(x.split('/')[0]!)
}

/** hunt v6.1 — loose v6 CIDR shape check (full validation happens in parseCidr6) */
function isV6Cidr(x: unknown): x is string {
  if (typeof x !== 'string') return false
  const slash = x.indexOf('/')
  const base = slash >= 0 ? x.slice(0, slash) : x
  if (slash >= 0 && !/^\d{1,3}$/.test(x.slice(slash + 1))) return false
  return base.includes(':') && net.isIPv6(base)
}

// ---------------- hunt v6.1 — zero-dependency IPv6 math (BigInt based) ----------------
/** a parsed IPv6 prefix: `network` already masked to `bits` (prefix length 0..128) */
interface Parsed6 {
  network: bigint
  bits: number
}

/** parse an IPv6 CIDR ('2606:4700::/32') → {network (masked), bits}. null on any garbage. */
function parseCidr6(cidr: string): Parsed6 | null {
  const t = cidr.trim()
  if (!t) return null
  const slash = t.indexOf('/')
  const base = slash >= 0 ? t.slice(0, slash) : t
  const bits = slash >= 0 ? Number(t.slice(slash + 1)) : 128
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null
  if (!base.includes(':') || !net.isIPv6(base)) return null
  const v = ipToBigInt(base)
  if (v === null) return null
  const hostBits = BigInt(128 - bits)
  const mask = hostBits === 0n ? (1n << 128n) - 1n : ~((1n << hostBits) - 1n) & ((1n << 128n) - 1n)
  return { network: v & mask, bits }
}

/**
 * canonical RFC 5952 lowercase v6 literal — 8 hex groups without leading
 * zeros, the LONGEST run of ≥2 zero groups compressed to '::' (leftmost on tie)
 */
function formatV6(v: bigint): string {
  const g: string[] = []
  for (let s = 112n; s >= 0n; s -= 16n) g.push(((v >> s) & 0xffffn).toString(16))
  let bs = -1
  let bl = 0
  for (let i = 0; i < 8; i++) {
    if (g[i] !== '0') continue
    let j = i
    while (j < 8 && g[j] === '0') j++
    if (j - i > bl) {
      bs = i
      bl = j - i
    }
    i = j
  }
  if (bl < 2) return g.join(':')
  return `${g.slice(0, bs).join(':')}::${g.slice(bs + bl).join(':')}`
}

/** random address inside a pre-parsed v6 prefix — ALL host bits randomized (anycast edge hunting) */
function randomFromParsed6(p: Parsed6): string {
  return formatV6(p.network + randBelow(1n << BigInt(128 - p.bits)))
}

/** random address inside an IPv6 CIDR string → canonical compressed v6 literal */
function randomAddress6(prefixCidr: string): string {
  const p = parseCidr6(prefixCidr)
  return p ? randomFromParsed6(p) : ''
}

/** a Parsed6 prefix as the CidrRange shape the exploration pool consumes */
function parsed6ToRange(p: Parsed6): CidrRange {
  const size = 1n << BigInt(128 - p.bits)
  return { start: p.network, end: p.network + size - 1n, isV4: false, size, key: `${formatV6(p.network)}/${p.bits}` }
}

/**
 * hunt v6.1 — ship the UI checklist ranges per provider (recon.providers[id].ranges):
 * up to HUNT_RECON_RANGES_CAP actual CIDR strings — v4 first, biggest networks
 * first (/20 before /24), then v6 prefixes (also biggest first). 'custom' ships
 * its parsed user pool (the UI does not need it, but it keeps the snapshot
 * self-describing). Called after every reconPool/reconV6 rebuild.
 */
function buildProviderRanges(): void {
  for (const id of HUNT_PROVIDER_IDS) {
    const st = recon.providers[id]
    if (id === 'custom') {
      st.ranges = customPool.length > 0 ? customPool.slice(0, HUNT_RECON_RANGES_CAP).map((r) => r.key) : undefined
      continue
    }
    const v4 = reconPool
      .filter((p) => p.provider === id)
      .sort((a, b) => (a.r.size > b.r.size ? -1 : a.r.size < b.r.size ? 1 : 0))
      .map((p) => p.cidr)
    const v6 = (reconV6[id] ?? [])
      .slice()
      .sort((a, b) => a.bits - b.bits)
      .map((p) => p.cidr)
    const merged = [...v4, ...v6]
    st.ranges = merged.length > 0 ? merged.slice(0, HUNT_RECON_RANGES_CAP) : undefined
  }
}

/**
 * pull every provider's authoritative range sources live; rebuild the
 * exploration pool. hunt v6.1 — the providers' published IPv6 prefixes are
 * pulled in parallel (goog.json/cloud.json ipv6Prefix, CF ips-v6, the RIPEstat
 * v6 half) into reconV6/reconV6All, recon.providers[*].cidrsV6 + .sources gain
 * the v6 keys ('goog-v6', 'cloud-v6', 'cf-ips-v6', 'ripe-v6'), and
 * recon.providers[*].ranges ships the UI checklist ranges.
 */
async function refreshHuntRecon(): Promise<void> {
  if (reconRefreshing) return
  reconRefreshing = true
  recon.status = 'loading'
  // v6.0 — 'custom' has no remote pull: its status stays 'idle' (it is always
  // "ready" in the sense that its pool IS the user's settings)
  for (const id of HUNT_PROVIDER_IDS) if (id !== 'custom') recon.providers[id].status = 'loading'
  broadcastRecon()
  try {
    const per = await Promise.all(
      HUNT_PROVIDER_IDS.filter((id) => id !== 'custom').map(async (id) => {
        const def = HUNT_PROVIDERS[id]
        const seen = new Set<string>()
        const entries: { cidr: string; source: string; r: CidrRange }[] = []
        const sources: Record<string, number> = {}
        await Promise.all(
          def.sources.map(async (src) => {
            // hunt v6.4 — time every source pull and record its health
            const t0 = Date.now()
            try {
              const list = await src.pull()
              recordSourceHealth(src.key, true, Date.now() - t0)
              sources[src.key] = list.length
              for (const cidr of list) {
                if (seen.has(cidr)) continue
                const r = parseCIDR(cidr)
                if (!r || r.size > MAX_IPS_PER_CIDR) continue
                seen.add(cidr)
                entries.push({ cidr, source: src.key, r })
              }
            } catch (e) {
              recordSourceHealth(src.key, false, 0, e)
              sources[src.key] = 0
            }
          }),
        )
        // hunt v6.1 — the same providers publish IPv6 prefixes too; pull them in
        // parallel to the v4 sources. A failing v6 source NEVER breaks the v4
        // pool (v6 simply stays empty — graceful).
        const v6seen = new Set<string>()
        const v6: ReconV6Prefix[] = []
        const v6sources: Record<string, number> = {}
        await Promise.all(
          (def.v6Sources ?? []).map(async (src) => {
            // hunt v6.4 — the v6 sources ride the same health tracking
            const t0 = Date.now()
            try {
              const list = await src.pull()
              recordSourceHealth(src.key, true, Date.now() - t0)
              v6sources[src.key] = list.length
              for (const cidr of list) {
                const p6 = parseCidr6(cidr)
                if (!p6) continue
                const key = `${formatV6(p6.network)}/${p6.bits}`
                if (v6seen.has(key)) continue
                v6seen.add(key)
                v6.push({ cidr: key, network: p6.network, bits: p6.bits, provider: id })
              }
            } catch (e) {
              recordSourceHealth(src.key, false, 0, e)
              v6sources[src.key] = 0
            }
          }),
        )
        return { id, entries, sources, v6, v6sources, ok: Object.values(sources).some((n) => n > 0) }
      }),
    )

    // merge into the global pool — first provider to claim a CIDR wins (ranges are disjoint in practice)
    const globalSeen = new Set<string>()
    const pool: typeof reconPool = []
    for (const { id, entries, sources, v6, v6sources, ok } of per) {
      const st = recon.providers[id]
      // hunt v6.1 — the sources record gains the v6 source keys ('goog-v6',
      // 'cloud-v6', 'cf-ips-v6', 'ripe-v6') so the UI chip row can show them
      st.sources = { ...sources, ...v6sources }
      st.updatedAt = ok ? Date.now() : st.updatedAt
      st.status = ok ? 'ready' : 'failed'
      st.cidrs = entries.length
      st.cidrsV6 = v6.length
      for (const e of entries) {
        if (globalSeen.has(e.cidr)) continue
        globalSeen.add(e.cidr)
        pool.push({ cidr: e.cidr, provider: id, source: e.source, r: e.r })
      }
    }
    // v6.0 — 'custom' never joins the remote pool merge; its recon entry stays
    // 'idle' and its counter mirrors the last normalized settings.customCidrs
    recon.providers.custom.status = 'idle'
    recon.providers.custom.sources = {}
    recon.providers.custom.cidrs = customPool.length
    if (pool.length === 0) throw new Error('no live ranges discovered from any provider')

    reconPool = pool
    exploreCache = null // force the sampler to rebuild over the fresh ranges
    // hunt v6.1 — rebuild the per-provider v6 pools + the flattened 'all' view
    // (first provider to claim a prefix wins, mirroring the v4 global merge)
    const v6Seen = new Set<string>()
    const v6All: typeof reconV6All = []
    for (const { id, v6 } of per) {
      reconV6[id] = v6
      for (const p of v6) {
        if (v6Seen.has(p.cidr)) continue
        v6Seen.add(p.cidr)
        v6All.push(p)
      }
    }
    reconV6All = v6All
    buildProviderRanges() // v6.1 — refresh recon.providers[*].ranges for the UI checklist
    const anyReady = per.some((p) => p.ok)
    recon.status = anyReady ? 'ready' : 'failed'
    recon.updatedAt = anyReady ? Date.now() : recon.updatedAt
    recon.fallback = false
    recon.ptr = ptrSnapshot()
    reconDirty = true
    persistRecon(true)
    console.log(
      `[recon] ready — ${per
        .map(
          (p) =>
            `${p.id} ${p.entries.length}+${p.v6.length}v6 (${Object.entries({ ...p.sources, ...p.v6sources })
              .map(([k, v]) => `${k} ${v}`)
              .join(' · ')})`,
        )
        .join(' · ')} → ${pool.length} live v4 CIDR(s) + ${reconV6All.length} v6 prefix(es)`,
    )
  } catch (e) {
    recon.status = reconPool.length > 0 ? recon.status : 'failed'
    recon.fallback = reconPool.length === 0
    console.error('[recon] refresh failed:', e instanceof Error ? e.message : e)
  } finally {
    reconRefreshing = false
    broadcastRecon()
  }
}

/**
 * rDNS fingerprint of one /24 — sample a few IPs and resolve PTR via DoH.
 * `*.1e100.net` = Google's user-facing edge (the prime hunting ground);
 * other google-ish PTRs = Google-owned but not necessarily edge.
 */
async function fingerprintBlock(block: string): Promise<void> {
  if (reconPtrBudget <= 0 || reconPtr.has(block)) return
  const parts = block.split('.')
  if (parts.length !== 4 || parts[3] !== '0/24') return
  // reserve synchronously so concurrent waves never double-query the same block
  reconPtr.set(block, { kind: 'unknown', checkedAt: Date.now() })
  reconPtrBudget -= RECON_PTR_SAMPLE
  try {
    const sampled = new Set<number>()
    while (sampled.size < RECON_PTR_SAMPLE) sampled.add(1 + Math.floor(Math.random() * 254))
    const ptrT0 = Date.now()
    const answers = await Promise.all(
      [...sampled].map(async (last) => {
        const name = `${last}.${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa`
        return (await dohQuery(name, 'PTR')).join(' ').toLowerCase()
      }),
    )
    const joined = answers.join(' ')
    // hunt v6.4 — PTR block fingerprint health (any resolved name proves the path works)
    recordSourceHealth('ptr', joined.length > 0, Date.now() - ptrT0, joined.length > 0 ? undefined : 'no answers')
    let kind: ReconPtrKind = 'unknown'
    if (joined.includes('.1e100.net')) kind = 'edge'
    else if (joined.includes('google')) kind = 'google'
    reconPtr.set(block, { kind, checkedAt: Date.now() })
    if (reconPtr.size > RECON_PTR_CACHE_MAX) {
      // drop the oldest unknown entries first
      const entries = [...reconPtr.entries()]
        .sort((a, b) => Number(b[1].kind === 'unknown') - Number(a[1].kind === 'unknown') || a[1].checkedAt - b[1].checkedAt)
        .slice(0, RECON_PTR_CACHE_MAX)
      reconPtr = new Map(entries)
    }
    if (kind !== 'unknown') {
      recon.ptr = ptrSnapshot()
      reconDirty = true
      persistRecon()
      broadcastRecon()
      if (kind === 'edge') console.log(`[recon] ptr — ${block} is Google EDGE (1e100.net) 🎯`)
    }
  } catch {
    /* fingerprinting is best-effort — never break sampling */
  }
}

/** ptr kind of a block, for hot-block tagging */
function ptrKindOf(block: string): ReconPtrKind | null {
  return reconPtr.get(block)?.kind ?? null
}

let huntKnowledge = new Map<string, HuntBlockStat>()
let knowledgeDirty = false
let knowledgeLastSave = 0

/**
 * /24 knowledge key of an IPv4 candidate. hunt v6.1 — IPv6 candidates have no
 * /24 blocks (and no PTR fingerprinting concept): they return null and every
 * caller (block learning, PTR lookup, hot blocks, sampling boost) skips them
 * instead of mis-keying or crashing.
 */
function blockKeyOf(ip: string): string | null {
  const p = ip.split('.')
  return p.length === 4 ? `${p[0]}.${p[1]}.${p[2]}.0/24` : null
}

function loadHuntKnowledge() {
  try {
    if (!fs.existsSync(KNOWLEDGE_FILE)) return
    const raw = JSON.parse(fs.readFileSync(KNOWLEDGE_FILE, 'utf8')) as {
      v?: number
      blocks?: Record<string, Partial<HuntBlockStat>>
    }
    if (!raw || typeof raw !== 'object' || !raw.blocks) return
    for (const [block, s] of Object.entries(raw.blocks).slice(0, KNOWLEDGE_MAX_BLOCKS)) {
      if (!s || typeof s.probed !== 'number' || s.probed <= 0) continue
      huntKnowledge.set(block, {
        probed: Math.min(s.probed, 1_000_000),
        healthy: Math.max(0, Math.min(s.healthy ?? 0, s.probed)),
        blocked: Math.max(0, s.blocked ?? 0),
        dead: Math.max(0, s.dead ?? 0),
        updatedAt: typeof s.updatedAt === 'number' ? s.updatedAt : 0,
        // v2 knowledge was google-only; only trust exact provider ids
        provider:
          s.provider === 'cloudflare' || s.provider === 'arvan' || s.provider === 'custom'
            ? s.provider
            : 'google',
      })
    }
    console.log(`[google-hunt] knowledge restored — ${huntKnowledge.size} learned /24 block(s)`)
  } catch (e) {
    console.error('[google-hunt] knowledge load failed:', e)
  }
}

function persistHuntKnowledge(force = false) {
  if (!knowledgeDirty) return
  const now = Date.now()
  if (!force && now - knowledgeLastSave < KNOWLEDGE_SAVE_MS) return
  knowledgeLastSave = now
  knowledgeDirty = false
  try {
    fs.mkdirSync(path.dirname(KNOWLEDGE_FILE), { recursive: true })
    // cap the file — keep the most-probed blocks only
    const entries = [...huntKnowledge.entries()]
      .sort((a, b) => b[1].probed - a[1].probed)
      .slice(0, KNOWLEDGE_MAX_BLOCKS)
    huntKnowledge = new Map(entries)
    const blocks: Record<string, HuntBlockStat> = {}
    for (const [block, s] of huntKnowledge) blocks[block] = { ...s, provider: s.provider ?? 'google' }
    fs.writeFileSync(KNOWLEDGE_FILE, JSON.stringify({ v: 3, blocks }))
  } catch (e) {
    console.error('[google-hunt] knowledge persist failed:', e)
  }
}

/**
 * Bayesian-smoothed healthy rate (0..1) with exhaustion decay.
 * An unknown block scores ≈0.03 — the real-world base healthy rate — so
 * blocks only outrank exploration once they EARN it; blocks where ~all 251
 * usable IPs were already probed decay to ~0 so we never hammer a dry well.
 */
function blockScore(s: HuntBlockStat): number {
  const rate = (s.healthy + 0.6) / (s.probed + 20)
  const exhaustion = s.probed >= BLOCK_CAPACITY ? 0.02 : s.probed >= 200 ? 0.15 : 1
  return rate * exhaustion
}

function recordBlockVerdict(ip: string, verdict: 'healthy' | 'blocked' | 'dead', provider: HuntProviderId) {
  const key = blockKeyOf(ip)
  if (!key) return // hunt v6.1 — v6 candidates never enter /24 block learning
  let s = huntKnowledge.get(key)
  if (!s) {
    s = { probed: 0, healthy: 0, blocked: 0, dead: 0, updatedAt: 0, provider }
    huntKnowledge.set(key, s)
  }
  if (!s.provider) s.provider = provider
  s.probed++
  if (verdict === 'healthy') s.healthy++
  else if (verdict === 'blocked') s.blocked++
  else s.dead++
  s.updatedAt = Date.now()
  knowledgeDirty = true
}

/** top learned blocks for the live UI (only blocks that actually produced healthy IPs) */
function topHuntBlocks(n: number): GoogleHuntBlockStat[] {
  const arr: GoogleHuntBlockStat[] = []
  for (const [block, s] of huntKnowledge) {
    if (s.probed <= 0 || s.healthy <= 0) continue
    const kind = ptrKindOf(block)
    arr.push({ block, probed: s.probed, healthy: s.healthy, score: blockScore(s), ptr: kind === 'unknown' ? null : kind })
  }
  // edge-fingerprinted blocks (rDNS = 1e100.net) are prime hunting ground — surface them first
  arr.sort((a, b) => Number(b.ptr === 'edge') - Number(a.ptr === 'edge') || b.score - a.score || b.healthy - a.healthy)
  return arr.slice(0, n)
}

function persistHuntHistory(st: GoogleHuntState) {
  if (st.tested <= 0) return
  try {
    fs.mkdirSync(path.dirname(HISTORY_FILE), { recursive: true })
    let runs: GoogleHuntHistoryRun[] = []
    try {
      const raw = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'))
      if (Array.isArray(raw)) runs = raw.slice(0, HISTORY_MAX_RUNS)
    } catch {}
    runs.unshift({
      id: `hunt-${st.startedAt ?? Date.now()}`,
      startedAt: st.startedAt ?? Date.now(),
      finishedAt: Date.now(),
      target: st.target,
      stopped: st.stopped,
      host: st.host,
      port: st.port,
      tested: st.tested,
      healthy: st.healthy,
      blocked: st.blocked,
      dead: st.dead,
      tcpAlive: st.tcpAlive,
      verify: st.verify,
      healthyIps: st.healthyIps.slice(0, 100),
      provider: st.provider,
      perProvider: st.perProvider,
      // v7.0 — scheduler-triggered runs are marked in the persisted history
      auto: st.auto === true,
    })
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(runs.slice(0, HISTORY_MAX_RUNS)))
  } catch (e) {
    console.error('[google-hunt] history persist failed:', e)
  }
}

interface HuntRuntime {
  state: GoogleHuntState
  settings: ReturnType<typeof normalizeHuntSettings>
  stopFlag: boolean
  stamps: number[]
  /** every candidate this run already consumed (cross-wave dedupe) */
  tried: Set<string>
  /** hunt v6.4 — remaining RST-forensics probe budget (reset at hunt start) */
  forensicsBudget: number
}

let hunt: HuntRuntime | null = null

function huntSnapshot(): GoogleHuntState | null {
  if (!hunt) return null
  return {
    ...hunt.state,
    healthyIps: [...hunt.state.healthyIps],
    recent: [...hunt.state.recent],
    hotBlocks: topHuntBlocks(6),
  }
}

function broadcastHunt() {
  const s = huntSnapshot()
  if (s) io.emit('google-hunt:state', s)
}

function normalizeHuntSettings(raw?: Partial<GoogleHuntSettings>) {
  // v5 — the speed preset picks the TCP/TLS pool ceilings. Backward compat:
  // an old client that explicitly sent `concurrency` (no `speed`) still gets a
  // pool derived from that value; `concurrency` stays exposed as the TCP ceiling.
  const speed: HuntSpeedKey =
    raw?.speed && raw.speed in HUNT_SPEED_PRESETS ? (raw.speed as HuntSpeedKey) : 'normal'
  const preset = HUNT_SPEED_PRESETS[speed]
  const legacyConcurrency =
    raw?.speed === undefined && raw?.concurrency !== undefined
      ? clampInt(raw.concurrency, 32, 1024, preset.tcpMax)
      : null
  const tcpPoolMax = legacyConcurrency ?? preset.tcpMax
  const tlsPoolMax = legacyConcurrency !== null ? clampInt(Math.round(tcpPoolMax * 0.3), 16, 384, preset.tlsMax) : preset.tlsMax
  // hunt v6.0 — 'custom' provider ranges: user-supplied IPv4 CIDRs. Validate hard:
  // each entry must parse via parseCIDR, be IPv4 and hold ≤ 65 536 IPs (≤ /16);
  // deduped, capped at HUNT_CUSTOM_MAX_CIDRS, stored as canonical 'a.b.c.d/p'.
  const customSeen = new Set<string>()
  const customCidrs: string[] = []
  if (Array.isArray(raw?.customCidrs)) {
    for (const entry of (raw.customCidrs as unknown[]).slice(0, 256)) {
      if (typeof entry !== 'string') continue
      const r = parseCIDR(entry.trim())
      if (!r || !r.isV4 || r.size > HUNT_CUSTOM_MAX_SIZE || r.size > MAX_IPS_PER_CIDR) continue
      if (customSeen.has(r.key)) continue
      customSeen.add(r.key)
      customCidrs.push(r.key)
      if (customCidrs.length >= HUNT_CUSTOM_MAX_CIDRS) break
    }
  }
  // hunt v6.1 — range-checklist allow-list (selectedCidrs): v4 entries must
  // parse via parseCIDR (IPv4 only), v6 entries via parseCidr6; canonically
  // deduped and capped at HUNT_SELECTED_MAX_CIDRS. Non-empty ⇒ the hunt runs
  // ONLY these ranges (explorePool swaps the provider pool for selectedPool).
  const selectedSeen = new Set<string>()
  const selectedCidrs: string[] = []
  // v7.0 — parallel ISP source labels: labels[i] annotates selectedCidrs[i].
  // Only 'AS<digits>' strings are accepted; anything else (or a missing/short
  // raw array) stores '' = unlabelled. Both arrays stay EXACTLY aligned — one
  // label consumed per ACCEPTED (canonical, deduped) cidr — so legacy payloads
  // without labels degrade to an all-'' array (zero behavior change).
  const selectedLabels: string[] = []
  const rawLabels = Array.isArray(raw?.selectedLabels) ? (raw.selectedLabels as unknown[]) : null
  let labelCursor = 0
  const AS_LABEL_RE = /^AS\d{1,10}$/
  const pushSelected = (key: string) => {
    selectedSeen.add(key)
    selectedCidrs.push(key)
    let lab = ''
    const rl = rawLabels ? rawLabels[labelCursor] : undefined
    if (typeof rl === 'string') {
      const t = rl.trim()
      if (AS_LABEL_RE.test(t)) lab = t
    }
    labelCursor++
    selectedLabels.push(lab)
  }
  if (Array.isArray(raw?.selectedCidrs)) {
    for (const entry of (raw.selectedCidrs as unknown[]).slice(0, HUNT_SELECTED_MAX_CIDRS * 2)) {
      if (typeof entry !== 'string') continue
      const t = entry.trim()
      if (!t) continue
      if (t.includes(':')) {
        const p6 = parseCidr6(t)
        if (!p6) continue
        const key = `${formatV6(p6.network)}/${p6.bits}`
        if (selectedSeen.has(key)) continue
        pushSelected(key)
      } else {
        const r = parseCIDR(t)
        if (!r || !r.isV4 || r.size > MAX_IPS_PER_CIDR) continue
        if (selectedSeen.has(r.key)) continue
        pushSelected(r.key)
      }
      if (selectedCidrs.length >= HUNT_SELECTED_MAX_CIDRS) break
    }
  }
  // hunt v6.3 — per-provider probe-target overrides. Only 'google' and
  // 'cloudflare' are honored: arvan + custom are probed SNI-less on the IP by
  // design, so their entries are dropped entirely. Every field is validated
  // independently (bad field ⇒ dropped; absent/legacy payload ⇒ empty map ⇒
  // zero behavior change):
  //   host → hostname-ish, 1..253 chars, ≥1 dot (or exactly 'localhost')
  //   port → integer 1..65535
  //   path → starts with '/', ≤256 chars
  const providerOverrides: Partial<Record<HuntProviderId, HuntTargetOverride>> = {}
  if (raw?.providerOverrides && typeof raw.providerOverrides === 'object') {
    const rawOv = raw.providerOverrides as Record<string, unknown>
    const HOST_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i
    for (const id of ['google', 'cloudflare'] as const) {
      const o = rawOv[id]
      if (!o || typeof o !== 'object') continue
      const rec = o as Record<string, unknown>
      const ov: HuntTargetOverride = {}
      if (typeof rec.host === 'string') {
        const h = rec.host.trim()
        if (h.length >= 1 && h.length <= 253 && HOST_RE.test(h) && (h.includes('.') || h.toLowerCase() === 'localhost')) {
          ov.host = h
        }
      }
      if (typeof rec.port === 'number' && Number.isInteger(rec.port) && rec.port >= 1 && rec.port <= 65535) {
        ov.port = rec.port
      }
      if (typeof rec.path === 'string') {
        const p = rec.path.trim()
        if (p.startsWith('/') && p.length <= 256) ov.path = p
      }
      if (ov.host !== undefined || ov.port !== undefined || ov.path !== undefined) providerOverrides[id] = ov
    }
  }
  return {
    target: clampInt(raw?.target, 1, 100, 10),
    // hunt v6.4 — RST-injection forensics ships ON (absent/legacy payload ⇒ true;
    // only an explicit false turns it off)
    forensics: raw?.forensics !== false,
    batchSize: clampInt(raw?.batchSize, 500, 10_000, 3000),
    concurrency: tcpPoolMax,
    verify: clampInt(raw?.verify, 0, 3, 1),
    provider: normalizeProviderSelection(raw?.provider),
    speed,
    tcpPoolMax,
    tlsPoolMax,
    customCidrs,
    enableV6: raw?.enableV6 === true,
    selectedCidrs,
    selectedLabels,
    providerOverrides,
    hardCap: HUNT_HARD_CAP,
  }
}

// ---------------- hunt v5 — bounded async channel (pipeline plumbing) ----------------
/**
 * Minimal typed async queue with backpressure:
 *   • push()  awaits while the channel is full (producer paces itself) and
 *             returns false when the channel is closed or the run stopped
 *             (the caller simply drops the item)
 *   • pull()  awaits while empty and resolves null once closed AND drained
 *             (or the run stopped) — the worker exits
 *   • close() releases every waiter, wakeAll() is the stop-safety hatch so
 *             nothing can ever hang on a flipped stopFlag
 * The two pipeline stages communicate through these instead of a wave barrier.
 */
class BoundedChannel<T> {
  private buf: T[] = []
  private consumers: (() => void)[] = []
  private producers: (() => void)[] = []
  private closed = false
  constructor(private readonly capacity: number) {}
  /** items currently buffered */
  get depth(): number {
    return this.buf.length
  }
  /** producer side — awaits while full; false ⇒ closed/stopped, drop the item */
  async push(item: T, stopped: () => boolean): Promise<boolean> {
    while (!this.closed && !stopped() && this.buf.length >= this.capacity) {
      await new Promise<void>((wake) => this.producers.push(wake))
    }
    if (this.closed || stopped()) return false
    this.buf.push(item)
    this.wakeOne(this.consumers)
    return true
  }
  /** consumer side — null ⇒ closed and drained (or stopped): exit now */
  async pull(stopped: () => boolean): Promise<T | null> {
    for (;;) {
      const item = this.buf.shift()
      if (item !== undefined) {
        this.wakeOne(this.producers)
        return item
      }
      if (this.closed || stopped()) return null
      await new Promise<void>((wake) => this.consumers.push(wake))
    }
  }
  /** release every parked waiter (close / stop safety) */
  wakeAll(): void {
    this.release(this.consumers)
    this.release(this.producers)
  }
  /** no more items will ever arrive */
  close(): void {
    this.closed = true
    this.wakeAll()
  }
  private wakeOne(q: (() => void)[]): void {
    q.shift()?.()
  }
  private release(q: (() => void)[]): void {
    const ws = q.splice(0, q.length)
    for (const w of ws) w()
  }
}

/** v5 — initial pool size: half the ceiling, clamped to sane minimums */
const initialTcpWorkers = (tcpMax: number) => Math.min(tcpMax, Math.max(32, Math.ceil(tcpMax / 2)))
const initialTlsWorkers = (tlsMax: number) => Math.min(tlsMax, Math.max(8, Math.ceil(tlsMax / 2)))

// ---------------- v4 exploration pool: per-provider recon ranges (fallback = static) ----------------

/**
 * The exploration pool for a provider selection. When recon has live data
 * (each provider's own published sources) it completely replaces the static
 * fallbacks — fresh, authoritative, and it rotates whenever a provider
 * rotates its ranges.
 */
function explorePool(sel: HuntProviderSelection): { pool: { r: CidrRange; w: number; provider: HuntProviderId }[]; total: bigint } {
  // hunt v6.1 — the user's range checklist (selectedCidrs) replaces the provider
  // pool ENTIRELY for this run: v4+v6 mixed, uniform weight (w=3 like custom),
  // for EVERY provider selection. With provider 'all' the pipeline probes run
  // custom-style (SNI-less on the IP, any-HTTP=healthy) because range ownership
  // is ambiguous → the pool entries are internally labelled 'custom'.
  if (selectedExplore && selectedExplore.pool.length > 0) {
    return { pool: selectedExplore.pool, total: selectedExplore.total }
  }
  // hunt v6.0 — the 'custom' provider is fed ONLY by the user's ranges
  // (settings.customCidrs parsed once per hunt into customPool). It never
  // touches the recon pool, so custom ranges can never leak into 'all'.
  if (sel === 'custom') {
    const pool = customPool.map((r) => ({ r, w: 3, provider: 'custom' as const }))
    return { pool, total: pool.reduce((acc, p) => acc + BigInt(p.w) * p.r.size, 0n) }
  }
  if (reconPool.length === 0) {
    // static fallbacks — only used until the first successful recon pull
    const ids = sel === 'all' ? HUNT_PROVIDER_IDS : [sel]
    const pool: { r: CidrRange; w: number; provider: HuntProviderId }[] = []
    for (const id of ids) {
      for (const l of HUNT_PROVIDERS[id].fallback) {
        const c = parseCIDR(l)
        if (c && c.size <= MAX_IPS_PER_CIDR) pool.push({ r: c, w: 3, provider: id })
      }
    }
    return { pool, total: pool.reduce((acc, p) => acc + BigInt(p.w) * p.r.size, 0n) }
  }
  const stamp = `${recon.updatedAt}:${sel}`
  if (!exploreCache || exploreCache.stamp !== stamp) {
    const filtered = sel === 'all' ? reconPool : reconPool.filter((p) => p.provider === sel)
    const pool = filtered.map((p) => ({ r: p.r, w: RECON_SOURCE_WEIGHT[p.source] ?? 2, provider: p.provider }))
    exploreCache = { pool, total: pool.reduce((acc, p) => acc + BigInt(p.w) * p.r.size, 0n), stamp }
  }
  return { pool: exploreCache.pool, total: exploreCache.total }
}

function pickFromRangePool(sel: HuntProviderSelection): { ip: string; provider: HuntProviderId; v6?: boolean; isp?: string } | null {
  const { pool, total } = explorePool(sel)
  if (pool.length === 0 || total <= 0n) return null
  // hunt v6.1 fix — a mixed v4+v6 pool (selectedCidrs checklist) must be sampled
  // PER-RANGE uniformly: size-proportional weighting lets one /32 v6 range
  // (2^96 addresses) mathematically drown every ticked /20 v4 range (2^12 —
  // v4 share of the universe ≈ 0.00003%). A checklist is an explicit
  // allow-list: each ticked range earns an equal share of the candidates.
  // The recon pool (v4-only) keeps its size-proportional roll.
  const selectedActive = selectedExplore !== null && selectedExplore.pool.length > 0
  let entry: { r: CidrRange; w: number; provider: HuntProviderId; isp?: string }
  if (selectedActive) {
    entry = pool[Number(randBelow(BigInt(pool.length)))]
  } else {
    let pick = randBelow(total)
    entry = pool[pool.length - 1]
    for (const p of pool) {
      const w = BigInt(p.w) * p.r.size
      if (pick < w) {
        entry = p
        break
      }
      pick -= w
    }
  }
  const v = entry.r.start + randBelow(entry.r.size)
  // hunt v6.1 — v6 ranges only enter the pool through selectedPool (the
  // recon pool stays IPv4-only); generate the canonical compressed literal
  // v7.0 — a labelled selectedCidrs entry rides its ISP label onto the candidate
  if (entry.r.isV4) return { ip: bigIntToIP(v, true), provider: entry.provider, ...(entry.isp ? { isp: entry.isp } : {}) }
  return { ip: formatV6(v), provider: entry.provider, v6: true, ...(entry.isp ? { isp: entry.isp } : {}) }
}

/**
 * hunt v6.1 — one random address inside a random live v6 prefix of the active
 * selection ('all' merges every provider's pool; a single provider uses its
 * own). Returns null when the selection has no v6 prefixes (the sampler then
 * falls through to the v4 paths — enableV6 stays graceful without live v6).
 */
function pickFromV6Pool(sel: HuntProviderSelection): { ip: string; provider: HuntProviderId; v6: true } | null {
  const pool = sel === 'all' ? reconV6All : reconV6[sel]
  if (!pool || pool.length === 0) return null
  const p = pool[Number(randBelow(BigInt(pool.length)))]
  if (!p) return null
  return { ip: randomFromParsed6(p), provider: sel === 'all' ? p.provider : sel, v6: true }
}

/** exploitation cache — known productive blocks, rebuilt every few seconds */
let exploitCache: { blocks: string[]; providers: HuntProviderId[]; weights: number[]; total: number; builtAt: number; sel: string } | null = null

function pickFromKnowledge(sel: HuntProviderSelection): { ip: string; provider: HuntProviderId } | null {
  const now = Date.now()
  if (!exploitCache || now - exploitCache.builtAt > 5000 || exploitCache.sel !== sel) {
    const blocks: string[] = []
    const providers: HuntProviderId[] = []
    const weights: number[] = []
    let total = 0
    for (const [block, s] of huntKnowledge) {
      if (s.probed <= 0 || s.probed >= BLOCK_CAPACITY) continue
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.0\/24$/.test(block)) continue // v6.1 — knowledge is /24-v4 only (belt & braces)
      const prov = s.provider ?? 'google'
      if (sel !== 'all' && prov !== sel) continue
      // recon boost — blocks rDNS-verified as Google edge (1e100.net) are prime targets
      const boost = reconPtr.get(block)?.kind === 'edge' ? 2 : 1
      const w = blockScore(s) * boost
      if (w <= 0) continue
      blocks.push(block)
      providers.push(prov)
      weights.push(w)
      total += w
    }
    exploitCache = { blocks, providers, weights, total, builtAt: now, sel }
  }
  const c = exploitCache
  if (!c || c.blocks.length === 0 || c.total <= 0) return null
  let pick = Math.random() * c.total
  for (let i = 0; i < c.blocks.length; i++) {
    pick -= c.weights[i]!
    if (pick <= 0) {
      // random usable host inside the chosen /24
      const base = c.blocks[i]!.split('.').slice(0, 3).join('.')
      const last = 1 + Math.floor(Math.random() * 254)
      return { ip: `${base}.${last}`, provider: c.providers[i] ?? 'google' }
    }
  }
  return null
}

/**
 * v4 sampler — 30% exploration (per-provider reverse-engineered recon ranges)
 * + 70% exploitation of learned productive blocks (once any knowledge exists
 * for the selected provider), deduped across waves. Every fresh exploration IP
 * lazily rDNS-fingerprints its /24 (PTR budget-capped, Google edge only).
 * v5.9 — each candidate also carries the port it will be probed on
 * (cloudflare rotates its TLS port matrix, everyone else uses their def port).
 * v6.0 — the 'custom' provider explores the user's own ranges (customPool) and
 * skips PTR fingerprinting (a Google-edge concept) to save the DoH budget.
 * v6.1 — with settings.enableV6, ~15% of candidates (HUNT_V6_SAMPLE_RATE) are
 * generated inside a random live v6 prefix (anycast edge hunting; state
 * .v6Sampled counts them). A non-empty selectedCidrs checklist replaces the
 * provider pool entirely (selectedExplore) and marks every candidate .selected
 * (state.fromSelected); its v6 entries are hunted as-is and /24 knowledge is
 * bypassed so learned blocks can never leak across the allow-list.
 */
function sampleHuntIPs(
  n: number,
  tried: Set<string>,
  sel: HuntProviderSelection,
  enableV6: boolean,
): { ip: string; provider: HuntProviderId; port: number; v6?: boolean; selected?: boolean; isp?: string }[] {
  const selectedActive = selectedExplore !== null && selectedExplore.pool.length > 0
  // hunt v6.1 — only the PROVIDER pools roll the 15% v6 dice: an active
  // selectedCidrs checklist is a strict allow-list (its own v6 entries flow
  // through the selected pool instead) and 'custom' has no v6 source.
  const v6Rollable =
    enableV6 && !selectedActive && (sel === 'all' ? reconV6All.length > 0 : (reconV6[sel]?.length ?? 0) > 0)
  const picked = new Map<string, { provider: HuntProviderId; v6?: boolean; selected?: boolean; isp?: string }>()
  let knowledgeReady = false
  // hunt v6.1 — learned /24 blocks may point OUTSIDE the selected ranges, so
  // exploitation stays off for checklist runs (pure allow-list exploration)
  if (!selectedActive) {
    for (const s of huntKnowledge.values()) {
      if (s.probed > 0 && s.healthy > 0 && (sel === 'all' || (s.provider ?? 'google') === sel)) {
        knowledgeReady = true
        break
      }
    }
  }
  let guard = 0
  while (picked.size < n && guard < n * 20 + 500) {
    guard++
    let cand: { ip: string; provider: HuntProviderId; v6?: boolean; selected?: boolean; isp?: string } | null = null
    let fromExplore = false
    if (v6Rollable && Math.random() < HUNT_V6_SAMPLE_RATE) {
      cand = pickFromV6Pool(sel)
    }
    if (!cand && !selectedActive) {
      if (knowledgeReady && Math.random() >= HUNT_EXPLORE_RATE) cand = pickFromKnowledge(sel)
    }
    if (!cand) {
      cand = pickFromRangePool(sel)
      fromExplore = cand !== null
    }
    if (!cand || tried.has(cand.ip)) continue
    if (selectedActive) cand.selected = true
    picked.set(cand.ip, cand)
    // v6.0 — custom-range candidates skip PTR fingerprinting so a custom hunt
    // never burns the shared DoH PTR budget that Google hunting depends on
    // v6.1 — v6 candidates have no /24 block either (blockKeyOf returns null)
    const bk = fromExplore ? blockKeyOf(cand.ip) : null
    if (bk && cand.provider !== 'custom') void fingerprintBlock(bk)
  }
  for (const ip of picked.keys()) tried.add(ip)
  // port assignment happens HERE (not in pickFromKnowledge/pickFromRangePool)
  // so the ip-only dedupe map stays unchanged
  return [...picked.entries()].map(([ip, m]) => ({
    ip,
    provider: m.provider,
    // v6.3 — a per-provider port override replaces the provider default AND
    // the cloudflare TLS-port rotation for that run; without one, v5.9 rules
    port:
      huntOverrides[m.provider]?.port ??
      (m.provider === 'cloudflare' ? pickCfPort() : HUNT_PROVIDERS[m.provider].port),
    ...(m.v6 ? { v6: true } : {}),
    ...(m.selected ? { selected: true } : {}),
    ...(m.isp ? { isp: m.isp } : {}),
  }))
}

/**
 * hunt v6.3 — single resolution point for a candidate's probe target, shared
 * by stage A (display host) and stages B+C (SNI host + HTTP path):
 *   • arvan / custom stay SNI-less — the candidate IP itself is the host
 *     (v6.0 rule; overrides are deliberately ignored for these providers)
 *   • google / cloudflare honor this run's per-provider host/path override
 *     (huntOverrides) when present, else the provider default
 * The port override is applied earlier, at candidate build (sampleHuntIPs).
 */
function resolveProbeTarget(provider: HuntProviderId, ip: string, def: HuntProviderDef): { host: string; path: string } {
  if (provider === 'arvan' || provider === 'custom') return { host: ip, path: def.path }
  const o = huntOverrides[provider]
  return { host: o?.host ?? def.host, path: o?.path ?? def.path }
}

/**
 * stage B — TLS handshake (SNI = the provider host) + HTTP GET on the
 * provider's probe path. Stage A (raw TCP) already passed, so no TCP step here.
 * Returns the raw result (status + Server header) — the provider's classify()
 * turns it into a verdict (see HUNT_PROVIDERS).
 */
async function tlsHttpProbe(
  ip: string,
  port: number,
  host: string,
  timeoutMs: number,
  path: string,
): Promise<{ httpStatus?: number; tlsMs?: number; server?: string }> {
  const tlsStart = Date.now()
  let sock: import('node:tls').TLSSocket
  try {
    // RFC 6066: SNI must be a hostname — Node REFUSES IP literals (throws
    // "Setting the TLS ServerName to an IP address is not permitted"). Arvan
    // probes connect SNI-less (the edge then serves its default/customer cert).
    // hunt v6.1 — net.isIP (not isIPv4) so v6 candidate IPs also connect SNI-less
    const sni = net.isIP(host) ? undefined : host
    sock = await new Promise<import('node:tls').TLSSocket>((resolve, reject) => {
      const s = tls.connect(
        { host: ip, port, servername: sni, rejectUnauthorized: false, timeout: timeoutMs },
        () => resolve(s),
      )
      s.once('error', (e) => reject(e instanceof Error ? e : new Error(String(e))))
      s.once('timeout', () => reject(new Error('tls handshake timeout')))
    })
  } catch {
    return { tlsMs: Date.now() - tlsStart }
  }
  const tlsMs = Date.now() - tlsStart

  const res = await new Promise<{ status?: number; server?: string }>((resolve) => {
    let buf = ''
    let status: number | undefined
    let server: string | undefined
    let done = false
    const settle = () => {
      if (done) return
      done = true
      clearTimeout(timer)
      resolve({ status, server })
    }
    const timer = setTimeout(settle, Math.min(timeoutMs, 4000))
    sock.on('readable', function onReadable(this: import('node:tls').TLSSocket) {
      const chunk = this.read()
      if (!chunk) return
      buf += chunk.toString('latin1')
      if (status === undefined) {
        const m = buf.match(/^HTTP\/[\d.]+ (\d{3})/)
        if (m) status = Number(m[1])
      }
      if (server === undefined) {
        const sm = buf.match(/^server:\s*([^\r\n]+)/im)
        if (sm) server = sm[1]!.trim().slice(0, 120)
      }
      // wait for either the Server header or the end of the response headers
      if (status !== undefined && (server !== undefined || buf.includes('\r\n\r\n'))) {
        this.removeListener('readable', onReadable)
        settle()
      }
    })
    sock.once('error', () => settle())
    sock.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n`)
  })
  try {
    sock.destroy()
  } catch {}
  return { httpStatus: res.status, tlsMs, server: res.server }
}

/**
 * hunt v6.4 — RST-injection forensics probe. DELIBERATELY separate from
 * tlsHttpProbe (whose catch-swallowing semantics must stay untouched): this
 * probe exists to INSPECT the failure of a stage-B dead candidate.
 *   step 1 — raw TCP connect (tcping-style):
 *              ECONNREFUSED            ⇒ 'refused' (nothing listening)
 *              timeout / other failure ⇒ 'drop'    (path changed since stage A)
 *   step 2 — TLS handshake on the live socket (SNI rules identical to stage B):
 *              ECONNRESET / EPIPE      ⇒ 'rst'     (DPI injection signature)
 *              ETIMEDOUT / handshake timeout ⇒ 'drop'
 *              success / any other TLS error (EPROTO, cert, EHOSTUNREACH…) ⇒ 'live'
 * Never throws; cleans both sockets in every path.
 */
function classifyForensicsError(e: unknown): 'rst' | 'drop' | 'refused' | 'live' {
  const err = e as NodeJS.ErrnoException | undefined
  const code = err?.code ?? ''
  const msg = err instanceof Error ? err.message : String(err ?? '')
  if (code === 'ECONNRESET' || code === 'EPIPE') return 'rst'
  if (code === 'ETIMEDOUT' || code === 'ERR_TLS_HANDSHAKE_TIMEOUT' || /handshake timeout/i.test(msg)) return 'drop'
  return 'live'
}

async function rstForensicsProbe(
  ip: string,
  port: number,
  host: string,
  timeoutMs: number,
): Promise<'rst' | 'drop' | 'refused' | 'live' | null> {
  // ---- step 1 — raw TCP connect (same shape as tcping, but error-coded) ----
  let raw: net.Socket
  try {
    raw = await new Promise<net.Socket>((resolve, reject) => {
      const s = net.connect({ host: ip, port })
      let done = false
      const fail = (e: Error) => {
        if (done) return
        done = true
        s.removeAllListeners()
        s.destroy()
        reject(e)
      }
      s.setTimeout(timeoutMs, () => fail(new Error('tcp connect timeout')))
      s.once('error', fail)
      s.once('connect', () => {
        if (done) return
        done = true
        // swallow-guard stays attached: between this resolve and the TLS
        // attachment a late RST must never crash the process
        s.once('error', () => {})
        s.setTimeout(0)
        resolve(s)
      })
    })
  } catch (e) {
    // unreachable at TCP despite the earlier stage-A pass = the path changed
    return (e as NodeJS.ErrnoException)?.code === 'ECONNREFUSED' ? 'refused' : 'drop'
  }
  // ---- step 2 — TLS handshake over the live socket, error-code forensics ----
  // RFC 6066: never put an IP literal into servername (same rule as stage B)
  const sni = net.isIP(host) ? undefined : host
  return await new Promise((resolve) => {
    let settled = false
    const finish = (v: 'rst' | 'drop' | 'refused' | 'live') => {
      if (settled) return
      settled = true
      try {
        tsock.destroy()
      } catch {}
      try {
        raw.destroy()
      } catch {}
      resolve(v)
    }
    let tsock: import('node:tls').TLSSocket
    try {
      tsock = tls.connect({ socket: raw, port, servername: sni, rejectUnauthorized: false })
    } catch (e) {
      try {
        raw.destroy()
      } catch {}
      resolve(classifyForensicsError(e))
      return
    }
    tsock.setTimeout(timeoutMs, () => finish('drop'))
    tsock.once('error', (e) => finish(classifyForensicsError(e)))
    tsock.once('secureConnect', () => finish('live'))
  })
}

/**
 * hunt v5.9 — COLO (datacenter) detection for healthy Cloudflare edges.
 * Same forced-IP TLS connect as tlsHttpProbe (SNI/Host = www.cloudflare.com,
 * which any anycast CF edge answers for) but accumulates the WHOLE response
 * until socket close/timeout — unlike tlsHttpProbe we need the BODY: its
 * `colo=XXX` line names the datacenter that served the request (IATA code).
 * NEVER throws — any TLS/timeout/parse failure returns null so a trace
 * problem can never take a TLS worker down; the candidate just ships colo-less.
 */
async function cfTraceProbe(ip: string, port: number, timeoutMs: number): Promise<string | null> {
  let sock: import('node:tls').TLSSocket | null = null
  try {
    sock = await new Promise<import('node:tls').TLSSocket>((resolve, reject) => {
      const s = tls.connect(
        { host: ip, port, servername: 'www.cloudflare.com', rejectUnauthorized: false, timeout: timeoutMs },
        () => resolve(s),
      )
      s.once('error', (e) => {
        try {
          s.destroy()
        } catch {}
        reject(e instanceof Error ? e : new Error(String(e)))
      })
      s.once('timeout', () => reject(new Error('tls handshake timeout')))
    })
    // Connection: close → the edge ends the response by closing the socket;
    // accumulate everything and bound the wait with a hard timer in case a
    // keep-alive answer never closes.
    const sk = sock
    const body = await new Promise<string>((resolve) => {
      let buf = ''
      let done = false
      const settle = () => {
        if (done) return
        done = true
        clearTimeout(timer)
        resolve(buf)
      }
      const timer = setTimeout(settle, Math.min(timeoutMs, 4000))
      sk.on('data', (c: Buffer) => {
        buf += c.toString('latin1')
      })
      sk.once('end', settle)
      sk.once('close', settle)
      sk.once('error', settle)
      sk.write(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nUser-Agent: ${UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n`)
    })
    const m = body.match(/^colo=([A-Za-z0-9]{3})\s*$/m)
    return m ? m[1]!.toUpperCase() : null
  } catch {
    return null
  } finally {
    try {
      sock?.destroy()
    } catch {}
  }
}

/**
 * Start the hunt. MUST stay synchronous (no await before the return) —
 * the socket ack serialises whatever is passed, and acking a Promise would
 * deliver `{}` to the client instead of the real state.
 */
function startGoogleHunt(raw?: Partial<GoogleHuntSettings>, opts?: { auto?: boolean }): GoogleHuntState {
  if (hunt && hunt.state.running) return huntSnapshot()!
  const settings = normalizeHuntSettings(raw)
  exploitCache = null
  // hunt v6.0 — parse the user's custom CIDR ranges ONCE per hunt; the entries
  // are already validated/canonical so parseCIDR cannot fail here
  customPool = settings.customCidrs.map((c) => parseCIDR(c)).filter((r): r is CidrRange => r !== null)
  // hunt v6.1 — parse the range-checklist allow-list ONCE per hunt (v4 entries
  // via parseCIDR, v6 via parseCidr6 — both already validated/canonicalized in
  // normalizeHuntSettings). A non-empty selectedPool REPLACES the provider pool
  // for this run (explorePool); the next hunt without selectedCidrs reverts to
  // the normal pools because the pool is rebuilt from scratch on every start.
  // v7.0 — each entry rides its per-index ISP label: settings.selectedCidrs is
  // already EXACTLY aligned with settings.selectedLabels by normalizeHuntSettings
  // (same accepted/deduped sequence), so map index i = label index i.
  selectedPool = (settings.selectedCidrs ?? [])
    .map((entry, i): { r: CidrRange; isV6: boolean; isp?: string } | null => {
      if (entry.includes(':')) {
        const p6 = parseCidr6(entry)
        return p6 ? { r: parsed6ToRange(p6), isV6: true, isp: settings.selectedLabels?.[i] || undefined } : null
      }
      const r = parseCIDR(entry)
      return r ? { r, isV6: false, isp: settings.selectedLabels?.[i] || undefined } : null
    })
    .filter((e): e is { r: CidrRange; isV6: boolean; isp?: string } => e !== null)
  // prebuilt exploration pool (uniform weight w=3 like custom) — with provider
  // 'all' the probes run custom-style internally but stay provider-labelled
  selectedExplore =
    selectedPool.length > 0
      ? {
          pool: selectedPool.map(({ r, isp }) => ({
            r,
            w: 3,
            provider: settings.provider === 'all' ? 'custom' : settings.provider,
            // v7.0 — ISP source label rides the pool into the sampler
            ...(isp ? { isp } : {}),
          })),
          total: selectedPool.reduce((acc, p) => acc + 3n * p.r.size, 0n),
        }
      : null
  // hunt v6.3 — per-provider probe-target overrides (google + cloudflare only,
  // already validated in normalizeHuntSettings) ride the module-level singleton
  // like customPool/selectedPool so the sampler + both worker stages see them
  huntOverrides = settings.providerOverrides
  buildProviderRanges() // v6.1 — custom's checklist ranges ride the recon snapshot too
  hunt = {
    state: {
      running: true,
      finished: false,
      stopped: false,
      tested: 0,
      healthy: 0,
      blocked: 0,
      dead: 0,
      planned: 0,
      wave: 0,
      target: settings.target,
      hardCap: settings.hardCap,
      host:
        settings.provider === 'all'
          ? 'multi-provider'
          : // v6.3 — reflect the effective override in the state metadata so
            // the UI's «SNI: host:port» line stays truthful
            (huntOverrides[settings.provider]?.host ?? HUNT_PROVIDERS[settings.provider].host),
      port: huntOverrides[settings.provider]?.port ?? 443,
      startedAt: Date.now(),
      elapsedMs: 0,
      ipsPerSecond: 0,
      healthyIps: [],
      recent: [],
      tcpAlive: 0,
      verified: 0,
      hotBlocks: topHuntBlocks(6),
      verify: settings.verify,
      provider: settings.provider,
      perProvider: freshPerProvider(),
      // ----- parallel pipeline v5 telemetry -----
      inFlight: 0,
      tlsInFlight: 0,
      concurrency: initialTcpWorkers(settings.tcpPoolMax),
      tlsConcurrency: initialTlsWorkers(settings.tlsPoolMax),
      tcpPoolMax: settings.tcpPoolMax,
      tlsPoolMax: settings.tlsPoolMax,
      sampled: 0,
      v6Sampled: 0,
      fromSelected: 0,
      engine: 'pipeline-v5',
      // v7.0 — true when the hunt scheduler (not a user click) started this run
      auto: opts?.auto === true,
      // hunt v6.4 — all-zero forensics tally when enabled; the field stays
      // ABSENT when the run disabled forensics (legacy payload shape preserved)
      ...(settings.forensics ? { forensics: { rst: 0, drop: 0, refused: 0, live: 0 } as HuntForensicsTally } : {}),
    },
    settings,
    stopFlag: false,
    stamps: [],
    tried: new Set(),
    // hunt v6.4 — forensics probe budget (400/run), zeroed when disabled
    forensicsBudget: settings.forensics ? HUNT_FORENSICS_BUDGET : 0,
  }
  broadcastHunt()
  // hunt v5.9 — cloudflare runs probe the whole TLS port matrix, say so up front
  const portsNote =
    settings.provider === 'all' || settings.provider === 'cloudflare' ? ` · ports ${HUNT_CF_PORTS.join('/')}` : ''
  // hunt v6.0 — custom runs advertise how many user ranges they hunt
  const customNote = settings.provider === 'custom' ? ` · custom ${settings.customCidrs.length} CIDR(s)` : ''
  // hunt v6.1 — the range-checklist allow-list advertises itself (with its v6
  // share); the 15% v6 dice only applies to the provider pools, so when a
  // checklist is active the v6 sampling note is replaced by the selected note
  const selectedNote =
    selectedPool.length > 0
      ? ` · selected ${selectedPool.length} CIDR(s) (${selectedPool.filter((p) => p.isV6).length} v6)`
      : ''
  const v6Note = settings.enableV6 && selectedPool.length === 0 ? ' · v6 ~15%' : ''
  console.log(
    `[google-hunt] start (parallel pipeline v5) — provider ${settings.provider.toUpperCase()} · target ${settings.target} healthy · verify ×${settings.verify} · speed ${settings.speed} (tcp ${settings.tcpPoolMax} · tls ${settings.tlsPoolMax})${portsNote}${customNote}${selectedNote}${v6Note} · knowledge ${huntKnowledge.size} block(s) · recon ${recon.status} (${reconPool.length} CIDR)`,
  )
  // custom provider with zero usable ranges: say so up front, then let runHunt
  // hit the one-wave pool-exhausted break (the sampler simply returns nothing)
  if (settings.provider === 'custom' && settings.customCidrs.length === 0) {
    console.log('[google-hunt] custom provider selected but no CIDR ranges provided')
  }
  // stale recon? refresh in the background — the hunt starts on the current pool regardless
  if (Date.now() - recon.updatedAt > RECON_TTL_MS) void refreshHuntRecon()
  void runHunt()
  return huntSnapshot()!
}

/**
 * hunt v5 — "parallel pipeline": the wave-barrier model is gone.
 *
 *   feeder ──▶ tcpChan ──▶ TCP pool (stage A) ──▶ tlsChan ──▶ TLS pool (stages B+C)
 *
 * Candidates stream through two bounded async channels: the feeder never waits
 * for a wave to finish, the TCP pool feeds the TLS pool continuously, and an
 * adaptive controller breathes both pools every second (grow on backpressure,
 * shrink on drain) inside the run's speed-preset ceilings.
 * v5.9 — candidates carry their own probe port (cloudflare rotates the TLS
 * port matrix 443/2053/2083/2087/2096/8443) and healthy cloudflare edges get a
 * /cdn-cgi/trace COLO lookup attached.
 * v6.0 — healthy candidates get a jitterMs stat (TLS max−min across the probe
 * + verification passes) and the 'custom' provider hunts the user's own ranges.
 * v6.1 — v6 candidates (enableV6 sampling / selected v6 checklist ranges) ride
 * the same TCP→TLS pipeline untouched (net/tls accept v6 literals; the Host
 * header stays the SNI hostname exactly like v4). The run state carries
 * v6Sampled and fromSelected, and a selectedCidrs+all run probes custom-style
 * while the candidates keep the user's provider label as-is.
 */
async function runHunt(): Promise<void> {
  const rt = hunt!
  const st = rt.state
  // engine always fills all three buckets (freshPerProvider) — keep a non-partial alias for TS
  const per: Record<HuntProviderId, HuntProviderStats> = st.perProvider ?? freshPerProvider()
  st.perProvider = per

  // ---- pipeline plumbing ----
  const tcpPoolMax = rt.settings.tcpPoolMax
  const tlsPoolMax = rt.settings.tlsPoolMax
  // hunt v6.1 — candidates carry their v6/selected provenance through the pipeline
  const tcpChan = new BoundedChannel<{ ip: string; provider: HuntProviderId; port: number; v6?: boolean; selected?: boolean; isp?: string }>(tcpPoolMax * 2)
  const tlsChan = new BoundedChannel<{ ip: string; provider: HuntProviderId; port: number; tcpMs: number; v6?: boolean; selected?: boolean; isp?: string }>(tlsPoolMax * 3)
  /** the run is over the moment it was stopped OR a newer run replaced it */
  const isStopped = () => rt.stopFlag || hunt !== rt
  let poolExhausted = false
  // hunt v6.1 — a selectedCidrs run with provider 'all' probes custom-style
  // (SNI-less on the IP, any-HTTP=healthy) but keeps the user's provider label
  // as-is on every candidate
  const selectedAllRun = selectedPool.length > 0 && rt.settings.provider === 'all'
  const providerLabel = (p: HuntProviderId): string => (p === 'custom' && selectedAllRun ? 'all' : p)
  // hunt v6.1 — ambiguous-ownership runs never write /24 knowledge (that would
  // leak user-selected blocks into later plain-custom hunts)
  const learnKnowledge = !selectedAllRun

  // ---- exact worker bookkeeping (increment on spawn, decrement in the worker's finally) ----
  let tcpWorkers = 0
  let tlsWorkers = 0
  let tcpInFlight = 0
  let tlsInFlight = 0
  /** controller-set targets — surplus workers exit before pulling their next item (never killed mid-probe) */
  let desiredTcp = tcpPoolMax
  let desiredTls = tlsPoolMax
  const tcpWorkerPromises: Promise<void>[] = []
  const tlsWorkerPromises: Promise<void>[] = []

  const pushRecent = (c: GoogleHuntCandidate) => {
    st.recent.push(c)
    if (st.recent.length > 12) st.recent.splice(0, st.recent.length - 12)
    const now = Date.now()
    rt.stamps.push(now)
    if (rt.stamps.length > 2048) rt.stamps.splice(0, 1024)
  }

  // ---- stage A — cheap raw TCP connect (kills most candidates for free) ----
  const tcpWorkerBody = async (): Promise<void> => {
    try {
      for (;;) {
        if (isStopped()) return
        // adaptive shrink — surplus workers step out BEFORE pulling their next item
        if (tcpWorkers > desiredTcp) return
        const item = await tcpChan.pull(isStopped)
        if (item === null) return
        const { ip, provider, port, v6, selected, isp } = item
        const def = HUNT_PROVIDERS[provider]
        // v6.0 — custom ranges are probed SNI-less on the IP (like Arvan's)
        // v6.3 — probe host resolves through the shared override-aware helper
        const probeHost = resolveProbeTarget(provider, ip, def).host
        tcpInFlight++
        try {
          st.tested++
          per[provider].tested++
          const tcpMs = await tcping(ip, port, HUNT_TCP_TIMEOUT_MS)
          if (tcpMs === null) {
            st.dead++
            per[provider].dead++
            if (learnKnowledge) recordBlockVerdict(ip, 'dead', provider)
            pushRecent({
              ip,
              verdict: 'dead',
              host: probeHost,
              provider: providerLabel(provider),
              port,
              ...(v6 ? { v6: true } : {}),
              ...(selected ? { selected: true } : {}),
              // v7.0 — ISP source label rides the dead ticker rows too
              ...(isp ? { isp } : {}),
            })
            continue
          }
          st.tcpAlive++
          // target already met while this candidate was in-flight (or run is
          // over)? skip the expensive TLS stage — arvan's ~80% healthy rate
          // makes overshoot huge
          if (st.healthy >= st.target || isStopped()) continue
          // hand over to the TLS stage — bounded push paces the pipeline; on
          // stop the item is simply dropped
          await tlsChan.push({ ip, provider, port, tcpMs, v6, selected, isp }, isStopped)
        } finally {
          tcpInFlight--
        }
      }
    } catch (e) {
      // a single worker must never take the pipeline down
      console.error('[hunt-v5] tcp worker crashed:', e instanceof Error ? e.message : e)
    } finally {
      tcpWorkers--
    }
  }

  // ---- stages B+C — TLS probe + verification (the expensive part, alive-only) ----
  const tlsWorkerBody = async (): Promise<void> => {
    try {
      for (;;) {
        if (isStopped()) return
        if (tlsWorkers > desiredTls) return
        const item = await tlsChan.pull(isStopped)
        if (item === null) return
        const { ip, provider, port, tcpMs, v6, selected, isp } = item
        const def = HUNT_PROVIDERS[provider]
        // v6.0 — custom ranges are probed SNI-less on the IP (like Arvan's)
        // v6.3 — host+path resolve through the shared override-aware helper
        const { host: probeHost, path: probePath } = resolveProbeTarget(provider, ip, def)
        tlsInFlight++
        try {
          // ---- stage B — TLS + the provider's own probe
          const r = await tlsHttpProbe(ip, port, probeHost, HUNT_TIMEOUT_MS, probePath)
          let verdict: 'healthy' | 'blocked' | 'dead' =
            r.httpStatus === undefined ? 'dead' : def.classify(r.httpStatus, r.server ?? '')

          // ---- stage C — verification passes (flaky IPs never reach the list)
          let attempts = 1
          /** v6.0 — TLS ms of every verification pass (feeds the jitter stat) */
          const verifyTlsMs: (number | undefined)[] = []
          if (verdict === 'healthy' && rt.settings.verify > 0) {
            for (let v = 0; v < rt.settings.verify && verdict === 'healthy'; v++) {
              if (isStopped()) break
              const rv = await tlsHttpProbe(ip, port, probeHost, HUNT_TIMEOUT_MS, probePath)
              verifyTlsMs.push(rv.tlsMs)
              const v2: 'healthy' | 'blocked' | 'dead' =
                rv.httpStatus === undefined ? 'dead' : def.classify(rv.httpStatus, rv.server ?? '')
              if (v2 === 'healthy') attempts++
              else verdict = v2
            }
          }

          // hunt v5.9 — COLO detection: healthy cloudflare edges get asked
          // /cdn-cgi/trace which datacenter served them (FRA/DXB/AMS/…).
          // Google/Arvan edges have no trace endpoint → colo stays undefined.
          let colo: string | undefined
          // hunt v6.0 — jitter stat: TLS latency spread (|max−min|) across the
          // stage-B probe + every verification pass; needs ≥2 samples. Blocked/
          // dead candidates and single-probe verifications ship without it.
          let jitterMs: number | undefined
          /** hunt v6.4 — forensics label for stage-B deads (set in the dead branch below) */
          let rstLabel: GoogleHuntCandidate['rst'] | undefined
          if (verdict === 'healthy') {
            if (provider === 'cloudflare') {
              colo = (await cfTraceProbe(ip, port, HUNT_TIMEOUT_MS)) ?? undefined
              // run stopped/replaced while the trace was in flight — never
              // attach a late candidate to a superseded state (drop it)
              if (isStopped()) continue
            }
            const samples = [r.tlsMs, ...verifyTlsMs].filter((n): n is number => typeof n === 'number')
            if (samples.length >= 2) jitterMs = Math.max(...samples) - Math.min(...samples)
            st.healthy++
            per[provider].healthy++
            if (attempts >= 2) st.verified++
            st.healthyIps.push({
              ip,
              verdict,
              httpStatus: r.httpStatus,
              tcpMs,
              tlsMs: r.tlsMs,
              host: probeHost,
              attempts,
              provider: providerLabel(provider),
              server: r.server,
              port,
              colo,
              jitterMs,
              // hunt v6.1 — v6/selected provenance rides healthy candidates
              // v7.0 — ISP source label rides too (present only for labelled selectedCidrs)
              ...(v6 ? { v6: true } : {}),
              ...(selected ? { selected: true } : {}),
              ...(isp ? { isp } : {}),
            })
          } else if (verdict === 'blocked') {
            st.blocked++
            per[provider].blocked++
          } else {
            st.dead++
            per[provider].dead++
            // hunt v6.4 — budgeted RST-injection forensics over STAGE-B deads
            // only (TCP-stage deads are already plain dead — nothing to classify;
            // verification-flipped deads keep r.httpStatus, so they skip too).
            // Every other dead (odd counter) gets one probe until the run
            // budget drains; stopped runs skip entirely.
            if (r.httpStatus === undefined && rt.settings.forensics !== false && rt.forensicsBudget > 0 && st.dead % 2 === 1 && !isStopped()) {
              rt.forensicsBudget--
              rstLabel = (await rstForensicsProbe(ip, port, probeHost, RST_FORENSICS_TIMEOUT_MS)) ?? undefined
              if (rstLabel && st.forensics) st.forensics[rstLabel]++
            }
          }
          if (learnKnowledge) recordBlockVerdict(ip, verdict, provider)
          pushRecent({
            ip,
            verdict,
            httpStatus: r.httpStatus,
            tcpMs,
            tlsMs: r.tlsMs,
            host: probeHost,
            provider: providerLabel(provider),
            server: r.server,
            port,
            colo,
            // v6.0 — jitter rides healthy candidates only (blocked/dead omit it)
            ...(jitterMs !== undefined ? { jitterMs } : {}),
            // hunt v6.4 — forensics label rides the dead ticker rows
            ...(rstLabel ? { rst: rstLabel } : {}),
            // hunt v6.1 — v6/selected provenance rides every ticker candidate
            // v7.0 — ISP source label rides too
            ...(v6 ? { v6: true } : {}),
            ...(selected ? { selected: true } : {}),
            ...(isp ? { isp } : {}),
          })
        } finally {
          tlsInFlight--
        }
      }
    } catch (e) {
      console.error('[hunt-v5] tls worker crashed:', e instanceof Error ? e.message : e)
    } finally {
      tlsWorkers--
    }
  }

  const spawnTcpWorkers = (n: number) => {
    for (let i = 0; i < n; i++) {
      tcpWorkers++
      tcpWorkerPromises.push(tcpWorkerBody())
    }
  }
  const spawnTlsWorkers = (n: number) => {
    for (let i = 0; i < n; i++) {
      tlsWorkers++
      tlsWorkerPromises.push(tlsWorkerBody())
    }
  }

  // ---- feeder — streams sampled candidates into the TCP channel ----
  const feederBody = async (): Promise<void> => {
    try {
      while (!isStopped() && st.healthy < st.target && st.tested < st.hardCap && st.planned < st.hardCap) {
        st.wave++
        const size = Math.min(rt.settings.batchSize, st.hardCap - st.planned)
        if (size <= 0) break
        const cands = sampleHuntIPs(size, rt.tried, rt.settings.provider, rt.settings.enableV6 === true)
        if (cands.length === 0) {
          // small pools (e.g. arvan's 31 /24s) can exhaust before the target is
          // reached — spinning forever would peg the CPU; stop and report instead
          console.log('[google-hunt] wave skipped — candidate pool exhausted for the selected provider(s)')
          poolExhausted = true
          break
        }
        st.planned += cands.length
        // hunt v6.1 — v6 / selected provenance counters (per generated candidate)
        for (const c of cands) {
          if (c.v6) st.v6Sampled = (st.v6Sampled ?? 0) + 1
          if (c.selected) st.fromSelected = (st.fromSelected ?? 0) + 1
        }
        console.log(
          `[google-hunt] wave ${st.wave} — feeding ${cands.length} IPs into the pipeline (${Math.round((1 - HUNT_EXPLORE_RATE) * 100)}% from learned blocks)`,
        )
        for (const c of cands) {
          if (isStopped()) break
          // bounded push — awaits while the channel is full (backpressure paces sampling)
          if (await tcpChan.push(c, isStopped)) st.sampled++
          else break // stopped — the run is over, the rest of the batch is dropped
        }
      }
    } finally {
      // no more candidates will ever arrive — wake every TCP waiter
      tcpChan.close()
    }
  }

  // ---- adaptive controller — breathes both pools every second ----
  const controller = setInterval(() => {
    try {
      if (hunt !== rt) {
        clearInterval(controller)
        return
      }
      // stop safety — wake every parked channel waiter so nothing can hang
      if (rt.stopFlag) {
        tcpChan.wakeAll()
        tlsChan.wakeAll()
      }
      st.concurrency = tcpWorkers
      st.tlsConcurrency = tlsWorkers
      // TCP pool — grow while the TLS stage is hungry, shrink when it is drained
      if (tlsChan.depth > tlsPoolMax && tcpWorkers < tcpPoolMax) {
        desiredTcp = tcpPoolMax
        spawnTcpWorkers(Math.min(64, tcpPoolMax - tcpWorkers))
      } else if (tlsChan.depth === 0 && tcpWorkers > Math.max(32, Math.floor(tcpPoolMax / 2))) {
        desiredTcp = Math.max(32, Math.floor(tcpPoolMax / 2))
      }
      // TLS pool — grow while its channel piles up, shrink when it is drained
      if (tlsChan.depth >= 2 * tlsPoolMax && tlsWorkers < tlsPoolMax) {
        desiredTls = tlsPoolMax
        spawnTlsWorkers(Math.min(32, tlsPoolMax - tlsWorkers))
      } else if (tlsChan.depth === 0 && tlsWorkers > Math.max(8, Math.floor(tlsPoolMax / 2))) {
        desiredTls = Math.max(8, Math.floor(tlsPoolMax / 2))
      }
    } catch (e) {
      console.error('[hunt-v5] controller tick failed:', e instanceof Error ? e.message : e)
    }
  }, 1000)

  // ---- broadcast ticker — 500ms, same cadence as v4 plus pipeline telemetry ----
  let tickCount = 0
  const ticker = setInterval(() => {
    if (hunt !== rt) {
      clearInterval(ticker)
      clearInterval(controller)
      return
    }
    st.elapsedMs = Date.now() - (st.startedAt ?? Date.now())
    st.inFlight = tcpInFlight + tlsInFlight
    st.tlsInFlight = tlsInFlight
    const now = Date.now()
    rt.stamps = rt.stamps.filter((t) => now - t < 3000)
    st.ipsPerSecond =
      rt.stamps.length >= 2
        ? Math.round((rt.stamps.length / Math.min(3000, now - rt.stamps[0]!)) * 1000)
        : 0
    st.hotBlocks = topHuntBlocks(6)
    broadcastHunt()
    persistHuntKnowledge() // throttled to 10s internally
    if (++tickCount % 10 === 0) {
      console.log(
        `[hunt-v5] tested ${st.tested} · alive ${st.tcpAlive} · tls ${st.healthy} · tcp ${tcpWorkers}/${tcpPoolMax} · tls ${tlsWorkers}/${tlsPoolMax} · in-flight ${tcpInFlight + tlsInFlight}`,
      )
    }
  }, 500)

  spawnTcpWorkers(initialTcpWorkers(tcpPoolMax))
  spawnTlsWorkers(initialTlsWorkers(tlsPoolMax))
  const feeder = feederBody()

  try {
    // the feeder closes tcpChan in its finally → TCP workers drain & exit
    await feeder
    clearInterval(controller) // no more adaptive spawning — drain only from here
    await Promise.all(tcpWorkerPromises)
    // every TCP hand-off has completed — nothing can reach tlsChan anymore
    tlsChan.close()
    await Promise.all(tlsWorkerPromises)

    st.running = false
    st.finished = true
    st.stopped = rt.stopFlag
    st.elapsedMs = Date.now() - (st.startedAt ?? Date.now())
    st.hotBlocks = topHuntBlocks(6)
    // hunt v6.1 — v6 / selected tallies appear only when the run actually used them
    const v6SelectedNote =
      (st.v6Sampled ?? 0) > 0 || (st.fromSelected ?? 0) > 0
        ? ` · v6-sampled ${st.v6Sampled ?? 0} · from-selected ${st.fromSelected ?? 0}`
        : ''
    // hunt v6.3 — effective per-provider probe-target overrides (host/port/path)
    const overrideCount = Object.values(rt.settings.providerOverrides ?? {}).filter(
      (o) => o !== undefined && (o.host !== undefined || o.port !== undefined || o.path !== undefined),
    ).length
    const overrideNote = overrideCount > 0 ? ` · override ×${overrideCount}` : ''
    // hunt v6.4 — forensics tallies (only buckets > 0 stay readable; 'idle' when
    // the run classified nothing)
    let forensicsNote = ''
    if (rt.settings.forensics !== false && st.forensics) {
      const f = st.forensics
      const parts = (['rst', 'drop', 'refused', 'live'] as const)
        .filter((k) => f[k] > 0)
        .map((k) => `${k} ${f[k]}`)
      forensicsNote = parts.length > 0 ? ` · forensics ${parts.join(' / ')}` : ' · forensics idle'
    }
    console.log(
      `[google-hunt] finished — tested ${st.tested} (tcp-alive ${st.tcpAlive}) · healthy ${st.healthy} (verified ${st.verified}) · blocked ${st.blocked} · dead ${st.dead} · per-provider ${HUNT_PROVIDER_IDS.map((id) => `${id} ${per[id].healthy}/${per[id].tested}`).join(' · ')}${st.stopped ? ' (stopped by user)' : ''}${poolExhausted ? ' (pool exhausted)' : ''}${v6SelectedNote}${overrideNote}${forensicsNote}`,
    )
    // hunt v5.9 — datacenter tally of the healthy cloudflare edges (top 8, desc)
    const coloTally = new Map<string, number>()
    for (const c of st.healthyIps) {
      if (c.colo) coloTally.set(c.colo, (coloTally.get(c.colo) ?? 0) + 1)
    }
    if (coloTally.size > 0) {
      const top = [...coloTally.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8)
      console.log(`[google-hunt] colo — ${top.map(([code, n]) => `${code} ${n}`).join(' · ')}`)
    }
  } catch (e) {
    st.running = false
    st.finished = true
    st.error = e instanceof Error ? e.message : String(e)
    console.error('[google-hunt] crashed:', st.error)
  } finally {
    clearInterval(ticker)
    clearInterval(controller)
    // wake anything still parked (crash path / stop) and drain every worker
    tcpChan.close()
    tlsChan.close()
    await Promise.allSettled([...tcpWorkerPromises, ...tlsWorkerPromises])
  }
  persistHuntKnowledge(true)
  persistHuntHistory(st)
  // v7.1 — scheduler journal: record the outcome of every scheduler-triggered
  // run — normal finish, user stop AND crash alike (honest history). `st` here
  // is the GoogleHuntState of the finished run; scheduled runs carry auto:true.
  if (st.auto === true) {
    journalPush({
      at: Date.now(),
      kind: 'done',
      tested: st.tested,
      healthy: st.healthy,
      stopped: st.stopped,
      durationMs: Date.now() - (st.startedAt ?? Date.now()),
    })
  }
  broadcastHunt()
}

function stopGoogleHunt(): GoogleHuntState | null {
  if (hunt && hunt.state.running) {
    hunt.stopFlag = true
    console.log('[google-hunt] stop requested')
  }
  return huntSnapshot()
}

function resetGoogleHunt(): GoogleHuntState | null {
  if (hunt && hunt.state.running) return huntSnapshot()
  hunt = null
  return null
}

// ============================================================================
// ------------- WARP endpoint scanner (hunt v6.2 / P3 — WireGuard UDP) --------
// A standalone WireGuard-flavoured prober for Cloudflare WARP endpoints: it
// generates a best-effort WARP identity (registering it with
// api.cloudflareclient.com when reachable), crafts a REAL Noise-IKpsk2
// handshake initiation (X25519 + ChaCha20-Poly1305 + keyed BLAKE2s) and fires
// it at every endpoint of the canonical WARP ranges × selected UDP ports.
// Any datagram that answers (type-2 handshake / type-3 cookie) marks the
// endpoint alive. Everything below is self-contained and warp-prefixed —
// zero impact on the scan pipeline, the hunt, or any other subsystem.
// ============================================================================

// ---------------- keyed BLAKE2s (RFC 7693) — compact pure-TS ----------------
const BLAKE2S_IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
])
const BLAKE2S_SIGMA = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
])
const blake2sRotl = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0

function blake2sG(v: Uint32Array, a: number, b: number, c: number, d: number, x: number, y: number): void {
  // RFC 7693 G — ROTR16 ≡ ROTL16, ROTR12 ≡ ROTL20, ROTR8 ≡ ROTL24, ROTR7 ≡ ROTL25
  v[a] = (v[a] + v[b] + x) >>> 0
  v[d] = blake2sRotl(v[d] ^ v[a], 16)
  v[c] = (v[c] + v[d]) >>> 0
  v[b] = blake2sRotl(v[b] ^ v[c], 20)
  v[a] = (v[a] + v[b] + y) >>> 0
  v[d] = blake2sRotl(v[d] ^ v[a], 24)
  v[c] = (v[c] + v[d]) >>> 0
  v[b] = blake2sRotl(v[b] ^ v[c], 25)
}

function blake2sCompress(h: Uint32Array, block: Buffer, t: number, last: boolean): void {
  const m = new Uint32Array(16)
  for (let i = 0; i < 16; i++) m[i] = block.readUInt32LE(i * 4)
  const v = new Uint32Array(16)
  for (let i = 0; i < 8; i++) {
    v[i] = h[i]
    v[i + 8] = BLAKE2S_IV[i]
  }
  v[12] = (v[12] ^ (t >>> 0)) >>> 0
  v[13] = (v[13] ^ Math.floor(t / 0x100000000)) >>> 0
  if (last) v[14] = (v[14] ^ 0xffffffff) >>> 0
  for (let r = 0; r < 10; r++) {
    const s = r * 16
    blake2sG(v, 0, 4, 8, 12, m[BLAKE2S_SIGMA[s]], m[BLAKE2S_SIGMA[s + 1]])
    blake2sG(v, 1, 5, 9, 13, m[BLAKE2S_SIGMA[s + 2]], m[BLAKE2S_SIGMA[s + 3]])
    blake2sG(v, 2, 6, 10, 14, m[BLAKE2S_SIGMA[s + 4]], m[BLAKE2S_SIGMA[s + 5]])
    blake2sG(v, 3, 7, 11, 15, m[BLAKE2S_SIGMA[s + 6]], m[BLAKE2S_SIGMA[s + 7]])
    blake2sG(v, 0, 5, 10, 15, m[BLAKE2S_SIGMA[s + 8]], m[BLAKE2S_SIGMA[s + 9]])
    blake2sG(v, 1, 6, 11, 12, m[BLAKE2S_SIGMA[s + 10]], m[BLAKE2S_SIGMA[s + 11]])
    blake2sG(v, 2, 7, 8, 13, m[BLAKE2S_SIGMA[s + 12]], m[BLAKE2S_SIGMA[s + 13]])
    blake2sG(v, 3, 4, 9, 14, m[BLAKE2S_SIGMA[s + 14]], m[BLAKE2S_SIGMA[s + 15]])
  }
  for (let i = 0; i < 8; i++) h[i] = (h[i] ^ v[i] ^ v[i + 8]) >>> 0
}

/** keyed BLAKE2s (RFC 7693) — key ≤ 32B padded to a 64B block; digestLen 16 or 32 */
function blake2s(input: Buffer, digestLen: number, key?: Buffer): Buffer {
  const keyLen = key && key.length > 0 ? Math.min(key.length, 32) : 0
  const h = new Uint32Array(BLAKE2S_IV) // copies the IV
  h[0] = (h[0] ^ 0x01010000 ^ (keyLen << 8) ^ digestLen) >>> 0 // param block
  let data = input
  if (keyLen > 0) {
    const kb = Buffer.alloc(64) // pad key to a full block: key || 0x00…
    key.copy(kb, 0, 0, keyLen)
    data = Buffer.concat([kb, input])
  }
  const total = data.length
  if (total === 0) {
    blake2sCompress(h, Buffer.alloc(64), 0, true) // empty message ⇒ single zero block, t=0
  } else {
    for (let off = 0; off < total; off += 64) {
      const end = Math.min(off + 64, total)
      const chunk = data.subarray(off, end)
      const block = end - off === 64 ? chunk : Buffer.concat([chunk, Buffer.alloc(64 - chunk.length)])
      blake2sCompress(h, block, end, end === total)
    }
  }
  const out = Buffer.alloc(digestLen)
  for (let i = 0; i < digestLen; i++) out[i] = (h[i >> 2] >>> (8 * (i & 3))) & 0xff
  return out
}

// lazy once-only RFC 7693 self-test — a broken blake2s degrades the whole
// subsystem to an error ack (never a module-level throw)
let warpSelfTestDone = false
let warpCryptoOk = true
const WARP_TEST_EMPTY = '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9'
const WARP_TEST_ABC = '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982'
// RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 vector (ct || tag)
const WARP_TEST_AEAD = 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691'
function warpRunSelfTest(): boolean {
  if (warpSelfTestDone) return warpCryptoOk
  warpSelfTestDone = true
  try {
    const vEmpty = blake2s(Buffer.alloc(0), 32).toString('hex')
    const vAbc = blake2s(Buffer.from('abc', 'utf8'), 32).toString('hex')
    const vAead = chacha20AeadSeal(
      Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex'),
      Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.", 'utf8'),
      Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex'),
      Buffer.from('070000004041424344454647', 'hex'),
    ).toString('hex')
    console.assert(vEmpty === WARP_TEST_EMPTY, `[warp] blake2s self-test FAIL (empty): ${vEmpty}`)
    console.assert(vAbc === WARP_TEST_ABC, `[warp] blake2s self-test FAIL (abc): ${vAbc}`)
    console.assert(vAead === WARP_TEST_AEAD, `[warp] chacha20-poly1305 self-test FAIL: ${vAead}`)
    warpCryptoOk = vEmpty === WARP_TEST_EMPTY && vAbc === WARP_TEST_ABC && vAead === WARP_TEST_AEAD
  } catch (e) {
    warpCryptoOk = false
    console.error('[warp] crypto self-test crashed:', e instanceof Error ? e.message : e)
  }
  if (warpCryptoOk) console.log('[warp] crypto self-test OK (RFC 7693 blake2s + RFC 8439 AEAD vectors) / تست رمزنگاری موفق')
  else console.error('[warp] crypto self-test FAILED — WARP scanning disabled / تست رمزنگاری شکست خورد — اسکن WARP غیرفعال')
  return warpCryptoOk
}

// ---------------- X25519 raw-key helpers (DER wrappers) ----------------
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex')
const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex')
const warpRawToPubKeyObject = (raw: Buffer) =>
  crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI, raw]), format: 'der', type: 'spki' })
const warpRawToPrivKeyObject = (raw: Buffer) =>
  crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8, raw]), format: 'der', type: 'pkcs8' })
const warpExportPubRaw = (ko: { export(options: { type: 'spki'; format: 'der' }): Buffer }): Buffer =>
  Buffer.from(ko.export({ format: 'der', type: 'spki' })).slice(-32)
const warpExportPrivRaw = (ko: { export(options: { type: 'pkcs8'; format: 'der' }): Buffer }): Buffer =>
  Buffer.from(ko.export({ format: 'der', type: 'pkcs8' })).slice(-32)
const warpGenerateKeypair = (): { privRaw: Buffer; pubRaw: Buffer } => {
  const kp = crypto.generateKeyPairSync('x25519')
  return { privRaw: warpExportPrivRaw(kp.privateKey), pubRaw: warpExportPubRaw(kp.publicKey) }
}

// ------------- AEAD: ChaCha20-Poly1305 (RFC 8439) — pure TS -----------------
// NOTE: node:crypto's chacha20-poly1305 is unavailable under bun (BoringSSL
// ships no chacha EVP — getCiphers() lists none), while the WireGuard Noise
// cipher suite is fixed to ChaChaPoly. The AEAD is therefore implemented
// inline and self-tested against the RFC 8439 §2.8.2 vector at start.
const CHACHA20_CONSTANTS = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574])
const POLY1305_P = (1n << 130n) - 5n
const POLY1305_R_CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn

function chacha20Block(key: Buffer, counter: number, nonce: Buffer): Buffer {
  const st = new Uint32Array(16)
  st.set(CHACHA20_CONSTANTS, 0)
  for (let i = 0; i < 8; i++) st[4 + i] = key.readUInt32LE(i * 4)
  st[12] = counter >>> 0
  st[13] = nonce.readUInt32LE(0)
  st[14] = nonce.readUInt32LE(4)
  st[15] = nonce.readUInt32LE(8)
  const w = new Uint32Array(st) // working copy
  const qr = (a: number, b: number, c: number, d: number): void => {
    w[a] = (w[a] + w[b]) >>> 0
    w[d] = blake2sRotl(w[d] ^ w[a], 16)
    w[c] = (w[c] + w[d]) >>> 0
    w[b] = blake2sRotl(w[b] ^ w[c], 12)
    w[a] = (w[a] + w[b]) >>> 0
    w[d] = blake2sRotl(w[d] ^ w[a], 8)
    w[c] = (w[c] + w[d]) >>> 0
    w[b] = blake2sRotl(w[b] ^ w[c], 7)
  }
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12)
    qr(1, 5, 9, 13)
    qr(2, 6, 10, 14)
    qr(3, 7, 11, 15) // columns
    qr(0, 5, 10, 15)
    qr(1, 6, 11, 12)
    qr(2, 7, 8, 13)
    qr(3, 4, 9, 14) // diagonals
  }
  const out = Buffer.alloc(64)
  for (let i = 0; i < 16; i++) out.writeUInt32LE((w[i] + st[i]) >>> 0, i * 4)
  return out
}

function chacha20Xor(key: Buffer, counter: number, nonce: Buffer, data: Buffer): Buffer {
  const out = Buffer.alloc(data.length)
  for (let off = 0; off < data.length; off += 64) {
    const ks = chacha20Block(key, counter + off / 64, nonce)
    const n = Math.min(64, data.length - off)
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i]
  }
  return out
}

const polyLE = (b: Buffer): bigint => {
  let x = 0n
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i])
  return x
}

function poly1305(key: Buffer, msg: Buffer): Buffer {
  const r = polyLE(key.subarray(0, 16)) & POLY1305_R_CLAMP
  const s = polyLE(key.subarray(16, 32))
  let acc = 0n
  for (let off = 0; off < msg.length; off += 16) {
    const chunk = msg.subarray(off, Math.min(off + 16, msg.length))
    const block = polyLE(chunk) | (1n << BigInt(8 * chunk.length)) // append the 0x01 byte
    acc = ((acc + block) * r) % POLY1305_P
  }
  acc = (acc + s) & ((1n << 128n) - 1n)
  const tag = Buffer.alloc(16)
  for (let i = 0; i < 16; i++) tag[i] = Number((acc >> BigInt(8 * i)) & 0xffn)
  return tag
}

const warpLE64 = (n: number): Buffer => {
  const b = Buffer.alloc(8)
  b.writeBigUInt64LE(BigInt(n) & 0xffffffffffffffffn, 0)
  return b
}

/** RFC 8439 AEAD_CHACHA20_POLY1305 seal (ct || 16B tag) */
function chacha20AeadSeal(key: Buffer, plain: Buffer, aad: Buffer, nonce: Buffer): Buffer {
  const polyKey = chacha20Block(key, 0, nonce).subarray(0, 32)
  const ct = chacha20Xor(key, 1, nonce, plain) // data blocks start at counter 1
  const macData = Buffer.concat([
    aad,
    Buffer.alloc((16 - (aad.length % 16)) % 16), // pad16
    ct,
    Buffer.alloc((16 - (ct.length % 16)) % 16), // pad16
    warpLE64(aad.length),
    warpLE64(ct.length),
  ])
  return Buffer.concat([ct, poly1305(polyKey, macData)])
}

/** WG Noise seal — AEAD with the all-zero 12-byte nonce (counter 0) */
function warpSeal(key: Buffer, plain: Buffer, aad: Buffer): Buffer {
  return chacha20AeadSeal(key, plain, aad, Buffer.alloc(12))
}

// ---------------- hash chaining (Noise-IKpsk2 style) ----------------
const warpH = (data: Buffer): Buffer => blake2s(data, 32)
function warpKDF2(chain: Buffer, input: Buffer): { c: Buffer; k: Buffer } {
  return {
    c: blake2s(input, 32, Buffer.concat([chain, Buffer.from([1])])),
    k: blake2s(input, 32, Buffer.concat([chain, Buffer.from([2])])),
  }
}

const warpLE32 = (n: number): Buffer => {
  const b = Buffer.alloc(4)
  b.writeUInt32LE(n >>> 0, 0)
  return b
}

/**
 * Build a 148-byte WireGuard handshake initiation (message_type=1) exactly per
 * the Noise-IKpsk2 spec: type+reserved(4) · sender(4) · ephemeral(32) ·
 * enc-static(48) · enc-timestamp(28) · mac1(16) · mac2 zero-filled(16).
 * A fresh ephemeral key + TAI64N timestamp is generated on EVERY call.
 */
function warpBuildInitiation(clientStaticPrivRaw: Buffer, clientStaticPubRaw: Buffer, serverPubRaw: Buffer): Buffer {
  // 1-4. protocol + noise labels, then chain the responder's static public key
  let c = warpH(Buffer.from('WireGuard v1 zx2c4 Jason@zx2c4.com', 'utf8'))
  let h = warpH(Buffer.from('Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s', 'utf8'))
  h = warpH(Buffer.concat([h, Buffer.alloc(32)]))
  h = warpH(Buffer.concat([h, serverPubRaw]))
  // 5-7. ephemeral keypair, DH1, KDF2
  const eph = warpGenerateKeypair()
  const dh1 = crypto.diffieHellman({
    privateKey: warpRawToPrivKeyObject(clientStaticPrivRaw),
    publicKey: warpRawToPubKeyObject(serverPubRaw),
  })
  let k: Buffer
  ;({ c, k } = warpKDF2(c, dh1))
  // 8-9. chain the ephemeral public key, encrypt our static public key (48B)
  h = warpH(Buffer.concat([h, eph.pubRaw]))
  const encStatic = warpSeal(k, clientStaticPubRaw, h)
  // 10. KDF2 with our static public key
  ;({ c, k } = warpKDF2(c, clientStaticPubRaw))
  // 11-12. TAI64N timestamp (8B big-endian secs + 0x400000000000000a, 4B nanos)
  const tai64n = Buffer.alloc(12)
  tai64n.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000)) + 0x400000000000000an, 0)
  tai64n.writeUInt32BE(Math.min(999999999, (Date.now() % 1000) * 1_000_000), 8)
  const encTs = warpSeal(k, tai64n, h)
  // 13. packet body — 116B (LE32(1) covers type=1 + 3 reserved zero bytes)
  const packet = Buffer.concat([warpLE32(1), warpLE32(crypto.randomInt(0, 0x100000000)), eph.pubRaw, encStatic, encTs])
  // 14-15. mac1 (keyed blake2s with HASH(LABEL_MAC1 || server pubkey)) + zero mac2
  const mac1 = blake2s(packet, 16, blake2s(Buffer.concat([Buffer.from('mac1----', 'utf8'), serverPubRaw]), 32))
  return Buffer.concat([packet, mac1, Buffer.alloc(16)]) // 148B
}

// ---------------- WARP identity (lazy, once per boot, on first warp:start) ---
interface WarpIdentity {
  privRaw: Buffer
  pubRaw: Buffer
}
/** the widely-published public Cloudflare WARP peer key (fallback when unregistered) */
const WARP_FALLBACK_SERVER_PUB = Buffer.from('bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 'base64')
let warpIdentity: WarpIdentity | null = null
let warpRegistered = false
let warpServerPub: Buffer = WARP_FALLBACK_SERVER_PUB

/** best-effort registration — never throws, never logs private keys */
async function warpInitIdentity(): Promise<void> {
  if (warpIdentity) return
  try {
    const kp = warpGenerateKeypair()
    warpIdentity = kp // raw keys live in memory ONLY
    console.log('[warp] identity attempt — generating X25519 keypair + registering with api.cloudflareclient.com … / در حال ساخت هویت و ثبت در کلادفلر …')
    const res = await fetch('https://api.cloudflareclient.com/v0a2158/reg', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'okhttp/3.12.1' },
      body: JSON.stringify({
        key: kp.pubRaw.toString('base64'),
        install_id: '',
        fcm_token: '',
        tos: new Date().toISOString(),
        model: 'PC',
        locale: 'en_US',
        timezone: 'Europe/Berlin',
      }),
      signal: AbortSignal.timeout(8000),
    })
    if (res.ok) {
      const j = (await res.json().catch(() => null)) as { config?: { peers?: { public_key?: unknown }[] } } | null
      const pk = j?.config?.peers?.[0]?.public_key
      const parsed = typeof pk === 'string' ? Buffer.from(pk, 'base64') : null
      if (parsed && parsed.length === 32) {
        warpServerPub = parsed
        warpRegistered = true
        console.log('[warp] identity result — REGISTERED (peer key acquired) — real handshakes possible / هویت ثبت شد — هندشیک واقعی ممکن است')
        return
      }
      console.warn('[warp] identity result — registration response had no usable peer key / پاسخ ثبت کلید معتبر نداشت')
    } else {
      console.warn(`[warp] identity result — registration failed (HTTP ${res.status}) / ثبت ناموفق (کد ${res.status})`)
    }
  } catch (e) {
    console.warn(`[warp] identity result — registration error: ${e instanceof Error ? e.message : String(e)} / خطای ثبت هویت`)
  }
  // non-fatal degrade — scanner machinery still runs, verdicts stay honest
  warpRegistered = false
  warpServerPub = WARP_FALLBACK_SERVER_PUB
  console.warn('[warp] continuing UNREGISTERED with the public WARP server key — endpoints may silently drop initiations / بدون هویت با کلید عمومی پیش‌فرض ادامه می‌دهیم — اکثر نقاط بی‌پاسخ خواهند بود')
}

// ---------------- scanner state (module singleton, mirrors the hunt) ---------
const WARP_FOUND_CAP = 200
const WARP_RECENT_CAP = 12
const WARP_SOCKET_CAP = 64 // hard socket ceiling — concurrency clamps to this
const WARP_DEFAULT_PORTS = [2408, 500, 1701, 4500]

interface WarpEp {
  endpoint: string
  ip: string
  port: number
  range: string
}

let warpSt: WarpScanState = {
  running: false,
  finished: false,
  stopped: false,
  tested: 0,
  alive: 0,
  planned: 0,
  target: 20,
  startedAt: null,
  elapsedMs: 0,
  epsPerSecond: 0,
  found: [],
  recent: [],
  ranges: WARP_RANGES.map((r) => r.cidr),
  ports: [...WARP_DEFAULT_PORTS],
  concurrency: 64,
  registered: false,
}
let warpRunning = false
let warpStopFlag = false
let warpTried = new Set<string>()
let warpStamps: number[] = [] // rolling eps window (like the hunt's stamps)
let warpSockets: dgram.Socket[] = []

const warpEps = (): number => {
  const now = Date.now()
  warpStamps = warpStamps.filter((t) => now - t < 3000)
  return warpStamps.length >= 2
    ? Math.round((warpStamps.length / Math.min(3000, now - warpStamps[0])) * 1000)
    : 0
}

const WARP_HISTORY_FILE = path.join(import.meta.dir, '..', '..', 'db', 'warp-history.json')

/** v7.4 — append the finished WARP scan to db/warp-history.json (hunt-history parity). File-level authoritative: re-reads before every append so API deletions survive. */
function persistWarpHistory(opts: { custom: boolean; exhausted: boolean }) {
  if (warpSt.tested <= 0) return
  try {
    fs.mkdirSync(path.dirname(WARP_HISTORY_FILE), { recursive: true })
    let runs: WarpHistoryRun[] = []
    try {
      const raw = JSON.parse(fs.readFileSync(WARP_HISTORY_FILE, 'utf8'))
      if (Array.isArray(raw)) runs = raw.slice(0, WARP_HISTORY_MAX_RUNS)
    } catch {}
    runs.unshift({
      id: `warp-${warpSt.startedAt ?? Date.now()}`,
      startedAt: warpSt.startedAt ?? Date.now(),
      finishedAt: Date.now(),
      target: warpSt.target,
      stopped: warpSt.stopped,
      tested: warpSt.tested,
      alive: warpSt.alive,
      planned: warpSt.planned,
      exhausted: opts.exhausted === true ? true : undefined,
      eps: warpSt.epsPerSecond,
      ports: [...warpSt.ports],
      ranges: [...warpSt.ranges],
      custom: opts.custom === true ? true : undefined,
      registered: warpRegistered === true ? true : undefined,
      found: warpSt.found.slice(0, WARP_HISTORY_FOUND_CAP),
      error: warpSt.error || undefined,
    })
    fs.writeFileSync(WARP_HISTORY_FILE, JSON.stringify(runs.slice(0, WARP_HISTORY_MAX_RUNS)))
    console.log(`[warp] history persisted — ${runs.length} run(s) on file / تاریخچه WARP ذخیره شد`)
  } catch (e) {
    console.error('[warp] history persist failed:', e)
  }
}

/** fresh snapshot per call (found ≤200, recent ≤12, live registered flag) */
function warpScanSnapshot(): WarpScanState {
  return {
    ...warpSt,
    elapsedMs: warpSt.startedAt && warpSt.running ? Date.now() - warpSt.startedAt : warpSt.elapsedMs,
    epsPerSecond: warpEps(),
    found: warpSt.found.slice(0, WARP_FOUND_CAP),
    recent: warpSt.recent.slice(-WARP_RECENT_CAP),
    // honest: the effective ranges of the last/current scan (canonical at module init, overridden per scan)
    ranges: [...warpSt.ranges],
    ports: [...warpSt.ports],
    concurrency: warpSt.concurrency,
    registered: warpRegistered,
  }
}

/** v6.6 — clean user-supplied /24 CIDRs: strings only, exact a.b.c.0/24 shape (WARP_RANGE_RE), trimmed, deduped, capped at WARP_CUSTOM_RANGES_CAP. Zero valid entries ⇒ [] (caller falls back to canonical WARP_RANGES). */
function normalizeWarpRanges(raw?: unknown): string[] {
  const src = raw as { ranges?: unknown } | undefined
  const req = Array.isArray(src?.ranges) ? (src.ranges as unknown[]) : []
  const seen = new Set<string>()
  const out: string[] = []
  for (const entry of req.slice(0, 128)) {
    if (typeof entry !== 'string') continue
    const cidr = entry.trim()
    if (!WARP_RANGE_RE.test(cidr)) continue // strict a.b.c.0/24 (regex already bounds octets 0..255)
    if (seen.has(cidr)) continue
    seen.add(cidr)
    out.push(cidr)
    if (out.length >= WARP_CUSTOM_RANGES_CAP) break // silently drop beyond cap
  }
  return out
}

function normalizeWarpSettings(raw?: Partial<WarpScanSettings>) {
  const seen = new Set<number>()
  const ports: number[] = []
  const req = Array.isArray(raw?.ports) ? (raw.ports as unknown[]) : []
  for (const p of req.slice(0, 24)) {
    const n = Math.floor(Number(p))
    if (!Number.isFinite(n) || !WARP_UDP_PORTS.includes(n)) continue // only known WARP ports
    if (seen.has(n)) continue
    seen.add(n)
    ports.push(n)
    if (ports.length >= 8) break
  }
  return {
    target: clampInt(raw?.target, 1, 200, 20),
    ports: ports.length > 0 ? ports : [...WARP_DEFAULT_PORTS],
    concurrency: Math.min(clampInt(raw?.concurrency, 32, 1024, 64), 128), // ≤128, sockets cap at 64
    timeoutMs: clampInt(raw?.timeoutMs, 500, 3000, 1200),
    ranges: normalizeWarpRanges(raw), // [] ⇒ canonical ranges (legacy-safe)
  }
}

/** ranges × 256 host octets × active ports (canonical 7 ⇒ 1792 × ports; custom ≤16 ⇒ ≤4096 × ports) */
function warpBuildUniverse(ranges: string[], ports: number[]): WarpEp[] {
  const out: WarpEp[] = []
  for (const cidr of ranges) {
    const prefix = (cidr.split('/')[0] ?? cidr).split('.').slice(0, 3).join('.')
    for (let o = 0; o < 256; o++) {
      const ip = `${prefix}.${o}`
      for (const port of ports) out.push({ endpoint: `${ip}:${port}`, ip, port, range: cidr })
    }
  }
  return out
}

/** Fisher–Yates with crypto.randomInt — probe order is unpredictable */
function warpShuffle<T>(arr: T[]): T[] {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1)
    const tmp = arr[i]
    arr[i] = arr[j]
    arr[j] = tmp
  }
  return arr
}

function warpMakeSocket(): dgram.Socket | null {
  try {
    const sock = dgram.createSocket('udp4')
    // surface send errors via the callback instead of crashing the process
    sock.on('error', () => {})
    try {
      sock.bind(0, '0.0.0.0') // ephemeral port; send() is queued until bound
    } catch {
      /* implicit bind on send */
    }
    warpSockets.push(sock)
    return sock
  } catch {
    return null
  }
}

interface WarpProbeResult {
  alive: boolean
  sockDead: boolean
  kind?: 'handshake' | 'cookie'
  rttMs?: number
}

/** send one initiation → await exactly one matching response datagram (or timeout) */
function warpProbeOnce(sock: dgram.Socket, ep: WarpEp, initiation: Buffer, timeoutMs: number): Promise<WarpProbeResult> {
  return new Promise((resolve) => {
    let settled = false
    const sentAt = Date.now()
    const finish = (alive: boolean, sockDead = false, kind?: 'handshake' | 'cookie') => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      sock.removeListener('message', onMsg)
      resolve({ alive, sockDead, kind, rttMs: alive ? Date.now() - sentAt : undefined })
    }
    const onMsg = (msg: Buffer, rinfo: dgram.RemoteInfo) => {
      if (rinfo.address !== ep.ip || rinfo.port !== ep.port) return // not our endpoint
      const kind: 'handshake' | 'cookie' | undefined =
        msg.length > 0 && msg[0] === 2 ? 'handshake' : msg.length > 0 && msg[0] === 3 ? 'cookie' : undefined
      if (!kind) return // not a WireGuard response — keep waiting
      finish(true, false, kind)
    }
    const timer = setTimeout(() => finish(false), timeoutMs)
    sock.on('message', onMsg)
    sock.send(initiation, ep.port, ep.ip, (err) => {
      if (err) finish(false, true) // send failed — socket is suspect
    })
  })
}

function warpRecordAlive(ep: WarpEp, kind: 'handshake' | 'cookie', rttMs: number): void {
  warpSt.alive++
  const entry: WarpEndpoint = {
    endpoint: ep.endpoint,
    ip: ep.ip,
    port: ep.port,
    rttMs,
    response: kind,
    range: ep.range,
    attempts: 1,
  }
  if (warpSt.found.length < WARP_FOUND_CAP) warpSt.found.push(entry)
  warpSt.recent.push(entry)
  if (warpSt.recent.length > WARP_RECENT_CAP) warpSt.recent.shift()
}

async function runWarpScan(settings: { target: number; ports: number[]; concurrency: number; timeoutMs: number; ranges: string[]; custom: boolean }): Promise<void> {
  const universe = warpShuffle(warpBuildUniverse(settings.ranges, settings.ports))
  warpSt.planned = universe.length
  warpSt.concurrency = Math.max(1, Math.min(settings.concurrency, WARP_SOCKET_CAP))
  // ≈4 ticks/s broadcast while running + a final broadcast — hunt-ticker cadence
  const ticker = setInterval(() => {
    if (!warpRunning) return
    warpSt.elapsedMs = Date.now() - (warpSt.startedAt ?? Date.now())
    io.emit('warp:state', warpScanSnapshot())
  }, 250)
  let universeExhausted = false
  try {
    await warpInitIdentity() // lazy once per boot; registration is best-effort
    if (warpStopFlag) return
    if (!warpIdentity) {
      warpSt.error = 'X25519 identity generation failed / ساخت هویت X25519 ناموفق بود'
      console.error('[warp] aborted — no X25519 identity available / بدون هویت متوقف شد')
      return
    }
    console.log(
      `[warp] probing ${universe.length} endpoint(s) (${settings.ranges.length} ranges × 256 × ${settings.ports.length} ports) with ${warpSt.concurrency} socket(s) · timeout ${settings.timeoutMs}ms — ${warpRegistered ? 'REGISTERED identity' : 'UNREGISTERED (public key) — most endpoints may silently drop'}${settings.custom ? ' · custom' : ''}`,
    )
    let next = 0 // shared cursor — the universe is the plan
    const worker = async (wid: number): Promise<void> => {
      let sock = warpMakeSocket()
      if (!sock) return
      let sockErrors = 0
      try {
        while (!warpStopFlag && warpSt.alive < settings.target && next < universe.length) {
          const ep = universe[next++]
          if (!ep) break
          warpTried.add(ep.endpoint)
          // fresh initiation per probe — new ephemeral, sender index, timestamp
          const initiation = warpBuildInitiation(warpIdentity.privRaw, warpIdentity.pubRaw, warpServerPub)
          const r = await warpProbeOnce(sock, ep, initiation, settings.timeoutMs)
          warpSt.tested++
          warpStamps.push(Date.now())
          if (r.alive && r.kind) warpRecordAlive(ep, r.kind, r.rttMs ?? 0)
          if (r.sockDead) {
            // recreate once; a second error drops this worker
            try {
              sock.close()
            } catch {}
            const idx = warpSockets.indexOf(sock)
            if (idx >= 0) warpSockets.splice(idx, 1)
            sockErrors++
            if (sockErrors >= 2) {
              console.warn(`[warp] worker #${wid} dropped after 2 socket errors / کارگر #${wid} پس از ۲ خطای سوکت حذف شد`)
              return
            }
            const fresh = warpMakeSocket()
            if (!fresh) {
              console.warn(`[warp] worker #${wid} dropped — socket factory failed / کارگر #${wid} حذف شد`)
              return
            }
            sock = fresh
          }
        }
      } finally {
        try {
          sock.close()
        } catch {}
        const idx = warpSockets.indexOf(sock)
        if (idx >= 0) warpSockets.splice(idx, 1)
      }
    }
    await Promise.all(Array.from({ length: warpSt.concurrency }, (_, i) => worker(i)))
    universeExhausted = next >= universe.length
  } catch (e) {
    warpSt.error = e instanceof Error ? e.message : String(e)
    console.error('[warp] scan crashed:', warpSt.error)
  } finally {
    clearInterval(ticker)
    // cleanup — every dgram socket dies with the run, no strays
    for (const s of warpSockets.splice(0, warpSockets.length)) {
      try {
        s.close()
      } catch {}
    }
    warpRunning = false
    warpSt.running = false
    warpSt.finished = true
    warpSt.stopped = warpStopFlag
    warpSt.elapsedMs = Date.now() - (warpSt.startedAt ?? Date.now())
    warpSt.concurrency = 0
    warpSt.epsPerSecond = warpEps()
    persistWarpHistory({ custom: settings.custom, exhausted: universeExhausted })
    io.emit('warp:state', warpScanSnapshot())
    const suffix = warpSt.stopped ? ' (stopped by user)' : universeExhausted ? ' (universe exhausted)' : ''
    console.log(
      `[warp] finished — tested ${warpSt.tested} · alive ${warpSt.alive} · eps ${warpSt.epsPerSecond} · ports ${warpSt.ports.join('/')}${suffix}`,
    )
    console.log(
      `[warp] پایان اسکن — آزموده ${warpSt.tested} · زنده ${warpSt.alive} · سرعت ${warpSt.epsPerSecond}/ثانیه · پورت‌ها ${warpSt.ports.join('/')}${warpSt.stopped ? ' (توسط کاربر متوقف شد)' : universeExhausted ? ' (فضای جست‌وجو تمام شد)' : ''}`,
    )
    warpStopFlag = false
  }
}

/**
 * Start the WARP scan. MUST stay synchronous (same trap as startGoogleHunt —
 * acking a Promise would deliver `{}` to the client instead of the state).
 */
function startWarpScan(raw?: Partial<WarpScanSettings>): WarpScanState {
  warpRunSelfTest() // lazy once — a broken blake2s degrades to an error ack
  if (warpRunning) return warpScanSnapshot()
  if (!warpCryptoOk) {
    warpSt.running = false
    warpSt.finished = true
    warpSt.stopped = false
    warpSt.error = 'WARP crypto self-test failed — keyed BLAKE2s is broken on this runtime / تست رمزنگاری WARP ناموفق بود — اسکن غیرفعال است'
    io.emit('warp:state', warpScanSnapshot())
    return warpScanSnapshot()
  }
  const settings = normalizeWarpSettings(raw)
  // v6.6 — non-empty custom /24 ranges override the canonical 7 (legacy-safe: absent/empty ⇒ canonical)
  const effectiveRanges = settings.ranges.length > 0 ? settings.ranges : WARP_RANGES.map((r) => r.cidr)
  warpRunning = true
  warpSt.running = true
  warpSt.finished = false
  warpSt.stopped = false
  warpSt.error = undefined
  warpSt.tested = 0
  warpSt.alive = 0
  warpSt.planned = 0
  warpSt.target = settings.target
  warpSt.startedAt = Date.now()
  warpSt.elapsedMs = 0
  warpSt.epsPerSecond = 0
  warpSt.found = []
  warpSt.recent = []
  warpSt.ports = [...settings.ports]
  warpSt.ranges = [...effectiveRanges] // set BEFORE the first broadcast so the snapshot is honest
  warpSt.concurrency = Math.max(1, Math.min(settings.concurrency, WARP_SOCKET_CAP))
  warpStopFlag = false
  warpTried = new Set<string>()
  warpStamps = []
  io.emit('warp:state', warpScanSnapshot())
  console.log(
    `[warp] start — target ${settings.target} · ports ${settings.ports.join('/')} · concurrency ${warpSt.concurrency} · timeout ${settings.timeoutMs}ms · registered ${warpRegistered ? 'yes' : 'no (will try)'} / شروع اسکن WARP`,
  )
  void runWarpScan({ ...settings, ranges: effectiveRanges, custom: settings.ranges.length > 0 })
  return warpScanSnapshot()
}

function stopWarpScan(): WarpScanState | null {
  if (warpRunning) {
    warpStopFlag = true
    console.log('[warp] stop requested / توقف درخواست شد')
  }
  return warpScanSnapshot()
}

function resetWarpScan(): WarpScanState | null {
  if (warpRunning) return warpScanSnapshot() // only while idle
  // NOTE: warpSt.ranges intentionally left as-is — reset clears found/recent counters only (last scan's ranges stay honest)
  warpSt.found = []
  warpSt.recent = []
  warpSt.tested = 0
  warpSt.alive = 0
  warpSt.planned = 0
  warpSt.target = 20
  warpSt.finished = false
  warpSt.stopped = false
  warpSt.error = undefined
  warpSt.startedAt = null
  warpSt.elapsedMs = 0
  warpSt.epsPerSecond = 0
  warpTried = new Set<string>()
  warpStamps = []
  return warpScanSnapshot()
}

// ------------------------------------------------------------------ server
const httpServer = createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({
    ok: true,
    service: 'scan-service',
    running: !!(job && !job.summary),
    auto: autoSnapshot(),
    queue: { total: queue.length, waiting: queue.filter((i) => i.status === 'waiting').length },
  }))
})

io.attach(httpServer)

// restore the schedulers + queue + hunt knowledge + recon before accepting connections
loadAuto()
loadHuntSchedule()
loadQueue()
loadHuntKnowledge()
loadReconFile()
// pull Google's published ranges shortly after boot, then refresh on a 6h TTL
setTimeout(() => void refreshHuntRecon(), 2000)
setInterval(() => {
  if (Date.now() - recon.updatedAt > RECON_TTL_MS) void refreshHuntRecon()
}, 15 * 60_000)

io.on('connection', (socket) => {
  // v7.0 integration — socket.io serializes a MISSING ack argument to null over
  // the wire; a bare `cb(...)` then throws TypeError and (unhandled) takes the
  // whole engine down (observed live during v7.0 QA). Wrapping every handler
  // registration guarantees the handler's declared params are always callable:
  // any null/undefined slot inside the handler's DECLARED ARITY (fn.length)
  // becomes a no-op function. This covers both malformed shapes:
  //   emit(ev)                    → handler(cb) gets cb=undefined
  //   emit(ev, undefined, ack)    → handler(cb) gets cb=null (+ an ignored ack)
  // Real payloads pass through untouched; no-arg handlers (fn.length 0) are
  // never padded. (The v7.0 hunt-schedule handlers additionally self-guard.)
  const rawOn = socket.on.bind(socket) as (ev: string, fn: (...a: unknown[]) => void) => void
  socket.on = ((ev: string, fn: (...a: unknown[]) => void) => {
    rawOn(ev, (...a: unknown[]) => {
      for (let i = 0; i < fn.length; i++) {
        if (a[i] === null || a[i] === undefined) a[i] = () => {}
      }
      return fn(...a)
    })
  }) as typeof socket.on
  socket.on('scan:start', (cfg) => {
    startScan(cfg ?? {})
  })
  socket.on('scan:stop', () => stopScan())
  socket.on('scan:state', (cb) => {
    cb({
      running: !!(job && !job.summary),
      summary: job?.summary ?? null,
      progress: job?.progress ?? null,
      results: job ? (job.summary ? job.summary.results : job.results) : [],
      logs: job?.logs ?? [],
    })
  })
  socket.on('auto-scan:state', (cb) => cb(autoSnapshot()))
  socket.on('auto-scan:set', (payload: AutoScanSetPayload, ack) => {
    try {
      const enabled = !!payload?.enabled
      const intervalMinutes = clampInt(payload?.intervalMinutes, AUTO_MIN_INTERVAL_MIN, AUTO_MAX_INTERVAL_MIN, auto.intervalMinutes)
      if (payload?.config) auto.config = normalizeConfig(payload.config)
      if (payload?.notifyUrl != null) {
        auto.notifyUrl = String(payload.notifyUrl).trim().slice(0, 500)
      }
      auto.intervalMinutes = intervalMinutes
      auto.enabled = enabled && !!auto.config
      if (auto.enabled) {
        auto.nextRunAt = Date.now() + auto.intervalMinutes * 60_000
        scheduleAuto()
        log('info', `⏰ اسکن خودکار فعال شد — هر ${auto.intervalMinutes} دقیقه${auto.notifyUrl ? ' | وب‌هوک فعال' : ''}`, `⏰ Auto-scan enabled — every ${auto.intervalMinutes} min${auto.notifyUrl ? ' | webhook on' : ''}`)
      } else {
        unscheduleAuto()
        log('info', '⏰ اسکن خودکار غیرفعال شد', '⏰ Auto-scan disabled')
      }
      persistAuto()
      broadcastAutoState()
      ack(autoSnapshot())
    } catch {
      ack(autoSnapshot())
    }
  })
  socket.on('auto-scan:notify-test', (url, ack) => {
    const u = typeof url === 'string' ? url.trim().slice(0, 500) : ''
    if (!u || !/^https?:\/\//i.test(u)) {
      ack({ ok: false, error: 'invalid url' })
      return
    }
    void sendWebhook(u, {
      event: 'notify-test',
      service: 'clean-ip-scanner-web',
      ts: Date.now(),
      message: 'Clean IP Scanner — webhook test ✔',
    }).then((ok) => {
      log(
        ok ? 'success' : 'warn',
        ok ? `📣 وب‌هوک تست ارسال شد (${u})` : `📣 ارسال وب‌هوک تست ناموفق بود (${u})`,
        ok ? `📣 Test webhook sent (${u})` : `📣 Test webhook failed (${u})`,
      )
      ack({ ok, error: ok ? undefined : 'request failed' })
    })
  })
  socket.on('telegram:set', (payload, ack) => {
    try {
      if (payload?.token != null) auto.telegramToken = String(payload.token).trim().slice(0, 200)
      if (payload?.chatId != null) auto.telegramChatId = String(payload.chatId).trim().slice(0, 100)
      if (payload?.digest === true || payload?.digest === false) {
        auto.telegramDigest = payload.digest
        // switching digest OFF flushes anything buffered so nothing is lost
        if (!auto.telegramDigest && queueDigestBuffer.length > 0) void flushQueueDigest()
      }
      persistAuto()
      broadcastAutoState()
      ack(autoSnapshot())
    } catch {
      ack(autoSnapshot())
    }
  })
  socket.on('telegram:test', async (ack) => {
    if (!auto.telegramToken || !auto.telegramChatId) {
      ack({ ok: false, error: 'not configured' })
      return
    }
    const r = await sendTelegramMessage(
      '🧪 <b>Clean IP Scanner</b>\nپیام آزمایشی — اتصال تلگرام برقرار است ✔',
    )
    log(
      r.ok ? 'success' : 'warn',
      r.ok
        ? `📣 پیام آزمایشی تلگرام ارسال شد (chat ${auto.telegramChatId})`
        : `📣 ارسال تلگرام آزمایشی ناموفق بود${r.error ? ` — ${r.error}` : ''}`,
      r.ok
        ? `📣 Telegram test message sent (chat ${auto.telegramChatId})`
        : `📣 Telegram test failed${r.error ? ` — ${r.error}` : ''}`,
    )
    ack({ ok: r.ok, status: r.status, error: r.error })
  })
  socket.on('queue:add', (payload, ack) => {
    try {
      const cfg = normalizeConfig(payload?.config ?? {})
      const label = String(payload?.label ?? '').trim().slice(0, 80) || presetLabelFa(cfg.preset)
      const item: QueueItem = {
        id: Math.random().toString(36).slice(2),
        label,
        config: cfg,
        addedAt: Date.now(),
        status: 'waiting',
      }
      queue.push(item)
      if (queue.length > QUEUE_MAX_ITEMS) queue.splice(0, queue.length - QUEUE_MAX_ITEMS)
      persistQueue()
      broadcastQueueState()
      const waiting = queue.filter((i) => i.status === 'waiting').length
      log('info', `➕ به صف اضافه شد: ${label} — ${waiting} آیتم در انتظار`, `➕ Added to queue: ${label} — ${waiting} item(s) waiting`)
      setTimeout(() => processQueue(), 100)
      ack(queueSnapshot())
    } catch {
      ack(queueSnapshot())
    }
  })
  socket.on('queue:remove', (id, ack) => {
    const idx = queue.findIndex((i) => i.id === id && i.status !== 'running')
    if (idx >= 0) {
      const [removed] = queue.splice(idx, 1)
      persistQueue()
      broadcastQueueState()
      log('info', `➖ از صف حذف شد: ${removed?.label ?? id}`, `➖ Removed from queue: ${removed?.label ?? id}`)
    }
    ack(queueSnapshot())
  })
  socket.on('queue:clear', (ack) => {
    const kept = queue.filter((i) => i.status === 'running')
    const removed = queue.length - kept.length
    queue.splice(0, queue.length, ...kept)
    persistQueue()
    broadcastQueueState()
    if (removed > 0) log('info', `🧹 صف پاک شد — ${removed} آیتم حذف شد`, `🧹 Queue cleared — ${removed} item(s) removed`)
    ack(queueSnapshot())
  })
  socket.on('queue:state', (cb) => cb(queueSnapshot()))
  socket.on('queue:move', (payload, ack) => {
    const id = String(payload?.id ?? '')
    const dir = payload?.dir === 1 ? 1 : -1
    const idx = queue.findIndex((i) => i.id === id)
    if (idx >= 0 && queue[idx]!.status === 'waiting') {
      // swap with the nearest neighbour that is also waiting (skips finished/running/disabled)
      let j = idx + dir
      while (j >= 0 && j < queue.length && queue[j]!.status !== 'waiting') j += dir
      if (j >= 0 && j < queue.length) {
        const [moved] = queue.splice(idx, 1)
        queue.splice(j, 0, moved!)
        persistQueue()
        broadcastQueueState()
        log('info', `↕️ ترتیب صف تغییر کرد: ${moved!.label}`, `↕️ Queue order changed: ${moved!.label}`)
      }
    }
    ack(queueSnapshot())
  })
  socket.on('queue:reorder', (payload, ack) => {
    const id = String(payload?.id ?? '')
    let index = clampInt(payload?.index, 0, queue.length - 1, -1)
    const idx = queue.findIndex((i) => i.id === id)
    if (idx >= 0 && index >= 0 && queue[idx]!.status === 'waiting') {
      const [moved] = queue.splice(idx, 1)
      // after removal the clamp may shift — re-clamp and keep waiting neighbours intact
      index = Math.min(index, queue.length)
      queue.splice(index, 0, moved!)
      persistQueue()
      broadcastQueueState()
      log('info', `↕️ ترتیب صف تغییر کرد: ${moved!.label}`, `↕️ Queue order changed: ${moved!.label}`)
    }
    ack(queueSnapshot())
  })
  socket.on('queue:toggle', (id, ack) => {
    const item = queue.find((i) => i.id === id && i.status === 'waiting')
    if (item) {
      item.enabled = item.enabled === false // default is enabled; flip
      persistQueue()
      broadcastQueueState()
      log(
        'info',
        item.enabled ? `▶️ آیتم صف فعال شد: ${item.label}` : `⏸️ آیتم صف موقتاً غیرفعال شد: ${item.label}`,
        item.enabled ? `▶️ Queue item enabled: ${item.label}` : `⏸️ Queue item paused: ${item.label}`,
      )
    }
    ack(queueSnapshot())
  })
  // edit a waiting queue item in place (label + scan config) — no remove/re-add needed
  socket.on('queue:update', (payload, ack) => {
    try {
      const id = String(payload?.id ?? '')
      const item = queue.find((i) => i.id === id && i.status === 'waiting')
      if (item) {
        if (payload?.label !== undefined) {
          const label = String(payload.label).trim().slice(0, 80)
          if (label) item.label = label
        }
        if (payload?.config && typeof payload.config === 'object') {
          // merge partial over the stored config; normalizeConfig re-clamps every field
          item.config = normalizeConfig({ ...item.config, ...payload.config })
        }
        persistQueue()
        broadcastQueueState()
        log('info', `✏️ آیتم صف ویرایش شد: ${item.label} — پورت ${item.config.port} · ${item.config.maxIPs} IP`, `✏️ Queue item updated: ${item.label} — port ${item.config.port} · ${item.config.maxIPs} IPs`)
      }
      ack(queueSnapshot())
    } catch {
      ack(queueSnapshot())
    }
  })
  socket.on('xray:probe', (payload: XrayProbeRequest, ack) => {
    void xrayProbe(payload ?? { ip: '', port: 443, host: 'speed.cloudflare.com' })
      .then((r) => {
        if (r.ok) {
          log(
            r.grade === 'excellent' || r.grade === 'good' ? 'success' : 'warn',
            `🔎 پروب Xray ${r.ip} — TLS ${r.tlsMs ?? '?'}ms · HTTP ${r.httpStatus ?? '—'} · ${r.cert?.subjectCN ?? '—'}`,
            `🔎 Xray probe ${r.ip} — TLS ${r.tlsMs ?? '?'}ms · HTTP ${r.httpStatus ?? '—'} · ${r.cert?.subjectCN ?? '—'}`,
          )
        } else {
          log('warn', `🔎 پروب Xray ${payload?.ip ?? '?'} ناموفق: ${r.error ?? 'unknown'}`, `🔎 Xray probe ${payload?.ip ?? '?'} failed: ${r.error ?? 'unknown'}`)
        }
        ack(r)
      })
      .catch(() =>
        ack({ ok: false, ip: String(payload?.ip ?? ''), host: 'speed.cloudflare.com', port: 443, error: 'probe crashed' }),
      )
  })
  socket.on('ping:rtt', (cb) => cb(Date.now()))
  // ----- standalone Google-friendly IP hunter (independent of the scan pipeline) -----
  socket.on('google-hunt:start', (payload, ack) => {
    ack(startGoogleHunt(payload ?? undefined))
  })
  socket.on('google-hunt:stop', (ack) => {
    ack(stopGoogleHunt())
  })
  socket.on('google-hunt:reset', (ack) => {
    ack(resetGoogleHunt())
  })
  socket.on('google-hunt:state', (cb) => cb(huntSnapshot()))
  // ----- hunt recon (reverse-engineered Google intelligence) -----
  socket.on('google-hunt:recon', (cb) => cb(reconSnapshot()))
  // ack MUST stay synchronous (same trap as hunt:start) — the real refresh
  // runs async and pushes updates via the google-hunt:recon broadcast
  socket.on('google-hunt:recon:refresh', (ack) => {
    void refreshHuntRecon()
    ack(reconSnapshot())
  })
  // ----- v7.0 — engine-side hunt scheduler -----
  // ack MUST stay synchronous (same trap as hunt:start) — setHuntSchedule is
  // fully sync so the client receives the fresh snapshot, never a serialized Promise
  socket.on('hunt-schedule:set', (payload, ack) => {
    try {
      if (typeof ack === 'function') ack(setHuntSchedule(payload))
    } catch {
      // never crash the engine on a malformed client — best-effort snapshot
      if (typeof ack === 'function') ack(huntScheduleSnapshot())
    }
  })
  // typeof guard: socket.io serializes a missing ack arg to null over the wire —
  // a bare cb(...) would throw and (unhandled) take the engine down (observed live)
  socket.on('hunt-schedule:state', (cb) => {
    if (typeof cb === 'function') cb(huntScheduleSnapshot())
  })
  // ----- WARP endpoint scanner (hunt v6.2 — WireGuard UDP probing) -----
  socket.on('warp:start', (payload, ack) => {
    ack(startWarpScan(payload ?? undefined))
  })
  socket.on('warp:stop', (ack) => {
    ack(stopWarpScan())
  })
  socket.on('warp:reset', (ack) => {
    ack(resetWarpScan())
  })
  socket.on('warp:state', (cb) => cb(warpScanSnapshot()))
  socket.on('check:ips', (payload: IpCheckPayload, ack) => {
    try {
      const ips = (Array.isArray(payload?.ips) ? payload.ips : [])
        .filter((ip): ip is string => typeof ip === 'string' && net.isIP(ip) !== 0)
        .slice(0, 50)
      const port = clampInt(payload?.port, 1, 65535, 443)
      const pingCount = clampInt(payload?.pingCount, 1, 6, 3)
      const timeoutMs = clampInt(payload?.timeoutMs, 200, 5000, 1500)
      if (ips.length === 0) {
        ack([])
        return
      }
      // small pool, never blocks a running scan
      let idx = 0
      const out: LiveResult[] = []
      const CHECK_CONCURRENCY = Math.min(25, Math.max(ips.length, 1))
      const worker = async () => {
        while (idx < ips.length) {
          const ip = ips[idx++]
          let recv = 0
          let totalDelay = 0
          for (let p = 0; p < pingCount; p++) {
            const ms = await tcping(ip, port, timeoutMs)
            if (ms !== null) {
              recv++
              totalDelay += ms
            }
          }
          out.push({
            ip,
            latencyMs: recv > 0 ? Math.round((totalDelay / recv) * 10) / 10 : 0,
            sent: pingCount,
            received: recv,
            lossRate: Math.round(((pingCount - recv) / pingCount) * 100) / 100,
          })
        }
      }
      void Promise.all(Array.from({ length: CHECK_CONCURRENCY }, () => worker())).then(() =>
        ack(out),
      )
    } catch {
      ack([])
    }
  })
})

// refuse to boot twice: a second instance must never linger as a zombie that
// shares the SQLite DB and timers with the real engine
httpServer.on('error', (err: NodeJS.ErrnoException) => {
  if (err?.code === 'EADDRINUSE') {
    console.error(`[scan-service] port ${PORT} already in use — another engine instance is running. Exiting.`)
    process.exit(1)
  }
  console.error('[scan-service] httpServer error:', err)
})

httpServer.listen(PORT, () => {
  console.log(`[scan-service] listening on :${PORT}`)
})
