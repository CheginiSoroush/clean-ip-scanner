/**
 * Clean IP Scanner — Web Edition
 * Shared protocol contract between the Next.js frontend (port 3000)
 * and the scan-engine mini service (socket.io, port 3003).
 *
 * This file is the single source of truth for the socket protocol.
 * DO NOT change event names or payload shapes without updating both sides.
 */

export const SCAN_SOCKET_PORT = 3003;

// ---------- Phases ----------
export type ScanPhase =
  | 'idle'
  | 'generating'
  | 'ping'
  | 'speed'
  | 'done'
  | 'stopped'
  | 'error';

export const PHASE_LABELS_FA: Record<ScanPhase, string> = {
  idle: 'آماده',
  generating: 'تولید لیست IP',
  ping: 'تست تأخیر (TCPing)',
  speed: 'تست سرعت واقعی',
  done: 'تکمیل شد',
  stopped: 'متوقف شد',
  error: 'خطا',
};

// ---------- Config ----------
export interface ScanConfig {
  /** preset id from cdn-presets.ts or "custom" */
  preset: string;
  /** extra/custom CIDR lines (one per line). When preset != custom it is merged with preset ranges */
  customRanges?: string;
  /** TCP port to scan (1..65535) */
  port: number;
  /** TCP pings per IP (1..8) */
  pingCount: number;
  /** connect timeout ms (200..5000) */
  timeoutMs: number;
  /** parallel workers for ping phase (16..1024) */
  concurrency: number;
  /** how many random IPs to sample from ranges (10..200000) */
  maxIPs: number;
  /** how many best candidates to speed-test (1..30) */
  speedTestCount: number;
  /** download speed-test host (SNI), default speed.cloudflare.com */
  speedHost?: string;
  /** minimum latency (ms) filter — keep results with latency <= value, 0 = off */
  maxLatencyMs?: number;
}

export const DEFAULT_SCAN_CONFIG: ScanConfig = {
  preset: 'cloudflare',
  customRanges: '',
  port: 443,
  pingCount: 4,
  timeoutMs: 1500,
  concurrency: 256,
  maxIPs: 2000,
  speedTestCount: 10,
  speedHost: 'speed.cloudflare.com',
  maxLatencyMs: 0,
};

// ---------- Results ----------
export interface LiveResult {
  ip: string;
  /** average latency ms across successful pings */
  latencyMs: number;
  sent: number;
  received: number;
  /** 0..1 */
  lossRate: number;
  /** bytes per second, present after speed phase */
  downloadSpeed?: number;
  uploadSpeed?: number;
  /** download+upload bytes/s */
  totalSpeed?: number;
}

export interface ScanProgress {
  phase: ScanPhase;
  /** IPs processed in ping phase */
  scanned: number;
  /** total IPs to scan in ping phase */
  total: number;
  /** responsive IPs found so far */
  alive: number;
  /** elapsed since scan start, ms */
  elapsedMs: number;
  /** index within speed phase */
  speedTested: number;
  speedTotal: number;
  /** rolling avg latency of the last processed batch (ms) — for live sparkline */
  recentLatency: number;
  /** ips per second, rolling */
  ipsPerSecond: number;
}

export interface ScanSummary {
  status: 'done' | 'stopped' | 'error';
  config: ScanConfig;
  startedAt: number;
  elapsedMs: number;
  totalIPs: number;
  scanned: number;
  alive: number;
  speedTested: number;
  results: LiveResult[];
  error?: string;
  /** true when the scan was triggered by the scheduler (not by a user click) */
  auto?: boolean;
  /** set by the engine when IT persisted the scan itself (scheduled runs) — UI skips its own POST then */
  savedScanId?: string;
  /** true when the scan was executed by the multi-CDN queue (distinct toast/sound) */
  viaQueue?: boolean;
}

export interface ScanLogLine {
  ts: number;
  level: 'info' | 'success' | 'warn' | 'error';
  /** Persian (source of truth) message */
  message: string;
  /** optional English variant — the terminal renders it when the UI language is EN */
  messageEn?: string;
}

// ---------- Socket events ----------
/** payload for the lightweight health re-check of known IPs (favorites) */
export interface IpCheckPayload {
  ips: string[]
  port: number
  pingCount: number
  timeoutMs: number
}

// ---------- Scheduled auto-scan ----------
/** live state of the engine-side scheduler (broadcast + acked) */
export interface AutoScanState {
  enabled: boolean
  intervalMinutes: number
  /** engine epoch ms of the next scheduled run — null when disabled */
  nextRunAt: number | null
  /** engine epoch ms of the last (attempted) auto run */
  lastRunAt: number | null
  /** how many auto runs happened since the schedule was created */
  runsCount: number
  /** true while an auto-triggered scan is executing right now */
  running: boolean
  /** the config future auto runs will use */
  config: ScanConfig | null
  /** optional completion webhook URL (POSTed a JSON summary after each scheduled run) */
  notifyUrl: string
  /** true when a Telegram bot token + chat id are stored on the engine */
  telegramConfigured: boolean
  /** the chat id notifications are sent to (the bot token itself is NEVER exposed) */
  telegramChatId: string
  /** when true, finished QUEUE runs are collected and sent as ONE digest message instead of per-run spam */
  telegramDigest: boolean
}

export interface AutoScanSetPayload {
  enabled: boolean
  /** 5..1440 minutes */
  intervalMinutes: number
  /** required on first enable — the config auto runs will use */
  config: ScanConfig | null
  /** optional completion webhook URL (empty string = clear) */
  notifyUrl?: string | null
}

/** ack shape of the webhook / telegram test */
export interface NotifyTestResult {
  ok: boolean
  status?: number
  error?: string
}

// ---------- Xray-style TLS probe ("will this IP work in a proxy config?") ----------
export interface XrayProbeRequest {
  ip: string
  port: number
  /** SNI / Host the probe presents (same value the proxy config would use) */
  host: string
  timeoutMs?: number
}

export interface XrayProbeResult {
  ok: boolean
  ip: string
  host: string
  port: number
  error?: string
  /** tcp connect ms */
  tcpMs?: number
  /** tls handshake ms (after tcp) */
  tlsMs?: number
  /** first-byte http ms (after tls) */
  httpMs?: number
  totalMs?: number
  tlsVersion?: string
  cipher?: string
  alpn?: string
  cert?: {
    subjectCN?: string
    issuer?: string
    validTo?: string
    daysLeft?: number
    /** did the leaf cert SAN cover the requested host? */
    matched?: boolean
  }
  httpStatus?: number
  grade?: 'excellent' | 'good' | 'weak' | 'fail'
}

// ---------- Multi-CDN scan queue ----------
export type QueueItemStatus = 'waiting' | 'running' | 'done' | 'skipped' | 'error'

export interface QueueItem {
  id: string
  /** human label shown in UI + saved as the DB scan label */
  label: string
  config: ScanConfig
  addedAt: number
  status: QueueItemStatus
  /** disabled items stay in place but are never picked by the processor (default true) */
  enabled?: boolean
  startedAt?: number
  finishedAt?: number
  /** set when the engine self-persisted the finished scan */
  savedScanId?: string
  /** compact outcome of the run (kept small for broadcast) */
  result?: {
    total: number
    alive: number
    clean: number
    bestIp?: string
    bestSpeedBps?: number
  } | null
}

export interface ScanQueueState {
  items: QueueItem[]
  /** true while a queued scan executes right now */
  running: boolean
  currentId: string | null
}

/** client → server */
export interface ClientToServerEvents extends GoogleHuntClientEvents, WarpClientEvents {
  'scan:start': (cfg: ScanConfig) => void;
  'scan:stop': () => void;
  /** request current state snapshot (used on reconnect) */
  'scan:state': (cb: (s: { running: boolean; summary: ScanSummary | null; progress: ScanProgress | null; results: LiveResult[]; logs: ScanLogLine[] }) => void) => void;
  'ping:rtt': (cb: (t: number) => void) => void;
  /**
   * Quick TCPing health check for specific IPs (watchlist).
   * Never conflicts with a running scan; acks with per-IP results.
   */
  'check:ips': (payload: IpCheckPayload, ack: (results: LiveResult[]) => void) => void;
  /**
   * Enable/disable the engine-side scheduled auto-scan.
   * Acks with the fresh scheduler state.
   */
  'auto-scan:set': (payload: AutoScanSetPayload, ack: (s: AutoScanState) => void) => void;
  /** request the current scheduler state */
  'auto-scan:state': (cb: (s: AutoScanState) => void) => void;
  /** send a test payload to the given webhook URL (validates reachability) */
  'auto-scan:notify-test': (url: string, ack: (r: NotifyTestResult) => void) => void;
  /** store/clear Telegram credentials (token undefined/null = unchanged, '' = clear) */
  'telegram:set': (
    payload: { token?: string | null; chatId?: string | null; digest?: boolean | null },
    ack: (s: AutoScanState) => void,
  ) => void;
  /** send a Telegram test message using the stored credentials */
  'telegram:test': (ack: (r: NotifyTestResult) => void) => void;
  /** add the given config to the engine-side multi-CDN queue */
  'queue:add': (payload: { config: ScanConfig; label?: string }, ack: (s: ScanQueueState) => void) => void;
  /** remove one queue item (never the running one) */
  'queue:remove': (id: string, ack: (s: ScanQueueState) => void) => void;
  /** remove every non-running queue item */
  'queue:clear': (ack: (s: ScanQueueState) => void) => void;
  /** request the current queue snapshot */
  'queue:state': (cb: (s: ScanQueueState) => void) => void;
  /** swap a waiting item with its neighbour (dir -1 = earlier, +1 = later) */
  'queue:move': (payload: { id: string; dir: -1 | 1 }, ack: (s: ScanQueueState) => void) => void;
  /** enable/disable a waiting queue item (disabled items are skipped by the processor) */
  'queue:toggle': (id: string, ack: (s: ScanQueueState) => void) => void;
  /** drag & drop reorder — move a WAITING item to the given array index (clamped) */
  'queue:reorder': (payload: { id: string; index: number }, ack: (s: ScanQueueState) => void) => void;
  /** edit a WAITING queue item in place (label + partial scan config, engine re-clamps every field) */
  'queue:update': (
    payload: { id: string; label?: string; config?: Partial<ScanConfig> },
    ack: (s: ScanQueueState) => void,
  ) => void;
  /**
   * Xray-style connectivity probe: real TLS handshake against the raw IP with the
   * given SNI (exactly what a proxy core does when connecting through a CDN),
   * plus an HTTP GET to measure TTFB. Acks with full cert/timing details.
   */
  'xray:probe': (payload: XrayProbeRequest, ack: (r: XrayProbeResult) => void) => void;
}

/** server → client */
export interface ServerToClientEvents extends GoogleHuntServerEvents, WarpServerEvents {
  'scan:progress': (p: ScanProgress) => void;
  /** emitted when a candidate passes speed test (final result) */
  'scan:result': (r: LiveResult) => void;
  /** emitted for each responsive IP found in ping phase (throttled batch) */
  'scan:alive': (batch: LiveResult[]) => void;
  'scan:done': (s: ScanSummary) => void;
  'scan:log': (l: ScanLogLine) => void;
  'scan:error': (e: { message: string }) => void;
  'pong:rtt': (t: number) => void;
  /** broadcast whenever the scheduler state changes (set enabled/disabled, run finished…) */
  'auto-scan:state': (s: AutoScanState) => void;
  /** broadcast whenever the scan queue changes (add/remove/item progressed…) */
  'queue:state': (s: ScanQueueState) => void;
}

// ---------- Google-friendly IP hunter (fully independent of the scan pipeline) ----------
/**
 * A standalone engine-side hunter that generates thousands of random candidate
 * IPs from known Google CIDR ranges and probes each one the way a client would:
 * TCP → TLS with SNI of a Google host → HTTP GET /generate_204.
 *   204 / 200 / 3xx  → healthy (Google serves this IP without a 403 block)
 *   403 / other 4xx5xx → blocked (Google refuses this IP)
 *   connect/TLS/HTTP failure → dead
 * It keeps hunting in waves until the target count of healthy IPs is reached,
 * the user stops it, or a hard safety cap of tested IPs is hit.
 */
export type GoogleHuntVerdict = 'healthy' | 'blocked' | 'dead'

export interface GoogleHuntCandidate {
  ip: string
  verdict: GoogleHuntVerdict
  /** HTTP status returned by the edge (204/200/3xx healthy, 403 blocked…) */
  httpStatus?: number
  /** tcp connect ms */
  tcpMs?: number
  /** tls handshake ms */
  tlsMs?: number
  /** the SNI/Host used for the probe */
  host: string
  /** total successful probes including verification passes (1 = single probe, no verify) */
  attempts?: number
  /** which provider's range this candidate came from (hunt v4) */
  provider?: string
  /** Server response header captured during the probe (edge fingerprint) */
  server?: string
  /** TCP port actually probed (hunt v5.9 multi-port matrix — cloudflare rotates 443/2053/2083/2087/2096/8443; default 443) */
  port?: number
  /** Cloudflare datacenter code from /cdn-cgi/trace (e.g. FRA, DXB, AMS — hunt v5.9, cloudflare provider only) */
  colo?: string
  /** TLS latency spread across probe + verification passes in ms (|max−min|, ≥2 attempts — hunt v6.0 jitter stat) */
  jitterMs?: number
  /** sampled from an IPv6 prefix (ip holds the bare v6 literal — bracket it for ip:port display) — hunt v6.1 */
  v6?: boolean
  /** sampled from the user's selected-range checklist (selectedCidrs) — hunt v6.1 */
  selected?: boolean
  /** anti-censorship forensics verdict for dead candidates (hunt v6.4): 'rst' = connection reset mid-handshake (DPI-injection signature), 'drop' = silent timeout after ClientHello, 'refused' = nothing listening (genuinely dead), 'live' = edge answered at a lower layer */
  rst?: 'rst' | 'drop' | 'refused' | 'live'
  /** v7.0 — ISP source label when sampled from a labelled selectedCidrs entry (e.g. 'AS197207'; absent = unlabelled) */
  isp?: string
}

/** hunt v6.4 — anti-censorship forensics tallies over dead candidates (budgeted per run) */
export interface HuntForensicsTally {
  /** TCP RST injected during/after the TLS handshake — censorship signature */
  rst: number
  /** silent drop — no reply, no reset */
  drop: number
  /** TCP refused — nothing listening, genuinely dead */
  refused: number
  /** lower-layer liveness without usable HTTP */
  live: number
}

/** hunt v6.4 — last recon pull health for a single named source (rate-limit resilience) */
export interface HuntSourceHealth {
  ok: boolean
  /** last successful pull latency ms (0 when failed) */
  ms: number
  /** short failure reason (≤80 chars, e.g. 'HTTP 429') */
  err?: string
  /** epoch ms of the last attempt */
  at: number
}

/** live stat for one learned /24 block (adaptive sampling intelligence) */
export interface GoogleHuntBlockStat {
  /** /24 CIDR, e.g. "142.250.0.0/24" */
  block: string
  /** candidates probed inside this block (this + past hunts) */
  probed: number
  /** confirmed healthy IPs found inside this block */
  healthy: number
  /** 0..1 Bayesian-smoothed healthy rate (drives the sampler) */
  score: number
  /** rDNS fingerprint: 'edge' = IPs resolve to *.1e100.net (Google user-facing edge) */
  ptr?: 'edge' | 'google' | null
}

// ---------- hunt recon v4: reverse-engineering every provider's own infrastructure ----------
/**
 * Instead of trusting a hardcoded CIDR list, the hunter reads the SAME
 * authoritative sources each provider itself publishes, live at runtime:
 *   google     ① DNS TXT _netblocks.google.com / _netblocks3.google.com (official SPF v4 ranges, via DoH)
 *              ② https://www.gstatic.com/ipranges/goog.json (every Google-owned prefix)
 *              ③ https://www.gstatic.com/ipranges/cloud.json (GCP prefixes)
 *              ④ rDNS (PTR) fingerprints — /24 blocks whose IPs resolve to *.1e100.net
 *                are Google's user-facing edge (exactly what the hunt wants) and get a sampling boost.
 *   cloudflare ① https://www.cloudflare.com/ips-v4 (official plain-text CIDR list)
 *              ② https://api.cloudflare.com/client/v4/ips (official JSON, AS13335)
 *   arvan      ① BGP-announced prefixes of AS61173 via RIPEstat (ArvanCloud publishes no official JSON)
 */
export type GoogleHuntReconStatus = 'idle' | 'loading' | 'ready' | 'failed'

/** providers the hunter can align itself with */
export type HuntProviderId = 'google' | 'cloudflare' | 'arvan' | 'custom'
export type HuntProviderSelection = HuntProviderId | 'all'

/** live recon snapshot for ONE provider */
export interface HuntProviderRecon {
  status: GoogleHuntReconStatus
  /** last successful pull of this provider's sources (0 = never) */
  updatedAt: number
  /** raw discovered IPv4 CIDR counts per authoritative source key */
  sources: Record<string, number>
  /** total live IPv4 CIDRs merged into this provider's pool (deduped) */
  cidrs: number
  /** total live IPv6 prefixes merged into this provider's pool (hunt v6.1 — goog.json v6 + CF ips-v6) */
  cidrsV6?: number
  /** actual ranges for the UI checklist (v4 first then v6, biggest first, cap HUNT_RECON_RANGES_CAP) — hunt v6.1 */
  ranges?: string[]
}

/** per-provider hunt counters (live + persisted in history) */
export interface HuntProviderStats {
  tested: number
  healthy: number
  blocked: number
  dead: number
}

/** live snapshot of the reverse-engineered range intelligence (all providers) */
export interface GoogleHuntRecon {
  status: GoogleHuntReconStatus
  /** last successful recon pull across all providers (0 = never) */
  updatedAt: number
  /** per-provider recon intelligence */
  providers: Record<HuntProviderId, HuntProviderRecon>
  /** total live IPv4 CIDRs merged into the exploration pool (deduped across providers) */
  total: number
  /** rDNS (PTR) fingerprinting progress over candidate /24 blocks (Google edge) */
  ptr: { scanned: number; edge: number; top: string[] }
  /** true when recon has no live data and the static fallback pool is in use */
  fallback?: boolean
  /** hunt v6.4 — last-pull health per named source key (rate-limit resilience observability) */
  health?: Record<string, HuntSourceHealth>
}

export interface GoogleHuntState {
  running: boolean
  /** hunt reached target / hard cap / stopped / crashed */
  finished: boolean
  /** finished because the user pressed stop */
  stopped: boolean
  /** candidates probed so far (all waves) */
  tested: number
  healthy: number
  blocked: number
  dead: number
  /** candidates generated so far (all waves) */
  planned: number
  /** which wave is currently executing (1-based) */
  wave: number
  /** healthy IPs the user asked for (auto-stop when reached) */
  target: number
  /** safety cap of tested candidates */
  hardCap: number
  /** SNI/Host used */
  host: string
  port: number
  startedAt: number | null
  elapsedMs: number
  /** candidates probed per second (rolling) */
  ipsPerSecond: number
  /** accumulated healthy candidates (kept in engine memory until reset) */
  healthyIps: GoogleHuntCandidate[]
  /** last few probes for the live ticker (max ~12) */
  recent: GoogleHuntCandidate[]
  // ----- funnel architecture (v2) -----
  /** candidates that passed the cheap TCP stage (funnel stage 2 of 3) */
  tcpAlive: number
  /** confirmed candidates that survived extra verification passes (attempts ≥ 2) */
  verified: number
  /** top learned /24 blocks (max 6, live from the adaptive sampler) */
  hotBlocks: GoogleHuntBlockStat[]
  /** extra confirmation probes required per healthy IP (0=fast 1=balanced 2=strict) */
  verify: number
  /** provider selection for this run ('all' | google | cloudflare | arvan) */
  provider: string
  /** live per-provider counters (hunt v4) */
  perProvider: Partial<Record<HuntProviderId, HuntProviderStats>>
  // ----- parallel pipeline telemetry (v5 — barrier-free split-pool engine) -----
  /** candidates currently inside the pipeline (TCP + TLS + verify stages) */
  inFlight?: number
  /** candidates currently in the expensive TLS stage */
  tlsInFlight?: number
  /** current live TCP-stage worker count (adaptive within tcpPoolMax) */
  concurrency?: number
  /** current live TLS-stage worker count (adaptive within tlsPoolMax) */
  tlsConcurrency?: number
  /** configured TCP-stage pool ceiling for this run */
  tcpPoolMax?: number
  /** configured TLS-stage pool ceiling for this run */
  tlsPoolMax?: number
  /** candidates fed into the pipeline so far (replaces wave planning) */
  sampled?: number
  /** candidates sampled from IPv6 prefixes this run (hunt v6.1) */
  v6Sampled?: number
  /** candidates sampled from the user's selected-range checklist this run (hunt v6.1) */
  fromSelected?: number
  /** parallel engine generation marker ('pipeline-v5') */
  engine?: string
  error?: string
  /** hunt v6.4 — budgeted RST-injection forensics tallies over dead candidates (absent when forensics disabled) */
  forensics?: HuntForensicsTally
  /** v7.0 — true when this run was triggered by the hunt scheduler (not a user click) */
  auto?: boolean
}

// ---------- v7.0 — engine-side hunt scheduler (mirrors the auto-scan scheduler) ----------
/**
 * v7.6 — compact per-fire settings echo. Captured from the scheduler's stored
 * settings snapshot the moment a scheduled hunt FIRES, so later edits (drift
 * updates / re-captures) never rewrite what an older journal entry actually
 * used. Key scalars only — the full GoogleHuntSettings stays in
 * HuntScheduleState.settings. Absent on legacy journal entries and on
 * done/postponed events.
 */
export interface HuntScheduleFireSettings {
  /** provider whose ranges were hunted ('all' | google | cloudflare | arvan | custom) */
  provider?: string
  /** stop-after-N-healthy target (1..100) */
  target?: number
  /** candidates per wave (500..10000) */
  batchSize?: number
  /** parallel TCP probes (32..1024) */
  concurrency?: number
  /** SNI/Host presented to every candidate */
  host?: string
  /** TCP port (1..65535) */
  port?: number
  /** parallel-engine preset ('calm' | 'normal' | 'fast' | 'insane') */
  speed?: string
  /** extra confirmation probes per healthy candidate (0..3) */
  verify?: number
}

export interface HuntScheduleJournalEntry {
  /**
   * v7.1 — one hunt-scheduler journal event. The engine records every scheduler
   * action so postponements (invisible in run history) and fire→done pairing are
   * auditable from the UI. Newest-first in HuntScheduleState.journal, capped at
   * HUNT_SCHEDULE_JOURNAL_CAP. Survives engine restarts (db/hunt-schedule.json).
   */
  /** engine epoch ms of the event */
  at: number
  /** fire = scheduler triggered a hunt · done = that hunt finished · postponed = fire skipped (a manual run was active) */
  kind: 'fire' | 'done' | 'postponed'
  /** kind=done — candidates tested by the scheduled run */
  tested?: number
  /** kind=done — healthy IPs found by the scheduled run */
  healthy?: number
  /** kind=done — the run was stopped early */
  stopped?: boolean
  /** kind=done — run duration ms (finishedAt − startedAt) */
  durationMs?: number
  /**
   * v7.6 — kind=fire — compact echo of the settings THIS fire used (see
   * HuntScheduleFireSettings). Absent on legacy entries / other kinds.
   */
  settings?: HuntScheduleFireSettings
}

/** v7.1 — max journal entries kept engine-side (newest-first) */
export const HUNT_SCHEDULE_JOURNAL_CAP = 20

/**
 * Runs the hunt automatically every N minutes with a stored settings snapshot.
 * Survives engine restarts (db/hunt-schedule.json, boot grace period).
 * A scheduled fire while a hunt is already running is POSTPONED (warn log),
 * never queued — the next round is scheduled regardless.
 */
export interface HuntScheduleState {
  enabled: boolean
  /** 5..1440 minutes between scheduled runs */
  intervalMinutes: number
  /** engine epoch ms of the next scheduled run — null when disabled */
  nextRunAt: number | null
  /** engine epoch ms of the last (attempted) scheduled run */
  lastRunAt: number | null
  /** how many scheduled runs happened since the schedule was created */
  runsCount: number
  /** true while a scheduler-triggered hunt is executing right now */
  running: boolean
  /** the hunt settings future scheduled runs will use (normalized); null = defaults will be used on enable */
  settings: GoogleHuntSettings | null
  /**
   * v7.1 — newest-first journal of scheduler events (max HUNT_SCHEDULE_JOURNAL_CAP).
   * Absent ⇒ legacy-safe (older engine snapshots / hooks must not assume it).
   */
  journal?: HuntScheduleJournalEntry[]
}

export interface HuntScheduleSetPayload {
  enabled: boolean
  /** 5..1440 minutes */
  intervalMinutes: number
  /** settings scheduled runs will use; null = keep the stored ones (first enable falls back to normalized defaults) */
  settings: GoogleHuntSettings | null
}

export interface GoogleHuntSettings {
  /** stop as soon as this many healthy IPs are found (1..100) */
  target: number
  /** hunt v6.4 — run budgeted RST-injection forensics on dead candidates (default true) */
  forensics?: boolean
  /** candidates per wave (500..10000) */
  batchSize: number
  /** parallel probes (32..1024) */
  concurrency: number
  /** SNI/Host presented to every candidate */
  host: string
  /** TCP port (1..65535, default 443) */
  port: number
  /** extra confirmation probes per healthy candidate (0..3, default 1) */
  verify?: number
  /** which provider's ranges to hunt ('all' | google | cloudflare | arvan, default 'all') */
  provider?: string
  /** parallel engine preset: 'calm' | 'normal' | 'fast' | 'insane' (controls TCP/TLS pool ceilings, default 'normal') */
  speed?: string
  /** user-provided IPv4 CIDR ranges for the 'custom' provider (max 64, each ≤ /16 effective size, default []) */
  customCidrs?: string[]
  /**
   * v7.0 — parallel ISP source labels for selectedCidrs: labels[i] annotates
   * selectedCidrs[i] ("AS<digits>" e.g. 'AS197207', or '' = unlabelled).
   * Absent/shorter ⇒ missing entries unlabelled (legacy-safe). Labels ride
   * healthy candidates as `isp` so the UI can profile latency per ISP.
   */
  selectedLabels?: string[]
  /** include the provider's IPv6 prefixes in sampling (~15% of candidates, default false) — hunt v6.1 */
  enableV6?: boolean
  /** explicit range-checklist allow-list over the recon pool. Non-empty ⇒ engine hunts ONLY these ranges (v4+v6 mixed, max HUNT_SELECTED_MAX_CIDRS, replaces the provider pool for this run) — hunt v6.1 */
  selectedCidrs?: string[]
  /** hunt v6.3 — per-provider probe-target overrides. Applied to google + cloudflare only; arvan and custom stay SNI-less on the IP by design */
  providerOverrides?: Partial<Record<HuntProviderId, HuntTargetOverride>>
}

/** hunt v6.3 — custom probe target for one provider (each field optional; unset ⇒ provider default) */
export interface HuntTargetOverride {
  /** SNI/Host presented in the TLS ClientHello (hostname, 1..253 chars) */
  host?: string
  /** TCP port override (1..65535; replaces the provider default / CF port rotation for this run) */
  port?: number
  /** HTTP probe path override (starts with '/', ≤256 chars; default = provider path) */
  path?: string
}

// ---------- hunt v6.1: range checklist + config-generator SNI/fragment presets ----------
/** max user-selected CIDRs per hunt (range checklist allow-list) */
export const HUNT_SELECTED_MAX_CIDRS = 512
/** max ranges shipped per provider in the recon snapshot for the UI checklist */
export const HUNT_RECON_RANGES_CAP = 256
/** common SNI choices for the config generator (clean-IP + custom-SNI pattern) */
export const HUNT_SNI_PRESETS: string[] = [
  'www.cloudflare.com',
  'speed.cloudflare.com',
  'cloudflare-dns.com',
  'time.is',
  'zula.ir',
  'dns.google',
  'www.google.com',
  'www.gstatic.com',
]
/** xray fragment presets (Hiddify/NekoBox parse the `fragment` URI param on vless links) */
export interface HuntFragmentPreset {
  id: string
  value: string
}
export const HUNT_FRAGMENT_PRESETS: HuntFragmentPreset[] = [
  { id: 'none', value: '' },
  { id: 'tlshello', value: '1-3,tlshello,10-20' },
  { id: 'tls-long', value: '2-6,tlshello,50-100' },
  { id: 'http', value: '1-3,http,10-20' },
]

/** one finished hunt as persisted in db/hunt-history.json (served by /api/hunt) */
export interface GoogleHuntHistoryRun {
  id: string
  startedAt: number
  finishedAt: number
  target: number
  stopped: boolean
  host: string
  port: number
  tested: number
  healthy: number
  blocked: number
  dead: number
  tcpAlive: number
  verify: number
  healthyIps: GoogleHuntCandidate[]
  /** provider selection of the run (hunt v4) */
  provider?: string
  /** per-provider counters of the run (hunt v4) */
  perProvider?: Partial<Record<HuntProviderId, HuntProviderStats>>
  /** v7.0 — true when the run was triggered by the hunt scheduler */
  auto?: boolean
}

/** client → server */
export interface GoogleHuntClientEvents {
  'google-hunt:start': (payload: Partial<GoogleHuntSettings> | undefined, ack: (s: GoogleHuntState) => void) => void
  'google-hunt:stop': (ack: (s: GoogleHuntState | null) => void) => void
  /** clear the accumulated results (only while idle) */
  'google-hunt:reset': (ack: (s: GoogleHuntState | null) => void) => void
  /** request the current snapshot (reconnect restore) */
  'google-hunt:state': (cb: (s: GoogleHuntState | null) => void) => void
  /** fetch the recon snapshot (connect-time restore) */
  'google-hunt:recon': (cb: (r: GoogleHuntRecon | null) => void) => void
  /** trigger a live recon refresh (ack resolves immediately with the current snapshot) */
  'google-hunt:recon:refresh': (ack: (r: GoogleHuntRecon | null) => void) => void
  /** v7.0 — enable/disable the engine-side hunt scheduler (acks with the fresh state) */
  'hunt-schedule:set': (payload: HuntScheduleSetPayload, ack: (s: HuntScheduleState) => void) => void
  /** v7.0 — request the current scheduler snapshot */
  'hunt-schedule:state': (cb: (s: HuntScheduleState) => void) => void
}

/** server → client */
export interface GoogleHuntServerEvents {
  /** broadcast on every progress tick and on finish */
  'google-hunt:state': (s: GoogleHuntState) => void
  /** broadcast whenever the recon intelligence updates */
  'google-hunt:recon': (r: GoogleHuntRecon) => void
  /** v7.0 — broadcast whenever the hunt scheduler state changes */
  'hunt-schedule:state': (s: HuntScheduleState) => void
}

// ---------- WARP endpoint scanner (hunt v6.2 / P3 — WireGuard UDP probing) ----------
/**
 * A standalone engine-side scanner that probes Cloudflare WARP endpoints over
 * UDP the way a WireGuard client would: it registers (best-effort) a WARP
 * identity via api.cloudflareclient.com, crafts a real WireGuard handshake
 * initiation packet (Curve25519 + ChaCha20-Poly1305 + keyed Blake2s) and sends
 * it to random endpoints across the canonical WARP ranges × known UDP ports.
 * Any response datagram (92-byte type-2 handshake or 64-byte type-3 cookie)
 * marks the endpoint live.
 */
export interface WarpEndpoint {
  /** 'ip:port' as displayed/copied */
  endpoint: string
  ip: string
  port: number
  /** ms until the response datagram arrived */
  rttMs?: number
  /** response kind seen (wireguard message types 2 / 3) */
  response?: 'handshake' | 'cookie'
  /** source /24 range the endpoint was sampled from */
  range?: string
  /** 1 = responded on first try */
  attempts?: number
}

export interface WarpScanState {
  running: boolean
  finished: boolean
  stopped: boolean
  tested: number
  alive: number
  /** endpoints generated so far (tested + queued) */
  planned: number
  /** stop as soon as this many live endpoints are found */
  target: number
  startedAt: number | null
  elapsedMs: number
  /** endpoints probed per second (rolling) */
  epsPerSecond?: number
  /** accumulated live endpoints (kept in engine memory until reset) */
  found: WarpEndpoint[]
  /** last few probes for the live ticker (max ~12) */
  recent: WarpEndpoint[]
  /** the /24 ranges being scanned */
  ranges: string[]
  /** UDP ports in rotation */
  ports: number[]
  /** current live UDP worker count */
  concurrency?: number
  /** whether the engine holds a registered WARP identity for real handshakes */
  registered?: boolean
  error?: string
}

export interface WarpScanSettings {
  /** stop as soon as this many live endpoints are found (1..200) */
  target: number
  /** UDP ports to rotate (subset of WARP_UDP_PORTS, 1..8 entries) */
  ports: number[]
  /** parallel UDP probes (32..1024, default 256) */
  concurrency: number
  /** per-probe response timeout ms (500..3000, default 1200) */
  timeoutMs?: number
  /**
   * v6.6 — custom /24 ranges to probe (overrides WARP_RANGES when non-empty).
   * Each entry must be an exact IPv4 /24 CIDR (a.b.c.0/24). Max
   * WARP_CUSTOM_RANGES_CAP entries; absent/empty ⇒ canonical ranges (legacy-safe).
   */
  ranges?: string[]
}

/** v6.6 — max user-supplied /24 ranges per WARP scan (honest universe cap) */
export const WARP_CUSTOM_RANGES_CAP = 16

/** v6.6 — strict /24 IPv4 CIDR shape (a.b.c.0/24, octets 0..255) */
export const WARP_RANGE_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}0\/24$/

/** known WARP UDP ports (2408 is the client default) */
export const WARP_UDP_PORTS: number[] = [2408, 500, 1701, 4500, 2404, 2407, 2409, 2410]
/** canonical Cloudflare WARP endpoint ranges (162.159.192.x = engage.cloudflareclient.com) */
export const WARP_RANGES: { cidr: string; label: string }[] = [
  { cidr: '162.159.192.0/24', label: 'engage' },
  { cidr: '162.159.193.0/24', label: 'warp-2' },
  { cidr: '162.159.195.0/24', label: 'warp-3' },
  { cidr: '188.114.96.0/24', label: 'warp-a' },
  { cidr: '188.114.97.0/24', label: 'warp-b' },
  { cidr: '188.114.98.0/24', label: 'warp-c' },
  { cidr: '188.114.99.0/24', label: 'warp-d' },
]

/** client → server */
export interface WarpClientEvents {
  'warp:start': (payload: Partial<WarpScanSettings> | undefined, ack: (s: WarpScanState) => void) => void
  'warp:stop': (ack: (s: WarpScanState | null) => void) => void
  /** clear the accumulated found endpoints (only while idle) */
  'warp:reset': (ack: (s: WarpScanState | null) => void) => void
  /** request the current snapshot (reconnect restore) */
  'warp:state': (cb: (s: WarpScanState | null) => void) => void
}

/** server → client */
export interface WarpServerEvents {
  /** broadcast on every progress tick and on finish */
  'warp:state': (s: WarpScanState) => void
}

// ------------- WARP scan history (API contract for /api/warp-history) -------------

/** v7.4 — live endpoints persisted per WARP history run (mirrors hunt's healthyIps cap of 100) */
export const WARP_HISTORY_FOUND_CAP = 100

/** v7.4 — max WARP runs kept in db/warp-history.json (mirrors the hunt history cap of 30) */
export const WARP_HISTORY_MAX_RUNS = 30

/**
 * v7.4 — one finished WARP UDP scan, persisted engine-side so the panel can
 * show past scans exactly the way hunt history does (closing the last big
 * hunt/WARP asymmetry). Same shape philosophy as GoogleHuntHistoryRun: small
 * summary fields + a capped per-item list; engine-written, API-sanitized,
 * never blindly trusted. Deletion is file-level via DELETE /api/warp-history
 * (the engine re-reads the file before every append, so deletes are
 * authoritative — same contract as /api/hunt).
 */
export interface WarpHistoryRun {
  /** `warp-<startedAt>` — stable delete key */
  id: string
  startedAt: number
  finishedAt: number
  /** stop as soon as this many live endpoints are found (settings echo) */
  target: number
  /** true when the user stopped the run early */
  stopped: boolean
  /** probes actually sent */
  tested: number
  /** live endpoints found during THIS run */
  alive: number
  /** universe size at plan time (ranges × 256 hosts × ports) */
  planned: number
  /** true when the whole universe was probed without reaching the target */
  exhausted?: boolean
  /** probes/second measured at finish */
  eps?: number
  /** UDP ports in rotation (settings echo) */
  ports: number[]
  /** effective /24 ranges probed (canonical or custom, settings echo) */
  ranges: string[]
  /** true when user-supplied custom ranges were used (v6.6) */
  custom?: boolean
  /** true when the engine held a registered WARP identity (real handshakes) */
  registered?: boolean
  /** live endpoints of this run (capped at WARP_HISTORY_FOUND_CAP) */
  found: WarpEndpoint[]
  /** engine-side failure message, when the scan crashed mid-run */
  error?: string
}

// ---------- Xray probe persistence (API contract for /api/probes) ----------
export interface ProbeRecordPayload {
  ip: string
  host: string
  port: number
  grade: 'excellent' | 'good' | 'weak' | 'fail'
  tcpMs?: number
  tlsMs?: number
  httpStatus?: number
  ok: boolean
}

// ---------- helpers ----------
export function formatBytesPerSec(bps: number): string {
  if (!bps || bps <= 0) return '—';
  const mb = bps / (1024 * 1024);
  if (mb >= 1) return `${mb.toFixed(2)} MB/s`;
  return `${(bps / 1024).toFixed(1)} KB/s`;
}

export function formatLatency(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  return `${ms.toFixed(ms < 10 ? 1 : 0)} ms`;
}

// ---------- v6.7 — xray generator presets + settings backup ----------

/** v6.7 — one saved config-generator template (protocol/transport/host/port/path) */
export interface XrayPreset {
  /** short random id (8 hex chars, server-assigned) */
  id: string
  /** display name, 1..40 chars after trim */
  name: string
  /** SNI/Host the preset fills into the generator, 1..253 hostname chars */
  host: string
  /** port, 1..65535 */
  port: number
  protocol: 'vless' | 'vmess' | 'trojan'
  transport: 'ws' | 'tcp'
  /** ws path, '/'-prefixed, ≤64 chars (ignored for tcp) */
  wsPath: string
  /** epoch ms (server-assigned) */
  createdAt: number
}

/** v6.7 — max saved generator presets per app (honest cap, mirrors the API) */
export const XRAY_PRESETS_CAP = 12

/** v6.7 — export envelope produced by GET /api/settings/export (tokens only when requested) */
export interface SettingsExport {
  kind: 'clean-ip-scanner-settings'
  schemaVersion: 1
  exportedAt: string
  dns?: {
    zoneId?: string
    recordName?: string
    recordType?: 'A' | 'AAAA'
    ttl?: number
    proxied?: boolean
    autoPush?: boolean
    autoPushMin?: number
    autoPushMaxIps?: number
    /** raw Cloudflare API token — present ONLY when the export explicitly requested tokens */
    cfToken?: string
  }
  telegram?: {
    chatId?: string
    autoOnFinish?: boolean
    /** raw bot token — present ONLY when the export explicitly requested tokens */
    botToken?: string
  }
}
