/**
 * Smart best-IP scoring engine.
 *
 * Combines every signal the scanner already collects into a single 0–100
 * score so the dashboard can recommend the best candidate, not just the
 * fastest one:
 *
 *   1. Xray probe grade  (0–34)  — real TLS handshake verdict per SNI
 *   2. TLS handshake ms  (0–24)  — lower is better; ping-latency fallback
 *                                  when the IP was never probed
 *   3. Packet loss       (0–16)
 *   4. Download speed    (0–16)
 *   5. Stability         (0–10)  — favorite star, low ping, "clean" flag
 *
 * The function is pure & synchronous so it can run inside useMemo on every
 * live result batch without any perf concern (≤500 rows typical).
 */

export type ScoreGrade = 'excellent' | 'good' | 'weak' | 'fail'

export interface ScoreBreakdown {
  /** probe verdict component (0–34) */
  grade: number
  /** TLS handshake component (0–24) */
  tls: number
  /** packet-loss component (0–16) */
  loss: number
  /** download speed component (0–16) */
  speed: number
  /** stability component (0–10) */
  stab: number
}

export type ScoreReason =
  | { kind: 'grade'; grade: Exclude<ScoreGrade, 'fail'> }
  | { kind: 'tls'; label: string }
  | { kind: 'loss-zero' }
  | { kind: 'loss-low'; label: string }
  | { kind: 'speed'; label: string }
  | { kind: 'latency'; label: string }
  | { kind: 'favorite' }

export interface IpScore {
  ip: string
  /** 0–100 */
  score: number
  breakdown: ScoreBreakdown
  /** human-readable "why" chips, ordered strongest-first */
  reasons: ScoreReason[]
  /** true when the IP was TLS-probed (score is more trustworthy) */
  probed: boolean
}

export interface ScoreInput {
  ip: string
  latencyMs: number
  /** 0..1 */
  lossRate: number
  /** bytes/sec (undefined before the speed phase) */
  totalSpeed?: number
}

export interface ProbeSummaryLike {
  grade?: ScoreGrade
  /** null = probed but TLS never measured (failed probe row from persistence) */
  tlsMs?: number | null
  ok: boolean
}

/** tunable factor weights (what-if scoring) — defaults reproduce the classic 34/24/16/16/10 mix */
export interface ScoreWeights {
  grade: number
  tls: number
  loss: number
  speed: number
  stab: number
}

/** raw max points per component (used to scale custom weights) */
export const COMPONENT_MAX: ScoreWeights = {
  grade: 34,
  tls: 24,
  loss: 16,
  speed: 16,
  stab: 10,
}

export const DEFAULT_WEIGHTS: ScoreWeights = { ...COMPONENT_MAX }

/** hard clamp for the tuning sliders */
export const WEIGHT_SLIDER_MAX = 40

export function clampWeights(w: Partial<ScoreWeights> | null | undefined): ScoreWeights {
  const out = { ...DEFAULT_WEIGHTS }
  if (w) {
    for (const k of ['grade', 'tls', 'loss', 'speed', 'stab'] as const) {
      const v = Number(w[k])
      if (Number.isFinite(v)) out[k] = Math.max(0, Math.min(WEIGHT_SLIDER_MAX, Math.round(v)))
    }
  }
  return out
}

export const SCORE_WEIGHT_PRESETS: Record<string, { label: string; labelEn: string; w: ScoreWeights }> = {
  default: { label: 'متعادل', labelEn: 'Balanced', w: { ...DEFAULT_WEIGHTS } },
  probe: { label: 'پروب‌محور', labelEn: 'Probe-first', w: { grade: 40, tls: 30, loss: 12, speed: 10, stab: 8 } },
  speed: { label: 'سرعت‌محور', labelEn: 'Speed-first', w: { grade: 20, tls: 16, loss: 12, speed: 40, stab: 12 } },
  latency: { label: 'تأخیرمحور', labelEn: 'Latency-first', w: { grade: 24, tls: 34, loss: 18, speed: 12, stab: 12 } },
}

/** visual band for score chips / ring color */
export type ScoreBand = 'elite' | 'strong' | 'ok' | 'low'

export function scoreBand(score: number): ScoreBand {
  if (score >= 85) return 'elite'
  if (score >= 70) return 'strong'
  if (score >= 55) return 'ok'
  return 'low'
}

export const SCORE_BAND_STYLES: Record<ScoreBand, string> = {
  elite: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  strong: 'border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400',
  ok: 'border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  low: 'border-zinc-500/40 bg-zinc-500/10 text-zinc-500',
}

export const SCORE_BAND_HEX: Record<ScoreBand, string> = {
  elite: '#10b981', // emerald-500
  strong: '#14b8a6', // teal-500
  ok: '#f59e0b', // amber-500
  low: '#71717a', // zinc-500
}

function gradePoints(grade?: ScoreGrade, probed: boolean = false): number {
  if (!probed || !grade) return 0
  switch (grade) {
    case 'excellent':
      return 34
    case 'good':
      return 26
    case 'weak':
      return 8
    default:
      return 0
  }
}

function tlsPoints(tlsMs: number | undefined | null, latencyMs: number, probed: boolean): number {
  if (probed) {
    // null = probed but TLS never measured (failed probe row) → small fallback credit from ping
    if (tlsMs == null) {
      if (latencyMs < 50) return 8
      return 0
    }
    if (tlsMs < 60) return 24
    if (tlsMs < 120) return 20
    if (tlsMs < 250) return 13
    if (tlsMs < 500) return 6
    return 0
  }
  // never probed → partial credit from TCP ping so the ranking still works
  if (latencyMs < 50) return 14
  if (latencyMs < 120) return 9
  if (latencyMs < 250) return 4
  return 0
}

function lossPoints(lossRate: number): number {
  if (lossRate <= 0) return 16
  if (lossRate < 0.05) return 12
  if (lossRate < 0.15) return 7
  if (lossRate < 0.25) return 3
  return 0
}

const MIB = 1024 * 1024

function speedPoints(totalSpeed?: number): number {
  const bps = totalSpeed ?? 0
  if (bps >= 40 * MIB) return 16
  if (bps >= 20 * MIB) return 13
  if (bps >= 10 * MIB) return 9
  if (bps >= 2 * MIB) return 5
  if (bps > 0) return 2
  return 0
}

function stabPoints(input: ScoreInput, favorite: boolean): number {
  let pts = 0
  if (favorite) pts += 4
  if (input.latencyMs > 0 && input.latencyMs < 80) pts += 3
  if (input.lossRate < 0.25 && input.latencyMs < 300) pts += 3
  return Math.min(10, pts)
}

/** scale a raw component (0..max) onto the user-tuned weight axis */
function scaled(raw: number, max: number, weight: number): number {
  if (max <= 0) return 0
  return Math.round((raw / max) * weight * 10) / 10
}

export function computeIpScore(
  input: ScoreInput,
  probe: ProbeSummaryLike | undefined,
  favorite: boolean,
  fmt: { bytesPerSec: (bps: number) => string; latency: (ms: number) => string },
  weights: ScoreWeights = DEFAULT_WEIGHTS,
): IpScore {
  const probed = !!probe && (probe.grade !== undefined || probe.ok)
  const breakdown: ScoreBreakdown = {
    grade: scaled(gradePoints(probe?.grade, probed), COMPONENT_MAX.grade, weights.grade),
    tls: scaled(tlsPoints(probe?.tlsMs, input.latencyMs, probed), COMPONENT_MAX.tls, weights.tls),
    loss: scaled(lossPoints(input.lossRate), COMPONENT_MAX.loss, weights.loss),
    speed: scaled(speedPoints(input.totalSpeed), COMPONENT_MAX.speed, weights.speed),
    stab: scaled(stabPoints(input, favorite), COMPONENT_MAX.stab, weights.stab),
  }
  const score = Math.min(100, Math.round(breakdown.grade + breakdown.tls + breakdown.loss + breakdown.speed + breakdown.stab))

  const reasons: ScoreReason[] = []
  if (probed && (probe?.grade === 'excellent' || probe?.grade === 'good' || probe?.grade === 'weak')) {
    reasons.push({ kind: 'grade', grade: probe.grade })
  }
  if (probed && probe?.tlsMs != null && probe.tlsMs < 250) {
    reasons.push({ kind: 'tls', label: fmt.latency(probe.tlsMs) })
  }
  if (input.lossRate <= 0) reasons.push({ kind: 'loss-zero' })
  else if (input.lossRate < 0.05) reasons.push({ kind: 'loss-low', label: `${(input.lossRate * 100).toFixed(1)}%` })
  if ((input.totalSpeed ?? 0) >= 10 * MIB) {
    reasons.push({ kind: 'speed', label: fmt.bytesPerSec(input.totalSpeed ?? 0) })
  }
  if (input.latencyMs > 0 && input.latencyMs < 120) {
    reasons.push({ kind: 'latency', label: fmt.latency(input.latencyMs) })
  }
  if (favorite) reasons.push({ kind: 'favorite' })

  return { ip: input.ip, score, breakdown, reasons, probed }
}

/** score every input; returns a map keyed by IP (order-independent lookups) */
export function computeIpScores(
  inputs: ScoreInput[],
  probes: Record<string, ProbeSummaryLike>,
  favorites: Set<string>,
  fmt: { bytesPerSec: (bps: number) => string; latency: (ms: number) => string },
  weights: ScoreWeights = DEFAULT_WEIGHTS,
): Record<string, IpScore> {
  const out: Record<string, IpScore> = {}
  for (const input of inputs) {
    out[input.ip] = computeIpScore(input, probes[input.ip], favorites.has(input.ip), fmt, weights)
  }
  return out
}

/** ranked best-first list of scored IPs */
export function rankScores(map: Record<string, IpScore>): IpScore[] {
  return Object.values(map).sort(
    (a, b) => b.score - a.score || a.ip.localeCompare(b.ip),
  )
}
