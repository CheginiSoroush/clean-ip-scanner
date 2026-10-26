/**
 * Formatting helpers for the Persian UI.
 * Numbers/durations stay latin (LTR-friendly), large counts get fa-IR grouping.
 */

const faFormatter = new Intl.NumberFormat('fa-IR')

/** Format a number with Persian digits + grouping (display only). */
export function faNum(n: number): string {
  if (!Number.isFinite(n)) return '۰'
  return faFormatter.format(n)
}

/** Format milliseconds as HH:MM:SS (latin digits, LTR). */
export function formatDurationHMS(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  const pad = (v: number) => String(v).padStart(2, '0')
  return `${pad(h)}:${pad(m)}:${pad(s)}`
}

/** Clamp a number into [min, max]; returns fallback when not finite. */
export function clampInt(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min
  return Math.min(max, Math.max(min, Math.round(value)))
}

export function clampNumber(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min
  return Math.min(max, Math.max(min, value))
}

/**
 * Sanitize + clamp a ScanConfig coming from UI state into a valid config.
 * Single source of truth used by the start button AND the keyboard shortcut.
 */
export function sanitizeScanConfig(
  config: import('@/lib/scan-protocol').ScanConfig,
): import('@/lib/scan-protocol').ScanConfig {
  // lazy import would be nicer, but type-only usage keeps this tree-shakeable
  const dflt = {
    port: 443,
    speedHost: 'speed.cloudflare.com',
  } as const
  return {
    preset: config.preset || 'cloudflare',
    customRanges: config.customRanges ?? '',
    port: clampInt(config.port || dflt.port, 1, 65535),
    pingCount: clampInt(config.pingCount, 1, 8),
    timeoutMs: clampInt(config.timeoutMs, 200, 5000),
    concurrency: clampInt(config.concurrency, 16, 1024),
    maxIPs: clampInt(config.maxIPs, 50, 50000),
    speedTestCount: clampInt(config.speedTestCount, 1, 30),
    speedHost: (config.speedHost ?? '').trim() || dflt.speedHost,
    maxLatencyMs: Math.max(0, Math.round(config.maxLatencyMs ?? 0)),
  }
}
