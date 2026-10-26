/**
 * Typed contracts for the REST API consumed by the frontend.
 * The backend (Task 2-b) implements these routes under /api.
 */

export interface StatsResponse {
  totalScans: number
  totalIPsScanned: number
  totalCleanIPs: number
  bestIp: { ip: string; latencyMs: number; totalSpeed: number } | null
  lastScanAt: string | null
}

export interface ScanListItem {
  id: string
  preset: string
  label: string | null
  port: number
  maxIPs: number
  totalIPs: number
  scannedIPs: number
  aliveIPs: number
  speedTested: number
  status: string
  durationMs: number
  createdAt: string
  resultCount: number
  /** max totalSpeed among results (bytes/s) — 0 when no speed data */
  bestSpeed: number
  /** avg latency of results (ms) */
  avgLatency: number
}

export interface GeoInfo {
  ip: string
  countryCode: string
  country: string
  city: string
  isp: string
  asn: string
}

export interface GeoResponse {
  geo: Record<string, GeoInfo>
}

export interface FavoriteItem {
  id: string
  ip: string
  label: string | null
  note: string | null
  addedAt: string
  lastCheckAt: string | null
  lastLatencyMs: number | null
  lastLossRate: number | null
  lastStatus: string | null
  checksCount: number
}

export interface FavoritesResponse {
  favorites: FavoriteItem[]
}

export interface ScansListResponse {
  scans: ScanListItem[]
}

export interface ScanDetailResult {
  ip: string
  latencyMs: number
  sent: number
  received: number
  lossRate: number
  downloadSpeed: number
  uploadSpeed: number
  totalSpeed: number
  rank: number
}

export interface ScanDetailScan extends ScanListItem {
  rangesText: string
  speedTestCount: number
  pingCount: number
  timeoutMs: number
  concurrency: number
}

export interface ScanDetailResponse {
  scan: ScanDetailScan
  results: ScanDetailResult[]
}

/** countryCode (e.g. "US") → emoji flag */
export function countryFlag(cc: string): string {
  if (!cc || cc.length !== 2 || !/^[a-zA-Z]{2}$/.test(cc)) return '🌐'
  return String.fromCodePoint(
    ...[...cc.toUpperCase()].map((c) => 127397 + c.charCodeAt(0)),
  )
}

/** Generic JSON fetcher with graceful failure. */
export async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return (await res.json()) as T
}
