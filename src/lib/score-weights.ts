/**
 * Persisted score-weight store (localStorage-backed, cross-tab synced).
 * Used by the "what-if" score tuning dialog; consumers re-render live
 * via useSyncExternalStore so every score chip / banner / sort reacts.
 */
import { useSyncExternalStore } from 'react'
import { clampWeights, DEFAULT_WEIGHTS, type ScoreWeights } from '@/lib/ip-score'

const KEY = 'cis-score-weights'

let cached: ScoreWeights | null = null
const listeners = new Set<() => void>()

function read(): ScoreWeights {
  if (cached) return cached
  let next = { ...DEFAULT_WEIGHTS }
  try {
    if (typeof window !== 'undefined') {
      const raw = window.localStorage.getItem(KEY)
      if (raw) next = clampWeights(JSON.parse(raw))
    }
  } catch {
    /* private mode / corrupted value */
  }
  cached = next // ALWAYS cache — getSnapshot must return a stable reference or React loops forever
  return cached
}

export function getScoreWeights(): ScoreWeights {
  return read()
}

export function setScoreWeights(w: ScoreWeights): void {
  const next = clampWeights(w)
  cached = next
  try {
    window.localStorage.setItem(KEY, JSON.stringify(next))
  } catch {
    /* private mode */
  }
  listeners.forEach((l) => l())
}

export function resetScoreWeights(): void {
  setScoreWeights({ ...DEFAULT_WEIGHTS })
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb)
  return () => listeners.delete(cb)
}

const isDefault = (w: ScoreWeights) =>
  (['grade', 'tls', 'loss', 'speed', 'stab'] as const).every((k) => w[k] === DEFAULT_WEIGHTS[k])

export { isDefault as isDefaultWeights }

/** React hook — re-renders whenever the weights change (any tab) */
export function useScoreWeights(): ScoreWeights {
  return useSyncExternalStore(subscribe, getScoreWeights, () => DEFAULT_WEIGHTS)
}
