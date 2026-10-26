'use client'

/**
 * Tiny WebAudio chime module — zero dependencies, no audio files needed.
 * Used for audible feedback on scan finish / errors (toggleable in the header).
 * Persists the preference in localStorage under "cis-sound".
 */

const STORAGE_KEY = 'cis-sound'
const SOUND_EVENT = 'cis-sound-change'

let ctx: AudioContext | null = null

export function isSoundEnabled(): boolean {
  if (typeof window === 'undefined') return false
  try {
    return window.localStorage.getItem(STORAGE_KEY) !== '0'
  } catch {
    return true
  }
}

/** subscribe for useSyncExternalStore — reacts to own toggles + cross-tab 'storage' */
export function subscribeSound(cb: () => void): () => void {
  window.addEventListener(SOUND_EVENT, cb)
  window.addEventListener('storage', cb)
  return () => {
    window.removeEventListener(SOUND_EVENT, cb)
    window.removeEventListener('storage', cb)
  }
}

export function setSoundEnabled(v: boolean) {
  try {
    window.localStorage.setItem(STORAGE_KEY, v ? '1' : '0')
  } catch {
    /* private mode etc. */
  }
  try {
    window.dispatchEvent(new Event(SOUND_EVENT))
  } catch {
    /* ignore */
  }
}

function getCtx(): AudioContext | null {
  if (typeof window === 'undefined') return null
  try {
    if (!ctx) {
      const AC =
        window.AudioContext ??
        (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
      if (!AC) return null
      ctx = new AC()
    }
    if (ctx.state === 'suspended') void ctx.resume()
    return ctx
  } catch {
    return null
  }
}

function tone(ac: AudioContext, freq: number, startAt: number, dur: number, gain = 0.06, type: OscillatorType = 'sine') {
  const osc = ac.createOscillator()
  const g = ac.createGain()
  osc.type = type
  osc.frequency.value = freq
  g.gain.setValueAtTime(0, ac.currentTime + startAt)
  g.gain.linearRampToValueAtTime(gain, ac.currentTime + startAt + 0.015)
  g.gain.exponentialRampToValueAtTime(0.0001, ac.currentTime + startAt + dur)
  osc.connect(g)
  g.connect(ac.destination)
  osc.start(ac.currentTime + startAt)
  osc.stop(ac.currentTime + startAt + dur + 0.05)
}

export type ChimeKind = 'success' | 'error' | 'info' | 'queue'

/** Play a short UI chime. Safe to call anywhere; no-ops when muted or unsupported. */
export function playChime(kind: ChimeKind = 'success') {
  if (!isSoundEnabled()) return
  const ac = getCtx()
  if (!ac) return
  try {
    switch (kind) {
      case 'success':
        // rising two-note "all good" motif
        tone(ac, 659.25, 0, 0.14) // E5
        tone(ac, 880, 0.12, 0.22) // A5
        break
      case 'queue':
        // distinct three-note "queue item finished" arpeggio (E5 → G#5 → B5)
        tone(ac, 659.25, 0, 0.12)
        tone(ac, 830.61, 0.1, 0.12)
        tone(ac, 987.77, 0.2, 0.26)
        break
      case 'error':
        // descending minor motif
        tone(ac, 329.63, 0, 0.18, 0.07, 'triangle') // E4
        tone(ac, 246.94, 0.16, 0.3, 0.07, 'triangle') // B3
        break
      case 'info':
        tone(ac, 783.99, 0, 0.16, 0.045) // G5
        break
    }
  } catch {
    /* never break the UI over audio */
  }
}
