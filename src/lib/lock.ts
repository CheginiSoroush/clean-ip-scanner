import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

/**
 * Optional single-user PIN lock — a privacy gate for the dashboard.
 *
 * Storage (Setting table):
 *   lock.salt   random hex, per-enable
 *   lock.hash   sha256(`${salt}:${pin}`) — the PIN itself is never stored
 *   lock.secret random hex returned as the unlocked cookie value
 *
 * The cookie `cis-unlock` (httpOnly) must equal lock.secret for API access
 * while the lock is enabled. Note: the scan ENGINE is a separate local
 * process and remains reachable on localhost — this gate protects the web
 * UI + data APIs of a shared machine, not the loopback interface itself.
 */

export const UNLOCK_COOKIE = 'cis-unlock'
const KEY_HASH = 'lock.hash'
const KEY_SALT = 'lock.salt'
const KEY_SECRET = 'lock.secret'

const PIN_RE = /^\d{4,8}$/

/** naive in-memory brute-force throttle: 6 failures / 60s */
const attempts: { count: number; resetAt: number } = { count: 0, resetAt: 0 }

function throttle(): { ok: boolean; retryAfter: number } {
  const now = Date.now()
  if (now > attempts.resetAt) {
    attempts.count = 0
    attempts.resetAt = now + 60_000
  }
  if (attempts.count >= 6) {
    return { ok: false, retryAfter: Math.ceil((attempts.resetAt - now) / 1000) }
  }
  return { ok: true, retryAfter: 0 }
}

function recordFailure() {
  attempts.count += 1
}

function hashPin(pin: string, salt: string): string {
  return createHash('sha256').update(`${salt}:${pin}`).digest('hex')
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a)
  const bb = Buffer.from(b)
  return ba.length === bb.length && timingSafeEqual(ba, bb)
}

export interface LockState {
  enabled: boolean
  unlocked: boolean
}

export async function getLockState(): Promise<LockState> {
  const rows = await db.setting.findMany({
    where: { key: { in: [KEY_HASH, KEY_SALT, KEY_SECRET] } },
  })
  const map = Object.fromEntries(rows.map((r) => [r.key, r.value]))
  const enabled = !!(map[KEY_HASH] && map[KEY_SALT] && map[KEY_SECRET])
  if (!enabled) return { enabled: false, unlocked: false }
  const store = await cookies()
  const token = store.get(UNLOCK_COOKIE)?.value
  const unlocked = !!token && !!map[KEY_SECRET] && safeEqual(token, map[KEY_SECRET]!)
  return { enabled: true, unlocked }
}

/** non-null → the request must be rejected with this 423 response */
export async function lockGuard(): Promise<NextResponse | null> {
  try {
    const state = await getLockState()
    if (!state.enabled || state.unlocked) return null
    return NextResponse.json({ error: 'locked' }, { status: 423 })
  } catch {
    // if the lock machinery itself fails, never hard-block the app
    return null
  }
}

export type LockActionResult =
  | { ok: true; unlocked: boolean; cookie?: string }
  | { ok: false; reason: 'invalid_pin' | 'wrong_pin' | 'mismatch' | 'throttled' | 'bad_request'; retryAfter?: number }

export async function enableLock(pin: string, confirm: string, currentPin?: string): Promise<LockActionResult> {
  const state = await getLockState()
  if (state.enabled) {
    // re-enabling over an active lock requires the current PIN
    if (!currentPin) return { ok: false, reason: 'bad_request' }
    const check = await verifyLock(currentPin)
    if (!check.ok) return check
  }
  if (!PIN_RE.test(pin) || pin !== confirm) return { ok: false, reason: 'mismatch' }
  const salt = randomBytes(16).toString('hex')
  const secret = randomBytes(32).toString('hex')
  await db.$transaction([
    db.setting.upsert({ where: { key: KEY_SALT }, update: { value: salt }, create: { key: KEY_SALT, value: salt } }),
    db.setting.upsert({ where: { key: KEY_HASH }, update: { value: hashPin(pin, salt) }, create: { key: KEY_HASH, value: hashPin(pin, salt) } }),
    db.setting.upsert({ where: { key: KEY_SECRET }, update: { value: secret }, create: { key: KEY_SECRET, value: secret } }),
  ])
  return { ok: true, unlocked: true, cookie: secret }
}

export async function disableLock(pin: string): Promise<LockActionResult> {
  const state = await getLockState()
  if (!state.enabled) return { ok: true, unlocked: false }
  const check = await verifyLock(pin)
  if (!check.ok) return check
  await db.setting.deleteMany({ where: { key: { in: [KEY_HASH, KEY_SALT, KEY_SECRET] } } })
  return { ok: true, unlocked: false, cookie: '' }
}

export async function verifyLock(pin: string): Promise<LockActionResult> {
  const t = throttle()
  if (!t.ok) return { ok: false, reason: 'throttled', retryAfter: t.retryAfter }
  if (!PIN_RE.test(pin)) return { ok: false, reason: 'invalid_pin' }
  const rows = await db.setting.findMany({ where: { key: { in: [KEY_HASH, KEY_SALT, KEY_SECRET] } } })
  const map = Object.fromEntries(rows.map((r) => [r.key, r.value]))
  const salt = map[KEY_SALT]
  const hash = map[KEY_HASH]
  const secret = map[KEY_SECRET]
  if (!salt || !hash || !secret) return { ok: false, reason: 'bad_request' }
  if (!safeEqual(hashPin(pin, salt), hash)) {
    recordFailure()
    return { ok: false, reason: 'wrong_pin' }
  }
  attempts.count = 0
  return { ok: true, unlocked: true, cookie: secret }
}
