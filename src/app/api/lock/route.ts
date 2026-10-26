import { NextRequest, NextResponse } from 'next/server'
import { UNLOCK_COOKIE, disableLock, enableLock, getLockState, verifyLock } from '@/lib/lock'

export const dynamic = 'force-dynamic'

function cookieResponse(body: Record<string, unknown>, cookie?: string) {
  const res = NextResponse.json(body)
  if (cookie !== undefined) {
    res.cookies.set({
      name: UNLOCK_COOKIE,
      value: cookie,
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: cookie === '' ? 0 : 60 * 60 * 24 * 30, // 30 days
    })
  }
  return res
}

/** GET /api/lock — is the lock enabled, and does this browser hold the unlock cookie? */
export async function GET() {
  try {
    const state = await getLockState()
    return NextResponse.json(state)
  } catch (e) {
    return NextResponse.json({ error: 'lock_state_failed', detail: String(e) }, { status: 500 })
  }
}

/**
 * POST /api/lock
 *  { action: 'verify', pin }              → sets the unlock cookie on success
 *  { action: 'enable', pin, confirm, currentPin? }
 *  { action: 'disable', pin }
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => null)
    const action = typeof body?.action === 'string' ? body.action : ''
    const pin = typeof body?.pin === 'string' ? body.pin : ''
    const confirm = typeof body?.confirm === 'string' ? body.confirm : ''
    const currentPin = typeof body?.currentPin === 'string' ? body.currentPin : undefined

    if (action === 'verify') {
      const r = await verifyLock(pin)
      if (!r.ok) {
        return NextResponse.json({ ok: false, reason: r.reason, retryAfter: r.retryAfter }, { status: r.reason === 'throttled' ? 429 : 401 })
      }
      return cookieResponse({ ok: true, unlocked: true }, r.cookie)
    }

    if (action === 'enable') {
      const r = await enableLock(pin, confirm, currentPin)
      if (!r.ok) {
        return NextResponse.json({ ok: false, reason: r.reason }, { status: 400 })
      }
      return cookieResponse({ ok: true, unlocked: true }, r.cookie)
    }

    if (action === 'disable') {
      const r = await disableLock(pin)
      if (!r.ok) {
        return NextResponse.json({ ok: false, reason: r.reason, retryAfter: r.retryAfter }, { status: r.reason === 'throttled' ? 429 : 401 })
      }
      return cookieResponse({ ok: true, unlocked: false }, r.cookie ?? '')
    }

    return NextResponse.json({ error: 'bad_action' }, { status: 400 })
  } catch (e) {
    return NextResponse.json({ error: 'lock_action_failed', detail: String(e) }, { status: 500 })
  }
}
