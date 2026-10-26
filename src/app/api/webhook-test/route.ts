import { NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'

/**
 * POST /api/webhook-test — demo receiver for the auto-scan completion webhook.
 * Useful to validate the engine's "Send test" button and notifications
 * without an external service. Logs the payload on the server.
 */
export async function POST(request: Request) {
  const denied = await lockGuard()
  if (denied) return denied

  let body: unknown = null
  try {
    body = await request.json()
  } catch {
    body = null
  }
  console.log('[webhook-test] received payload:', JSON.stringify(body)?.slice(0, 500))
  return NextResponse.json({ ok: true, receivedAt: new Date().toISOString() })
}
