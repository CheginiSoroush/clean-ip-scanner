import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

/**
 * GET /api/sub — the subscription feed for V2rayNG / Hiddify / …
 *
 * All saved configs (oldest first, capped at 500) are newline-joined and
 * served base64-encoded as text/plain, per the de-facto "base64 subscription"
 * convention. Response headers follow the client hints:
 *   profile-title            base64("Clean IP Scanner")
 *   profile-update-interval  6 (hours)
 *   profile-web-page-url     "/" (dashboard root)
 *   cache-control            no-store
 *
 * NOTE: deliberately NOT behind the optional PIN lockGuard — external
 * subscription clients cannot present the unlock cookie. It only ever serves
 * URIs the user explicitly saved for this purpose.
 */
export async function GET() {
  try {
    const rows = await db.savedConfig.findMany({
      orderBy: { createdAt: 'asc' },
      take: 500,
      select: { uri: true },
    })
    const text = rows.map((r) => r.uri).join('\n')
    return new NextResponse(Buffer.from(text, 'utf8').toString('base64'), {
      status: 200,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'profile-title': Buffer.from('Clean IP Scanner', 'utf8').toString('base64'),
        'profile-update-interval': '6',
        'profile-web-page-url': '/',
        'cache-control': 'no-store',
      },
    })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_build_sub', detail: String(e) }, { status: 500 })
  }
}
