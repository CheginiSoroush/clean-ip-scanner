import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

/**
 * Telegram digest settings (hunt v6.3) — single row (id=1).
 *
 * GET → { configured, chatId?, autoOnFinish?, tokenHint? }
 * PUT ← { botToken?, chatId, autoOnFinish } → { ok, tokenHint }
 *
 * The bot token NEVER leaves the server raw — responses carry a masked
 * `tokenHint` ('••••' + last 4). An omitted/empty token keeps the stored one.
 */

const TOKEN_MIN = 20
const TOKEN_MAX = 60

function maskToken(token: string): string {
  const last4 = token.slice(-4)
  return `••••${last4}`
}

// GET /api/telegram — settings (masked token)
export async function GET() {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const row = await db.telegramSettings.findUnique({ where: { id: 1 } })
    return NextResponse.json(
      row
        ? {
            configured: true,
            chatId: row.chatId,
            autoOnFinish: row.autoOnFinish,
            tokenHint: maskToken(row.botToken),
            updatedAt: row.updatedAt.toISOString(),
          }
        : { configured: false },
    )
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_read_telegram', detail: String(e) }, { status: 500 })
  }
}

// PUT /api/telegram — upsert settings (empty botToken = keep the stored token)
export async function PUT(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const body = (await req.json()) as {
      botToken?: unknown
      chatId?: unknown
      autoOnFinish?: unknown
    }

    const chatId = typeof body.chatId === 'string' ? body.chatId.trim() : ''
    if (!chatId || chatId.length > 64) {
      return NextResponse.json({ error: 'invalid_chat_id' }, { status: 400 })
    }
    if (typeof body.autoOnFinish !== 'boolean') {
      return NextResponse.json({ error: 'invalid_auto_on_finish' }, { status: 400 })
    }

    // same keep-if-empty rules as the DNS token
    const existing = await db.telegramSettings.findUnique({ where: { id: 1 } })
    const rawToken = typeof body.botToken === 'string' ? body.botToken.trim() : ''
    let botToken = rawToken
    if (rawToken === '') {
      if (!existing) {
        return NextResponse.json({ error: 'token_required' }, { status: 400 })
      }
      botToken = existing.botToken
    } else if (rawToken.length < TOKEN_MIN || rawToken.length > TOKEN_MAX) {
      return NextResponse.json({ error: 'invalid_token' }, { status: 400 })
    }

    await db.telegramSettings.upsert({
      where: { id: 1 },
      update: { botToken, chatId, autoOnFinish: body.autoOnFinish },
      create: { id: 1, botToken, chatId, autoOnFinish: body.autoOnFinish },
    })

    return NextResponse.json({ ok: true, tokenHint: maskToken(botToken) })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_save_telegram', detail: String(e) }, { status: 500 })
  }
}
