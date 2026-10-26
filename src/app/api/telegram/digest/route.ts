import { NextRequest, NextResponse } from 'next/server'
import { lockGuard } from '@/lib/lock'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

/**
 * Telegram hunt digest (hunt v6.3, extended v7.6).
 *
 * POST /api/telegram/digest { text?, attach? } — relays a client-composed
 * summary to the configured chat. Plain text (no parse_mode) with web-page
 * preview disabled so bare IPs never turn into link previews.
 *
 * v7.6 — optional `attach` (scheduler-journal CSV auto-attach): when present,
 * the file is uploaded AFTER the text via sendDocument (multipart/form-data,
 * Blob + filename, optional caption ≤1024 chars). `ok` is true only when EVERY
 * attempted part succeeded; `sent` lists the parts that went through.
 */

const TG_TIMEOUT_MS = 15_000
const MAX_TEXT = 4000
const MAX_CAPTION = 1024
const MAX_ATTACH_BYTES = 512 * 1024
const DEFAULT_FILENAME = 'journal.csv'

interface TgResponse {
  ok?: boolean
  description?: string
}

interface DigestAttach {
  /** attachment filename (sanitized; defaults to journal.csv) */
  filename?: string
  /** raw CSV text content (BOM handled client-side) */
  content: string
  /** optional short caption (≤1024 chars) */
  caption?: string
}

/** strip path separators + control/quote chars from the attachment filename */
function safeFilename(raw: unknown): string {
  if (typeof raw !== 'string' || !raw.trim()) return DEFAULT_FILENAME
  const cleaned = raw
    .replace(/[/\\?%*:|"<>]/g, '')
    .replace(/[\x00-\x1f]/g, '')
    .trim()
  return cleaned.slice(0, 120) || DEFAULT_FILENAME
}

export async function POST(req: NextRequest) {
  const denied = await lockGuard()
  if (denied) return denied

  try {
    const body = (await req.json().catch(() => null)) as
      | { text?: unknown; attach?: unknown }
      | null

    const text = body && typeof body.text === 'string' ? body.text.trim() : ''
    const rawAttach =
      body && body.attach && typeof body.attach === 'object' && !Array.isArray(body.attach)
        ? (body.attach as Partial<DigestAttach>)
        : null
    const content = rawAttach && typeof rawAttach.content === 'string' ? rawAttach.content : ''
    const attach: DigestAttach | null =
      rawAttach && content
        ? {
            filename: safeFilename(rawAttach.filename),
            content,
            caption:
              typeof rawAttach.caption === 'string' && rawAttach.caption.trim()
                ? rawAttach.caption.trim().slice(0, MAX_CAPTION)
                : undefined,
          }
        : null

    // v7.6 — at least one part must be present (text-only legacy clients unaffected)
    if (!text && !attach) {
      return NextResponse.json({ error: 'invalid_body' }, { status: 400 })
    }
    if (attach && Buffer.byteLength(attach.content, 'utf8') > MAX_ATTACH_BYTES) {
      return NextResponse.json({ error: 'attach_too_large' }, { status: 413 })
    }

    const row = await db.telegramSettings.findUnique({ where: { id: 1 } })
    if (!row) {
      return NextResponse.json({ error: 'not_configured' }, { status: 400 })
    }

    const sent: string[] = []
    const tgPost = async (method: string, bodyInit: BodyInit) =>
      fetch(`https://api.telegram.org/bot${encodeURIComponent(row.botToken)}/${method}`, {
        method: 'POST',
        cache: 'no-store',
        signal: AbortSignal.timeout(TG_TIMEOUT_MS),
        body: bodyInit,
      })

    const readTg = async (res: Response): Promise<{ ok: boolean; error?: string }> => {
      const json = (await res.json().catch(() => null)) as TgResponse | null
      if (res.ok && json?.ok) return { ok: true }
      const description =
        json && typeof json.description === 'string' && json.description
          ? json.description
          : `telegram_http_${res.status}`
      return { ok: false, error: description }
    }

    let firstError: string | null = null

    // part 1 — plain-text message (unchanged v6.3 behaviour)
    if (text) {
      let r: { ok: boolean; error?: string }
      try {
        const res = await tgPost(
          'sendMessage',
          JSON.stringify({
            chat_id: row.chatId,
            text: text.slice(0, MAX_TEXT),
            disable_web_page_preview: true,
          }),
        )
        r = await readTg(res)
      } catch {
        r = { ok: false, error: 'telegram_unreachable' }
      }
      if (r.ok) sent.push('message')
      else firstError ??= r.error ?? 'message_failed'
    }

    // part 2 — v7.6 journal-CSV document (multipart; standard FormData/Blob)
    if (attach) {
      let r: { ok: boolean; error?: string }
      try {
        const form = new FormData()
        form.append('chat_id', row.chatId)
        if (attach.caption) form.append('caption', attach.caption)
        form.append(
          'document',
          new Blob([attach.content], { type: 'text/csv;charset=utf-8' }),
          attach.filename,
        )
        r = await readTg(await tgPost('sendDocument', form))
      } catch {
        r = { ok: false, error: 'telegram_unreachable' }
      }
      if (r.ok) sent.push('document')
      else firstError ??= r.error ?? 'document_failed'
    }

    if (sent.length > 0 && !firstError) {
      return NextResponse.json({ ok: true, sent })
    }
    return NextResponse.json(
      { ok: false, error: firstError ?? 'digest_failed', sent },
      { status: sent.length > 0 ? 200 : 502 },
    )
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_send_digest', detail: String(e) }, { status: 500 })
  }
}
