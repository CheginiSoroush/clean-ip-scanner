import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

// DELETE /api/favorites/[ip]
export async function DELETE(_req: NextRequest, ctx: { params: Promise<{ ip: string }> }) {
  const { ip } = await ctx.params
  const decoded = decodeURIComponent(ip).trim()
  try {
    const res = await db.favorite.deleteMany({ where: { ip: decoded } })
    if (res.count === 0) return NextResponse.json({ error: 'not_found' }, { status: 404 })
    return NextResponse.json({ ok: true })
  } catch (e) {
    return NextResponse.json({ error: 'failed_to_delete', detail: String(e) }, { status: 500 })
  }
}
