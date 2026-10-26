'use client'

/**
 * ShareDialog — builds a plain-text report of scan results,
 * shows a live preview and offers copy-to-clipboard / TXT download.
 */

import { useMemo, useState } from 'react'
import { Check, Copy, Download, Link2, Share2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useI18n } from '@/components/i18n-provider'
import { Input } from '@/components/ui/input'
import type { LiveResult } from '@/lib/scan-protocol'
import { cn } from '@/lib/utils'

export interface ShareMeta {
  preset?: string
  date?: number
  port?: number
  total?: number
  alive?: number
}

interface ShareDialogProps {
  open: boolean
  onOpenChange: (v: boolean) => void
  results: LiveResult[]
  meta?: ShareMeta | null
  /** when set, a real shareable ?share=<id> link is offered */
  savedId?: string | null
}

const W = { rank: 3, ip: 23, lat: 9, loss: 6, dl: 10, ul: 10, total: 12 } as const

function mbps(bps: number | undefined): string {
  if (!bps || bps <= 0) return '—'
  return (bps / 1048576).toFixed(2)
}

export function buildShareReport(results: LiveResult[], meta?: ShareMeta | null): string {
  const sorted = [...results].sort(
    (a, b) => (b.totalSpeed ?? 0) - (a.totalSpeed ?? 0) || a.latencyMs - b.latencyMs,
  )
  const line = '─'.repeat(78)
  const head: string[] = [line, '  Clean IP Scanner — Web Edition']
  if (meta?.preset || meta?.date) {
    const bits: string[] = []
    if (meta.preset) bits.push(meta.preset)
    if (meta.port) bits.push(`port ${meta.port}`)
    if (meta.date) bits.push(new Date(meta.date).toISOString().replace('T', ' ').slice(0, 16) + ' UTC')
    head.push(`  ${bits.join(' · ')}`)
  }
  if (meta && (meta.total || meta.alive)) {
    head.push(`  ${meta.alive ?? sorted.length}/${meta.total ?? sorted.length} responsive · ${sorted.length} clean IPs`)
  } else {
    head.push(`  ${sorted.length} clean IPs`)
  }
  head.push(line)

  const header =
    '#'.padEnd(W.rank) +
    'IP'.padEnd(W.ip) +
    'Latency'.padStart(W.lat) +
    'Loss'.padStart(W.loss) +
    'DL MB/s'.padStart(W.dl) +
    'UL MB/s'.padStart(W.ul) +
    'Total'.padStart(W.total)

  const rows = sorted.slice(0, 100).map((r, i) => {
    const rank = String(i + 1).padEnd(W.rank)
    const ip = r.ip.slice(0, W.ip).padEnd(W.ip)
    const lat = `${r.latencyMs.toFixed(1)}ms`.padStart(W.lat)
    const loss = `${Math.round(r.lossRate * 100)}%`.padStart(W.loss)
    const dl = mbps(r.downloadSpeed).padStart(W.dl)
    const ul = mbps(r.uploadSpeed).padStart(W.ul)
    const total =
      (r.totalSpeed ?? 0) > 0
        ? `${mbps(r.totalSpeed)} MB/s`.padStart(W.total)
        : '—'.padStart(W.total)
    return `${rank}${ip}${lat}${loss}${dl}${ul}${total}`
  })

  const footer = [
    line,
    `  Generated ${new Date().toISOString().replace('T', ' ').slice(0, 16)} UTC — Clean IP Scanner Web Edition`,
  ]
  return [...head, header, ...rows, ...footer].join('\n')
}

export function ShareDialog({ open, onOpenChange, results, meta, savedId }: ShareDialogProps) {
  const { t, dir } = useI18n()
  const [copied, setCopied] = useState(false)
  const [linkCopied, setLinkCopied] = useState(false)
  const report = useMemo(() => buildShareReport(results, meta), [results, meta])
  const shareLink = useMemo(
    () => (savedId && typeof window !== 'undefined' ? `${window.location.origin}/?share=${savedId}` : null),
    [savedId],
  )

  const handleCopy = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(report)
      } else {
        const ta = document.createElement('textarea')
        ta.value = report
        ta.style.position = 'fixed'
        ta.style.opacity = '0'
        document.body.appendChild(ta)
        ta.select()
        document.execCommand('copy')
        document.body.removeChild(ta)
      }
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      setCopied(false)
    }
  }

  const handleCopyLink = async () => {
    if (!shareLink) return
    try {
      await navigator.clipboard.writeText(shareLink)
      setLinkCopied(true)
      window.setTimeout(() => setLinkCopied(false), 1800)
    } catch {
      setLinkCopied(false)
    }
  }

  const handleDownload = () => {
    const blob = new Blob([report], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `clean-ip-report-${new Date().toISOString().slice(0, 10)}.txt`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent dir={dir} className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Share2 className="size-4 text-emerald-500" aria-hidden />
            {t('share.title')}
          </DialogTitle>
          <DialogDescription>{t('share.desc')}</DialogDescription>
        </DialogHeader>

        {shareLink ? (
          <div className="space-y-1.5">
            <p className="text-[11px] font-medium text-muted-foreground">{t('share.link.label')}</p>
            <div className="flex items-center gap-1.5">
              <Input
                readOnly
                dir="ltr"
                value={shareLink}
                onFocus={(e) => e.currentTarget.select()}
                className="h-8 flex-1 bg-background/60 font-mono text-[11px]"
                aria-label={t('share.link.label')}
              />
              <Button
                variant="outline"
                size="sm"
                className="h-8 shrink-0 gap-1 px-2.5 text-[11px]"
                onClick={handleCopyLink}
                aria-label={t('share.link.copy')}
              >
                {linkCopied ? <Check className="size-3" aria-hidden /> : <Link2 className="size-3" aria-hidden />}
                {linkCopied ? t('share.copied') : t('share.link.copy')}
              </Button>
            </div>
            <p className="text-[10px] text-muted-foreground">{t('share.link.hint')}</p>
          </div>
        ) : null}

        {results.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">{t('share.empty')}</p>
        ) : (
          <div className="space-y-2">
            <p className="text-[11px] font-medium text-muted-foreground">{t('share.preview')}</p>
            <pre
              dir="ltr"
              className="scrollbar-thin max-h-80 overflow-auto rounded-lg border bg-zinc-950 p-3 font-mono text-[10.5px] leading-4 text-zinc-200"
            >
              {report}
            </pre>
          </div>
        )}

        <DialogFooter className="gap-2 sm:gap-0">
          <Button variant="ghost" size="sm" onClick={() => onOpenChange(false)}>
            {t('fav.cancel')}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleDownload}
            disabled={results.length === 0}
            aria-label={t('share.download.aria')}
          >
            <Download className="size-3.5" aria-hidden />
            {t('share.download')}
          </Button>
          <Button
            size="sm"
            onClick={handleCopy}
            disabled={results.length === 0}
            aria-label={t('share.copy.aria')}
            className={cn(
              'gap-1.5 border-0 bg-gradient-to-l from-emerald-600 to-teal-500 text-white hover:from-emerald-500 hover:to-teal-400',
              copied && 'from-emerald-500 to-emerald-500',
            )}
          >
            {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
            {copied ? t('share.copied') : t('share.copy')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
