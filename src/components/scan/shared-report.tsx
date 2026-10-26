'use client'

/**
 * SharedReport — read-only viewer for a scan shared via a `?share=<scanId>` link.
 * Fetches the scan detail from the public API and renders a rich summary
 * (meta cards, top results table for sm+, mobile cards for phones) plus
 * report copy/download. Anyone opening the link sees this dialog.
 */

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { faIR, enUS } from 'date-fns/locale'
import { Check, Copy, Download, Share2, Signal, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { fetchJson, type ScanDetailResponse } from '@/lib/api-types'
import { formatDurationHMS } from '@/lib/format-fa'
import { getPreset } from '@/lib/cdn-presets'
import { buildShareReport } from '@/components/scan/share-dialog'
import { formatBytesPerSec, formatLatency, type LiveResult } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import { cn } from '@/lib/utils'

/** detail rows are ranked server-side and always carry speed numbers */
type SharedRow = LiveResult & { rank: number; downloadSpeed: number; totalSpeed: number }

const MEDAL_STYLES = [
  'border-amber-500/40 bg-amber-500/10 text-amber-500',
  'border-zinc-400/40 bg-zinc-400/10 text-zinc-400',
  'border-orange-500/40 bg-orange-500/10 text-orange-500',
]

interface SharedReportProps {
  scanId: string | null
  onClear: () => void
}

export function SharedReport({ scanId, onClear }: SharedReportProps) {
  const { t, num, lang, dir, dateLocale } = useI18n()
  const [copied, setCopied] = useState(false)
  const open = !!scanId

  const query = useQuery<ScanDetailResponse>({
    queryKey: ['shared-scan', scanId],
    queryFn: () => fetchJson<ScanDetailResponse>(`/api/scans/${scanId}`),
    enabled: !!scanId,
    retry: 1,
  })

  const data = query.data ?? null
  const scan = data?.scan
  const results = useMemo(() => (data?.results ?? []) as unknown as SharedRow[], [data])
  const dateFnsLocale = lang === 'fa' ? faIR : enUS
  const presetName = scan
    ? lang === 'fa'
      ? (getPreset(scan.preset)?.nameFa ?? scan.preset)
      : (getPreset(scan.preset)?.name ?? scan.preset)
    : ''

  const report = useMemo(() => {
    if (!scan) return ''
    return buildShareReport(results, {
      preset: presetName,
      date: new Date(scan.createdAt).getTime(),
      port: scan.port,
      total: scan.totalIPs,
      alive: scan.aliveIPs,
    })
  }, [scan, results, presetName])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(report)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      setCopied(false)
    }
  }

  const handleDownload = () => {
    const blob = new Blob([report], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `clean-ip-report-${scanId?.slice(-6) ?? 'shared'}.txt`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClear()}>
      <DialogContent dir={dir} className="max-h-[88vh] max-w-2xl overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Share2 className="size-4 text-emerald-500" aria-hidden />
            {t('shared.title')}
          </DialogTitle>
          <DialogDescription>{t('shared.desc')}</DialogDescription>
        </DialogHeader>

        {query.isLoading ? (
          <div className="flex flex-col items-center gap-3 py-14 text-center">
            <Signal className="size-6 animate-pulse text-emerald-500" aria-hidden />
            <p className="text-sm text-muted-foreground">{t('shared.loading')}</p>
          </div>
        ) : query.isError || !scan ? (
          <div className="flex flex-col items-center gap-2 py-12 text-center">
            <X className="size-6 text-red-400" aria-hidden />
            <p className="text-sm font-semibold">{t('shared.notfound.title')}</p>
            <p className="text-xs text-muted-foreground">{t('shared.notfound.sub')}</p>
          </div>
        ) : (
          <div className="space-y-4">
            {/* headline meta */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                {presetName}
              </Badge>
              <span className="font-mono" dir="ltr">
                :{num(scan.port)}
              </span>
              <span className="text-muted-foreground">
                {formatDistanceToNow(new Date(scan.createdAt), {
                  addSuffix: true,
                  locale: dateFnsLocale,
                })}
              </span>
              {scan.label ? (
                <span className="truncate rounded-full bg-muted px-2 py-0.5 text-[10px] text-muted-foreground">
                  {scan.label}
                </span>
              ) : null}
            </div>

            {/* stats grid */}
            <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
              {[
                [t('history.meta.results'), num(scan.resultCount)],
                [t('history.meta.alive'), `${num(scan.aliveIPs)}/${num(scan.totalIPs)}`],
                [t('history.meta.duration'), formatDurationHMS(scan.durationMs)],
                [t('shared.best.speed'), results[0] ? formatBytesPerSec(results[0].totalSpeed) : '—'],
              ].map(([k, v]) => (
                <div key={k} className="rounded-lg border bg-background/40 p-2.5">
                  <div className="text-[10px] text-muted-foreground">{k}</div>
                  <div className="mt-0.5 font-mono font-semibold" dir="ltr">
                    {v}
                  </div>
                </div>
              ))}
            </div>

            {/* top-1 highlight */}
            {results[0] ? (
              <div className="flex items-center gap-3 rounded-xl border border-amber-500/30 bg-gradient-to-br from-amber-500/10 via-transparent to-emerald-500/5 p-3">
                <span className="flex size-9 items-center justify-center rounded-full border border-amber-500/40 bg-amber-500/10 text-amber-500">
                  🏆
                </span>
                <div className="min-w-0 flex-1">
                  <p className="font-mono text-sm font-bold" dir="ltr">
                    {results[0].ip}
                  </p>
                  <p className="mt-0.5 text-[11px] text-muted-foreground">
                    {formatLatency(results[0].latencyMs)} ·{' '}
                    <span className="font-semibold text-emerald-600 dark:text-emerald-400" dir="ltr">
                      {formatBytesPerSec(results[0].totalSpeed)}
                    </span>
                  </p>
                </div>
              </div>
            ) : null}

            {/* results — cards on phones, table on sm+ */}
            {results.length > 0 ? (
              <>
                <div className="space-y-1.5 sm:hidden">
                  {results.slice(0, 20).map((r, i) => (
                    <div
                      key={r.ip}
                      className="flex items-center gap-2 rounded-lg border bg-background/40 p-2.5"
                    >
                      <span
                        className={cn(
                          'inline-flex size-6 shrink-0 items-center justify-center rounded-full border text-[10px] font-bold',
                          i < 3 ? MEDAL_STYLES[i] : 'border-border text-muted-foreground',
                        )}
                        dir="ltr"
                      >
                        {num(r.rank)}
                      </span>
                      <span className="min-w-0 flex-1 truncate font-mono text-xs font-semibold" dir="ltr">
                        {r.ip}
                      </span>
                      <span className="shrink-0 font-mono text-[10px] text-muted-foreground" dir="ltr">
                        {formatLatency(r.latencyMs)}
                      </span>
                      <span className="shrink-0 font-mono text-[10px] font-bold text-emerald-600 dark:text-emerald-400" dir="ltr">
                        {formatBytesPerSec(r.totalSpeed)}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="scrollbar-thin hidden max-h-64 overflow-y-auto rounded-lg border sm:block">
                  <Table>
                    <TableHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                      <TableRow className="hover:bg-transparent">
                        <TableHead className="text-start text-xs">#</TableHead>
                        <TableHead className="text-start text-xs">IP</TableHead>
                        <TableHead className="text-start text-xs">{t('results.col.latency')}</TableHead>
                        <TableHead className="text-start text-xs">{t('results.col.loss')}</TableHead>
                        <TableHead className="text-start text-xs">{t('results.col.download')}</TableHead>
                        <TableHead className="text-start text-xs">{t('results.col.total')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {results.map((r) => (
                        <TableRow key={r.ip}>
                          <TableCell className="font-mono text-xs tabular-nums">{num(r.rank)}</TableCell>
                          <TableCell dir="ltr" className="text-left font-mono text-xs">
                            {r.ip}
                          </TableCell>
                          <TableCell dir="ltr" className="text-left font-mono text-xs tabular-nums">
                            {formatLatency(r.latencyMs)}
                          </TableCell>
                          <TableCell dir="ltr" className="text-left font-mono text-xs tabular-nums">
                            {(r.lossRate * 100).toFixed(1)}%
                          </TableCell>
                          <TableCell dir="ltr" className="text-left font-mono text-xs tabular-nums">
                            {formatBytesPerSec(r.downloadSpeed)}
                          </TableCell>
                          <TableCell
                            dir="ltr"
                            className="text-left font-mono text-xs font-semibold tabular-nums text-emerald-600 dark:text-emerald-400"
                          >
                            {formatBytesPerSec(r.totalSpeed)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </>
            ) : (
              <p className="py-6 text-center text-sm text-muted-foreground">{t('shared.empty')}</p>
            )}
          </div>
        )}

        {data ? (
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={onClear}>
              {t('fav.cancel')}
            </Button>
            <Button variant="outline" size="sm" onClick={handleDownload} disabled={results.length === 0}>
              <Download className="size-3.5" aria-hidden />
              {t('share.download')}
            </Button>
            <Button
              size="sm"
              onClick={handleCopy}
              disabled={results.length === 0}
              className={cn(
                'gap-1.5 border-0 bg-gradient-to-l from-emerald-600 to-teal-500 text-white hover:from-emerald-500 hover:to-teal-400',
                copied && 'from-emerald-500 to-emerald-500',
              )}
            >
              {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
              {copied ? t('share.copied') : t('share.copy')}
            </Button>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

