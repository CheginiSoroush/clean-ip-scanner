'use client'

import { memo, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { format, formatDistanceToNow } from 'date-fns'
import { faIR, enUS } from 'date-fns/locale'
import { toast } from 'sonner'
import {
  CalendarDays,
  Eye,
  FileDown,
  GitCompareArrows,
  History,
  Link2,
  RefreshCw,
  ServerOff,
  Share2,
  Trash2,
  X,
} from 'lucide-react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Calendar } from '@/components/ui/calendar'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  fetchJson,
  type ScanDetailResponse,
  type ScanListItem,
  type ScansListResponse,
} from '@/lib/api-types'
import { formatDurationHMS } from '@/lib/format-fa'
import { getPreset } from '@/lib/cdn-presets'
import { formatBytesPerSec, formatLatency, type LiveResult } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'
import { cn } from '@/lib/utils'
import dynamic from 'next/dynamic'

// heavy chart/dialog bundles load on demand — smaller initial JS
const ScanTrends = dynamic(
  () => import('@/components/scan/scan-trends').then((m) => m.ScanTrends),
  { ssr: false },
)
const ScanCompareDialog = dynamic(
  () => import('@/components/scan/scan-compare-dialog').then((m) => m.ScanCompareDialog),
  { ssr: false },
)
const ShareDialog = dynamic(
  () => import('@/components/scan/share-dialog').then((m) => m.ShareDialog),
  { ssr: false },
)

const STATUS_CLS: Record<string, string> = {
  done: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  stopped: 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  error: 'border-red-500/30 bg-red-500/10 text-red-500',
}

const STATUS_KEY: Record<string, DictKey> = {
  done: 'history.status.done',
  stopped: 'history.status.stopped',
  error: 'history.status.error',
}

function HistoryPanelInner() {
  const { t, num, lang, dir, dateLocale } = useI18n()
  const qc = useQueryClient()
  const [detailId, setDetailId] = useState<string | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [compareOpen, setCompareOpen] = useState(false)
  const [shareOpen, setShareOpen] = useState(false)

  const list = useQuery<ScansListResponse>({
    queryKey: ['scans'],
    queryFn: () => fetchJson<ScansListResponse>('/api/scans'),
    retry: false,
  })

  const detail = useQuery<ScanDetailResponse>({
    queryKey: ['scan-detail', detailId],
    queryFn: () => fetchJson<ScanDetailResponse>(`/api/scans/${detailId}`),
    enabled: !!detailId,
  })

  const handleDelete = async (id: string) => {
    setDeletingId(id)
    try {
      const res = await fetch(`/api/scans/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('HTTP error')
      toast.success(t('history.toast.delete.ok'))
      qc.invalidateQueries({ queryKey: ['scans'] })
      qc.invalidateQueries({ queryKey: ['stats'] })
    } catch {
      toast.error(t('history.toast.delete.fail'))
    } finally {
      setDeletingId(null)
    }
  }

  const handleExport = (id: string, fmt: 'txt' | 'csv' | 'json') => {
    window.open(`/api/scans/${id}/export?format=${fmt}`, '_blank')
  }

  // real shareable link — anyone opening it sees the read-only SharedReport dialog
  const handleCopyLink = async (id: string) => {
    try {
      await navigator.clipboard.writeText(`${window.location.origin}/?share=${id}`)
      toast.success(t('share.link.copied'))
    } catch {
      toast.error(t('results.toast.copy.fail'))
    }
  }

  const scans = list.data?.scans ?? []
  const dateFnsLocale = lang === 'fa' ? faIR : enUS
  const presetName = (id: string) =>
    lang === 'fa' ? (getPreset(id)?.nameFa ?? id) : (getPreset(id)?.name ?? id)

  // ---- v7.7 — custom date-range filter (quick chips + from/to calendar pickers) ----
  const [quickRange, setQuickRange] = useState<'all' | '24h' | '7d'>('all')
  const [fromDate, setFromDate] = useState<Date | null>(null)
  const [toDate, setToDate] = useState<Date | null>(null)

  /** start-of-day / end-of-day epoch ms for the picked dates */
  const customWindow = useMemo(() => {
    if (!fromDate && !toDate) return null
    let from = -Infinity
    let to = Infinity
    if (fromDate) from = new Date(fromDate.getFullYear(), fromDate.getMonth(), fromDate.getDate()).getTime()
    if (toDate) to = new Date(toDate.getFullYear(), toDate.getMonth(), toDate.getDate()).getTime() + 86_399_999
    // swapped picks are normalized (later picker wins) instead of silently matching nothing
    if (Number.isFinite(from) && Number.isFinite(to) && from > to) [from, to] = [to, from]
    return { from, to }
  }, [fromDate, toDate])

  const filteredScans = useMemo(() => {
    if (customWindow) {
      return scans.filter((s) => {
        const ts = new Date(s.createdAt).getTime()
        return ts >= customWindow.from && ts <= customWindow.to
      })
    }
    if (quickRange === 'all') return scans
    const cutoff = quickRange === '24h' ? Date.now() - 86_400_000 : Date.now() - 7 * 86_400_000
    return scans.filter((s) => new Date(s.createdAt).getTime() >= cutoff)
  }, [scans, quickRange, customWindow])

  const rangeActive = customWindow !== null || quickRange !== 'all'
  const pickDay = (d: Date | null) =>
    d ? format(d, 'yyyy-MM-dd') : null

  const setQuick = (rid: 'all' | '24h' | '7d') => {
    setQuickRange(rid)
    setFromDate(null)
    setToDate(null)
  }

  return (
    <div className="space-y-4">
      {scans.length > 0 ? <ScanTrends scans={scans} /> : null}
      <div className="rounded-xl border bg-card/60 p-4 backdrop-blur sm:p-6">
      {/* Title */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="flex size-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
            <History className="size-4" aria-hidden />
          </span>
          <h2 className="text-base font-bold">{t('history.title')}</h2>
          {scans.length > 0 ? (
            <Badge variant="outline" className="text-muted-foreground">
              {t('history.count', { n: num(scans.length) })}
            </Badge>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="h-9 gap-1.5"
            onClick={() => setCompareOpen(true)}
            disabled={scans.filter((s) => s.resultCount > 0).length < 2}
            title={t('history.compare.title')}
          >
            <GitCompareArrows className="size-3.5" aria-hidden />
            {t('history.compare')}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-9 gap-1.5"
            onClick={() => list.refetch()}
            disabled={list.isFetching}
          >
            <RefreshCw
              className={cn('size-3.5', list.isFetching && 'animate-spin')}
              aria-hidden
            />
            {t('history.refresh')}
          </Button>
        </div>
      </div>

      {/* v7.7 — date-range filter row (quick chips + custom from/to calendar pickers) */}
      {scans.length > 0 ? (
        <div className="mt-4 flex flex-wrap items-center gap-1.5">
          <span className="me-1 hidden items-center gap-1 text-[11px] font-semibold text-muted-foreground sm:inline-flex">
            <CalendarDays className="size-3.5" aria-hidden />
            {t('history.filter.title')}
          </span>
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={t('history.filter.title')}>
            {(['24h', '7d', 'all'] as const).map((rid) => (
              <button
                key={rid}
                type="button"
                aria-pressed={quickRange === rid && !customWindow}
                onClick={() => setQuick(rid)}
                className={cn(
                  'flex h-9 items-center rounded-md border px-2.5 py-1 text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/60',
                  quickRange === rid && !customWindow
                    ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                    : 'border-border bg-background/40 text-muted-foreground hover:bg-background/70 hover:text-foreground',
                )}
              >
                {t(`hist.range.${rid}`)}
              </button>
            ))}
          </div>
          <span aria-hidden className="mx-0.5 h-5 w-px shrink-0 self-center bg-border" />
          <Popover>
            <PopoverTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className={cn(
                  'h-9 gap-1.5 text-[11px]',
                  fromDate && 'border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
                )}
              >
                <CalendarDays className="size-3.5" aria-hidden />
                {fromDate ? <span dir="ltr" className="font-mono">{pickDay(fromDate)}</span> : t('history.range.from')}
              </Button>
            </PopoverTrigger>
            <PopoverContent align="start" className="w-auto p-0">
              <Calendar
                mode="single"
                selected={fromDate ?? undefined}
                onSelect={(d) => setFromDate(d ?? null)}
                disabled={{ after: new Date() }}
                locale={dateFnsLocale}
              />
            </PopoverContent>
          </Popover>
          <Popover>
            <PopoverTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className={cn(
                  'h-9 gap-1.5 text-[11px]',
                  toDate && 'border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
                )}
              >
                <CalendarDays className="size-3.5" aria-hidden />
                {toDate ? <span dir="ltr" className="font-mono">{pickDay(toDate)}</span> : t('history.range.to')}
              </Button>
            </PopoverTrigger>
            <PopoverContent align="start" className="w-auto p-0">
              <Calendar
                mode="single"
                selected={toDate ?? undefined}
                onSelect={(d) => setToDate(d ?? null)}
                disabled={{ after: new Date() }}
                locale={dateFnsLocale}
              />
            </PopoverContent>
          </Popover>
          {rangeActive ? (
            <>
              <Badge variant="outline" className="text-muted-foreground">
                {t('history.count', { n: num(filteredScans.length) })}
              </Badge>
              <Button
                variant="ghost"
                size="sm"
                className="h-9 gap-1 px-2 text-[11px] text-muted-foreground"
                onClick={() => {
                  setQuickRange('all')
                  setFromDate(null)
                  setToDate(null)
                }}
                aria-label={t('history.range.clear')}
              >
                <X className="size-3.5" aria-hidden />
                {t('history.range.clear')}
              </Button>
            </>
          ) : null}
        </div>
      ) : null}

      {/* Error */}
      {list.isError ? (
        <div className="mt-6 flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-red-500/30 bg-red-500/5 py-10 text-center">
          <ServerOff className="size-7 text-red-400" aria-hidden />
          <div>
            <p className="text-sm font-semibold">
              {t('history.error.title')}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {t('history.error.sub')}
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => list.refetch()}
            className="h-9"
          >
            {t('history.retry')}
          </Button>
        </div>
      ) : null}

      {/* Empty */}
      {!list.isError && !list.isLoading && scans.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-14 text-center">
          <span className="flex size-16 items-center justify-center rounded-full border border-dashed border-border bg-background/40">
            <History className="size-7 text-muted-foreground" aria-hidden />
          </span>
          <div>
            <p className="text-sm font-semibold">{t('history.empty.title')}</p>
            <p className="mt-1 text-xs text-muted-foreground">
              {t('history.empty.sub')}
            </p>
          </div>
        </div>
      ) : null}

      {/* List */}
      {scans.length > 0 && filteredScans.length === 0 ? (
        <div className="mt-5 flex h-12 items-center justify-center rounded-lg border border-dashed bg-background/40 px-3 text-center text-[11px] text-muted-foreground">
          {t('history.range.empty')}
        </div>
      ) : filteredScans.length > 0 ? (
        <div className="scrollbar-thin mt-5 max-h-96 overflow-auto rounded-lg border">
          <Table className="min-w-[560px]">
            <TableHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur">
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-start text-xs">{t('history.col.time')}</TableHead>
                <TableHead className="text-start text-xs">{t('history.col.preset')}</TableHead>
                <TableHead className="text-start text-xs">{t('history.col.port')}</TableHead>
                <TableHead className="text-start text-xs">
                  {t('history.col.alive')}
                </TableHead>
                <TableHead className="hidden text-start text-xs sm:table-cell">
                  {t('history.col.duration')}
                </TableHead>
                <TableHead className="text-start text-xs">{t('history.col.status')}</TableHead>
                <TableHead className="hidden text-start text-xs md:table-cell">
                  {t('history.col.results')}
                </TableHead>
                <TableHead className="text-start text-xs">{t('history.col.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredScans.map((scan: ScanListItem) => {
                const statusCls = STATUS_CLS[scan.status] ?? 'border-zinc-500/30 bg-zinc-500/10 text-zinc-500'
                const statusLabel = STATUS_KEY[scan.status] ? t(STATUS_KEY[scan.status]) : scan.status
                return (
                  <TableRow key={scan.id} className="transition-colors">
                    <TableCell className="text-xs">
                      <span
                        title={new Date(scan.createdAt).toLocaleString(dateLocale)}
                      >
                        {formatDistanceToNow(new Date(scan.createdAt), {
                          addSuffix: true,
                          locale: dateFnsLocale,
                        })}
                      </span>
                      {scan.label ? (
                        <span className="ms-1 block text-[10px] text-muted-foreground">
                          {scan.label}
                        </span>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-xs font-medium">
                      {presetName(scan.preset)}
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs" dir="ltr">
                        {scan.port}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs tabular-nums" dir="ltr">
                        {scan.aliveIPs}/{scan.totalIPs}
                      </span>
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      <span className="font-mono text-xs" dir="ltr">
                        {formatDurationHMS(scan.durationMs)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={cn('px-1.5 py-0 text-[10px]', statusCls)}>
                        {statusLabel}
                      </Badge>
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      <span className="font-mono text-xs font-semibold text-emerald-600 dark:text-emerald-400" dir="ltr">
                        {scan.resultCount}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8"
                          aria-label={t('history.view', { id: scan.id })}
                          onClick={() => setDetailId(scan.id)}
                        >
                          <Eye className="size-3.5" aria-hidden />
                        </Button>

                        <Button
                          variant="ghost"
                          size="icon"
                          className="hidden size-8 text-teal-600 hover:text-teal-600 dark:text-teal-400 sm:inline-flex"
                          aria-label={t('share.link.copy')}
                          title={t('share.link.copy')}
                          onClick={() => void handleCopyLink(scan.id)}
                        >
                          <Link2 className="size-3.5" aria-hidden />
                        </Button>

                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="size-8"
                              aria-label={t('history.export', { id: scan.id })}
                            >
                              <FileDown className="size-3.5" aria-hidden />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="start">
                            {(['txt', 'csv', 'json'] as const).map((fmt) => (
                              <DropdownMenuItem
                                key={fmt}
                                className="cursor-pointer justify-between gap-2"
                                onClick={() => handleExport(scan.id, fmt)}
                              >
                                <span className="font-mono" dir="ltr">
                                  .{fmt}
                                </span>
                                <span className="text-xs text-muted-foreground">
                                  {t('history.export.item')}
                                </span>
                              </DropdownMenuItem>
                            ))}
                          </DropdownMenuContent>
                        </DropdownMenu>

                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="size-8 text-red-500 hover:text-red-600"
                              aria-label={t('history.delete', { id: scan.id })}
                              disabled={deletingId === scan.id}
                            >
                              <Trash2 className="size-3.5" aria-hidden />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent dir={dir}>
                            <AlertDialogHeader>
                              <AlertDialogTitle>
                                {t('history.delete.title')}
                              </AlertDialogTitle>
                              <AlertDialogDescription>
                                {t('history.delete.desc', { preset: presetName(scan.preset) })}
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>{t('history.cancel')}</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => handleDelete(scan.id)}
                                className="bg-destructive text-white hover:bg-destructive/90"
                              >
                                {t('history.delete.confirm')}
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      ) : null}

      {/* Compare dialog */}
      <ScanCompareDialog open={compareOpen} onOpenChange={setCompareOpen} scans={scans} />

      {/* Detail dialog */}
      <Dialog
        open={!!detailId}
        onOpenChange={(open) => {
          if (!open) setDetailId(null)
        }}
      >
        <DialogContent dir={dir} className="max-h-[85vh] max-w-2xl overflow-y-auto sm:max-w-3xl">
          {detail.data ? (
            <>
              <DialogHeader>
                <DialogTitle className="flex flex-wrap items-center gap-2">
                  {t('history.detail.title')}
                  <Badge variant="outline" className={cn('text-[10px]', STATUS_CLS[detail.data.scan.status])}>
                    {STATUS_KEY[detail.data.scan.status]
                      ? t(STATUS_KEY[detail.data.scan.status])
                      : detail.data.scan.status}
                  </Badge>
                </DialogTitle>
                <DialogDescription>
                  {presetName(detail.data.scan.preset)}
                  {' · '}
                  <span dir="ltr" className="font-mono">
                    {detail.data.scan.port}
                  </span>
                  {' · '}
                  {formatDistanceToNow(new Date(detail.data.scan.createdAt), {
                    addSuffix: true,
                    locale: dateFnsLocale,
                  })}
                </DialogDescription>
              </DialogHeader>

              {/* Meta */}
              <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
                {[
                  [t('history.meta.duration'), formatDurationHMS(detail.data.scan.durationMs)],
                  [t('history.meta.alive'), `${detail.data.scan.aliveIPs}`],
                  [t('history.meta.total'), `${detail.data.scan.totalIPs}`],
                  [t('history.meta.results'), `${detail.data.scan.resultCount}`],
                  [t('history.meta.pings'), `${detail.data.scan.pingCount}`],
                  [t('history.meta.timeout'), `${detail.data.scan.timeoutMs} ms`],
                  [t('history.meta.conc'), `${detail.data.scan.concurrency}`],
                  [t('history.meta.speedtest'), `${detail.data.scan.speedTested}/${detail.data.scan.speedTestCount}`],
                ].map(([k, v]) => (
                  <div
                    key={k}
                    className="rounded-lg border bg-background/40 p-2.5"
                  >
                    <div className="text-[10px] text-muted-foreground">{k}</div>
                    <div className="mt-0.5 font-mono font-semibold" dir="ltr">
                      {v}
                    </div>
                  </div>
                ))}
              </div>

              {/* Ranges */}
              <div>
                <div className="mb-1 text-xs font-semibold text-muted-foreground">
                  {t('history.ranges')}
                </div>
                <pre
                  dir="ltr"
                  className="scrollbar-thin max-h-32 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] leading-5 text-zinc-400"
                >
                  {detail.data.scan.rangesText || '—'}
                </pre>
              </div>

              {/* Results table */}
              <div>
                <div className="mb-1 flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-muted-foreground">
                    {t('history.results', { n: num(detail.data.results.length) })}
                  </span>
                  {detail.data.results.length > 0 ? (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 gap-1.5 px-2.5 text-[11px] border-teal-500/30 text-teal-700 hover:bg-teal-500/10 hover:text-teal-700 dark:text-teal-400 dark:hover:text-teal-300"
                      onClick={() => setShareOpen(true)}
                      aria-label={t('share.aria')}
                    >
                      <Share2 className="size-3" aria-hidden />
                      {t('share.title')}
                    </Button>
                  ) : null}
                </div>
                <div className="scrollbar-thin max-h-80 overflow-y-auto rounded-lg border">
                  <Table>
                    <TableHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                      <TableRow className="hover:bg-transparent">
                        <TableHead className="text-start text-xs">{t('history.col.rank')}</TableHead>
                        <TableHead className="text-start text-xs">{t('history.col.ip')}</TableHead>
                        <TableHead className="text-start text-xs">{t('history.col.latency')}</TableHead>
                        <TableHead className="text-start text-xs">{t('history.col.loss')}</TableHead>
                        <TableHead className="text-start text-xs">{t('history.col.download')}</TableHead>
                        <TableHead className="text-start text-xs">{t('history.col.total')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {detail.data.results.map((r) => (
                        <TableRow key={r.ip}>
                          <TableCell className="font-mono text-xs tabular-nums">
                            {num(r.rank)}
                          </TableCell>
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
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center py-16">
              <RefreshCw className="size-6 animate-spin text-muted-foreground" aria-hidden />
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Share dialog (history detail) */}
      <ShareDialog
        open={shareOpen}
        onOpenChange={(v) => {
          setShareOpen(v)
          if (v && !detailId) setShareOpen(false)
        }}
        results={(detail.data?.results ?? []) as LiveResult[]}
        meta={
          detail.data
            ? {
                preset: presetName(detail.data.scan.preset),
                date: new Date(detail.data.scan.createdAt).getTime(),
                port: detail.data.scan.port,
                total: detail.data.scan.totalIPs,
                alive: detail.data.scan.aliveIPs,
              }
            : null
        }
      />
      </div>
    </div>
  )
}

/** memoized — panels only re-render when their props actually change (socket ticks re-render the page) */
export const HistoryPanel = memo(HistoryPanelInner)
