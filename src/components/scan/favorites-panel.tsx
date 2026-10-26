'use client'

/**
 * FavoritesPanel — IP watchlist with real TCPing health re-checks.
 * Health status: healthy (low loss + latency) / degraded / dead.
 */

import { memo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { faIR, enUS } from 'date-fns/locale'
import { toast } from 'sonner'
import {
  Activity,
  FileDown,
  HeartPulse,
  Loader2,
  Plus,
  RefreshCw,
  ServerOff,
  Star,
  Trash2,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { fetchJson, type FavoriteItem, type FavoritesResponse } from '@/lib/api-types'
import { formatLatency, type LiveResult } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'
import { cn } from '@/lib/utils'

const STATUS_CLS: Record<string, { cls: string; dot: string }> = {
  healthy: {
    cls: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
    dot: 'bg-emerald-500',
  },
  degraded: {
    cls: 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400',
    dot: 'bg-amber-500',
  },
  dead: {
    cls: 'border-red-500/30 bg-red-500/10 text-red-500',
    dot: 'bg-red-500',
  },
}

const STATUS_KEY: Record<string, DictKey> = {
  healthy: 'fav.status.healthy',
  degraded: 'fav.status.degraded',
  dead: 'fav.status.dead',
}

interface FavoritesPanelProps {
  checkIps: (ips: string[], port: number) => Promise<LiveResult[]>
  connected: boolean
  /** default scan port (used for health checks) */
  port: number
}

function FavoritesPanelInner({ checkIps, connected, port }: FavoritesPanelProps) {
  const { t, num, lang, dir } = useI18n()
  const qc = useQueryClient()
  const [manualIp, setManualIp] = useState('')
  const [checking, setChecking] = useState(false)

  const list = useQuery<FavoritesResponse>({
    queryKey: ['favorites'],
    queryFn: () => fetchJson<FavoritesResponse>('/api/favorites'),
    retry: false,
  })

  const favorites = list.data?.favorites ?? []

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['favorites'] })
  }

  const addMutation = useMutation({
    mutationFn: async (ip: string) => {
      const res = await fetch('/api/favorites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      })
      if (!res.ok) throw new Error('HTTP error')
      return res.json()
    },
    onSuccess: (_d, ip) => {
      toast.success(t('fav.toast.add', { ip }))
      invalidate()
    },
    onError: () => toast.error(t('fav.toast.add.error')),
  })

  const removeMutation = useMutation({
    mutationFn: async (ip: string) => {
      const res = await fetch(`/api/favorites/${encodeURIComponent(ip)}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('HTTP error')
      return res.json()
    },
    onSuccess: (_d, ip) => {
      toast.success(t('fav.toast.remove', { ip }))
      invalidate()
    },
    onError: () => toast.error(t('fav.toast.remove.error')),
  })

  const handleCheckAll = async () => {
    if (checking) return
    if (favorites.length === 0) {
      toast.error(t('fav.toast.none'))
      return
    }
    if (!connected) {
      toast.error(t('fav.toast.offline'))
      return
    }
    setChecking(true)
    try {
      const results = await checkIps(
        favorites.map((f) => f.ip),
        port,
      )
      if (results.length === 0) {
        toast.error(t('fav.toast.engine.fail'))
        return
      }
      const res = await fetch('/api/favorites', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ results }),
      })
      if (!res.ok) throw new Error('HTTP error')
      const healthy = results.filter((r) => r.received > 0).length
      toast.success(
        t('fav.toast.check.ok', {
          total: num(results.length),
          ok: num(healthy),
          dead: num(results.length - healthy),
        }),
      )
      invalidate()
    } catch {
      toast.error(t('fav.toast.check.fail'))
    } finally {
      setChecking(false)
    }
  }

  const handleCheckOne = async (ip: string) => {
    if (!connected) {
      toast.error(t('fav.toast.offline'))
      return
    }
    try {
      const results = await checkIps([ip], port)
      const r = results[0]
      if (!r) {
        toast.error(t('fav.toast.one.fail'))
        return
      }
      await fetch('/api/favorites', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ results: [r] }),
      })
      if (r.received > 0) {
        toast.success(t('fav.toast.one.ok', { ip, lat: formatLatency(r.latencyMs) }))
      } else {
        toast.info(t('fav.toast.one.dead', { ip }))
      }
      invalidate()
    } catch {
      toast.error(t('fav.toast.one.fail'))
    }
  }

  const handleAddManual = () => {
    const ip = manualIp.trim()
    if (!ip) return
    if (!/^[0-9a-fA-F.:]+$/.test(ip)) {
      toast.error(t('fav.toast.invalid'))
      return
    }
    addMutation.mutate(ip)
    setManualIp('')
  }

  const handleExportCsv = () => {
    if (favorites.length === 0) return
    const esc = (v: string | number | null | undefined) => {
      const s = v == null ? '' : String(v)
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
    }
    const header = [
      'ip',
      'label',
      'note',
      'status',
      'latency_ms',
      'loss_rate',
      'checks_count',
      'added_at',
      'last_check_at',
    ].join(',')
    const rows = favorites.map((f) =>
      [
        f.ip,
        f.label ?? '',
        f.note ?? '',
        f.lastStatus ?? '',
        f.lastLatencyMs ?? '',
        f.lastLossRate ?? '',
        f.checksCount,
        f.addedAt,
        f.lastCheckAt ?? '',
      ]
        .map(esc)
        .join(','),
    )
    // BOM so Excel renders UTF-8 (Persian labels/notes) correctly
    const csv = '\uFEFF' + [header, ...rows].join('\r\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `clean-ip-favorites-${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    toast.success(t('fav.toast.csv', { n: num(favorites.length) }))
  }

  const dateFnsLocale = lang === 'fa' ? faIR : enUS

  return (
    <div className="rounded-xl border bg-card/60 p-4 backdrop-blur sm:p-6">
      {/* Title + actions */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="flex size-8 items-center justify-center rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-400">
            <Star className="size-4" aria-hidden />
          </span>
          <h2 className="text-base font-bold">{t('fav.title')}</h2>
          {favorites.length > 0 ? (
            <Badge variant="outline" className="text-muted-foreground">
              <span dir="ltr">{num(favorites.length)}</span> IP
            </Badge>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1">
            <Input
              value={manualIp}
              onChange={(e) => setManualIp(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleAddManual()
              }}
              placeholder={t('fav.add.placeholder')}
              dir="ltr"
              className="h-9 w-40 font-mono text-xs"
              aria-label={t('fav.add.aria')}
            />
            <Button
              variant="outline"
              size="icon"
              className="size-9 shrink-0"
              onClick={handleAddManual}
              disabled={!manualIp.trim() || addMutation.isPending}
              aria-label={t('fav.add.btn')}
            >
              <Plus className="size-4" aria-hidden />
            </Button>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="h-9 gap-1.5"
            onClick={handleExportCsv}
            disabled={favorites.length === 0}
            title={t('fav.csv.title')}
          >
            <FileDown className="size-3.5" aria-hidden />
            {t('fav.csv')}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-9 gap-1.5"
            onClick={handleCheckAll}
            disabled={checking || favorites.length === 0 || !connected}
            title={t('fav.checkall.title')}
          >
            {checking ? (
              <Loader2 className="size-3.5 animate-spin" aria-hidden />
            ) : (
              <HeartPulse className="size-3.5" aria-hidden />
            )}
            {t('fav.checkall')}
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-9"
            onClick={() => list.refetch()}
            disabled={list.isFetching}
            aria-label={t('fav.refresh.aria')}
          >
            <RefreshCw className={cn('size-3.5', list.isFetching && 'animate-spin')} aria-hidden />
          </Button>
        </div>
      </div>

      {/* Error */}
      {list.isError ? (
        <div className="mt-6 flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-red-500/30 bg-red-500/5 py-10 text-center">
          <ServerOff className="size-7 text-red-400" aria-hidden />
          <p className="text-sm font-semibold">{t('fav.error.title')}</p>
          <Button variant="outline" size="sm" onClick={() => list.refetch()} className="h-9">
            {t('fav.retry')}
          </Button>
        </div>
      ) : null}

      {/* Empty */}
      {!list.isError && !list.isLoading && favorites.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-14 text-center">
          <span className="flex size-16 items-center justify-center rounded-full border border-dashed border-border bg-background/40">
            <Star className="size-7 text-muted-foreground" aria-hidden />
          </span>
          <div>
            <p className="text-sm font-semibold">{t('fav.empty.title')}</p>
            <p className="mt-1 max-w-xs text-xs text-muted-foreground">
              {t('fav.empty.sub')}
            </p>
          </div>
        </div>
      ) : null}

      {/* List */}
      {favorites.length > 0 ? (
        <div className="scrollbar-thin mt-5 max-h-96 overflow-auto rounded-lg border">
          <Table className="min-w-[480px]">
            <TableHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur">
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-start text-xs">{t('fav.col.ip')}</TableHead>
                <TableHead className="text-start text-xs">{t('fav.col.status')}</TableHead>
                <TableHead className="text-start text-xs">{t('fav.col.latency')}</TableHead>
                <TableHead className="hidden text-start text-xs sm:table-cell">{t('fav.col.lastcheck')}</TableHead>
                <TableHead className="hidden text-start text-xs md:table-cell">{t('fav.col.checks')}</TableHead>
                <TableHead className="text-start text-xs">{t('fav.col.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {favorites.map((f: FavoriteItem) => {
                const statusMeta = STATUS_CLS[f.lastStatus ?? ''] ?? null
                const statusLabel = STATUS_KEY[f.lastStatus ?? ''] ? t(STATUS_KEY[f.lastStatus ?? '']) : null
                return (
                  <TableRow key={f.id} className="group transition-colors">
                    <TableCell dir="ltr" className="text-left font-mono text-xs font-medium">
                      {f.ip}
                    </TableCell>
                    <TableCell>
                      {statusMeta && statusLabel ? (
                        <Badge variant="outline" className={cn('gap-1.5 px-1.5 py-0 text-[10px]', statusMeta.cls)}>
                          <span className={cn('size-1.5 animate-pulse rounded-full', statusMeta.dot)} aria-hidden />
                          {statusLabel}
                        </Badge>
                      ) : (
                        <span className="text-[10px] text-muted-foreground/60">{t('fav.unchecked')}</span>
                      )}
                    </TableCell>
                    <TableCell dir="ltr" className="text-left font-mono text-xs tabular-nums">
                      {f.lastLatencyMs != null && f.lastLatencyMs > 0
                        ? formatLatency(f.lastLatencyMs)
                        : '—'}
                      {f.lastLossRate != null && f.lastLossRate > 0 ? (
                        <span className="ms-1 text-[10px] text-muted-foreground" dir="ltr">
                          ({(f.lastLossRate * 100).toFixed(0)}% loss)
                        </span>
                      ) : null}
                    </TableCell>
                    <TableCell className="hidden text-xs text-muted-foreground sm:table-cell">
                      {f.lastCheckAt
                        ? formatDistanceToNow(new Date(f.lastCheckAt), {
                            addSuffix: true,
                            locale: dateFnsLocale,
                          })
                        : '—'}
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      <span className="font-mono text-xs tabular-nums text-muted-foreground" dir="ltr">
                        {num(f.checksCount)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <TooltipProvider delayDuration={150}>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="size-8"
                                onClick={() => handleCheckOne(f.ip)}
                                disabled={checking || !connected}
                                aria-label={t('fav.check.aria', { ip: f.ip })}
                              >
                                <HeartPulse className="size-3.5" aria-hidden />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>{t('fav.check.tooltip')}</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="size-8 text-red-500 hover:text-red-600"
                              aria-label={t('fav.delete.aria', { ip: f.ip })}
                            >
                              <Trash2 className="size-3.5" aria-hidden />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent dir={dir}>
                            <AlertDialogHeader>
                              <AlertDialogTitle>{t('fav.delete.title')}</AlertDialogTitle>
                              <AlertDialogDescription>
                                <span className="font-mono" dir="ltr">
                                  {f.ip}
                                </span>{' '}
                                {t('fav.delete.desc', { ip: '' })}
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>{t('fav.cancel')}</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => removeMutation.mutate(f.ip)}
                                className="bg-destructive text-white hover:bg-destructive/90"
                              >
                                {t('fav.delete.confirm')}
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

      {/* hint */}
      {favorites.length > 0 ? (
        <p className="mt-3 flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <Activity className="size-3" aria-hidden />
          {t('fav.hint', { port: num(port) })}
        </p>
      ) : null}
    </div>
  )
}

/** memoized — panels only re-render when their props actually change (socket ticks re-render the page) */
export const FavoritesPanel = memo(FavoritesPanelInner)
