'use client'

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { faIR, enUS } from 'date-fns/locale'
import { History, Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { formatLatency } from '@/lib/scan-protocol'
import { useI18n } from '@/components/i18n-provider'
import type { DictKey } from '@/lib/i18n'
import { fetchJson } from '@/lib/api-types'

type ProbeGrade = 'excellent' | 'good' | 'weak' | 'fail'

interface ProbeRecord {
  ip: string
  host: string
  port: number
  grade: ProbeGrade
  tcpMs?: number | null
  tlsMs?: number | null
  httpStatus?: number | null
  ok: boolean
  updatedAt: string
}

const GRADE_STYLES: Record<ProbeGrade, string> = {
  excellent: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  good: 'border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400',
  weak: 'border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400',
  fail: 'border-red-500/40 bg-red-500/10 text-red-500',
}

export interface ProbeHistoryDialogProps {
  open: boolean
  onOpenChange: (v: boolean) => void
}

export function ProbeHistoryDialog({ open, onOpenChange }: ProbeHistoryDialogProps) {
  const { t, num, dir, dateLocale } = useI18n()
  const [gradeFilter, setGradeFilter] = useState<string>('all')

  const query = useQuery({
    queryKey: ['probes', 'history', gradeFilter],
    queryFn: () =>
      fetchJson<{ probes: ProbeRecord[] }>(
        `/api/probes?all=1&limit=150${gradeFilter !== 'all' ? `&grade=${gradeFilter}` : ''}`,
      ),
    enabled: open,
    staleTime: 10_000,
  })

  const probes = query.data?.probes ?? []

  const counts = useMemo(() => {
    const c: Record<ProbeGrade, number> = { excellent: 0, good: 0, weak: 0, fail: 0 }
    for (const p of probes) c[p.grade]++
    return c
  }, [probes])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-w-lg flex-col overflow-hidden" dir={dir}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-lg bg-teal-500/10 text-teal-600 dark:text-teal-400">
              <History className="size-4" aria-hidden />
            </span>
            {t('ph.title')}
          </DialogTitle>
          <DialogDescription>{t('ph.desc')}</DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-[minmax(0,1fr)] gap-3">
          <div className="flex flex-wrap items-center gap-1.5">
            {(['excellent', 'good', 'weak', 'fail'] as const).map((g) => (
              <Badge
                key={g}
                variant="outline"
                className={cn('cursor-pointer px-1.5 py-0 text-[10px]', GRADE_STYLES[g], gradeFilter === g && 'ring-1 ring-current')}
                onClick={() => setGradeFilter((prev) => (prev === g ? 'all' : g))}
                role="button"
                aria-pressed={gradeFilter === g}
              >
                <span dir="ltr">{num(counts[g])}</span> {t(`xray.grade.${g}` as DictKey)}
              </Badge>
            ))}
            <div className="ms-auto">
              <Select value={gradeFilter} onValueChange={setGradeFilter}>
                <SelectTrigger className="h-7 w-28 text-[11px]" aria-label={t('ph.filter')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('ph.all')}</SelectItem>
                  {(['excellent', 'good', 'weak', 'fail'] as const).map((g) => (
                    <SelectItem key={g} value={g}>
                      {t(`xray.grade.${g}` as DictKey)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="max-h-80 min-h-32 overflow-y-auto rounded-lg border" role="list" aria-label={t('ph.title')}>
            {query.isLoading ? (
              <div className="flex h-32 items-center justify-center">
                <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden />
              </div>
            ) : probes.length === 0 ? (
              <div className="flex h-32 items-center justify-center text-xs text-muted-foreground">
                {t('ph.empty')}
              </div>
            ) : (
              <ul className="divide-y divide-border/60">
                {probes.map((p) => (
                  <li
                    key={`${p.ip}:${p.host}:${p.port}`}
                    role="listitem"
                    className="flex items-center gap-2 px-3 py-2 text-[11px] transition-colors hover:bg-emerald-500/[0.04]"
                  >
                    <span className={cn('inline-flex items-center rounded-md border px-1 py-0 text-[9px] font-semibold', GRADE_STYLES[p.grade])}>
                      {t(`xray.grade.${p.grade}` as DictKey)}
                    </span>
                    <span className="font-mono font-semibold" dir="ltr">
                      {p.ip}
                      <span className="text-muted-foreground">:{num(p.port)}</span>
                    </span>
                    <span className="hidden min-w-0 flex-1 truncate font-mono text-[10px] text-muted-foreground sm:inline" dir="ltr">
                      {p.host}
                    </span>
                    <span className="font-mono text-[10px] text-muted-foreground" dir="ltr">
                      {p.tlsMs != null ? `TLS ${formatLatency(p.tlsMs)}` : p.tcpMs != null ? `TCP ${formatLatency(p.tcpMs)}` : '—'}
                    </span>
                    <span className="shrink-0 text-[10px] text-muted-foreground" title={new Date(p.updatedAt).toLocaleString(dateLocale)}>
                      {formatDistanceToNow(new Date(p.updatedAt), { addSuffix: true, locale: dir === 'rtl' ? faIR : enUS })}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {probes.length > 0 ? (
            <p className="text-center text-[10px] text-muted-foreground">
              {t('ph.count', { n: num(probes.length) })}
            </p>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  )
}
